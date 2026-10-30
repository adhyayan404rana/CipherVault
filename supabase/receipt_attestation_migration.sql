-- Run once in an existing hosted Supabase project after deploying signed receipts.
create or replace function public.cv_receipt(p_id uuid,p_receipt jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare t public.cv_transfers; field text;
begin
  select * into t from public.cv_transfers where id=p_id and recipient_id=auth.uid() and status='sent' and expires_at>now() for update;
  if not found or jsonb_typeof(p_receipt)<>'object'
     or not (p_receipt ?& array['sha256','signature_valid','network_seconds','decrypt_seconds','aes_seconds','hash_seconds','signature_seconds','receive_seconds','recovered_at','recorded_at','attestation_message','attestation_signature','recipient_public_key','recipient_fingerprint'])
     or p_receipt->>'sha256'<>t.manifest->>'original_sha256' or p_receipt->'signature_valid'<>'true'::jsonb
     or (select count(*) from jsonb_object_keys(p_receipt))<>14 then raise exception 'Receipt denied'; end if;
  foreach field in array array['network_seconds','decrypt_seconds','aes_seconds','hash_seconds','signature_seconds','receive_seconds'] loop
    if jsonb_typeof(p_receipt->field)<>'number' or (p_receipt->>field)::float8 not between 0 and 3600 then raise exception 'Invalid receipt timing'; end if;
  end loop;
  if length(p_receipt->>'recovered_at')>40 or p_receipt->>'recovered_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' then raise exception 'Invalid recovery timestamp'; end if;
  perform (p_receipt->>'recovered_at')::timestamptz;
  update public.cv_transfers set status='verified',receipt=p_receipt||jsonb_build_object('recorded_at',now()) where id=p_id;
end $$;
