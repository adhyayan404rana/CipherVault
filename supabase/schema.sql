-- Run once in Supabase SQL Editor. No service-role key is needed by the application.
create table public.cv_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check(username ~ '^[A-Za-z0-9_-]{3,32}$'),
  public_key text not null check(length(public_key) between 400 and 2000),
  fingerprint text not null check(fingerprint ~ '^[0-9a-f]{64}$')
);
create table public.cv_private_keys (
  user_id uuid primary key references public.cv_profiles(user_id) on delete cascade,
  wrapped_key jsonb not null check(pg_column_size(wrapped_key)<10000)
);
create table public.cv_transfers (
  id uuid primary key,
  sender_id uuid not null references public.cv_profiles(user_id),
  recipient_id uuid not null references public.cv_profiles(user_id),
  manifest jsonb not null,
  message text not null check(length(message)<4096),
  signature text not null check(length(signature)=512),
  public_key text not null,
  fingerprint text not null,
  object_path text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now()+interval '24 hours'),
  timings jsonb not null check(pg_column_size(timings)<2048),
  upload_seconds double precision check(upload_seconds between 0 and 3600),
  status text not null default 'draft' check(status in ('draft','sent','verified')),
  receipt jsonb,
  check(sender_id<>recipient_id),
  check(object_path=sender_id::text||'/'||id::text||'.cvault'),
  check(expires_at>created_at and expires_at<=created_at+interval '24 hours'),
  check((manifest->>'size_bytes')::bigint between 0 and 20971520),
  check((manifest->>'package_bytes')::bigint between 25 and 20975616),
  check(manifest->>'original_sha256' ~ '^[0-9a-f]{64}$'),
  check(manifest->>'package_sha256' ~ '^[0-9a-f]{64}$'),
  check(manifest->>'id'=id::text and manifest->>'sender_id'=sender_id::text and manifest->>'recipient_id'=recipient_id::text)
);
create index cv_transfers_sender on public.cv_transfers(sender_id,created_at desc);
create index cv_transfers_recipient on public.cv_transfers(recipient_id,created_at desc);
create table public.cv_results (
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check(kind in ('benchmarks','avalanche','lengths','password_lengths','hash_resistance','vault_metrics','hash_metrics','signature_metrics')),
  value jsonb not null check(pg_column_size(value)<250000),
  primary key(user_id,kind)
);
create table public.cv_compute_limits (
  user_id uuid primary key references auth.users(id) on delete cascade,
  used integer not null default 0,
  reset_at timestamptz not null
);

alter table public.cv_profiles enable row level security;
alter table public.cv_private_keys enable row level security;
alter table public.cv_transfers enable row level security;
alter table public.cv_results enable row level security;
alter table public.cv_compute_limits enable row level security;
revoke all on public.cv_profiles,public.cv_private_keys,public.cv_transfers,public.cv_results,public.cv_compute_limits from anon,authenticated;
grant select on public.cv_profiles,public.cv_private_keys to authenticated;
grant select,insert,delete on public.cv_transfers to authenticated;
grant select,insert,update,delete on public.cv_results to authenticated;
create policy cv_directory on public.cv_profiles for select to authenticated using(true);
create policy cv_own_wrapped_key on public.cv_private_keys for select to authenticated using(user_id=auth.uid());
create policy cv_participant_read on public.cv_transfers for select to authenticated
  using(sender_id=auth.uid() or (recipient_id=auth.uid() and status in ('sent','verified')));
create policy cv_sender_insert on public.cv_transfers for insert to authenticated with check(
  sender_id=auth.uid() and status='draft' and receipt is null and upload_seconds is null
  and created_at between now()-interval '1 minute' and now()+interval '1 minute'
  and public_key=(select p.public_key from public.cv_profiles p where p.user_id=auth.uid())
  and fingerprint=(select p.fingerprint from public.cv_profiles p where p.user_id=auth.uid())
  and (select count(*) from public.cv_transfers t where t.sender_id=auth.uid())<100
);
create policy cv_sender_delete on public.cv_transfers for delete to authenticated using(sender_id=auth.uid());
create policy cv_own_results on public.cv_results for all to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());

-- Atomic immutable public identity + owner-only encrypted private key.
create function public.cv_enroll(p_username text,p_public_key text,p_fingerprint text,p_wrapped_key jsonb)
returns void language plpgsql security definer set search_path='' as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_wrapped_key->>'iterations'<>'600000' or length(p_wrapped_key->>'ciphertext')>6000
     or p_wrapped_key->>'salt' is null or p_wrapped_key->>'nonce' is null then
    raise exception 'Invalid encrypted signing identity';
  end if;
  insert into public.cv_profiles values(auth.uid(),p_username,p_public_key,p_fingerprint);
  insert into public.cv_private_keys values(auth.uid(),p_wrapped_key);
end $$;

-- Publishing requires an uploaded object of the expected size. No client UPDATE grants.
create function public.cv_publish(p_id uuid,p_upload_seconds double precision)
returns void language plpgsql security definer set search_path='' as $$
declare t public.cv_transfers;
begin
  select * into t from public.cv_transfers where id=p_id and sender_id=auth.uid() and status='draft' and expires_at>now() for update;
  if not found or p_upload_seconds is null or p_upload_seconds<0 or p_upload_seconds>3600 or p_upload_seconds='NaN'::float8 then raise exception 'Publish denied'; end if;
  if not exists(select 1 from storage.objects o where o.bucket_id='cipher-packages' and o.name=t.object_path and (o.metadata->>'size')::bigint=(t.manifest->>'package_bytes')::bigint) then raise exception 'Encrypted upload incomplete'; end if;
  update public.cv_transfers set status='sent',upload_seconds=p_upload_seconds where id=p_id;
end $$;

-- One acknowledgement per recipient. Does not accept plaintext or arbitrary row updates.
create function public.cv_receipt(p_id uuid,p_receipt jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare t public.cv_transfers; field text;
begin
  select * into t from public.cv_transfers where id=p_id and recipient_id=auth.uid() and status='sent' and expires_at>now() for update;
  if not found or jsonb_typeof(p_receipt)<>'object'
     or not (p_receipt ?& array['sha256','signature_valid','network_seconds','decrypt_seconds','aes_seconds','hash_seconds','signature_seconds','receive_seconds','recovered_at','recorded_at'])
     or p_receipt->>'sha256'<>t.manifest->>'original_sha256' or p_receipt->'signature_valid'<>'true'::jsonb
     or (select count(*) from jsonb_object_keys(p_receipt))<>10 then raise exception 'Receipt denied'; end if;
  foreach field in array array['network_seconds','decrypt_seconds','aes_seconds','hash_seconds','signature_seconds','receive_seconds'] loop
    if jsonb_typeof(p_receipt->field)<>'number' or (p_receipt->>field)::float8 not between 0 and 3600 then raise exception 'Invalid receipt timing'; end if;
  end loop;
  if length(p_receipt->>'recovered_at')>40 or p_receipt->>'recovered_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' then raise exception 'Invalid recovery timestamp'; end if;
  perform (p_receipt->>'recovered_at')::timestamptz;
  update public.cv_transfers set status='verified',receipt=p_receipt||jsonb_build_object('recorded_at',now()) where id=p_id;
end $$;

create function public.cv_compute_slot() returns void language plpgsql security definer set search_path='' as $$
declare used_now integer;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  insert into public.cv_compute_limits values(auth.uid(),1,now()+interval '5 minutes')
  on conflict(user_id) do update set used=case when public.cv_compute_limits.reset_at<now() then 1 else public.cv_compute_limits.used+1 end,
    reset_at=case when public.cv_compute_limits.reset_at<now() then now()+interval '5 minutes' else public.cv_compute_limits.reset_at end
  returning used into used_now;
  if used_now>30 then raise exception 'Compute limit reached. Wait five minutes'; end if;
end $$;
revoke all on function public.cv_enroll(text,text,text,jsonb),public.cv_publish(uuid,double precision),public.cv_receipt(uuid,jsonb),public.cv_compute_slot() from public,anon;
grant execute on function public.cv_enroll(text,text,text,jsonb),public.cv_publish(uuid,double precision),public.cv_receipt(uuid,jsonb),public.cv_compute_slot() to authenticated;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('cipher-packages','cipher-packages',false,20975616,array['application/octet-stream']);
create policy cv_cipher_insert on storage.objects for insert to authenticated with check(
  bucket_id='cipher-packages' and exists(select 1 from public.cv_transfers t where t.object_path=name and t.sender_id=auth.uid() and t.status='draft' and t.expires_at>now())
);
create policy cv_cipher_read on storage.objects for select to authenticated using(
  bucket_id='cipher-packages' and exists(select 1 from public.cv_transfers t where t.object_path=name and t.expires_at>now()
    and (t.sender_id=auth.uid() or (t.recipient_id=auth.uid() and t.status in ('sent','verified'))))
);
create policy cv_cipher_delete on storage.objects for delete to authenticated using(
  bucket_id='cipher-packages' and exists(select 1 from public.cv_transfers t where t.object_path=name and t.sender_id=auth.uid())
);
-- No storage UPDATE policy: upload tokens cannot overwrite existing ciphertext.
-- Expiry blocks new reads; sender deletion removes stored bytes. Signed download URLs
-- remain usable for at most 60 seconds. Schedule storage cleanup separately if desired.
