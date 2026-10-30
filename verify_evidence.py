"""Verify a CipherVault chain-of-custody JSON bundle without an account or network."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def decoded(value):
    if not isinstance(value, str):
        raise ValueError('Missing encoded evidence.')
    return base64.b64decode(value, validate=True)


def event_hash(event):
    return hashlib.sha256(decoded(event['message']) + decoded(event['signature'])).hexdigest()


def signed_event(event, label):
    public_bytes = decoded(event['public_key'])
    if hashlib.sha256(public_bytes).hexdigest() != event['fingerprint']:
        raise ValueError(f'{label} fingerprint mismatch.')
    public = serialization.load_der_public_key(public_bytes)
    if not isinstance(public, rsa.RSAPublicKey) or not 2048 <= public.key_size <= 4096:
        raise ValueError(f'{label} key is unsupported.')
    message = decoded(event['message'])
    try:
        public.verify(decoded(event['signature']), message,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA256())
    except InvalidSignature as exc:
        raise ValueError(f'{label} signature is invalid.') from exc
    return json.loads(message.decode('utf-8'))


def verify(bundle):
    if bundle.get('format') != 'CipherVault chain of custody' or bundle.get('version') != 1:
        raise ValueError('Unsupported evidence bundle.')
    sender = bundle['sender']
    manifest = signed_event(sender, 'Sender')
    if manifest['id'] != bundle['transfer_id'] or not all(manifest.get(key) for key in
        ('sender_id', 'recipient_id', 'package_sha256', 'original_sha256')):
        raise ValueError('Sender manifest does not match this transfer.')
    previous = event_hash(sender)
    receiver = bundle.get('receiver')
    if receiver:
        receipt = signed_event(receiver, 'Receiver')
        expected = {'version': 1, 'transfer_id': manifest['id'], 'recipient_id': manifest['recipient_id'],
                    'manifest_sha256': hashlib.sha256(decoded(sender['message'])).hexdigest(),
                    'sender_event_sha256': previous, 'package_sha256': manifest['package_sha256'],
                    'recovered_sha256': manifest['original_sha256']}
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise ValueError('Receiver event breaks the chain.')
        previous = event_hash(receiver)
    verifiers = bundle.get('verifiers', [])
    if not isinstance(verifiers, list):
        raise ValueError('Invalid verifier list.')
    for verifier in verifiers:
        claim = signed_event(verifier, 'Verifier')
        if claim.get('version') != 1 or claim.get('transfer_id') != manifest['id'] or \
           claim.get('previous_event_sha256') != previous or claim.get('action') != 'verified evidence bundle' or \
           not claim.get('verifier_id'):
            raise ValueError('Verifier event breaks the chain.')
        previous = event_hash(verifier)
    return {'transfer_id': manifest['id'], 'sender_signature': 'valid',
            'receiver_signature': 'valid' if receiver else 'absent', 'verifier_signatures': len(verifiers),
            'sender_fingerprint': sender['fingerprint'],
            'receiver_fingerprint': receiver['fingerprint'] if receiver else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    try:
        if args.bundle.stat().st_size > 50_000:
            raise ValueError('Evidence bundle is too large.')
        result = verify(json.loads(args.bundle.read_text(encoding='utf-8')))
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        parser.exit(1, f'Evidence verification failed: {exc}\n')
    print(json.dumps(result, indent=2))
    print('Compare the fingerprints through a trusted channel. Device timestamps are claims.')


if __name__ == '__main__':
    main()
