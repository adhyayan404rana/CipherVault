# CipherVault

Secure File Transfer and Cryptographic Performance Analysis with an AI Assistant.
A runnable college project using Python 3.11+, Streamlit, cryptography, Pandas and Matplotlib.
The original synopsis PDF is preserved.

**New: accounts and hosted transfers.** Run `.\.venv\Scripts\python.exe hosted_app.py`
and open **http://localhost:8502** in normal/incognito windows to test two accounts.
The existing Streamlit dashboard remains on port 8501. See [HOSTING.md](HOSTING.md)
for the account demo, Supabase setup and Vercel deployment instructions.

## Install and launch (Windows PowerShell)

```powershell
Set-Location 'C:\IS Lab Project'
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://localhost:8501`. Activation is optional; these commands avoid PowerShell
execution-policy changes. Use the Windows `py` launcher if `python` resolves to an
MSYS interpreter without pip. Stop Streamlit with Ctrl+C. Streamlit binds to localhost;
only the explicitly started transfer receiver binds to the LAN.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Features and architecture

- `crypto_service.py`: AES-256-GCM, validated packages, password derivation, SHA-256,
  RSA-PSS with SHA-256, encrypted private-key exports and an isolated avalanche experiment.
- `app.py`: seven dashboard sections, upload/download workflows, immediate measured timings.
- `transfer_service.py` and `receiver/`: an on-demand standard-library HTTPS server and
  browser receiver; no additional backend framework or build pipeline.
- `storage_service.py`: standard-library SQLite saves measurements, public signatures
  and encrypted packages between browser refreshes; no plaintext or private-key storage.
- `benchmark_service.py`: verified measurements, three trials, medians, graphs and CSV.
- `ai_service.py`: optional real Gemini REST requests; account model discovery or configured model.
- `tests/`: crypto, format validation, HTTPS loopback transfer, replay, expiry, benchmarks,
  and stubbed AI request-contract tests. Stubbed tests are not live provider verification.
  Optional Node 22+ tests execute the actual receiver JavaScript with Web Crypto and
  real HTTPS requests through a minimal DOM adapter; these do not test a physical phone UI.

## File encryption and recovery

### Ready-to-use demo files

The `demo_files/` folder contains `demo.txt` and `demo_key.key`. In **File vault**,
choose **Key file**, upload both files, encrypt, and download the package. Decrypt
with the same key file. Alternatively, choose **Password** and use the same password
for encryption and recovery. Existing password packages still require their original password.

Key files must contain exactly 32 raw bytes (256 bits), not hexadecimal text or RSA PEM.
The supplied key is for demonstrations only and is excluded from Git. Keep real key
files securely stored and separate from encrypted packages. Keys are never bundled
with ciphertext or saved in the results database. Device transfer uses passwords.

In **File Encryption and Decryption**, upload any file up to 20 MiB, including an empty
file. Use a strong password of at least 12 characters (prefer a randomly generated long
passphrase), encrypt, then download the `.cvault` package. Keep the password separately.
On Decrypt, upload that package and enter the password. Wrong passwords or modified
headers, ciphertext or tags fail authentication; no new plaintext download is released.
Successful recovery displays the authenticated original hash and downloads the original bytes.

File vault also shows a processing-time bar chart after each encryption/decryption.
Below the Encrypt/Decrypt tabs, **Plaintext size vs encryption & decryption time** plots successful
saved operations by original file size, with raw AES and complete workflow timings
separate, with password and key-file results labelled independently. Both use AES-256;
password workflow timings include password derivation overhead. Encrypt/decrypt files
of different sizes to build the curves. **Run File
vault size benchmark** generates actual six-size measurements without uploading a file;
the **Graph data** selector switches between file operations and benchmark medians
when both exist. Running the benchmark automatically selects its results and shows
separate encryption and decryption graphs. **Run password character-length analysis**
compares 12, 16, 24, 32 and 64 ASCII password characters using identical 1 MiB
plaintext and three trials per length. These workflow curves include password derivation;
raw AES and derivation timings are separate in the table and CSV. All passwords derive
256-bit AES keys, so longer passwords do not add AES rounds. Results survive refresh.
The Analysis lab separately compares actual AES-128/192/256 key sizes. Timings export as CSV.
Failed operations are not plotted as successes.

The binary format is `CVLT1` + 4-byte big-endian JSON-header length + UTF-8 JSON header +
ciphertext + 16-byte GCM tag. The full prefix/header is authenticated additional data.
Metadata records the algorithm, version, safe filename, original length, hash,
12-byte nonce and fixed KDF parameters. Password packages have a fresh 16-byte salt
and 32-byte AES keys derived with
PBKDF2-HMAC-SHA256, 600,000 iterations; this established password KDF is supported by
both Python and browser Web Crypto. A fresh random salt and nonce are generated for
every password package. Key-file packages use `RAW-KEY`, zero iterations and an empty
salt; every encryption still generates a fresh nonce. The parser rejects unsupported parameters before deriving a key,
preventing attacker-selected unbounded KDF work. Packages never contain passwords or keys.

Encryption/decryption workflow timing includes KDF, validation and hashing; raw AES
time and hashing time are also displayed separately. The original password or key file is needed again after
restart; no encryption key is silently regenerated for an existing file.

## Hashes and signatures

In **Hashing and Digital Signatures**, hash an uploaded file, compare two files by hash
and byte equality (including original and recovered files), or change one byte and
observe the new hash. A hash does not establish sender authenticity. Small demonstrations
do not prove SHA-256 preimage, second-preimage or collision resistance.

Generate a 3072-bit RSA key pair, sign a file, and export the signature and public PEM.
Verify with the file, `.sig` and a separately trusted public PEM. Selecting changed
content or another key demonstrates verification failure. RSA-PSS operates on a SHA-256
prehash via the library's Prehashed interface; hashing and RSA operation times are
separate. RSA does not encrypt files. Private keys live in Streamlit session memory;
optional private-key downloads use password-encrypted PKCS#8. Keep the key session open
or export it before refreshing/restarting. This MVP does not import private keys or provide a key store.

## Results after browser refresh

The app saves the selected page, latest encrypted packages, previous decryption
measurements, File vault timing history, hashes/comparisons, signatures/public keys,
verification outcomes and benchmark/analysis graphs in `local_data/results.sqlite3`.
They return after a browser refresh or app restart. This folder is excluded from Git.
**Saved results → Clear saved results** in the sidebar removes these saved outputs.

Passwords, AES key files, API keys, private RSA/TLS keys, recovered plaintext and transfer tokens
are never saved to this database. After refreshing, Decrypt shows your previous
measurements but requires the original password or key file again before releasing a recovered
download. The last successfully decrypted encrypted package is retained, so another
upload is optional. Hash-analysis plaintext examples are omitted from saved results;
their graphs and digest measurements remain. AI responses remain session-only.

An already-running receiver stays in process memory and a refreshed browser reattaches
to it. Refresh does not automatically start a receiver. App restart stops the process;
you must start the receiver again and provision its new certificate and token. Private
RSA signing keys remain session-only; existing signatures and their public keys persist.

This is one local workspace shared by browser tabs using this app on this OS account;
there is no multi-user login. Protect the OS account and project folder. Filenames,
hashes, public signatures and measurements are readable metadata in the local database;
file contents are retained only as authenticated ciphertext. Results already lost before
this persistence feature was introduced cannot be recovered automatically.

## Two-device HTTPS demonstration

1. Connect both devices to the same trusted private network. Guest Wi-Fi may isolate clients.
2. On the sender run `ipconfig` and find the Wi-Fi adapter's IPv4 address, such as
   `192.168.1.20`. In **Device-to-Device Transfer**, confirm that address and port 8765,
   then start the receiver. Do not expose it through router port forwarding.
3. Download the session receiver certificate. Transfer this **public certificate**
   to the receiver through a trusted channel, and compare its SHA-256 fingerprint with
   the one shown on the sender. Certificate trust must be set up before entering tokens
   or passwords. A new certificate is created each time the receiver server starts.
4. Trust this certificate on the receiver (see below), then open the displayed URL,
   for example `https://192.168.1.20:8765/`. A certificate-warning bypass alone is
   browser-dependent and may not enable Web Crypto. The page explains if cryptography
   is unavailable; it never falls back to insecure or simulated decryption.
5. Copy the **Signing-key fingerprint** shown on the sender into the corresponding
   receiver input, through a trusted channel. This is distinct from the TLS certificate
   fingerprint. It anchors the RSA-PSS transfer signature to the sender key you trust.
   On the sender choose a small file, enter a strong password and click **Encrypt and
   publish single-use transfer**. Give the receiver the token. Provision the password
   separately, for example verbally in person or via a separately authenticated channel;
   do not bundle it with the package or token. Verify whom you give it to.
6. On the receiver enter token and password, then click **Receive and decrypt**.
   The browser downloads ciphertext over HTTPS, derives the AES key locally, authenticates,
   verifies the RSA-PSS signed manifest and package digest against the trusted signing
   key, decrypts, checks the authenticated sender hash and offers the recovered download.
   The password is never included in a receiver network request.
7. On the sender click **Refresh receiver receipt** to see matching hash and measured
   network/decryption/total timings. Compare the downloaded bytes/hash with the original
   in the Hashing section if desired. Stop the receiver when finished.

### What the demonstration displays

The sender shows a session-only plaintext preview (first 512 bytes), a hexadecimal
ciphertext preview (first 256 bytes), original SHA-256, publication timestamp,
signature and measured encryption/hash/signing durations. The signature is over a
JSON manifest binding the encrypted package SHA-256, original file SHA-256, filename
and sender UTC timestamp. Download the manifest, signature and signing public key
together for later verification; this signature is not directly over `demo.txt`.

The receiver releases a decrypted preview/download only after the trusted-key
RSA-PSS check, AES-GCM authentication and original/recovered hash comparison all pass.
It displays success, both hashes, signature verification, sender/receiver timestamps,
network/decryption/hash/signature timings and throughput. Preview content is text
or hexadecimal and is never executed. Plaintext never goes back in the receipt.
The sender shows **File successfully transferred and recovered** when a receiver
receipt reports both matching hashes and successful signature verification.
Receipts remain client reports; device clocks are not a trusted timestamp authority.
Signing keys are held only in memory and are regenerated when the receiver restarts;
verify the new signing fingerprint and TLS certificate before another session.

Tokens are random 256-bit capabilities, expire after five minutes and allow one claim.
A separate, expiring single-use receipt token reports the recovered hash and timings.
Publishing again revokes outstanding transfer/receipt tokens. A failed decryption or
interrupted download consumes the token; publish a new transfer to retry.

### Certificate trust

Only trust a certificate whose fingerprint you verified. Remove it after the demo.

- Windows receiver: save the PEM as `ciphervault-receiver.pem`, then run:

  ```powershell
  certutil -user -addstore Root .\ciphervault-receiver.pem
  ```

  Remove the certificate afterward using **Manage user certificates** → Trusted Root
  Certification Authorities → Certificates → CipherVault local demo. Some managed
  devices prohibit user trust changes; use a permitted laptop in that case.
- Android: install the certificate using Settings → Security → Encryption & credentials
  → Install a certificate → CA certificate (wording varies). Chrome generally uses the
  system trust store; confirm the receiver page reports a secure connection.
- iOS: install the certificate profile, then enable its trust under Settings → General
  → About → Certificate Trust Settings. Remove the profile after the demonstration.
- If a phone expects DER `.cer` instead of PEM, convert the public certificate on Windows:

  ```powershell
  certutil -decode .\ciphervault-receiver.pem .\ciphervault-receiver.cer
  ```

The temporary TLS private key is written as encrypted PKCS#8 in the current user's OS
temporary directory for Python's TLS loader and deleted on an orderly receiver stop.
Its random wrapping password is held in memory only during setup and discarded after
TLS loading. Protect the OS account and temp directory. A crash can leave an encrypted
temporary file behind. The password-derived **file key** is never written by the transfer service.
This session certificate is for a controlled demo, not a production certificate authority.

### Windows private-network firewall

Set your trusted Wi-Fi connection's network profile to **Private** in Windows Settings.
If the receiver is blocked, run this narrowly scoped rule in an Administrator PowerShell:

```powershell
New-NetFirewallRule -DisplayName 'CipherVault Demo HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 -Profile Private -RemoteAddress LocalSubnet
```

Remove it after the demo:

```powershell
Remove-NetFirewallRule -DisplayName 'CipherVault Demo HTTPS'
```

Do not disable Windows Firewall or allow this receiver on Public networks. This app does
not modify firewall rules automatically. Binding to `0.0.0.0` also listens on other
interfaces; the private-profile/local-subnet firewall restriction is necessary.
HTTPS protects requests in transit only when the certificate is properly trusted.
Network observers can still see addresses, packet sizes and traffic timing. Same Wi-Fi
does not prove identity. There is no insecure HTTP receiver mode.

## Performance and avalanche analysis

In **Performance Dashboard**, run the benchmark. Default sizes are 1, 10 and 100 KiB,
then 1, 5 and 10 MiB. Three independent executions per size verify AES recovery, SHA-256
digests and RSA signatures; medians populate all five labelled graphs and the CSV.
RSA key generation is separately timed. AES benchmark curves exclude password derivation;
RSA curves exclude file hashing, which is recorded in separate CSV columns. No fabricated
experimental values appear before a run. Total benchmark duration includes setup/data
generation, repeats and correctness checks.

Throughput uses decimal MB/s: `input bytes / 1,000,000 / elapsed seconds`. Transfer network
throughput uses encrypted package bytes. Browser timings use monotonic `performance.now()`
(the receiver equivalent of Python `perf_counter()`); precision depends on browser timer
resolution. Network timing covers request submission through receipt of the complete
response body. Server response-write timing is labelled separately and does not establish
end-to-end delivery. Receiver decryption includes PBKDF2; raw AES time is also shown on
the receiver. Active total is encryption workflow + receiver receive/recovery; wall total
includes human waiting and receipt delivery. No clock synchronization is assumed.

The avalanche tab flips exactly one bit in one 16-byte block and compares two AES block
outputs under one random key. Its isolated ECB primitive is solely an educational
experiment, never file encryption. It does not reuse any GCM nonce. The changed-bit
count, percentage and elapsed time are actual measurements, not a security proof.

## Analysis lab

Open **Analysis lab** in the sidebar. Each of its three tabs has a Run button;
graphs remain empty until actual experiments finish.

- **Confusion & diffusion:** exactly one plaintext bit (diffusion) or one key bit
  (key sensitivity illustrating confusion) changes per trial. Graphs show measured
  changed ciphertext bits and first-trial bit maps. Samples span the complete input
  and key. This uses an isolated single-block AES primitive, never ECB file encryption
  or reused GCM nonces. Key sensitivity is not a formal proof of confusion.
- **Plaintext & key length:** AES-GCM encryption/decryption medians across six input
  sizes and 128/192/256-bit keys, with a fixed-plaintext key comparison. Every trial
  has a fresh key/nonce and checks recovery. These alternate key sizes are analysis
  only: production file encryption and transfer remain AES-256-GCM. Password length
  is not AES key length. Curves exclude setup and KDF, and record setup separately.
- **Hash resistance:** bounded full SHA-256 searches for preimages, second preimages
  and collisions, alongside intentionally truncated 8/12/16-bit SHA-256 prefix searches.
  Distinct candidates are checked by exact digest/prefix equality. Caps, failed trials,
  found counts and search/hash timings are recorded. A prefix match is not a full
  SHA-256 match. Graphs separately label theoretical generic classical work, approximately
  2^256 / 2^256 / 2^128 for ordinary short-message preimage/second-preimage/collision
  searches. Small searches, bit-change graphs and measured hash speed do not prove
  resistance or measure an exhaustive attack. The three sets of data export as CSV.

References: [NIST AES specification](https://csrc.nist.gov/pubs/fips/197/final),
[NIST hash properties](https://csrc.nist.gov/projects/hash-functions), and
[NIST generic hash strength discussion](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf).

## What the project protects

**Confidentiality:** AES-256-GCM encrypts file contents; password-derived keys and
passwords are never bundled with the package. The HTTPS receiver decrypts in the
second device's browser. Strong passwords and correct certificate trust are necessary.

**Integrity:** GCM authenticates the ciphertext and metadata before releasing recovered
plaintext. SHA-256 compares original/recovered bytes. Unauthenticated hashes alone
do not protect against an attacker replacing both a file and its hash.

**Authenticity:** RSA-PSS signatures verify that file content was signed by the private
key corresponding to the trusted public key. Trusted public-key provisioning links
that key to a sender. Transfer tokens authorize a download; they do not establish a
human identity. Signatures are a separate workflow; transfers are not automatically
signed. GCM authenticates possession of the shared key, not a named sender.

## Optional Gemini assistant

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `GEMINI_API_KEY` to your Google AI Studio key and restart the app. Optionally set
`GEMINI_MODEL` to a supported account model. With no model configured, the app discovers
Flash models supporting `generateContent` via the provider's models list; unavailable
models/quotas/connectivity produce a clear failure and elapsed-until-failure timing.
No API key is required for the rest of the project. Response latency includes model
discovery if needed and the full completed response. Never enter secrets in the question.
Only explicit questions and an allowlist of numeric benchmark fields are submitted after
the user selects the send checkbox; user documents are not automatically uploaded.

The REST contract and model listing follow Google's official documentation:
[generateContent](https://ai.google.dev/api/generate-content) and
[models.list](https://ai.google.dev/api/models#method:-models.list).
Provider access may incur charges and depends on your account configuration.

## Security boundaries and verification limits

Uploaded content is treated as bytes and is never executed. Safe filenames are offered
for download; arbitrary filesystem paths are not accepted. Header limits, fixed KDF
parameters and a 20 MiB file cap bound input processing. Files are handled in memory,
so multiple concurrent users multiply memory use. This is a single-user local demo;
the standard-library receiver is not a hardened production server and lacks a durable
audit trail, cross-session key vault, advanced rate limiting and production lifecycle manager.
Stop the receiver explicitly before closing the browser; closing a tab does not stop
its server thread. Process exit stops it. Python/Streamlit cannot guarantee secret-memory
zeroization; entered passwords remain in widget/session memory until the session ends.

Hashes and receiver timing receipts do not prove identity. Receipts are untrusted client
reports. Signatures establish authenticity only relative to a trusted public key; the app
does not build a PKI or exchange signed transfer manifests. Strong passwords remain
essential against offline guessing. The metadata (filename, length and hash) is not
encrypted inside downloaded packages, though it is authenticated and carried over TLS.

Automated HTTPS loopback tests exercise actual sockets, trusted certificate validation,
recovery, hash equality, unauthorized requests, tampering, expiry and replay. Physical
two-device/phone compatibility, firewall changes and a live Gemini request require an
appropriate network/device/API key and are not claimed by automated tests.
