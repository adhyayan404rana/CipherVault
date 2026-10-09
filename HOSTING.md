# CipherVault accounts and hosted transfers

The original Streamlit dashboard and LAN receiver are preserved. The optional web
edition implements the same core crypto tools, benchmarks, analysis graphs and AI
assistant, plus isolated accounts, inboxes and signed encrypted transfers. It uses
Flask with a small HTML/JavaScript dashboard; no React, Docker or extra API service.

## Try two accounts locally first

```powershell
Set-Location 'C:\IS Lab Project'
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe hosted_app.py
```

Open **http://localhost:8502** in a normal browser window and an incognito window.
Leave this terminal running. Local mode needs no cloud account or API key.

1. In the normal window create an account with an email such as `alice@example.test`
   and a password of at least 12 characters, then sign in.
2. Create signing identity `alice` with a separate signing passphrase. Generation,
   protection and hashing timings are displayed. Keep that passphrase safe; this
   demo has no signing-key recovery/reset feature.
3. In incognito create another account, e.g. `bob@example.test`, sign in and create
   identity `bob`. Local mode does not send confirmation emails.
4. Alice opens **Device transfer**, refreshes the recipient list, chooses Bob and
   uploads `demo_files\demo.txt`. Enter a file password and Alice's signing passphrase,
   then click **Encrypt, sign & send**.
5. Share the **file password** separately. Bob obtains Alice's signing-key fingerprint
   from Alice through a trusted channel; do not trust a substituted key solely because
   it arrived with ciphertext.
6. Bob opens **Device transfer**, clicks **Refresh transfers**, selects the inbox
   file and enters Alice's verified fingerprint and the file password. Click
   **Verify, receive & decrypt** and download the recovered file.
7. Alice refreshes transfers. Both see the verified receipt, hashes, UTC timestamps
   and actual measured timings. Previews are bounded, with binary files shown as hex.
8. Change one character in the original and verify its original RSA signature in
   **Integrity & signatures** to demonstrate rejection. File vault accepts existing
   `.cvault` password/key-file packages and `demo_key.key` (32 raw bytes).

Local accounts, password hashes, encrypted signing identities, ciphertext and numeric
results are stored separately in `local_data/accounts.sqlite3`. Session tokens are
hashed in that database. A persistent random cookie-signing secret is generated once
in `local_data/hosted-session.secret`; do not delete it casually. Neither local store
is committed. Normal/incognito windows have separate cookies and account workspaces.
Already verified transfers can be downloaded again until expiry; receipt recording
is single-use. Sender may delete a transfer and its ciphertext.

The original app still launches with:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

It runs on port 8501, retains its existing results and supports the original same-Wi-Fi
HTTPS receiver. That separate LAN listener remains a local feature; the hosted mode
uses account inboxes instead of opening a second port on Vercel.

## Deploy with Supabase and Vercel

## Original Streamlit application on Render

The separate Render service runs `app.py` using Python cryptography, Streamlit,
Matplotlib and `perf_counter()` timings. The Vercel account edition continues to
handle account-based transfers. `render.yaml` defines the Streamlit service;
its start command binds Streamlit to `0.0.0.0` and Render's `$PORT`.

The Render demo requires `CIPHERVAULT_DEMO_PASSWORD` (20+ characters) and
`CIPHERVAULT_RENDER_DEMO=true`. A generated deployment password is kept privately
in the local, ignored `local_data/render-demo-password.txt`; it is not a file
encryption password, an RSA signing passphrase, or a Supabase account password.

Results, uploaded files and keys remain in each Streamlit session; the hosted
demo does not read or write the original shared local SQLite results database.
Download outputs before refreshing, locking the laboratory, or leaving the page.
Files selected here are processed on Render's server, unlike the hosted account
edition's browser-based file encryption. Use nonsensitive demonstration files.
This shared access password is a demo gate, not individual user accounts.

The Device transfer section links to the Vercel account edition. The original LAN
receiver remains available locally; Render cannot expose its additional listener
through the Streamlit service's single public port. Gemini remains optional and
requires its own environment configuration on Render.

The free Render service sleeps after inactivity and loses in-memory sessions on
restart. Opening it may take about one minute after it sleeps; no keep-alive
service is needed. A paid instance can avoid the free service's idle sleep.

## Vercel account edition

The account edition is deployed at **https://ciphervault-alpha.vercel.app**.
The production dashboard, JavaScript assets and session endpoint return HTTP 200;
`/health` reports `mode: supabase`. Unauthenticated transfers, database tables and
the compute RPC reject access. The local automated suite passed **94 tests in 50.54s**.
Authenticated transfers against the live Supabase project still need verification
with two confirmed accounts; physical two-device testing has not been performed.

Before creating hosted accounts, set Supabase **Authentication > URL Configuration >
Site URL** to `https://ciphervault-alpha.vercel.app` and save. This controls the return
URL in confirmation emails. Local accounts are separate and do not migrate automatically.
For confirmation mail to addresses outside the Supabase project's team, configure
custom SMTP; the built-in mail service restricts recipients to team addresses.

### 1. Supabase

1. Create a Supabase project in your own account. Choose a strong database password;
   the app does not require that password or a service-role key.
2. In **SQL Editor**, run [supabase/schema.sql](supabase/schema.sql) **once**. It creates
   immutable public signing identities, owner-only encrypted private keys, transfers,
   account-scoped results, bounded compute counters and a private `cipher-packages`
   bucket with a 20 MiB + package-overhead file limit.
3. Under **Authentication**, enable email/password sign-in. Keep email confirmation
   enabled for a public deployment and configure SMTP if needed. Use two real email
   addresses and confirm each before signing in. Restrict signups to your demonstration
   users if the deployment should be private. Supabase's auth rate limits apply.
4. Obtain the project URL and **publishable API key** from project settings. Do not
   substitute a service-role/secret API key: the application deliberately uses each
   user's JWT and row-level security.

Supabase [Auth](https://supabase.com/docs/guides/auth) and
[RLS documentation](https://supabase.com/docs/guides/database/secure-data) explain how
accounts and row permissions work. Public directory entries contain username and
public signing key, not email, password or encrypted private-key data.

### 2. Vercel

1. Put the project in your own Git repository and import it into Vercel. Do not include
   `.env`, `.venv`, `local_data`, `.test-tools`, demo keys or downloaded outputs.
2. Select the **Flask** framework preset. The checked-in `pyproject.toml` points to
   `server:app`; `vercel.json` configures the Python function and excludes local/test
   artifacts. Leave the build command at its default. The Streamlit `app.py` is not
   the WSGI entrypoint.
3. Add these Vercel **Environment Variables**:

   | Name | Value |
   |---|---|
   | `CIPHERVAULT_HOSTED_MODE` | `supabase` |
   | `SUPABASE_URL` | Your project's `https://…supabase.co` URL |
   | `SUPABASE_PUBLISHABLE_KEY` | Your publishable key |
   | `CIPHERVAULT_SESSION_SECRET` | Random value generated below |
   | `GEMINI_API_KEY` | Optional; omit to keep the AI assistant unconfigured |
   | `GEMINI_MODEL` | Optional supported model; existing discovery also works |

   Generate the session secret locally and paste it into Vercel's environment settings:

   ```powershell
   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Do not paste your secret into chat or commit it. Keep the same value across
   deployments unless intentionally revoking all browser sessions.
4. Deploy. In Supabase Auth settings set the site's URL to your deployed HTTPS URL
   for confirmation emails. Open `/health`: it should report `mode: supabase`.
5. Create and confirm two accounts, then follow the local demonstration steps using
   the deployed website in normal/incognito windows or two separate devices.

The [Vercel Flask guide](https://vercel.com/docs/frameworks/backend/flask) describes
the supported deployment entrypoint. Cloud uploads go directly from the browser to
private Supabase storage through signed upload URLs, rather than sending 20 MiB through
a Vercel function. Downloads similarly use short-lived private URLs. This avoids
Vercel's [function request/response size limit](https://vercel.com/docs/functions/limitations).
Upload URLs expire according to Supabase's signed-upload lifetime (currently two hours);
they cannot overwrite existing ciphertext. Transfer access expires after 24 hours;
download URLs last 60 seconds. Expiry restricts access, but does not physically delete
expired objects: the sender can delete them; configure periodic cleanup for long-term use.

### 3. Verify access isolation after deployment

- Account A sends to B; B recovers exactly the uploaded bytes and both hashes match.
- A third account cannot list or download that transfer or read another user's results.
- Wrong password and untrusted signing fingerprint release no plaintext.
- Modified ciphertext, manifest or signature fails verification.
- B cannot overwrite A's upload, publish A's draft, alter metadata, or delete A's file.
- Receipts report successful verification once; timestamps and timings remain client
  reports and do not independently prove the receiver's identity or completion.

These live cloud checks are necessary: local automated tests do not validate your
deployed Supabase policies or account configuration.

## What stays private and where timing runs

File vault, hashing, RSA signatures and account-transfer encryption/decryption run in
the browser using Web Crypto. Password packages remain compatible with the Python
AES-256-GCM format. File passwords, uploaded raw AES keys, unwrapped RSA private keys
and recovered plaintext are not sent to the application or storage server. The private
RSA key is encrypted client-side with a separate passphrase, PBKDF2-600,000 and AES-GCM,
with authenticated data binding it to the account ID. Do not reuse account/file/signing
passwords. Account passwords are handled by Supabase Auth in cloud mode; local mode
stores salted Scrypt hashes.

Benchmark and analysis datasets are generated and timed on the Python server with
`perf_counter()`. Browser operations use `performance.now()`. CSVs and UI labels
identify raw AES, key derivation, hashing, complete workflow, key setup and signing.
Browser RSA-PSS APIs hash internally: signing/verification timings explicitly include
that hashing; standalone hash timing is shown separately and is not subtracted.
Actual AES-128/192/256 keys are confined to analysis; file workflows use AES-256 only.

Graphs and numeric results persist per account on the server. The latest encrypted
File vault download persists in an account-specific browser IndexedDB database; it is
not synchronised to other devices. Plaintext previews/download links and unlocked keys
are session-only and disappear on refresh/logout. Reloading requires credentials again
to recover plaintext, while receipts and measured results remain.

HTTPS, secure HttpOnly SameSite cookies, CSRF tokens, signature validation, private
storage and RLS protect the hosted workflow. This remains a college demo: trust the
application provider and device/browser. A malicious hosting administrator can change
delivered JavaScript; the design is not a guarantee against a compromised host. Sessions
expire and may require signing in again; this MVP has no automatic token refresh,
password reset screen, signing-key rotation or organisation admin console. Supabase
Auth can manage account recovery separately. It has not received an independent
security audit. Existing LAN transfer remains usable without any hosting setup.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The optional actual-Chrome test uses two isolated browser contexts. To enable it:

```powershell
npm install --prefix .test-tools --no-save --package-lock=false playwright
.\.venv\Scripts\python.exe -m pytest -q tests/test_hosted_browser.py
```

Chrome's default Windows installation is detected; set `CIPHERVAULT_TEST_CHROME` if
needed. Test accounts and keys use temporary storage and do not change your workspace.
