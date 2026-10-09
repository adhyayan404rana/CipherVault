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

## Deploy the dashboard on Vercel and the API on Render

The hosted dashboard lives at **https://ciphervault-alpha.vercel.app**.
Vercel builds only `hosted/index.html`, `app.js`, `crypto.js`, and `style.css`
using `build_frontend.cjs`; it does not run Streamlit or the Flask backend.
`vercel.json` forwards `/api/*` and `/health` to the Render backend without
changing the browser URL. The existing browser crypto, graphs, account UI,
measured timings, transfers and private storage workflows remain the same.

Render runs `server:app` with Gunicorn and `requirements-backend.txt`.
`CIPHERVAULT_API_ONLY=true` disables serving dashboard assets there; its root
returns API information. The previous separately hosted Streamlit laboratory is
replaced by this backend. The old Render demo-access password is no longer used.
The original `app.py` remains runnable locally on port 8501.

### 1. Supabase

Run `supabase/schema.sql` once on a new Supabase project. Do not rerun it on the
already configured project during migration. Accounts, encrypted signing keys,
private ciphertext, receipts and numeric results remain in Supabase; migrating
hosting does not copy or delete those records.

Keep email/password authentication and email confirmation enabled. Set
**Authentication > URL Configuration > Site URL** to
`https://ciphervault-alpha.vercel.app`. Configure custom SMTP for confirmation
mail to addresses outside the project's team. Local accounts do not migrate
into Supabase. The application uses a publishable key plus each user's JWT;
no service-role key is needed.

### 2. Render API and Vercel dashboard

Use the existing GitHub repository and `main` branch for both services.
`render.yaml` documents the free Render backend. Its build command is
`pip install -r requirements-backend.txt`; its start command is
`gunicorn server:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`.
Health check: `/health`.

Configure these environment variables on **Render**, never in frontend code:

| Name | Value |
|---|---|
| `CIPHERVAULT_HOSTED_MODE` | `supabase` |
| `CIPHERVAULT_API_ONLY` | `true` |
| `CIPHERVAULT_PUBLIC_ORIGIN` | `https://ciphervault-alpha.vercel.app` |
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_PUBLISHABLE_KEY` | Your publishable key |
| `CIPHERVAULT_SESSION_SECRET` | Persistent random secret, at least 32 characters |
| `GEMINI_API_KEY` | Optional real AI provider key |
| `GEMINI_MODEL` | Optional supported model |

Keep the previous session secret during migration so browser cookies remain
valid. Supabase access tokens still expire; signing in again may be necessary.
Session cookies are Secure, HttpOnly and SameSite=Strict. Requests go through
Vercel's same-origin proxy; the backend validates the configured frontend Origin
and CSRF token. It does not allow arbitrary cross-origin browser requests.

For Vercel choose the **Other** framework preset. `vercel.json` specifies build
command `node build_frontend.cjs` and output directory `frontend_dist`.
The frontend build copies four explicit public files, excluding secrets, local
data, private keys and Python source. Update the rewrite destinations if the
Render backend URL changes. No backend secrets are required on Vercel.

Browser encryption and decryption remain local Web Crypto operations. Signed
ciphertext uploads/downloads go directly to private Supabase storage; plaintext,
file passwords and unwrapped signing keys are not uploaded to the backend.
Python benchmarks and bounded analysis run on Render using `perf_counter()`.

The free Render backend may sleep after 15 minutes of inactivity; its first
request can take about a minute to wake it. The static dashboard stays available,
but account/API operations wait for the backend. No continuous ping service is
configured. A paid instance can avoid idle sleep. Supabase free projects may
pause after low activity; restore through its dashboard if needed.

Transfer access expires after 24 hours; signed download URLs last 60 seconds.
Expiry blocks new access but does not physically delete old ciphertext. Sender
deletion removes the object; schedule cleanup separately for long-term usage.

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
