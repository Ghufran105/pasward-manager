# 🔐 SecureVault

A zero-knowledge password manager built with Python + Streamlit, with a Groq-powered AI security advisor.

## Features
- Sign up / login with a master password (never stored)
- Add, edit, delete, search entries; passwords hidden by default, copy via the icon on the code box
- Strong password generator (uses `secrets`) and strength meter
- Auto-logout after 5 minutes of inactivity
- Login lock for 30 seconds after 5 failed attempts
- Encrypted backup export / import
- AI Advisor (Groq): vault health action plan + security Q&A. Passwords and keys are never sent to Groq.

## Security design
- Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, unique random salt per user
- Encryption: AES-256-GCM, unique random nonce per entry
- The database holds only encrypted blobs; if you forget the master password, data cannot be recovered
- Educational project: not independently audited. Don't rely on it for critical accounts.

## Run locally
```bash
python -m venv venv
venv\Scripts\activate        # Windows  (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
mkdir .streamlit             # skip if it exists
copy .streamlit\secrets.toml.example .streamlit\secrets.toml   # Mac/Linux: cp
# edit .streamlit/secrets.toml and paste your GROQ_API_KEY
streamlit run app.py
```

## Run tests
```bash
pip install pytest
python -m pytest -q
```

## Push to GitHub
```bash
git init
git add .
git commit -m "SecureVault password manager"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/securevault.git
git push -u origin main
```
Check that `.streamlit/secrets.toml` is NOT in the commit (it is in .gitignore).

## Deploy on Streamlit Cloud
1. Go to share.streamlit.io, connect GitHub, pick the repo, main file `app.py`
2. Advanced settings → Secrets → paste: `GROQ_API_KEY = "your-key"`
3. Deploy

**Important:** Streamlit Cloud resets local files when the app restarts, so the SQLite
database (`vault.db`) can be wiped. For real persistent use, replace `db.py` with a
Supabase/Postgres version (keep the same function names), or run the app locally.
