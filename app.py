"""SecureVault - zero-knowledge password manager (Streamlit + Groq AI advisor)."""
import json
import os
import time

import streamlit as st

import crypto_utils as cu
import db
import utils

SESSION_TIMEOUT = 300  # seconds of inactivity before auto-logout
MAX_IMPORT_BYTES = 5 * 1024 * 1024
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
PAGES = ["Vault", "Add New", "Generator", "AI Advisor", "Settings"]

st.set_page_config(page_title="SecureVault", page_icon="🔐", layout="centered")
db.init_db()


# ---------------------------------------------------------------- helpers
def get_secret(name: str, default: str = "") -> str:
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name, default)


def init_state():
    defaults = {"user": None, "key": None, "last_active": time.time(),
                "notice": None, "chat": [], "gen_pw": ""}
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)


def logout(reason: str = None):
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    init_state()
    st.session_state.notice = reason


def check_timeout():
    if st.session_state.user:
        if time.time() - st.session_state.last_active > SESSION_TIMEOUT:
            logout("You were logged out after 5 minutes of inactivity.")
        else:
            st.session_state.last_active = time.time()


def load_entries():
    """Decrypt all entries. Returns (list_of_dicts, number_of_undecryptable)."""
    out, bad = [], 0
    for row in db.list_entries(st.session_state.user):
        try:
            data = json.loads(cu.decrypt(st.session_state.key, row["blob"]))
            data["id"] = row["id"]
            data["updated_at"] = row["updated_at"]
            out.append(data)
        except (cu.DecryptionError, json.JSONDecodeError):
            bad += 1
    return out, bad


def encrypt_entry(site, username, password, notes) -> str:
    payload = json.dumps({"site": site.strip(), "username": username.strip(),
                          "password": password, "notes": notes.strip()})
    return cu.encrypt(st.session_state.key, payload)


def strength_meter(password: str):
    score, label, tips = utils.strength(password)
    st.progress(score / 100, text=f"Strength: {label} ({score}/100)")
    if tips and password:
        st.caption(" • ".join(tips[:3]))


# ------------------------------------------------------------------- auth
def handle_login(username: str, password: str):
    u = username.strip().lower()
    if not u or not password:
        st.error("Enter your username and master password.")
        return
    remaining = db.lock_remaining(u)
    if remaining > 0:
        st.error(f"Too many failed attempts. Try again in {remaining} seconds.")
        return
    user = db.get_user(u)
    if user is None:
        cu.derive_key(password, cu.new_salt())  # same timing as a real login
        st.error("Invalid username or master password.")
        return
    key = cu.derive_key(password, cu.b64d(user["salt"]))
    if cu.verify_key(key, user["verifier"]):
        db.reset_attempts(u)
        st.session_state.user = u
        st.session_state.key = key
        st.session_state.last_active = time.time()
        st.rerun()
    else:
        locked = db.record_failed_attempt(u)
        if locked > 0:
            st.error(f"Too many failed attempts. Locked for {locked} seconds.")
        else:
            st.error("Invalid username or master password.")


def handle_signup(username: str, p1: str, p2: str):
    u = username.strip().lower()
    if not utils.valid_username(u):
        st.error("Username: 3-32 characters, only a-z, 0-9 and underscore.")
        return
    if p1 != p2:
        st.error("Passwords do not match.")
        return
    ok, msg = utils.valid_master_password(p1)
    if not ok:
        st.error(msg)
        return
    salt = cu.new_salt()
    key = cu.derive_key(p1, salt)
    if db.create_user(u, cu.b64e(salt), cu.make_verifier(key)):
        st.success("Account created. Go to the Login tab.")
    else:
        st.error("That username is already taken.")


def auth_page():
    st.title("🔐 SecureVault")
    st.caption("Zero-knowledge password manager. Your master password is never stored.")
    if st.session_state.notice:
        st.warning(st.session_state.notice)
        st.session_state.notice = None
    tab_login, tab_signup = st.tabs(["Login", "Sign up"])
    with tab_login:
        with st.form("login_form"):
            u = st.text_input("Username", key="login_user")
            p = st.text_input("Master password", type="password", key="login_pass")
            go = st.form_submit_button("Login", key="login_btn")
        if go:
            handle_login(u, p)
    with tab_signup:
        st.warning("If you forget your master password, your data CANNOT be recovered. "
                   "Nobody, including the developer, can reset it.")
        with st.form("signup_form"):
            u = st.text_input("Choose a username", key="su_user")
            p1 = st.text_input("Master password (10+ chars)", type="password", key="su_pass")
            p2 = st.text_input("Confirm master password", type="password", key="su_pass2")
            go = st.form_submit_button("Create account", key="su_btn")
        if go:
            handle_signup(u, p1, p2)


# ------------------------------------------------------------------ pages
def vault_page():
    st.header("🗄️ Vault")
    entries, bad = load_entries()
    if bad:
        st.error(f"{bad} entr{'y' if bad == 1 else 'ies'} could not be decrypted "
                 "(corrupted or tampered data).")
    if not entries:
        st.info("Your vault is empty. Add your first password from 'Add New'.")
        return
    q = st.text_input("Search", placeholder="Search by site or username", key="vault_search")
    q = q.strip().lower()
    shown = [e for e in entries if q in e["site"].lower() or q in e["username"].lower()]
    st.caption(f"{len(shown)} of {len(entries)} entries")
    for e in shown:
        eid = e["id"]
        with st.expander(f"{e['site']}  —  {e['username']}"):
            if st.checkbox("Show password", key=f"show_{eid}"):
                st.code(e["password"], language=None)  # hover to copy
            else:
                st.text("••••••••••••")
                st.caption("Tick 'Show password' to reveal it and use the copy icon.")
            if e.get("notes"):
                st.write(e["notes"])
            score, label, _ = utils.strength(e["password"])
            st.caption(f"Strength: {label} ({score}/100)")
            with st.form(f"edit_form_{eid}"):
                site = st.text_input("Site / app", e["site"])
                user = st.text_input("Username / email", e["username"])
                pw = st.text_input("Password", e["password"], type="password")
                notes = st.text_area("Notes", e.get("notes", ""))
                save = st.form_submit_button("Save changes", key=f"save_{eid}")
            if save:
                if not site.strip() or not pw:
                    st.error("Site and password are required.")
                else:
                    db.update_entry(eid, st.session_state.user,
                                    encrypt_entry(site, user, pw, notes))
                    st.success("Updated.")
                    st.rerun()
            if st.session_state.get(f"confirm_{eid}"):
                st.warning("Delete this entry permanently?")
                c1, c2 = st.columns(2)
                if c1.button("Yes, delete", key=f"yes_{eid}"):
                    db.delete_entry(eid, st.session_state.user)
                    st.session_state.pop(f"confirm_{eid}", None)
                    st.rerun()
                if c2.button("Cancel", key=f"no_{eid}"):
                    st.session_state.pop(f"confirm_{eid}", None)
                    st.rerun()
            elif st.button("🗑️ Delete", key=f"del_{eid}"):
                st.session_state[f"confirm_{eid}"] = True
                st.rerun()


def _save_new_entry():
    s = st.session_state
    site, pw = s.get("add_site", ""), s.get("add_pw", "")
    if not site.strip() or not pw:
        s.add_msg = ("error", "Site name and password are required.")
        return
    db.add_entry(s.user, encrypt_entry(site, s.get("add_user", ""), pw, s.get("add_notes", "")))
    for k in ("add_site", "add_user", "add_pw", "add_notes"):
        s[k] = ""
    s.add_msg = ("success", "Saved (encrypted).")


def _fill_generated():
    st.session_state.add_pw = utils.generate_password(16)


def add_page():
    st.header("➕ Add New")
    msg = st.session_state.pop("add_msg", None)
    if msg:
        getattr(st, msg[0])(msg[1])
    st.text_input("Site / app name", key="add_site")
    st.text_input("Username / email", key="add_user")
    show = st.checkbox("Show password while typing", key="add_show")
    st.text_input("Password", key="add_pw", type="default" if show else "password")
    st.button("🎲 Generate strong password", on_click=_fill_generated, key="add_gen")
    strength_meter(st.session_state.get("add_pw", ""))
    st.text_area("Notes (optional)", key="add_notes")
    st.button("Save entry", on_click=_save_new_entry, key="add_save", type="primary")


def generator_page():
    st.header("🎲 Password Generator")
    length = st.slider("Length", 8, 64, 16, key="gen_len")
    c1, c2, c3 = st.columns(3)
    up = c1.checkbox("Uppercase", True, key="gen_up")
    nums = c2.checkbox("Numbers", True, key="gen_num")
    sym = c3.checkbox("Symbols", True, key="gen_sym")
    if st.button("Generate", key="gen_btn", type="primary") or not st.session_state.gen_pw:
        st.session_state.gen_pw = utils.generate_password(length, sym, nums, up)
    st.code(st.session_state.gen_pw, language=None)
    strength_meter(st.session_state.gen_pw)


def _groq(messages):
    key = get_secret("GROQ_API_KEY")
    if not key:
        return None, "GROQ_API_KEY is not set. Add it to .streamlit/secrets.toml or your environment."
    try:
        from groq import Groq
        client = Groq(api_key=key)
        r = client.chat.completions.create(model=GROQ_MODEL, messages=messages,
                                           temperature=0.4, max_tokens=700)
        return r.choices[0].message.content, None
    except Exception as exc:  # network, auth, rate limit...
        return None, f"Groq request failed: {type(exc).__name__}"


SYSTEM_PROMPT = ("You are a friendly cybersecurity advisor inside a password manager. "
                 "Give short, practical advice on passwords, 2FA, passkeys, phishing and "
                 "account safety. Use simple language. If the user pastes what looks like "
                 "a real password, tell them to never share it.")


def ai_page():
    st.header("🤖 AI Security Advisor")
    st.info("Your passwords and encryption key are NEVER sent to Groq. Only vault "
            "statistics (counts) and the questions you type are sent.")
    entries, _ = load_entries()
    tab_report, tab_chat = st.tabs(["Vault health report", "Ask the advisor"])
    with tab_report:
        pws = [e["password"] for e in entries]
        weak = sum(1 for p in pws if utils.strength(p)[0] < 50)
        reused = len(pws) - len(set(pws))
        short = sum(1 for p in pws if len(p) < 12)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Entries", len(pws))
        c2.metric("Weak", weak)
        c3.metric("Reused", reused)
        c4.metric("Under 12 chars", short)
        if st.button("Get AI action plan", key="ai_report", disabled=not pws):
            stats = (f"Vault stats: {len(pws)} passwords, {weak} weak, {reused} reused, "
                     f"{short} shorter than 12 characters. Give a prioritized action plan "
                     "in 5 short bullet points.")
            with st.spinner("Thinking..."):
                text, err = _groq([{"role": "system", "content": SYSTEM_PROMPT},
                                   {"role": "user", "content": stats}])
            st.error(err) if err else st.markdown(text)
    with tab_chat:
        for m in st.session_state.chat:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])
        question = st.chat_input("Ask about passwords, 2FA, phishing...", key="ai_input")
        if question:
            if any(len(p) >= 6 and p in question for p in [e["password"] for e in entries]):
                st.error("Your message contains one of your saved passwords, so it was "
                         "not sent. Never share real passwords with any AI.")
            else:
                st.session_state.chat.append({"role": "user", "content": question})
                msgs = [{"role": "system", "content": SYSTEM_PROMPT}] + st.session_state.chat[-10:]
                with st.spinner("Thinking..."):
                    text, err = _groq(msgs)
                if err:
                    st.error(err)
                    st.session_state.chat.pop()
                else:
                    st.session_state.chat.append({"role": "assistant", "content": text})
                    st.rerun()
        if st.session_state.chat and st.button("Clear chat", key="ai_clear"):
            st.session_state.chat = []
            st.rerun()


def settings_page():
    st.header("⚙️ Settings")
    user = db.get_user(st.session_state.user)
    st.subheader("Encrypted backup")
    backup = {"version": 1, "salt": user["salt"], "verifier": user["verifier"],
              "entries": [r["blob"] for r in db.list_entries(st.session_state.user)]}
    st.download_button("⬇️ Download encrypted backup", json.dumps(backup),
                       file_name="securevault_backup.json", mime="application/json",
                       key="dl_backup")
    st.caption("The backup is encrypted with your master password at the time of export.")
    st.subheader("Import backup")
    up = st.file_uploader("Backup file (.json)", type=["json"], key="imp_file")
    bpw = st.text_input("Master password of the backup", type="password", key="imp_pw")
    if st.button("Import", key="imp_btn"):
        if up is None or not bpw:
            st.error("Choose a file and enter its master password.")
        elif up.size > MAX_IMPORT_BYTES:
            st.error("File too large.")
        else:
            try:
                data = json.loads(up.getvalue().decode("utf-8"))
                bkey = cu.derive_key(bpw, cu.b64d(data["salt"]))
                if not cu.verify_key(bkey, data["verifier"]):
                    st.error("Wrong master password for this backup.")
                else:
                    n = 0
                    for blob in data["entries"]:
                        plain = cu.decrypt(bkey, blob)
                        db.add_entry(st.session_state.user,
                                     cu.encrypt(st.session_state.key, plain))
                        n += 1
                    st.success(f"Imported {n} entries.")
            except (KeyError, ValueError, TypeError, cu.DecryptionError):
                st.error("Invalid or corrupted backup file.")
    st.subheader("Security info")
    st.markdown("- Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, unique salt\n"
                "- Encryption: AES-256-GCM, unique nonce per entry\n"
                "- Auto-logout: 5 minutes of inactivity\n"
                "- Login lock: 30 seconds after 5 failed attempts")


# ------------------------------------------------------------------- main
def main():
    init_state()
    check_timeout()
    if not st.session_state.user:
        auth_page()
        return
    with st.sidebar:
        st.title("🔐 SecureVault")
        st.caption(f"Signed in as **{st.session_state.user}**")
        page = st.radio("Menu", PAGES, key="page")
        if st.button("Logout", key="logout_btn"):
            logout()
            st.rerun()
    {"Vault": vault_page, "Add New": add_page, "Generator": generator_page,
     "AI Advisor": ai_page, "Settings": settings_page}[page]()


main()
