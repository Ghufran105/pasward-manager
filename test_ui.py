import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from streamlit.testing.v1 import AppTest

APP = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app.py")
MASTER = "Correct-Horse-Battery-9"


@pytest.fixture(autouse=True)
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DB_PATH", str(tmp_path / "ui.db"))
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


def run():
    return AppTest.from_file(APP, default_timeout=60).run()


def signup(at, user="tester", pw=MASTER):
    at.text_input(key="su_user").set_value(user)
    at.text_input(key="su_pass").set_value(pw)
    at.text_input(key="su_pass2").set_value(pw)
    at.button(key="su_btn").click().run()
    return at


def login(at, user="tester", pw=MASTER):
    at.text_input(key="login_user").set_value(user)
    at.text_input(key="login_pass").set_value(pw)
    at.button(key="login_btn").click().run()
    return at


def test_full_flow():
    at = run()
    assert not at.exception
    signup(at)
    assert not at.exception and any("Account created" in s.value for s in at.success)
    login(at, pw="WrongPassword-123")
    assert any("Invalid" in e.value for e in at.error)
    login(at)
    assert not at.exception
    assert at.session_state["user"] == "tester"
    assert at.session_state["key"] is not None

    # add an entry
    at.sidebar.radio(key="page").set_value("Add New").run()
    at.text_input(key="add_site").set_value("github.com")
    at.text_input(key="add_user").set_value("me@x.com")
    at.text_input(key="add_pw").set_value("Sup3r-Secret-Pass!")
    at.button(key="add_save").click().run()
    assert not at.exception

    # vault shows it
    at.sidebar.radio(key="page").set_value("Vault").run()
    assert not at.exception
    assert any("github.com" in e.label for e in at.expander)

    # show password
    cb = [c for c in at.checkbox if c.key.startswith("show_")][0]
    cb.check().run()
    assert any("Sup3r-Secret-Pass!" in c.value for c in at.code)

    # other pages render
    for page in ("Generator", "AI Advisor", "Settings"):
        at.sidebar.radio(key="page").set_value(page).run()
        assert not at.exception, page

    # AI without key -> graceful error
    at.sidebar.radio(key="page").set_value("AI Advisor").run()
    at.button(key="ai_report").click().run()
    assert not at.exception
    assert any("GROQ_API_KEY" in e.value for e in at.error)

    # logout
    at.sidebar.radio(key="page").set_value("Vault").run()
    at.button(key="logout_btn").click().run()
    assert at.session_state["user"] is None and at.session_state["key"] is None


def test_lockout():
    at = run()
    signup(at, "locky")
    for _ in range(5):
        login(at, "locky", "WrongPassword-123")
    assert any("Locked" in e.value or "Too many" in e.value for e in at.error)
    login(at, "locky", MASTER)  # correct password still blocked while locked
    assert at.session_state["user"] is None


def test_weak_master_and_duplicate():
    at = run()
    signup(at, "weakling", "password1234")
    assert any("weak" in e.value.lower() for e in at.error)
    signup(at, "dupe")
    signup(at, "dupe")
    assert any("taken" in e.value for e in at.error)


def test_auto_logout():
    at = run()
    signup(at)
    login(at)
    assert at.session_state["user"] == "tester"
    at.session_state["last_active"] = 0
    at.run()
    assert at.session_state["user"] is None
    assert any("inactivity" in w.value for w in at.warning)
