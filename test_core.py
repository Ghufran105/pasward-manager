import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
import crypto_utils as cu, db, utils


@pytest.fixture(autouse=True)
def tmpdb(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DB_PATH", str(tmp_path / "t.db"))
    db.init_db()


def test_roundtrip_and_unique_nonce():
    key = cu.derive_key("master-pass-123", cu.new_salt())
    a, b = cu.encrypt(key, "secret"), cu.encrypt(key, "secret")
    assert a != b and cu.decrypt(key, a) == "secret"


def test_wrong_key_fails():
    k1 = cu.derive_key("one-password-1", cu.new_salt())
    k2 = cu.derive_key("two-password-2", cu.new_salt())
    with pytest.raises(cu.DecryptionError):
        cu.decrypt(k2, cu.encrypt(k1, "x"))


def test_tampered_data_fails():
    key = cu.derive_key("master-pass-123", cu.new_salt())
    raw = bytearray(cu.b64d(cu.encrypt(key, "secret")))
    raw[-1] ^= 1
    with pytest.raises(cu.DecryptionError):
        cu.decrypt(key, cu.b64e(bytes(raw)))
    with pytest.raises(cu.DecryptionError):
        cu.decrypt(key, "not-base64!!")


def test_verifier():
    salt = cu.new_salt()
    key = cu.derive_key("correct-horse-9", salt)
    v = cu.make_verifier(key)
    assert cu.verify_key(key, v)
    assert not cu.verify_key(cu.derive_key("wrong-horse-9", salt), v)


def test_db_entries_isolated_per_user():
    assert db.create_user("alice", "s", "v")
    assert not db.create_user("alice", "s", "v")
    db.create_user("bob", "s", "v")
    eid = db.add_entry("alice", "blob")
    db.delete_entry(eid, "bob")  # bob cannot delete alice's entry
    assert len(db.list_entries("alice")) == 1
    db.update_entry(eid, "bob", "hacked")
    assert db.list_entries("alice")[0]["blob"] == "blob"
    db.delete_entry(eid, "alice")
    assert db.list_entries("alice") == []


def test_rate_limit():
    db.create_user("carol", "s", "v")
    for _ in range(4):
        assert db.record_failed_attempt("carol") == 0
    assert db.record_failed_attempt("carol") > 0
    assert 0 < db.lock_remaining("carol") <= 30
    db.reset_attempts("carol")
    assert db.lock_remaining("carol") == 0


def test_sql_injection_is_inert():
    db.create_user("dave", "s", "v")
    assert db.get_user("x' OR '1'='1") is None


def test_generator():
    for n in (8, 16, 64):
        p = utils.generate_password(n)
        assert len(p) == n
        assert any(c.isdigit() for c in p) and any(c.isupper() for c in p)
    assert utils.generate_password(12, symbols=False).isalnum()
    assert utils.generate_password(5)  # clamps to 8
    assert len(utils.generate_password(5)) == 8


def test_strength_and_validation():
    assert utils.strength("password")[1] == "Weak"
    assert utils.strength("aaaaaaaaaaaa")[1] == "Weak"
    assert utils.strength("Tr0ub4dor&3-Horse-Battery")[1] == "Strong"
    assert utils.valid_username("ghufran_1") and not utils.valid_username("a b")
    assert not utils.valid_master_password("short")[0]
    assert not utils.valid_master_password("password1234")[0]
    assert utils.valid_master_password("Correct-Horse-Battery-9")[0]
