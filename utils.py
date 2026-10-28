"""Password generation, strength checking, and input validation."""
import math
import re
import secrets
import string

COMMON = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "welcome", "admin", "iloveyou", "111111", "pakistan", "peshawar",
}


def generate_password(length=16, symbols=True, numbers=True, uppercase=True) -> str:
    length = max(8, min(int(length), 128))
    pools = [string.ascii_lowercase]
    if uppercase:
        pools.append(string.ascii_uppercase)
    if numbers:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    # guarantee at least one char from every selected pool
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def strength(password: str):
    """Returns (score 0-100, label, list of tips)."""
    if not password:
        return 0, "Empty", ["Enter a password."]
    tips = []
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    else:
        tips.append("Add lowercase letters.")
    if re.search(r"[A-Z]", password):
        pool += 26
    else:
        tips.append("Add uppercase letters.")
    if re.search(r"\d", password):
        pool += 10
    else:
        tips.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    else:
        tips.append("Add symbols.")
    if len(password) < 12:
        tips.append("Use 12+ characters.")
    entropy = len(password) * math.log2(max(pool, 2))
    if password.lower() in COMMON or re.fullmatch(r"(.)\1+", password):
        entropy = min(entropy, 10)
        tips.append("This is a very common/guessable password.")
    lower = password.lower()
    if any(w in lower and len(password) <= len(w) + 6
           for w in COMMON if not w.isdigit() and len(w) >= 5):
        entropy = min(entropy, 20)
        tips.append("Built on a common word; add unrelated words or characters.")
    if re.search(r"(.)\1{2,}", password):
        entropy -= 8
        tips.append("Avoid repeated characters.")
    score = int(max(0, min(100, entropy / 80 * 100)))
    if score < 35:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Good"
    else:
        label = "Strong"
    return score, label, tips


def valid_username(username: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9_]{3,32}", username))


def valid_master_password(password: str):
    """Returns (ok, message)."""
    if len(password) < 10:
        return False, "Master password must be at least 10 characters."
    score, label, _ = strength(password)
    if score < 50:
        return False, f"Master password is too weak ({label}). Use a longer passphrase with mixed characters."
    return True, ""
