import re
import hashlib
import string
from urllib.request import urlopen
from urllib.error import URLError

COMMON_PASSWORDS = {
    "123456", "123456789", "password", "12345678", "qwerty",
    "111111", "123123", "abc123", "password1", "1q2w3e4r",
    "iloveyou", "admin", "welcome", "monkey", "dragon",
    "letmein", "trustno1", "12345", "qwerty123", "sunshine",
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcvbn", "123456", "qazwsx", "1qaz2wsx", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def rule_based_score(password: str) -> dict:
    score = 0
    notes = []

    # --- Length ---
    length = len(password)
    if length < 8:
        notes.append("Password is too short (fewer than 8 characters).")
    elif length < 12:
        score += 15
        notes.append("Length is acceptable but not ideal (12+ recommended).")
    elif length < 16:
        score += 25
        notes.append("Good length.")
    else:
        score += 35
        notes.append("Very good length.")

    # --- Character variety ---
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10
    if variety <= 1:
        notes.append("Only one character type used (e.g. lowercase only).")
    elif variety == 4:
        notes.append("Uses uppercase, lowercase, digits, and symbols together.")

    # --- Common passwords check ---
    if password in COMMON_PASSWORDS:
        score = min(score, 5)
        notes.append("Password is in the list of common passwords.")

    # --- Keyboard patterns check ---
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            score -= 15
            notes.append(f"Keyboard-walk pattern detected: '{pattern}'")
            break

    # --- All-digits or all-letters check ---
    if password.isdigit():
        score -= 15
        notes.append("Password contains digits only.")
    elif password.isalpha():
        score -= 10
        notes.append("Password contains letters only.")

    score = max(0, min(100, score))
    return {"score": score, "notes": notes}


def score_to_label(score: int) -> str:
    if score < 30:
        return "Very Weak"
    elif score < 60:
        return "Medium"
    elif score < 80:
        return "Strong"
    else:
        return "Very Strong"


def zxcvbn_analysis(password: str):
    """Runs entropy-based analysis using the zxcvbn library, if installed."""
    try:
        from zxcvbn import zxcvbn
    except ImportError:
        return None

    result = zxcvbn(password)
    return {
        "score": result["score"],  # 0-4
        "estimated_crack_time": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "feedback": result.get("feedback", {}),
    }


def hibp_breach_check(password: str, timeout: int = 5) -> dict:
    """
    Queries the Have I Been Pwned 'Pwned Passwords' API using k-anonymity.
    The SHA-1 hash of the password is computed locally; only the first 5
    characters (the prefix) are sent to the API. The API returns all hash
    suffixes matching that prefix, and the match is checked locally.
    The password itself is never transmitted.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        with urlopen(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=timeout) as response:
            data = response.read().decode("utf-8")
    except (URLError, TimeoutError):
        return {"checked": False, "message": "No internet connection or the API could not be reached."}

    for line in data.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return {"checked": True, "breached": True, "times_seen": int(count)}

    return {"checked": True, "breached": False}


def evaluate_password(password: str, check_hibp: bool = True):
    print(f"\n{'='*50}")
    print("PASSWORD STRENGTH EVALUATION")
    print(f"{'='*50}")

    # 1) Rule-based analysis
    result = rule_based_score(password)
    label = score_to_label(result["score"])
    print(f"\n[Rule-Based Analysis]")
    print(f"Score: {result['score']}/100  ->  Rating: {label}")
    for note in result["notes"]:
        print(f"  - {note}")

    # 2) zxcvbn comparison (if available)
    zx = zxcvbn_analysis(password)
    if zx:
        print(f"\n[zxcvbn Library Comparison]")
        print(f"Score: {zx['score']}/4")
        print(f"Estimated crack time (offline, slow hashing): {zx['estimated_crack_time']}")
    else:
        print("\n[zxcvbn Library]")
        print("  Not installed. To compare: pip install zxcvbn")

    # 3) HIBP breach check (requires internet)
    if check_hibp:
        print(f"\n[Have I Been Pwned Breach Check]")
        hibp = hibp_breach_check(password)
        if not hibp["checked"]:
            print(f"  {hibp['message']}")
        elif hibp["breached"]:
            print(f"  This password has been seen in data breaches {hibp['times_seen']:,} times!")
        else:
            print("  This password was not found in known breaches.")

    print(f"\n{'='*50}\n")


if __name__ == "__main__":
    print("Password Strength Checker - press Ctrl+C to quit")
    while True:
        try:
            password = input("\nEnter a password to test: ")
            if not password:
                continue
            evaluate_password(password)
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break