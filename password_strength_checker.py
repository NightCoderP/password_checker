import re
import hashlib
import string
from urllib.reguest import urlopen
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
