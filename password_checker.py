import re
from utils import setup_logging

log = setup_logging(__name__)

def check_password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search(r"[A-Z]", password):
        strength += 1
    if re.search(r"[a-z]", password):
        strength += 1
    if re.search(r"[0-9]", password):
        strength += 1
    if re.search(r"[@$!%*?&#]", password):
        strength += 1

    if strength <= 2:
        log.warning("Password is weak")
        return "Weak Password ❌"
    elif strength <= 3:
        log.info("Password is medium strength")
        return "Medium Password ⚠️"
    else:
        log.info("Password is strong")
        return "Strong Password ✅"


