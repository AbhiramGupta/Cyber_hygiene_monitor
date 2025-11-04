import math
import re

COMMON_SIMPLE = {"123456","password","12345678","qwerty","abc123","password1","111111","123456789"}

def estimate_bits_from_pool(password: str) -> float:
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'\d', password):
        pool += 10
    if re.search(r'[^A-Za-z0-9]', password):
        pool += 32
    if pool == 0:
        pool = 94
    return len(password) * math.log2(pool)

def check_wifi_password_strength(pw: str):
    reasons = []
    if not pw:
        return {"score": 0, "label": "very weak", "reasons": ["No password"]}

    lc = pw.lower()
    if lc in COMMON_SIMPLE or re.match(r'^[0-9]{4,}$', pw):
        reasons.append("Matches a common/obvious password or is numeric-only")
        return {"score": 5, "label": "very weak", "reasons": reasons}

    if len(pw) < 8:
        reasons.append("Too short (<8 characters)")
    elif len(pw) < 12:
        reasons.append("Short (8-11 chars) — consider longer password")

    classes = 0
    classes += 1 if re.search(r'[a-z]', pw) else 0
    classes += 1 if re.search(r'[A-Z]', pw) else 0
    classes += 1 if re.search(r'\d', pw) else 0
    classes += 1 if re.search(r'[^A-Za-z0-9]', pw) else 0
    if classes < 2:
        reasons.append("Low character variety (use upper, lower, digits, symbols)")

    bits = estimate_bits_from_pool(pw)
    if bits < 28:
        label = "very weak"
        score = 10
        reasons.append(f"Estimated entropy low ({int(bits)} bits)")
    elif bits < 36:
        label = "weak"
        score = 30
        reasons.append(f"Estimated entropy ({int(bits)} bits)")
    elif bits < 50:
        label = "moderate"
        score = 55
    elif bits < 70:
        label = "strong"
        score = 80
    else:
        label = "very strong"
        score = 95

    score += (len(pw) - 8) * 2
    score += (classes - 1) * 3
    score = max(0, min(100, int(score)))

    return {"score": score, "label": label, "reasons": reasons}

def mask_password(pw: str):
    if not pw:
        return None
    if len(pw) <= 4:
        return '*' * len(pw)
    return pw[0] + '*'*(len(pw)-2) + pw[-1]
