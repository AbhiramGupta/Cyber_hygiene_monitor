import sys
import os
import pytest

# ensure project root is on sys.path for test imports
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from wifi_utils import check_wifi_password_strength

def test_common_password_is_weak():
    r = check_wifi_password_strength("password")
    assert r["label"] in ("very weak", "weak")

def test_strong_passphrase():
    r = check_wifi_password_strength("CorrectHorse!BatteryStaple5")
    assert r["label"] in ("strong", "very strong")
