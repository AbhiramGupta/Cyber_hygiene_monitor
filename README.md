# Cyber Hygiene Monitor — Running tests

Prerequisites:
- Python 3.8+
- Install dependencies:

```bash
python -m pip install -r "e:\\Sem 4-1\\Cyber Hygenie monitor tool\\requirements.txt"
```

Run the interactive port test (optional):

```bash
python "e:\\Sem 4-1\\Cyber Hygenie monitor tool\\test_port.py"
```

Run automated tests (pytest):

```bash
python -m pip install pytest
pytest -q
```

Notes:
- The Flask app uses Windows commands (netsh, wmic, PowerShell). Running full checks may require an elevated prompt on Windows.
- WiFi passwords are analyzed for strength but not included plaintext in generated reports.
