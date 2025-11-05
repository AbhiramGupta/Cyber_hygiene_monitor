# 🛡️ Cyber Hygiene Monitor

**Cyber Hygiene Monitor** is a Python-based desktop web application built using **Flask** that performs a complete **system security assessment** on Windows devices.  
It helps users understand their system’s **security posture** by scanning key areas such as firewalls, open ports, Wi-Fi password strength, antivirus status, and Windows updates — and then generates a **comprehensive PDF report**.

---

## 🚀 Features

✅ **One-Click Security Scan** — click “Start Scan” to automatically analyze system security  
✅ **Security Scoring System** — quantifies your system’s posture on a 0–100 scale  
✅ **Open Port Detection** — identifies only critical, test, and vulnerable ports  
✅ **Firewall Status Check** — validates protection across public, private, and domain profiles  
✅ **Wi-Fi Security Analyzer** — evaluates saved Wi-Fi passwords’ strength  
✅ **Windows Updates & Antivirus Check** — ensures system protection and updates  
✅ **Automatic PDF Report Generation** — clean, professional, shareable report  
✅ **Run History Tracking** — keeps a record of past scans and improvements  

---

## 🧠 Scoring System Overview

Each component contributes to a total of **100 points**:

| Component         | Weight | Description |
|-------------------|---------|-------------|
| 🔥 Firewall       | 30 pts | Domain, Private, and Public firewall states |
| 🌐 Open Ports     | 20 pts | Deducts score for externally open common/test ports |
| 🧩 System Updates | 15 pts | Checks for pending Windows updates |
| 🦠 Antivirus      | 15 pts | Verifies Defender or other antivirus software |
| 📶 Wi-Fi Security | 20 pts | Analyzes password strength of saved networks |

> 🟢 **90–100:** Excellent  
> 🟡 **70–89:** Good  
> 🟠 **50–69:** Fair  
> 🔴 **Below 50:** Needs Immediate Attention  


---

## ⚙️ Installation (Local Setup)

> 🪟 **Supports Windows 10 / 11 only** (due to PowerShell and `netsh` usage)

### Step 1 — Clone the Repository
```bash
git clone https://github.com/AbhiramGupta/Cyber_hygiene_monitor.git
cd Cyber_hygiene_monitor
```

### Step 2 - Create & Activate Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3 - Install dependencies
```bash
pip install -r requirements.txt
or
pip install flask psutil fpdf pywin32
```
### Run the Application
```bash
python app.py
```

### Open the Browser
http://127.0.0.1:5000

Click “Start Security Scan” to run a full system assessment.
