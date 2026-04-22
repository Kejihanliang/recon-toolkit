# 🛡️ Penetration Testing Reconnaissance Toolkit

**Version:** 1.0  
**Author:** Security Tools Lab  
**License:** MIT License  
**Platform:** Linux/macOS/Windows (Python 3.8+)  
**Price:** $25 (Lifetime License)

---

## 📋 Description

A powerful, automated reconnaissance toolkit for penetration testers and security researchers. Automates the tedious information collection phase so you can focus on actual vulnerability discovery.

**Perfect for:**
- Bug Bounty hunters
- Penetration testers
- Security students
- CTF players

---

## ⚡ Features

### 🔍 Subdomain Discovery
- Passive subdomain enumeration via public APIs
- DNS zone transfer detection
- Subdomain bruteforce

### 🗺️ Port Scanning
- Fast top 100 ports scan
- Service version detection
- Banner grabbing

### 🌐 Web Technology Fingerprinting
- CMS detection (WordPress, Joomla, Drupal, etc.)
- WAF detection
- Technology stack identification
- HTTP headers analysis

### 📊 Vulnerability Scanning
- CORS misconfiguration checker
- Open redirect detector
- SSRF indicator
- Common endpoints discovery

### 📝 Reporting
- Export results to JSON/CSV/TXT
- Color-coded terminal output

---

## 🚀 Quick Start

### Prerequisites
```bash
pip install requests colorama dnspython
```

### Run
```bash
python recon.py --target example.com
```

---

## 💰 Why This Tool?

| Feature | Manual Work | Our Toolkit |
|---------|-------------|-------------|
| Subdomain Enum | 30-60 min | 2-5 min |
| Port Scan | 20-40 min | 5-10 min |
| Tech Detection | 15-30 min | 1-2 min |
| Total Time | 2-3 hours | 10-20 min |

**Save hours every pentest. Reinvest in actual hacking.**

---

## 📦 What's Included

1. **recon.py** - Main toolkit script
2. **README.pdf** - Full documentation
3. **wordlists/** - subdomain wordlists
4. **config.py** - configuration

---

## ⚙️ Usage Examples

### Basic Scan
```bash
python recon.py --target example.com
```

### Full Scan with All Modules
```bash
python recon.py --target example.com --full --export json
```

### Only Subdomain Enum
```bash
python recon.py --target example.com --subdomains
```

### Port Scan Only
```bash
python recon.py --target example.com --ports --export csv
```

---

## 🔒 Legal Notice

This tool is for **authorized penetration testing only**. Unauthorized scanning is illegal. The author is not responsible for misuse.

---

## 💬 Support

For questions or issues, contact via Gumroad page.

---

**Start saving time on your recon phase today!**
