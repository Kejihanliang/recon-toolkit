# 🛡️ Penetration Testing Recon Toolkit - Installation & Usage Guide

## Installation

### 1. Install Python Dependencies

```bash
# Linux/macOS
pip install -r requirements.txt

# Windows
pip install requests colorama dnspython
```

### 2. Verify Installation

```bash
python recon.py --help
```

---

## Quick Start

### Scan a Target (All Modules)
```bash
python recon.py --target example.com --full
```

### Scan a Target (Subdomains Only)
```bash
python recon.py --target example.com --subdomains
```

### Scan a Target (Ports Only)
```bash
python recon.py --target example.com --ports
```

### Scan a Target (Web Analysis Only)
```bash
python recon.py --target example.com --web
```

### Export Results
```bash
python recon.py --target example.com --full --export json   # Default
python recon.py --target example.com --full --export csv
python recon.py --target example.com --full --export txt
```

---

## Module Details

### 🔍 Subdomain Enumeration
Detects subdomains via:
- DNS resolution of common prefixes
- SRV record queries

### 🗺️ Port Scanning
Scans common ports including:
- Top 25 ports by default
- Optional: Top 100 ports with `--top-ports`

### 🌐 Web Analysis
Detects:
- CMS (WordPress, Joomla, Drupal, etc.)
- WAF (Cloudflare, Akamai, etc.)
- Security headers
- CORS misconfigurations

---

## Output Files

Results are saved to `results/` directory:
- `{domain}_{timestamp}.json` - Full results in JSON
- `{domain}_{timestamp}_subdomains.csv` - Subdomains in CSV
- `{domain}_{timestamp}_ports.csv` - Open ports in CSV
- `{domain}_{timestamp}.txt` - Human-readable report

---

## Troubleshooting

### DNS Resolution Errors
Install dnspython:
```bash
pip install dnspython
```

### Import Errors
Make sure you're using Python 3.8+:
```bash
python3 recon.py
```

### SSL Certificate Errors
The tool automatically handles SSL verification. If you get errors, your target may have certificate issues.

---

## License

MIT License - Free to use and modify for authorized security testing only.
