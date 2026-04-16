# Magento Scanner

<p align="center">
  <img src="https://img.shields.io/badge/python-3.7+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/false%20positives-0%25-success.svg" alt="Zero FP">
  <img src="https://img.shields.io/badge/status-active-brightgreen.svg" alt="Status">
</p>

<p align="center">
  <b>Definitive Magento CMS detection — 100% certain or skip.</b><br>
  <i>Zero false positives. Built for bulk scanning at scale.</i>
</p>

---

## 🎯 About

**Magento Scanner** is a high-performance CLI tool for identifying Magento-powered websites with **zero false positives**. Unlike typical CMS detectors that rely on weak heuristics, this scanner only confirms a match when **definitive Magento-exclusive fingerprints** are detected — otherwise, the target is skipped.

Designed for **bulk scanning** of large domain lists (tested on files with hundreds of thousands of domains) with memory-efficient streaming, connection pooling, and concurrent batch processing.

Ideal for:
- 🔍 Security researchers & bug bounty hunters
- 🛡️ Reconnaissance & asset discovery
- 📊 Large-scale CMS inventory mapping
- 🧰 Targeted vulnerability assessment

---

## ✨ Features

- ✅ **Zero false positives** — multi-layered definitive detection
- ⚡ **High throughput** — up to 300 concurrent threads, connection pooling
- 💾 **Memory efficient** — streaming domain reader, batch-based processing
- 🧠 **Smart detection** — HTML patterns, headers, cookies, REST API, version files
- 🔄 **Auto-dedup** — removes duplicate URLs on-the-fly
- 🎯 **Version & edition detection** — identifies Magento 1.x / 2.x and version numbers
- 📁 **Organized output** — timestamped folder with clean, detailed, and dead-site lists
- 📈 **Live stats** — real-time progress, ETA, speed tracking
- 🎨 **Clean CLI** — color-coded interactive menu
- 🔒 **Safe & non-intrusive** — read-only fingerprinting, no exploitation attempts

---

## 🔬 Detection Methods

The scanner uses **7 independent detection layers**. A target is confirmed as Magento only when at least one definitive indicator is found:

| # | Layer | Indicator | Edition |
|---|-------|-----------|---------|
| 1 | **HTTP Headers** | `x-magento-vary`, `x-magento-cache-control`, `x-magento-tags`, etc. | Magento 2.x |
| 2 | **Cookies** | `mage-cache-storage`, `mage-cache-sessid`, `mage-messages`, etc. | Magento 2.x |
| 3 | **HTML Patterns** | `data-mage-init` + `Magento_*` namespace | Magento 2.x |
| 4 | **RequireJS** | `mage/requirejs/mixins`, `require.config` with Magento modules | Magento 2.x |
| 5 | **Legacy Assets** | `js/varien/` + `skin/frontend/(default\|rwd\|base)/` | Magento 1.x |
| 6 | **Version Files** | `/magento_version`, `/pub/static/deployed_version.txt` | Both |
| 7 | **REST API** | `/rest/V1/store/storeConfigs` with valid Magento schema | Magento 2.x |

---

## 📦 Installation

### Clone the repository
```bash
git clone https://github.com/AnggaTechI/magento-scanner.git
cd magento-scanner
```

### Install dependencies
```bash
pip install requests urllib3
```

Or via `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

Run the scanner:
```bash
python magento_scanner.py
```

You'll be greeted with an interactive menu:

```
╔══════════════════════════════════════════════╗
║              MAGENTO SCANNER                 ║
╚══════════════════════════════════════════════╝
       CMS Scanner | Definitive Magento Detection
       100% certain or skip — no false positives
       github.com/AnggaTechI

  [1] Scan daftar domain
  [0] Exit

  [?] Pilih opsi:
```

Select `1`, then provide:

| Prompt | Description | Default | Range |
|--------|-------------|---------|-------|
| **Path file domain** | Path to your domain list file | - | - |
| **Threads** | Number of concurrent workers | `80` | 1–300 |
| **Batch size** | URLs processed per batch | `500` | 50–5000 |
| **Timeout** | HTTP request timeout (seconds) | `8` | 3–30 |

---

## 📋 Input Format

Plain text file with one domain per line. Comments (`#`) and empty lines are ignored. Protocol is auto-detected:

```
example.com
https://shop.example.org
http://store.example.net
# this line is ignored
subdomain.example.io
```

The scanner automatically:
- Adds `https://` if protocol is missing
- Strips trailing slashes
- Deduplicates entries
- Handles multiple encodings (UTF-8, Latin-1, CP1252)

---

## 📁 Output Structure

Each scan creates a timestamped folder:

```
Result-Magento_20260416_143022/
├── Magento_Sites.txt       # Clean URL list of confirmed Magento sites
├── Magento_Detailed.txt    # Full details with version, edition, and proof
└── Dead_Sites.txt          # Unreachable/errored domains with reason
```

### Example: `Magento_Sites.txt`
```
https://shop1.example.com
https://store.example.org
https://market.example.io
```

### Example: `Magento_Detailed.txt`
```
======================================================================
URL     : https://shop1.example.com
Version : 2.4.6
Edition : Magento 2.x
Proof   :
  ✔ Header: x-magento-vary
  ✔ Cookie: mage-cache-storage
  ✔ HTML: data-mage-init + Magento_* namespace
  ✔ /magento_version: Magento/2.4 (Community)
======================================================================
```

---

## 🖥️ Live Output Preview

```
[*] Counting domains...
[*] File: 45.2 MB | ~324,118 domains
[*] Threads: 80 | Batch: 500 | Timeout: 8s
[*] Output : Result-Magento_20260416_143022/
[*] Mode   : Definitive only — 0% false positive
[*] Scanning...

  [MAGENTO ✔] https://shop1.example.com | v2.4.6 | Magento 2.x
             └─ Header: x-magento-vary
             └─ Cookie: mage-cache-storage
             └─ HTML: data-mage-init + Magento_* namespace
  [DEAD] https://broken.example.net (CONN_FAILED)
  [MAGENTO ✔] https://store.example.org | v2.3.5 | Magento 2.x
             └─ HTML: mage/requirejs/mixins

[BATCH 1] 500/324,118 | 12 Magento | 47 Dead | 85/s | ETA 63m
```

---

## ⚙️ Performance Tips

| Scenario | Recommended Settings |
|----------|---------------------|
| **Small list** (<1,000) | `threads=30`, `batch=100` |
| **Medium list** (1K–50K) | `threads=80`, `batch=500` (defaults) |
| **Large list** (50K–500K) | `threads=150`, `batch=1000`, `timeout=6` |
| **Massive list** (500K+) | `threads=200–300`, `batch=2000`, `timeout=5` |
| **Slow network** | Lower threads, increase timeout to 15–20 |

> 💡 **Tip:** Higher thread counts = more speed, but also more CPU/network load and risk of rate-limiting. Test with a small sample first.

---

## 📊 Summary Report

At the end of each scan, you'll see:

```
═══════════════════════════════════════════════════════════
  SCAN COMPLETE
═══════════════════════════════════════════════════════════
  Total scanned    : 324,118
  Magento (100%)   : 2,847
  Dead/Error       : 18,229
  Not Magento      : 303,042
  Time             : 52.3 min
  Speed            : 103 domains/sec

[+] Results: Result-Magento_20260416_143022/

[VERSION]
    2.4.6                    : 912
    2.4.5                    : 645
    2.3.7                    : 388
    ...

[EDITION]
    Magento 2.x              : 2,691
    Magento 1.x              : 156
```

---

## 🛡️ Safety & Ethics

- ✅ **Read-only requests** — no POST, no forms, no exploits
- ✅ **Respects HTTP errors** — no retries or aggressive probing
- ✅ **Minimal footprint** — reads only first 200KB of HTML per target
- ✅ **Short timeouts** — won't hammer slow servers
- ⚠️ **Use responsibly** — only scan targets you're authorized to test

---

## ⚠️ Disclaimer

This tool is intended for **legal security research, authorized penetration testing, and educational purposes only**. You are responsible for ensuring you have explicit permission before scanning any target. The author assumes no liability for misuse or damage caused by this tool.

---

## 🤝 Contributing

Contributions are welcome! Ideas for improvement:

- Additional Magento fingerprints (themes, extensions, vendor signatures)
- Support for detecting known Magento CVEs
- JSON/CSV output formats
- Proxy rotation support
- Integration with other recon tools

**How to contribute:**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add: description'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**AnggaTechI**

- GitHub: [@AnggaTechI](https://github.com/AnggaTechI)

---

## ⭐ Support

If this tool is useful for your work, please consider giving it a **star ⭐** — it helps others discover the project!

For bugs, feature requests, or questions, open an [issue](https://github.com/AnggaTechI/magento-scanner/issues).

---

<p align="center">
  <i>Built with precision. Designed for accuracy at scale.</i><br>
  <sub>100% certain or skip — no false positives.</sub>
</p>
