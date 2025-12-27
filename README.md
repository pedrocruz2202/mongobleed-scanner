# 🩸 MongoBleed Scanner

**High-Performance MongoDB Heap Memory Leak Scanner (CVE-2025-14847)**

MongoBleed is a fast, asynchronous vulnerability scanner designed to detect **unauthenticated remote heap memory leaks** in MongoDB servers caused by **CVE-2025-14847**.

This tool is built for **Bug Hunters, Red Teamers, and Security Researchers** who need to scan large target lists efficiently and reliably.

---

## 🚨 Vulnerability Overview

* **CVE ID:** CVE-2025-14847
* **Product:** MongoDB
* **Attack Vector:** Remote / Unauthenticated
* **Root Cause:** Malformed `OP_COMPRESSED` message abusing `zlib` compression
* **Impact:** Heap Memory Disclosure
* **Authentication Required:** ❌ No

The vulnerability allows an attacker to trigger **out-of-bounds memory reads**, resulting in **heap memory leakage** from the MongoDB server.

---

## ✨ Features

* ⚡ Fully asynchronous (asyncio-based)
* 📂 Bulk scanning from file
* 🎯 Accurate detection with real leak validation
* 🧠 Minimal false positives
* 🧵 Adjustable concurrency & timeout
* 📝 Automatic vulnerable target logging
* 🔇 Silent failure handling for large scans

---

## 🛠 Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/black1hp/mongobleed-scanner.git
cd mongobleed-scanner
```

### 2️⃣ Install required libraries

```bash
pip3 install asyncio
```

> All other modules (`struct`, `zlib`, `argparse`, etc.) are part of Python standard library.

### 3️⃣ Python version

```text
Python 3.8+
```

---

## 📄 Target File Format

Targets must be provided in a **plain text file**, one target per line.

Supported formats:

```
IP
IP:PORT
DOMAIN
DOMAIN:PORT
```

### Example:

```text
0-0-dtoumi.pagerduty.com
0-web17665.pagerduty.com
example.com
192.168.1.10
10.10.10.10:27017
mongo.example.com:27017
```

---

## 🚀 Usage

```bash
python3 mongo-heap-leaks.py -i targets.txt
```

### Advanced Usage

```bash
python3 mongo-heap-leaks.py -i targets.txt -c 200 -t 5
```

### Options

| Flag | Description                     |
| ---- | ------------------------------- |
| `-i` | Input file with targets         |
| `-c` | Concurrency level (default: 50) |
| `-t` | Connection timeout in seconds   |

---

## ⚙️ Concurrency Tuning Guide

Choose concurrency based on your **network speed & system resources**:

| Internet Speed | Recommended `-c` |
| -------------- | ---------------- |
| 10 Mbps        | 20               |
| 50 Mbps        | 100              |
| 100 Mbps       | 250              |
| 1 Gbps         | 500 – 1000 ⚠️    |

> ⚠️ High concurrency on weak systems may cause packet loss or false negatives.

---

## 📂 Output

Vulnerable targets are automatically saved to:

```
vulnerable_targets.txt
```

Example entry:

```text
[2025-12-27 14:32:11] example.com:27017 - Leaked: 8192 bytes
```

---

## 🧠 Detection Logic

A target is considered **VULNERABLE** only if:

* MongoDB responds successfully
* Returned data size exceeds a safe threshold
* Actual leaked heap data is received

This ensures **real memory disclosure**, not just service availability.

---

## 👤 Author

**Black1hp**
Security Researcher | Bug Hunter | Red Teamer

* GitHub: [https://github.com/black1hp](https://github.com/black1hp)
* X (Twitter): [https://x.com/black1hp](https://x.com/black1hp)
* Medium: [https://medium.com/@black1hp](https://medium.com/@black1hp)
* LinkedIn: [https://www.linkedin.com/in/black1hp/](https://www.linkedin.com/in/black1hp/)

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and research purposes only**.
The author is not responsible for misuse or illegal activity.

---

## ⭐ Star the repo

If this tool helped you during your hunt, a ⭐ is always appreciated.
