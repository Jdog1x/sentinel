# 🛡️ SENTINEL
### AI-Powered Penetration Testing Recon & Report Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> SENTINEL is an autonomous reconnaissance and vulnerability analysis platform that chains industry-standard security tools with LLM-powered analysis to produce professional penetration test reports — in minutes.

---

## 📸 Screenshots

### Dashboard
![Dashboard](docs/Screenshot%20one.png)

### Findings Panel
![Findings](docs/Screenshot%20two.png)

### AI Chat
![AI Chat](docs/Screenshot%20three.png)

---

## ✨ Features

- 🔍 **Autonomous Recon** — Chains nmap, whois, DNS enumeration, and HTTP fingerprinting
- 🤖 **AI Analysis Engine** — LLM triages findings and prioritizes attack surface
- 🌐 **Web Dashboard** — Real-time scan monitoring and finding browser
- 📄 **Report Generator** — One-click professional PDF pentest reports
- 🔌 **Multi-LLM Backend** — Ollama (local), Anthropic Claude, or OpenAI
- 🧩 **Plugin Architecture** — Extend with new tools via simple adapters

---

## 🚀 Quick Start

```bash
git clone https://github.com/Jdog1x/sentinel.git
cd sentinel
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
sentinel scan scanme.nmap.org --fast --backend ollama
```

## 🖥️ CLI Usage

```bash
sentinel scan scanme.nmap.org --fast --backend ollama
sentinel scans
sentinel report <scan-id>
sentinel serve
```

## 🤖 LLM Backends

| Backend | Config |
|---|---|
| Ollama (local) | `LLM_BACKEND=ollama` |
| Anthropic Claude | `LLM_BACKEND=anthropic` |
| OpenAI | `LLM_BACKEND=openai` |

---

## ⚠️ Legal

SENTINEL is for authorized security testing only. Only scan targets you own or have explicit written permission to test.

---

## 📜 License

MIT