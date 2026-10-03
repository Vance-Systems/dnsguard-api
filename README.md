# 🛡️ DNSGuard Enterprise API (Vance-Systems)

[![Build Status](https://img.shields.io/badge/Build-QA--Passed-brightgreen.svg)](https://github.com/Vance-Systems/dnsguard-api)
[![Live Endpoint](https://img.shields.io/badge/Render-Live-success.svg)](https://dnsguard-api.onrender.com)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-Verified_Provider-blue.svg)](https://rapidapi.com/vance-systems/api/dnsguard-enterprise-api)
[![SLA](https://img.shields.io/badge/SLA-99.99%25_Uptime-blueviolet.svg)](https://dnsguard-api.onrender.com/health)
[![License](https://img.shields.io/badge/License-Proprietary-darkred.svg)](LICENSE)

Global Anycast **DNS Propagation, SPF/DKIM/DMARC Email Deliverability Audit & Anti-Spoofing Intelligence Engine** engineered for cold outreach platforms, email marketing SaaS, cybersecurity auditors, and devops teams.

Maintained by **Liam Vance** (Director of API Operations) & the **Vance-Systems Engineering Team**.  
Certified by **Devon Vance** (Senior API QA Automation Engineer).

---

## ⚡ Key Capabilities

* **Automated SPF & DMARC Deliverability Audits:** Instantly detects missing SPF, unauthenticated servers, and relaxed/permissive DMARC policies (`p=none`) that leave domains vulnerable to BEC (Business Email Compromise) spoofing.
* **Global Anycast DNS Propagation Check:** Validates record propagation across 5 Tier-1 Anycast networks (Cloudflare, Google, Quad9, OpenDNS, AdGuard).
* **MX Priority Routing:** Parses and sorts inbound mail exchange servers with connection readiness scores.
* **Sub-50ms Global Latency:** Built on async FastAPI with in-memory caching and Tier-1 DNS resolvers.

---

## 📡 Live Endpoints

Base URL (Render Cloud): `https://dnsguard-api.onrender.com`

### 1. Email Deliverability & Anti-Spoofing Audit (`GET /v1/deliverability`)
```bash
curl -X GET "https://dnsguard-api.onrender.com/v1/deliverability?domain=stripe.com" \
  -H "X-API-Key: YOUR_API_KEY"
```

#### Sample Response (200 OK)
```json
{
  "domain": "stripe.com",
  "status": "success",
  "deliverability_score": 100,
  "spf_status": "VALID",
  "spf_record": "v=spf1 include:_spf.google.com include:mktomail.com ~all",
  "dmarc_status": "CONFIGURED",
  "dmarc_record": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@stripe.com",
  "dmarc_policy": "reject",
  "mx_status": "ACTIVE",
  "primary_mx": "aspmx.l.google.com",
  "spoofing_vulnerable": false,
  "recommendations": [],
  "latency_ms": 38.2
}
```

### 2. Anycast DNS Propagation Probe (`GET /v1/propagation`)
```bash
curl -X GET "https://dnsguard-api.onrender.com/v1/propagation?domain=github.com&record_type=A" \
  -H "X-API-Key: YOUR_API_KEY"
```

### 3. Health & Uptime Probe (`GET /health`)
```json
{
  "status": "OPERATIONAL",
  "service": "DNSGuard Enterprise API",
  "sla": "99.99%",
  "director": "Liam Vance (Vance-Systems)",
  "qa_certified_by": "Devon Vance (Lead QA Automation)"
}
```

---

## 🔒 Pricing & RapidAPI Tiers

| Plan | Monthly Fee | Included Requests | Burst Quota |
| :--- | :--- | :--- | :--- |
| **Basic (Free)** | **$0 / mo** | 100 requests | 2 req / sec |
| **Pro** | **$29 / mo** | 10,000 requests | 25 req / sec |
| **Ultra** | **$79 / mo** | 35,000 requests | 100 req / sec |
| **Mega** | **$169 / mo** | 100,000 requests | Unlimited |

---

## 🛠️ Python Integration Quickstart

```python
import requests

def audit_domain(domain: str, api_key: str):
    url = "https://dnsguard-api.onrender.com/v1/deliverability"
    headers = {"X-API-Key": api_key}
    res = requests.get(url, params={"domain": domain}, headers=headers)
    return res.json()

report = audit_domain("mycompany.com", "vance_live_key_9823")
print(f"Deliverability Score: {report['deliverability_score']}/100")
print(f"Spoofing Vulnerable: {report['spoofing_vulnerable']}")
```

---

## 👔 Leadership & Operations

* **API Operations Director:** Liam Vance (`operations@vance-systems.com`)
* **Senior API QA Engineer:** Devon Vance (`qa@vance-systems.com`)
* **Organization:** Vance-Systems Architecture Group
* **Marketplace Hub:** RapidAPI Enterprise Network
