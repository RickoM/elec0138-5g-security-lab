# 5G Core Security Lab — ELEC0138 Group 1

**UCL ELEC0138 Security & Privacy · 2025/26**

A fully functional 5G Standalone core network deployed on AWS EC2, with a 7-tab interactive security demonstration covering live attacks and mitigations against Open5GS v2.7.6.

---

## Live Demo

Open `5g_demo.html` locally in your browser. The EC2 backend is at:

```
http://13.43.42.62:9999
```

No installation needed — the HTML file has no external dependencies.

---

## System Overview

| Component | Version | Role |
|---|---|---|
| [Open5GS](https://open5gs.org) | v2.7.6 | 5G SA Core (AMF, AUSF, UDM, UDR, NRF, SMF, UPF, PCF) |
| [UERANSIM](https://github.com/aligungr/UERANSIM) | v3.2.6 | 5G UE + gNB simulator |
| MongoDB | 6.0 | Subscriber database (Ki, OPc, IMSI) |
| FastAPI | — | REST proxy (`ue_proxy.py`) orchestrating all demo endpoints |
| Python proxy | — | MongoDB Wire Protocol WAF (`mongo_proxy.py`) |
| AWS EC2 | eu-west-2 | Ubuntu 22.04, `ip-172-31-11-220` |

**Test subscribers provisioned:**
- IMSI `001010000000001` — K: `465B5CE8B199B49FAA5F0A2EE238A6BC`
- IMSI `001010000000002` — second subscriber for multi-UE tests

---

## Repository Structure

```
5gc-aws-lab/
├── 5g_demo.html          # 7-tab interactive demo (open locally)
├── ue_proxy.py           # FastAPI backend — all attack + WAF endpoints
├── mongo_proxy.py        # MongoDB Wire Protocol WAF proxy (Tab 6)
├── config/
│   ├── my-ue.yaml        # UERANSIM UE config (MCC=001, MNC=01)
│   ├── my-gnb.yaml       # UERANSIM gNB config (AMF=127.0.0.5:38412)
│   └── udr.yaml.example  # Open5GS UDR config (password redacted)
└── docs/
    ├── report/
    │   ├── main.tex/.pdf             # Group report (UCL Harvard)
    │   └── elec0138_full_report.tex/.pdf  # Full independent project report
    └── references/
        ├── elec0138_harvard.bib      # natbib authoryear BibTeX
        └── elec0138_reflist.tex      # Paste-ready UCL Harvard reference list
```

---

## Demo Tabs

### Tab 1 — Architecture
End-to-end 5G SA network diagram: UE → gNB → AMF → AUSF → UDM → MongoDB.
Explains the UDR–MongoDB direct connection (`libmongoc`, no encryption) and the full demo system setup including the FastAPI proxy layer.

### Tab 2 — Registration
Live 9-step 5G-AKA mutual authentication via real UERANSIM processes.
Animated canvas sequence diagram driven by actual Open5GS log output.
UE receives IP `10.45.0.2` on `uesimtun0` on successful registration.

### Tab 3 — Data Proof
Real ICMP packets from the registered UE through Open5GS UPF to the public internet (`8.8.8.8`). Confirms the full user-plane path: UE → gNB → GTP-U → UPF → ogstun → Internet.

### Tab 4 — Authentication Attacks
| Attack | Description | Result |
|---|---|---|
| **Attack 1: Forged RES\*** | Attacker submits `deadbeef...` as RES\* without knowing Ki | `HTTP 401` — AUSF rejects, Ki never leaves UDM |
| **Attack 2: UDM SSRF** | Direct HTTP/2 POST to UDM SBI bypassing AMF and AUSF | `HTTP 400` — no OAuth2 Bearer token |

### Tab 5 — SQN Synchronisation DoS + WAF
Flooding authentication requests desynchronises the UE's SQN counter causing `SYNCH_FAILURE`. Rate-limiting WAF (5 req/10s per IMSI) blocks the flood. Live toggle between protected and unprotected states.

### Tab 6 — MongoDB Credential Exfiltration + Wire Protocol WAF
Three-step attack exploiting Open5GS's direct UDR→MongoDB plaintext connection:
1. Unauthenticated scan → blocked by MongoDB auth
2. Read `/etc/open5gs/udr.yaml` → recovers plaintext credentials
3. Authenticated query bypassing proxy → returns **AES-256 Fernet ciphertext** (mitigation holds)

**Novel mitigation:** `mongo_proxy.py` — a MongoDB Wire Protocol proxy on `:27018` that intercepts BSON responses and decrypts `gAAAAA...` Fernet-encrypted Ki/OPc fields before returning plaintext to Open5GS UDR. Zero changes to Open5GS source code required.

### Tab 7 — Rogue NF Registration via NRF
Exploits Open5GS shipping with mTLS **commented out** in `nrf.yaml`:
1. `PUT /nnrf-nfm` with `nfType:AMF`, no certificate, no token → **HTTP 201**
2. NRF returns `nfStatus:REGISTERED` — rogue process is now a trusted AMF
3. `GET /nnrf-disc?target-nf-type=UDM` → full UDM service profile returned
4. `POST /nudm-ueau` without Bearer → **HTTP 400** (OAuth2 partial mitigation)
5. `DELETE /nnrf-nfm` → **HTTP 204**, no audit log, fully undetectable

---

## Backend API Endpoints

All endpoints served by `ue_proxy.py` on port `9999`.

| Endpoint | Method | Tab | Description |
|---|---|---|---|
| `/health` | GET | — | Health check |
| `/ue/register` | POST | 2 | Spawn UERANSIM, begin 5G-AKA |
| `/ue/steps` | GET | 2 | Stream registration log steps |
| `/ue/stop` | POST | 2 | Kill UERANSIM processes |
| `/ue/ping` | GET | 3 | Ping via uesimtun0 interface |
| `/attack/auth-exploit` | POST | 4 | Forged RES* attack |
| `/attack/ssrf-udm` | POST | 4 | Direct UDM SBI call |
| `/waf/enable` | POST | 5 | Enable rate-limit WAF |
| `/waf/disable` | POST | 5 | Disable rate-limit WAF |
| `/waf/status` | GET | 5 | WAF state query |
| `/attack/sqn-dos` | POST | 5 | SQN flood DoS attempt |
| `/attack/sqn-reset` | POST | 5 | Reset SQN counter |
| `/attack/db-read-raw` | POST | 6 | Unauthenticated MongoDB scan |
| `/attack/db-read-raw-authed` | POST | 6 | Authenticated MongoDB read |
| `/attack/db-read-proxy` | POST | 6 | Read via decryption proxy |
| `/attack/db-trigger-auth` | POST | 6 | Trigger MongoDB auth check |
| `/attack/nrf-register-rogue` | POST | 7 | Register rogue NF |
| `/attack/nrf-discover-udm` | POST | 7 | NRF service discovery |
| `/attack/nrf-query-udm` | POST | 7 | Direct UDM SBI call |
| `/attack/nrf-deregister-rogue-v2` | POST | 7 | Silent deregistration |

---

## MongoDB Wire Protocol WAF (`mongo_proxy.py`)

Implements the same **trusted decryption boundary** principle as AWS Nitro Enclaves ([AWS, 2024](https://aws.amazon.com/blogs/industries/protect-5g-subscriber-credentials-in-the-cloud-with-aws-nitro-enclaves/)) in open-source software.

**How it works:**
- Binds to `127.0.0.1:27018`
- Open5GS UDR's `db_uri` points to `:27018` instead of `:27017`
- Proxies all BSON Wire Protocol traffic to MongoDB `:27017`
- Intercepts responses — detects `gAAAAA...` Fernet-encrypted fields
- Decrypts Ki and OPc in-place using key at `/home/ubuntu/mongo_encrypt.key`
- Returns plaintext to UDR transparently

**Start the proxy:**
```bash
python3 ~/mongo_proxy.py &
# or as a service:
sudo systemctl start mongo-proxy
```

---

## Security Findings Summary

| Attack | Vulnerability | Impact | Mitigation |
|---|---|---|---|
| Forged RES* | Cannot compute HMAC-SHA256 without Ki | Blocked by 5G-AKA design | Protocol (TS 33.501 §6.1.3) |
| UDM SSRF | Direct SBI without OAuth2 token | Auth data retrieval | OAuth2 enforcement (TS 33.501 §13.3) |
| SQN DoS | Flood auth requests desync SQN | Subscriber locked out | Rate-limit WAF |
| DB Exfiltration | UDR→MongoDB plaintext, creds in YAML | **SIM cloning** — confirmed SK Telecom April 2025 | AES-256 + Wire Protocol WAF |
| Rogue NF | NRF mTLS disabled by default | Full topology exposed | Enable mTLS in `nrf.yaml` (TS 33.501 §13.1) |

---

## Real-World Context

- **SK Telecom breach (April 2025):** Malware on production 5G core servers exfiltrated USIM authentication keys (Ki) for approximately 23–27 million subscribers. Regulator confirmed Ki was stored unencrypted and imposed a $97M fine. Direct parallel to Attack 4 in this lab. ([BleepingComputer](https://www.bleepingcomputer.com/news/security/sk-telecom-says-malware-breach-lasted-3-years-impacted-27-million-numbers/) / [The Register](https://www.theregister.com/2025/08/28/sk_telecom_regulator_fine/))

- **ENISA 5G Threat Landscape (2020):** Identifies rogue NF registration as a top control-plane threat. ([ENISA](https://www.enisa.europa.eu/publications/enisa-threat-landscape-report-for-5g-networks))

- **AWS Nitro Enclaves for 5G (2024):** AWS blog explicitly identifies the Open5GS UDR–MongoDB plaintext architecture as the core cloud vulnerability for subscriber credential protection. ([AWS](https://aws.amazon.com/blogs/industries/protect-5g-subscriber-credentials-in-the-cloud-with-aws-nitro-enclaves/))

---

## Running the Backend on EC2

```bash
# Start FastAPI proxy (port 9999)
cd ~
uvicorn ue_proxy:app --host 0.0.0.0 --port 9999 &

# Start MongoDB Wire Protocol WAF (port 27018)
python3 ~/mongo_proxy.py &

# Check both are running
ss -tlnp | grep -E "9999|27018"
```

---

## References

- Toulas, B. (2025). *SK Telecom says malware breach lasted 3 years, impacted 27 million numbers*. BleepingComputer.
- The Register (2025). *SK Telecom walloped with $97M fine after schoolkid security*.
- ENISA (2020). *ENISA Threat Landscape for 5G Networks*. Athens: ENISA.
- Amazon Web Services (2024). *Protect 5G subscriber credentials in the cloud with AWS Nitro Enclaves*.
- 3GPP (2023). TS 33.501: Security Architecture and Procedures for 5G System, v17.10.0.
- 3GPP (2023). TS 29.510: Network Function Repository Services, v17.5.0.

---

*ELEC0138 Security & Privacy · UCL · Group 1 · 2025/26*
