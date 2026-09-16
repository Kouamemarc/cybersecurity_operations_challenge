#!/usr/bin/env python3
"""
Générateur de logs multi-sources pour SOC — TechnoVision / Scénario 2 (SIEM).

Produit du bruit de fond légitime + des scénarios d'attaque injectés (mappés
MITRE ATT&CK), avec CORRÉLATION inter-sources (une même IP/domaine malveillant
apparaît dans plusieurs journaux). Sortie dans ./data/, un fichier par source :

  windows_security.log   JSON/ligne — 4624/4625/4688/4720
  sysmon.log             JSON/ligne — EventID 1 (process) / 3 (réseau) / 22 (DNS)
  linux_auth.log         syslog     — SSH / sudo
  web_access.log         combined   — Apache/Nginx
  firewall.log           syslog     — pfSense filterlog (block/pass)
  dns.log                syslog     — dnsmasq (query/reply)
  ATTACK_MANIFEST.json   corrigé    — attaques injectées + horodatage + MITRE

Usage :
  python generate_logs.py --hours 24 --eps 2 --seed 42
  python generate_logs.py --attacks dns_c2,port_scan
  python generate_logs.py --hours 48 --eps 5 --business-hours
"""
import argparse, json, random, os, string
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.getcwd(), "data")   # data/ dans le dossier d'ou on lance la commande

# ---------------------------------------------------------------- référentiels
USERS       = ["marc", "alice", "bruno", "chloe", "david", "svc_backup", "admin"]
HOSTS_WIN   = ["WIN-WKS01", "WIN-WKS02", "WIN-SRV01"]
HOST_LINUX  = "LNX-SRV01"
FW_HOST     = "pfsense"
INTERNAL    = "10.10.20."
IFACES      = ["em0", "em1"]          # em0 = WAN, em1 = LAN
WEB_PATHS   = ["/", "/index.html", "/login", "/api/users", "/static/app.js",
               "/products", "/cart", "/favicon.ico"]
UA_NORMAL   = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
               "Mozilla/5.0 (X11; Linux x86_64)",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]
DNS_LEGIT   = ["google.com","microsoft.com","github.com","ubuntu.com","cloudflare.com",
               "office365.com","windowsupdate.com","elastic.co","debian.org"]
DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

def rint(a, b): return random.randint(a, b)
def ext_ip():   return f"{rint(11,223)}.{rint(0,255)}.{rint(0,255)}.{rint(1,254)}"
def int_ip():   return INTERNAL + str(rint(10, 60))
def iso(ts):    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
def syslog_ts(ts): return ts.strftime("%b %d %H:%M:%S")
def rand_dom(n): return "".join(random.choice(string.ascii_lowercase) for _ in range(n))

# ---------------------------------------------------------------- bruit de fond
def bg_windows(ts):
    u, h = random.choice(USERS), random.choice(HOSTS_WIN)
    ev = random.choices([4624, 4688], weights=[3, 2])[0]
    base = {"@timestamp": iso(ts), "host": {"name": h}, "winlog": {"channel": "Security"},
            "event": {"code": ev, "provider": "Microsoft-Windows-Security-Auditing"},
            "user": {"name": u}}
    if ev == 4624:
        base["event"]["action"] = "logged-in"
        base["winlog"]["event_data"] = {"LogonType": str(random.choice([2, 3, 7, 10])),
                                        "IpAddress": int_ip()}
    else:
        base["event"]["action"] = "process-created"
        base["process"] = {"name": random.choice(["explorer.exe","chrome.exe","outlook.exe","svchost.exe","cmd.exe"]),
                            "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs"}
    return json.dumps(base)

def bg_sysmon(ts):
    h = random.choice(HOSTS_WIN)
    if random.random() < .35:                       # EventID 22 : requête DNS
        return json.dumps({"@timestamp": iso(ts), "host": {"name": h},
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational"},
            "event": {"code": 22, "provider": "Microsoft-Windows-Sysmon", "action": "dns-query"},
            "dns": {"question": {"name": random.choice(DNS_LEGIT)}}})
    return json.dumps({"@timestamp": iso(ts), "host": {"name": h},   # EventID 3 : réseau
        "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational"},
        "event": {"code": 3, "provider": "Microsoft-Windows-Sysmon", "action": "network-connect"},
        "network": {"protocol": "tcp"},
        "destination": {"ip": ext_ip() if random.random() < .3 else int_ip(),
                        "port": random.choice([80, 443, 445, 3389, 53])},
        "source": {"ip": int_ip()}})

def bg_linux(ts):
    u = random.choice(USERS)
    if random.random() < .5:
        return (f"{syslog_ts(ts)} {HOST_LINUX} sshd[{rint(1000,9999)}]: "
                f"Accepted password for {u} from {int_ip()} port {rint(40000,60000)} ssh2")
    return (f"{syslog_ts(ts)} {HOST_LINUX} sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; "
            f"USER=root ; COMMAND=/usr/bin/apt update")

def bg_web(ts):
    ip, path = int_ip(), random.choice(WEB_PATHS)
    code = random.choices([200, 304, 404], weights=[8, 2, 1])[0]
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
            f'"GET {path} HTTP/1.1" {code} {rint(200,5000)} '
            f'"-" "{random.choice(UA_NORMAL)}"')

def fw_line(ts, action, direction, src, dst, sport, dport, proto="tcp", iface="em0", flags="S"):
    """pfSense filterlog — format CSV IPv4 réel."""
    protonum = {"tcp": 6, "udp": 17, "icmp": 1}[proto]
    rule = rint(1, 30)
    tracker = 1000000000 + rint(0, 999)
    fields = [str(rule), "", "", str(tracker), iface, "match", action, direction, "4",
              "0x0", "", str(rint(50, 64)), str(rint(1, 65535)), "0", "DF",
              str(protonum), proto, str(rint(40, 1500)), src, dst,
              str(sport), str(dport)]
    if proto == "tcp":
        fields += [str(rint(0, 1000)), flags, "", "", "", ""]
    return f"{syslog_ts(ts)} {FW_HOST} filterlog[{rint(100,999)}]: " + ",".join(fields)

def bg_firewall(ts):
    if random.random() < .75:      # trafic LAN->WAN autorisé
        return fw_line(ts, "pass", "out", int_ip(), ext_ip(), rint(40000,60000),
                       random.choice([80,443,53]), iface="em1")
    return fw_line(ts, "block", "in", ext_ip(), int_ip(), rint(1000,65000),
                   random.choice([23,3389,445,1433,22]))   # scans/bruit bloqué

def dns_line(ts, domain, client, qtype="A", host=HOST_LINUX):
    return f"{syslog_ts(ts)} {host} dnsmasq[{rint(1000,9999)}]: query[{qtype}] {domain} from {client}"

def bg_dns(ts):
    return dns_line(ts, random.choice(DNS_LEGIT), int_ip())

# ---------------------------------------------------------------- attaques (MITRE)
def atk_bruteforce_ssh(ts, sink):
    """T1110 — bruteforce SSH puis succès (visible aussi côté firewall)."""
    src = ext_ip()
    for i in range(rint(15, 30)):
        t = ts + timedelta(seconds=i * 2)
        sink["linux"].append(f"{syslog_ts(t)} {HOST_LINUX} sshd[{rint(1000,9999)}]: "
            f"Failed password for {'invalid user ' if random.random()<.4 else ''}admin "
            f"from {src} port {rint(40000,60000)} ssh2")
        sink["fw"].append(fw_line(t, "pass", "in", src, int_ip(), rint(40000,60000), 22))
    t = ts + timedelta(seconds=62)
    sink["linux"].append(f"{syslog_ts(t)} {HOST_LINUX} sshd[{rint(1000,9999)}]: "
        f"Accepted password for admin from {src} port {rint(40000,60000)} ssh2")
    return ("T1110", f"Bruteforce SSH depuis {src} → succès sur 'admin' (corrélé firewall)")

def atk_powershell_enc(ts, sink):
    """T1059.001 — PowerShell encodé."""
    h = random.choice(HOSTS_WIN)
    b64 = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA..."
    sink["win"].append(json.dumps({"@timestamp": iso(ts), "host": {"name": h},
        "winlog": {"channel": "Security"}, "event": {"code": 4688, "action": "process-created"},
        "user": {"name": random.choice(USERS)},
        "process": {"name": "powershell.exe",
                    "command_line": f"powershell.exe -nop -w hidden -enc {b64}"}}))
    return ("T1059.001", f"PowerShell encodé (-enc) sur {h}")

def atk_new_account(ts, sink):
    """T1136 — création de compte."""
    sink["win"].append(json.dumps({"@timestamp": iso(ts), "host": {"name": "WIN-SRV01"},
        "winlog": {"channel": "Security", "event_data": {"TargetUserName": "svc_helpdesk",
                   "SubjectUserName": "admin"}},
        "event": {"code": 4720, "action": "user-account-created"}}))
    return ("T1136", "Création du compte 'svc_helpdesk' par 'admin' sur WIN-SRV01")

def atk_lateral_rdp(ts, sink):
    """T1021 — mouvement latéral RDP."""
    src = int_ip()
    sink["win"].append(json.dumps({"@timestamp": iso(ts), "host": {"name": "WIN-SRV01"},
        "winlog": {"channel": "Security", "event_data": {"LogonType": "10", "IpAddress": src}},
        "event": {"code": 4624, "action": "logged-in"}, "user": {"name": "admin"}}))
    return ("T1021", f"Logon RDP (type 10) vers WIN-SRV01 depuis {src}")

def atk_web_scan_exfil(ts, sink):
    """T1046 + T1041 — scan web puis exfiltration (corrélé firewall)."""
    src = ext_ip()
    for p in ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/../../etc/passwd", "/backup.zip"]:
        t = ts + timedelta(seconds=rint(0, 20))
        sink["web"].append(f'{src} - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
            f'"GET {p} HTTP/1.1" {random.choice([404,403,200])} {rint(100,900)} "-" "sqlmap/1.7"')
    t = ts + timedelta(seconds=40)
    sink["web"].append(f'{src} - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"POST /api/export HTTP/1.1" 200 {rint(5_000_000,50_000_000)} "-" "curl/8.0"')
    sink["fw"].append(fw_line(t, "pass", "out", int_ip(), src, 443, rint(40000,60000)))  # gros flux sortant
    return ("T1046/T1041", f"Scan web (sqlmap) depuis {src} puis exfiltration volumineuse (corrélé firewall)")

def atk_dns_c2(ts, sink):
    """T1071.004 — C2 / beaconing DNS vers domaine malveillant (DNS + Sysmon corrélés)."""
    victim = random.choice(HOSTS_WIN)
    client = int_ip()
    bad = f"{rand_dom(8)}.evil-c2.net"
    for i in range(rint(20, 40)):                    # beaconing à intervalle régulier
        t = ts + timedelta(seconds=i * 30)
        sink["dns"].append(dns_line(t, bad, client))
        sink["sysmon"].append(json.dumps({"@timestamp": iso(t), "host": {"name": victim},
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational"},
            "event": {"code": 22, "provider": "Microsoft-Windows-Sysmon", "action": "dns-query"},
            "dns": {"question": {"name": bad}}}))
    return ("T1071.004", f"Beaconing DNS vers {bad} depuis {victim} (~30s d'intervalle, DNS+Sysmon)")

def atk_dns_tunnel(ts, sink):
    """T1048.003 — exfiltration par tunneling DNS (sous-domaines longs encodés)."""
    client = int_ip()
    dom = "tunnel.exfil-data.io"
    for i in range(rint(30, 60)):
        t = ts + timedelta(seconds=i * 3)
        chunk = rand_dom(rint(40, 60))               # sous-domaine anormalement long
        sink["dns"].append(dns_line(t, f"{chunk}.{dom}", client, qtype="TXT"))
    return ("T1048.003", f"Tunneling DNS vers *.{dom} (sous-domaines longs, requêtes TXT)")

def atk_port_scan(ts, sink):
    """T1046 — scan de ports détecté par le firewall (nombreux blocks, 1 source, N ports)."""
    src = ext_ip()
    tgt = int_ip()
    for port in random.sample(range(1, 10000), rint(80, 150)):
        t = ts + timedelta(milliseconds=rint(0, 30000))
        sink["fw"].append(fw_line(t, "block", "in", src, tgt, rint(40000,60000), port))
    return ("T1046", f"Scan de ports depuis {src} vers {tgt} (>80 ports bloqués par le firewall)")

ATTACKS = {"bruteforce_ssh": atk_bruteforce_ssh, "powershell_enc": atk_powershell_enc,
           "new_account": atk_new_account, "lateral_rdp": atk_lateral_rdp,
           "web_scan_exfil": atk_web_scan_exfil, "dns_c2": atk_dns_c2,
           "dns_tunnel": atk_dns_tunnel, "port_scan": atk_port_scan}

# ---------------------------------------------------------------- réalisme horaire
def biased_offset(hours, business):
    """Renvoie un offset en secondes ; si business, concentre le bruit sur 8h-19h."""
    if not business:
        return random.uniform(0, hours * 3600)
    while True:
        off = random.uniform(0, hours * 3600)
        h = (datetime.now(timezone.utc) - timedelta(hours=hours)
             + timedelta(seconds=off)).hour
        # accepte plus souvent en heures ouvrées
        if 8 <= h <= 19 or random.random() < .15:
            return off

# ---------------------------------------------------------------- moteur
def _recent_offset(hours):
    return random.uniform(max(0,(hours-1))*3600, hours*3600)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--eps", type=float, default=2, help="événements de bruit / seconde (approx)")
    ap.add_argument("--attacks", default="all", help="csv parmi: " + ",".join(ATTACKS) + " | all | none")
    ap.add_argument("--business-hours", action="store_true", help="concentre le bruit sur 8h-19h")
    ap.add_argument("--recent", action="store_true", help="tasse TOUS les evenements sur la derniere heure (ideal demo temps reel)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(OUT, exist_ok=True)
    global biased_offset
    if a.recent:
        _orig = biased_offset
        biased_offset = lambda hours, business: _recent_offset(hours)

    sink = {"win": [], "sysmon": [], "linux": [], "web": [], "fw": [], "dns": []}
    start = datetime.now(timezone.utc) - timedelta(hours=a.hours)
    total = int(a.hours * 3600 * a.eps)

    # bruit de fond : 6 sources pondérées
    gens = [("win", bg_windows, .22), ("sysmon", bg_sysmon, .18), ("linux", bg_linux, .15),
            ("web", bg_web, .15), ("fw", bg_firewall, .20), ("dns", bg_dns, .10)]
    keys   = [g[0] for g in gens]
    funcs  = {g[0]: g[1] for g in gens}
    weights= [g[2] for g in gens]
    for _ in range(total):
        ts = start + timedelta(seconds=biased_offset(a.hours, a.business_hours))
        k = random.choices(keys, weights=weights)[0]
        sink[k].append(funcs[k](ts))

    # attaques
    if a.attacks == "all":    chosen = list(ATTACKS)
    elif a.attacks == "none": chosen = []
    else:                     chosen = [x.strip() for x in a.attacks.split(",") if x.strip() in ATTACKS]

    manifest = []
    for name in chosen:
        at = start + timedelta(seconds=biased_offset(a.hours, a.business_hours))
        tech, desc = ATTACKS[name](at, sink)
        manifest.append({"scenario": name, "mitre": tech, "time_utc": iso(at), "description": desc})

    files = {"win": "windows_security.log", "sysmon": "sysmon.log", "linux": "linux_auth.log",
             "web": "web_access.log", "fw": "firewall.log", "dns": "dns.log"}
    for k, fname in files.items():
        with open(os.path.join(OUT, fname), "w", encoding="utf-8") as f:
            f.write("\n".join(sink[k]) + "\n")
    with open(os.path.join(OUT, "ATTACK_MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print("Logs générés dans ./data/ :")
    for k, fname in files.items():
        print(f"  {fname:24} {len(sink[k]):6} lignes")
    print(f"\n{len(manifest)} scénario(s) d'attaque injecté(s) (voir ATTACK_MANIFEST.json) :")
    for m in manifest:
        print(f"  [{m['mitre']:13}] {m['description']}")

if __name__ == "__main__":
    main()