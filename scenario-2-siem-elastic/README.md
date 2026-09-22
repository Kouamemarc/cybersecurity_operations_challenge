# Scénario 2 — Centralisation et corrélation des logs de sécurité (SIEM)

SIEM basé sur la **suite Elastic** (Elasticsearch, Logstash, Kibana) pour centraliser,
normaliser et corréler les logs de six sources, détecter les incidents et les investiguer.

Projet **Cybersecurity Operations Challenge** — client fictif *TechnoVision*.
Auteur : **Marc Bohoussou** · Fil rouge : **MITRE ATT&CK**.

---

## 1. Architecture

Cluster Elastic **2 nœuds** sécurisé (TLS + authentification), déployé via Docker Compose.

![Architecture SIEM Elastic](../docs/scenario1%20elk.png)

| Composant | Rôle |
|-----------|------|
| Elasticsearch (es01, es02) | Stockage et recherche, cluster 2 nœuds, sécurité activée |
| Logstash | Ingestion des 6 sources, parsing (grok/csv/json), normalisation ECS |
| Kibana | Exploration (Discover), règles de détection (Security), dashboards |

Voir le Dossier d'Architecture Détaillée : [`../architecture/DAT-SOC-TechnoVision.md`](../architecture/DAT-SOC-TechnoVision.md).

---

## 2. Déploiement

Prérequis : Docker + Docker Compose, ~8 Go de RAM, et le paramètre noyau Elasticsearch :

```bash
sudo sysctl -w vm.max_map_count=262144        # Linux/WSL ; persistant via /etc/sysctl.d/
```

Lancement :

```bash
cp env.example .env          # renseigner ELASTIC_PASSWORD et KIBANA_PASSWORD
docker compose up -d
docker compose ps            # attendre es01, es02, kibana "healthy"
```

Kibana : `https://localhost:5601` (utilisateur `elastic`). Le service `setup` génère les
certificats au premier démarrage puis s'arrête (`exited`), c'est normal.

Le cluster expose : TLS de bout en bout, authentification native, licence *basic*.

---

## 3. Données : dataset synthétique

Les ressources n'ayant pas été fournies, un **générateur de logs synthétique** a été
conçu ([`tools/generate_logs.py`](tools/generate_logs.py)). Il produit un bruit de fond
légitime et injecte des scénarios d'attaque documentés, mappés MITRE ATT&CK.

```bash
python tools/generate_logs.py --hours 24 --eps 3 --seed 42 --recent
```

- `--recent` : horodate les logs sur la dernière heure (détection en temps réel réaliste).
- `--eps` : événements de bruit par seconde (monter pour simuler un gros volume).
- `--seed` : reproductibilité.

Sortie dans `data/` : un fichier par source + `ATTACK_MANIFEST.json` (le « corrigé » listant
chaque attaque injectée, son horodatage et sa technique MITRE).

**Sources générées :** Windows Security, Sysmon, Linux auth, Web (Apache/Nginx),
Firewall pfSense, DNS.

**Attaques injectées :**

| Scénario | Technique MITRE |
|----------|-----------------|
| Bruteforce SSH → succès | T1110 |
| PowerShell encodé | T1059.001 |
| Création de compte | T1136 |
| Mouvement latéral RDP | T1021 |
| Scan web + exfiltration | T1046 / T1041 |
| Beaconing DNS (C2) | T1071.004 |
| Tunneling DNS | T1048.003 |
| Scan de ports (firewall) | T1046 |

> Le dataset est synthétique et assumé comme tel : l'objectif est de valider le pipeline,
> les règles et les investigations, pas de simuler un vrai parc.

---

## 4. Ingestion et normalisation

Le pipeline [`logstash/pipeline/logstash.conf`](logstash/pipeline/logstash.conf) lit les
6 fichiers, applique un parsing adapté à chaque format et normalise les champs vers **ECS** :

| Source | Parsing | Index |
|--------|---------|-------|
| Windows / Sysmon | JSON (codec) | `soc-windows-*` / `soc-sysmon-*` |
| Linux auth | grok (SSH/sudo) | `soc-linux-*` |
| Web | grok COMBINEDAPACHELOG | `soc-web-*` |
| Firewall pfSense | grok + csv (filterlog) | `soc-firewall-*` |
| DNS dnsmasq | grok | `soc-dns-*` |

Un **index template** (`soc-mapping`) force les types corrects (`source.ip` en `ip`,
ports en `integer`, champs en `keyword`) — indispensable pour les agrégations des règles
threshold. À créer avant l'ingestion :

```bash
# voir tools/ ou la section mapping ; type ip/integer/keyword sur soc-*
```

Ré-ingestion propre (après régénération des logs) :

```bash
docker compose exec logstash sh -c "rm -f /usr/share/logstash/data/sincedb_*"
docker compose restart logstash
```
  
---

## 5. Détection

**10 règles** de détection, importables en un fichier :
[`siem-rules/soc_detection_rules.ndjson`](siem-rules/soc_detection_rules.ndjson)
(Kibana → Security → Rules → Import). Chaque règle porte sa technique MITRE, sa sévérité
et son score de risque. Types utilisés : *query* (KQL) et *threshold* (agrégation).

Points notables :
- Règle **multi-sources** (beaconing DNS) couvrant `soc-dns-*` et `soc-sysmon-*`.
- Règle de **corrélation** : intrusion SSH réussie rapprochée du bruteforce (T1110).

### Amélioration des faux positifs

La règle « intrusion SSH réussie » générait initialement de nombreux faux positifs
(logins `admin` internes légitimes). Elle a été affinée en excluant le sous-réseau interne :

```
event.dataset : "linux.auth" and event.outcome : "success"
  and user.name : "admin" and not source.ip : "10.10.20.0/24"
```

→ ne conserve que les succès venant d'une IP externe (le véritable attaquant).
Les faux positifs historiques ont été marqués *closed / false positive*.

---

## 6. Visualisation

Dashboard `SOC — Supervision générale` (Kibana → Dashboard), exporté dans
[`dashboard/export.ndjson`](dashboard/export.ndjson). Panels principaux :

- Volume de logs par source dans le temps (**qualité des collectes**)
- Répartition des sources
- Top IP sources (point d'entrée d'investigation)
- Authentifications SSH : échecs vs succès
- Top ports bloqués par le firewall (scans)
- Domaines DNS les plus longs (tunneling)

---

## 7. Structure du dossier

```
scenario-2-siem-elastic/
├── docker-compose.yml            # cluster 2 nœuds + Kibana + Logstash
├── env.example                   # variables (versions, mots de passe)
├── logstash/pipeline/            # pipeline de parsing + ECS
├── tools/generate_logs.py        # générateur de dataset synthétique
├── siem-rules/                   # règles de détection (NDJSON)
├── dashboard/                    # dashboard exporté (NDJSON)
├── data/                         # logs générés (non versionné)
└── README.md
```

`data/` est ignoré par Git (volumineux et reproductible via le générateur + `--seed`).

---

## 8. Correspondance avec les livrables attendus

| Livrable (sujet) | Réalisé |
|------------------|---------|
| Architecture SIEM (DAT) | `../architecture/` |
| Déploiement ELK, 2 nœuds, TLS/auth, rétention | `docker-compose.yml` |
| Intégration multi-sources + pipelines Logstash | `logstash/` (6 sources) |
| ≥10 règles de détection + MITRE | `siem-rules/` (10 règles) |
| Dashboards + qualité des collectes | `dashboard/export.ndjson` |
| Investigation + faux positifs | `RAPPORT.md` (§8, §10) |
