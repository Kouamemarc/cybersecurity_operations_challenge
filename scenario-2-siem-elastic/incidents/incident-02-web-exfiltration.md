# Rapport d'investigation — Incident #02

| | |
|---|---|
| **Titre** | Scan web (sqlmap) puis exfiltration de données depuis une IP externe |
| **Analyste** | Marc Bohoussou |
| **Date de détection** | 2026-09-21 07:43 UTC |
| **Sévérité** | Critique |
| **Statut** | Clôturé (investigation) |
| **Règles déclenchées** | User-Agent d'outil offensif (T1595), Exfiltration de données via endpoint web (T1041) |

---

## 1. Résumé exécutif

Une adresse IP externe (`21.227.148.148`) a mené une reconnaissance web automatisée
(outil sqlmap) contre le serveur web de TechnoVision, testant plusieurs chemins sensibles.
La séquence s'est terminée, ~40 secondes plus tard, par une requête `POST /api/export`
retournant **~37 Mo de données** — une exfiltration réussie. L'attaque, entièrement
extérieure au réseau, a été reconstruite par corrélation des journaux web et firewall.

---

## 2. Chronologie des événements (UTC)

| Horodatage | Source | Événement | MITRE |
|------------|--------|-----------|-------|
| 07:43:55 | web.access | Début du scan — requêtes GET vers des chemins sensibles, User-Agent `sqlmap/1.7` | T1595 / T1046 |
| 07:43:56 → 07:44:10 | web.access | Rafale de requêtes : `/admin`, `/.env`, `/wp-login.php`, `/phpmyadmin`, `/../../etc/passwd`, `/backup.zip` | T1595 |
| 07:44:35 | web.access | **`POST /api/export` → HTTP 200, 36 981 368 octets (~37 Mo), User-Agent `curl/8.0`** — exfiltration | T1041 |
| 07:44:35 | network.firewall | Flux sortant volumineux corrélé vers l'IP externe | T1041 |

> Durée totale de l'attaque : **~40 secondes** (07:43:55 → 07:44:35 UTC).

---

## 3. Indicateurs de compromission (IoC)

| Type | Valeur | Commentaire |
|------|--------|-------------|
| IP source | `21.227.148.148` | Attaquant (externe) |
| User-Agent | `sqlmap/1.7` | Outil de scan/injection |
| User-Agent | `curl/8.0` | Outil d'exfiltration |
| Endpoint ciblé | `POST /api/export` | Canal d'exfiltration |
| Volume exfiltré | ~37 Mo (36 981 368 octets) | Réponse HTTP 200 anormalement volumineuse |
| Chemins sondés | `/admin`, `/.env`, `/../../etc/passwd`, `/backup.zip`… | Reconnaissance de fichiers sensibles |

---

## 4. Analyse et étendue

- **Vecteur** : application web exposée, endpoint `/api/export` accessible sans contrôle suffisant.
- **Déroulé** : reconnaissance automatisée (sqlmap) → identification d'un endpoint exploitable → exfiltration massive via un simple POST.
- **Corrélation multi-sources** : l'IP `21.227.148.148` apparaît dans les logs **web** (scan + exfil) **et** dans les logs **firewall** (flux sortant volumineux au même instant) — ce qui confirme l'exfiltration réelle des données, au-delà du simple code HTTP 200.
- **Signal vs bruit** : l'attaque se distingue par un User-Agent d'outil offensif et un volume de réponse anormal, non par le volume de requêtes (seulement 7 événements).

---

## 5. Cadre MITRE ATT&CK

| Tactique | Technique | ID | Observé |
|----------|-----------|----|---------|
| Reconnaissance | Active Scanning | T1595 | Requêtes sqlmap vers chemins sensibles |
| Discovery | Network Service Discovery | T1046 | Sondage de l'application web |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `POST /api/export`, ~37 Mo sortis |

---

## 6. Réponse et remédiation

**Actions immédiates**
- [ ] Bloquer l'IP `21.227.148.148` au firewall.
- [ ] Restreindre / authentifier l'endpoint `/api/export` (contrôle d'accès, rate limiting).
- [ ] Auditer les données potentiellement exfiltrées (~37 Mo) et évaluer l'impact (RGPD si données personnelles).

**Durcissement**
- [ ] WAF devant l'application (blocage des User-Agents d'outils offensifs, des patterns de traversée `../`).
- [ ] Rate limiting et détection d'anomalie de volume sur les réponses.
- [ ] Journalisation applicative renforcée sur les endpoints sensibles.

**Amélioration de la détection**
- [ ] Règle sur les réponses volumineuses : `http.response.body.bytes > 1000000` sur `/api/export`.
- [ ] Règle sur les User-Agents offensifs (sqlmap, nikto, curl vers endpoints internes).

---

## 7. Preuves

- Timeline `Investigation - Scan web & Exfiltration (T1046-T1041)`.
- Événement clé (exfiltration) :
  `21.227.148.148 - - [21/Sep/2026:07:44:35 +0000] "POST /api/export HTTP/1.1" 200 36981368 "-" "curl/8.0"`
- Dashboard : panels « Top IP sources » et « SSH/anomalies ».
