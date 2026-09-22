# Rapport d'investigation — Incident #01

| | |
|---|---|
| **Titre** | Attaque par force brute SSH sur l'endpoint Linux SOC-LNX-01 |
| **Analyste** | Marc Bohoussou |
| **Date de détection** | 2026-09-22 10:23 UTC |
| **Sévérité** | Medium |
| **Statut** | Clôturé (investigation) |
| **Règle déclenchée** | SSH Bruteforce — échecs multiples (T1110) |
| **Source des données** | **Endpoint réel** — Elastic Agent sur SOC-LNX-01 (`/var/log/auth.log`) |

---

## 1. Résumé exécutif

Le serveur Linux SOC-LNX-01 a fait l'objet d'une attaque par force brute SSH ciblant le
compte `baduser`. **18 tentatives d'authentification échouées** ont été enregistrées depuis
une même adresse source, déclenchant la règle de détection *SSH Bruteforce*. L'attaque a
été détectée en temps réel sur des **logs réels** collectés par Elastic Agent. Aucune
authentification réussie n'a été observée : la compromission a échoué.

---

## 2. Chronologie des événements (UTC)

| Horodatage | Source | Événement | MITRE |
|------------|--------|-----------|-------|
| 2026-09-22 10:23:37 | linux.auth (réel) | Premier échec d'authentification SSH — `baduser` depuis `127.0.0.1` | T1110 |
| 10:23:37 → 12:44:10 | linux.auth (réel) | Série de **18 échecs** sur le compte `baduser`, dépassant le seuil de détection (5) | T1110 |
| ~10:24 puis 12:44 | Detection engine | Génération d'alertes *SSH Bruteforce* (severity Medium, risk score 47) | — |
| — | linux.auth | **Aucun** `Accepted password` observé pour `baduser` | — |

> Fenêtre d'observation : 10:23:37 → 12:44:10 UTC (les tentatives ont été rejouées en
> plusieurs salves lors des tests de détection).

---

## 3. Indicateurs de compromission (IoC)

| Type | Valeur | Commentaire |
|------|--------|-------------|
| IP source | `127.0.0.1` | Origine des tentatives (test local sur la VM) |
| Compte ciblé | `baduser` | Utilisateur inexistant (`invalid user`) |
| Hôte | SOC-LNX-01 (`192.168.56.20`) | Système visé |
| Service / port | SSH — 22/tcp | Service exposé |
| Nombre d'échecs | 18 | Tous en échec, aucun succès |

---

## 4. Analyse et étendue

- **Vecteur** : service SSH exposé, tentatives répétées sur un compte inexistant
  (`Failed password for invalid user baduser`).
- **Résultat** : aucune authentification réussie → **pas de compromission**. L'attaque a
  été détectée et serait bloquée par les mesures de remédiation ci-dessous.
- **Origine des données** : logs **réels** de l'endpoint, collectés par Elastic Agent,
  parsés en ECS (`source.ip`, `user.name`, `event.outcome`) et indexés dans `soc-linux-*` —
  les mêmes règles que les sources synthétiques s'y appliquent.
- **Limite d'attribution** : les tentatives apparaissent depuis `127.0.0.1` (test local).
  En scénario d'attaque distante (depuis la VM Kali via le lab), le NAT Hyper-V présente
  l'IP de l'hôte (`192.168.56.1`) ; la détection reste valide, seule l'IP source distincte
  est masquée.

---

## 5. Cadre MITRE ATT&CK

| Tactique | Technique | ID | Observé |
|----------|-----------|----|---------|
| Credential Access | Brute Force | T1110 | 18 échecs d'authentification SSH depuis une même source |

---

## 6. Réponse et remédiation

**Actions immédiates**
- [ ] Bloquer l'IP source au niveau du firewall / hôte.
- [ ] Vérifier qu'aucune session `baduser` n'a abouti (confirmé : aucun succès).

**Durcissement**
- [ ] Authentification SSH par clé uniquement (`PasswordAuthentication no`).
- [ ] Fail2ban : bannissement automatique après N échecs.
- [ ] Restreindre l'exposition SSH (VPN, allow-list d'IP).
- [ ] Politique de mots de passe forts + désactivation des comptes inexistants sollicités.

**Amélioration de la détection**
- [ ] Règle threshold en place (≥ 5 échecs par `source.ip`) — validée sur données réelles.
- [ ] Compléter par une règle de corrélation « échecs multiples puis succès » (règle #10).

---

## 7. Preuves

- Règle : *SSH Bruteforce — échecs multiples* (threshold, `source.ip` ≥ 5, T1110).
- Agrégation Elasticsearch : 18 échecs `baduser` depuis `127.0.0.1`, 10:23:37 → 12:44:10 UTC.
- Événement type :
  `2026-09-22T10:23:37Z soc-lnx sshd[...]: Failed password for invalid user baduser from 127.0.0.1 port ... ssh2`
- Alertes Kibana : 2 alertes *SSH Bruteforce*, severity Medium, source `127.0.0.1`.

> 📷 **[Capture]** — Vue Alerts avec les alertes SSH Bruteforce (source 127.0.0.1).
> 📷 **[Capture]** — Détail d'un événement réel (`agent.type: filebeat`, champs ECS renseignés).
