# Cybersecurity Operations Challenge

Mise en place et exploitation d'un **centre opérationnel de sécurité (SOC)** complet
pour détecter, analyser et répondre à des incidents dans un environnement simulé
(entreprise fictive *TechnoVision*, datasets APT29 / APT28).

**Stack :** Wazuh (EDR) · Elastic Stack (SIEM) · TheHive + Cortex (SOAR)
**Fil rouge :** MITRE ATT&CK

## Équipe

| Membre |
|--------|------|
| Kouamé Marc Bohoussou |
| Wahiba Fay |
| --- |

## Périmètre

- **Scénario 1 —** Détection et réponse aux menaces avancées (EDR)
- **Scénario 2 —** Centralisation et corrélation des logs (SIEM)
- **Scénario 3 —** Automatisation et orchestration (SOAR)

## Structure du dépôt

```
00-architecture/        DAT, PDS, schémas
scenario-1-edr-wazuh/   configs, règles, playbooks, incidents
scenario-2-siem-elastic/ pipelines, règles, dashboards
scenario-3-soar/        connecteurs, playbooks, analyseurs
docs/                   rapports d'incident, démo
```