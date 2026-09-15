# TechnoVision — Architecture SOC
# Bibliothèque : diagrams (mingrammer)
# Génère : technovision_soc.png

from diagrams import Diagram, Cluster, Edge
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall
from diagrams.generic.storage import Storage
from diagrams.generic.blank import Blank


with Diagram(
    "TechnoVision — SOC",
    filename="technovision_soc",
    show=False,
    direction="LR",
    graph_attr={
        "splines": "ortho",
        "nodesep": "0.7",
        "ranksep": "1.0",
        "pad": "0.5",
    },
):

    # ==========================================================
    # SEGMENT ENTREPRISE — endpoints
    # ==========================================================
    with Cluster("SEGMENT ENTREPRISE — endpoints"):

        # Windows 01 : Wazuh Agent + Sysmon + Winlogbeat
        win01 = Rack("Windows 01\nWazuh Agent\nSysmon\nWinlogbeat")

        # Windows 02 : Wazuh Agent + Sysmon + Winlogbeat
        win02 = Rack("Windows 02\nWazuh Agent\nSysmon\nWinlogbeat")

        # Linux : Wazuh Agent + auditd + Filebeat
        linux = Rack("Linux Server\nWazuh Agent\nauditd\nFilebeat")

    # ==========================================================
    # SEGMENT SOC — management
    # ==========================================================
    with Cluster("SEGMENT SOC — management"):

        # EDR : Wazuh Manager avec Indexer + Dashboard intégrés
        wazuh = Rack(
            "EDR\nWazuh Manager\nIndexer + Dashboard intégrés"
        )

        # SIEM : normalisation
        logstash = Rack("SIEM\nLogstash\nNormalisation")

        # SIEM : stockage
        elasticsearch = Storage("SIEM\nElasticsearch")

        # SIEM : visualisation
        kibana = Rack("SIEM\nKibana")

        # SOAR : gestion des cas / ticketing
        thehive = Rack("SOAR\nTheHive\nCas / Ticketing")

        # SOAR : analyse des IoC
        cortex = Rack("SOAR\nCortex\nAnalyse IoC")

        # Notifications
        notifications = Rack("Notifications\nEmail / Slack")

        # Fil rouge MITRE ATT&CK
        mitre = Blank("MITRE ATT&CK")

    # ==========================================================
    # THREAT INTELLIGENCE
    # ==========================================================
    with Cluster("THREAT INTELLIGENCE"):

        # Threat Intelligence appelée par Cortex
        virustotal = Firewall("VirusTotal")
        urlhaus = Firewall("URLhaus")

        # MISP optionnel
        misp = Firewall("MISP\noptionnel")

    # ==========================================================
    # POSTE ANALYSTE SOC — séparé
    # ==========================================================
    analyst = Rack("Analyste SOC")

    # ==========================================================
    # P1 — CŒUR LIVRÉ
    # ==========================================================

    # Les trois agents Wazuh vers Wazuh Manager.
    # Télémétrie chiffrée TCP/1514.
    p1 = Edge(
        color="darkgreen",
        style="solid",
        penwidth="3",
        label="P1 • télémétrie chiffrée\nTCP/1514",
    )

    win01 >> p1 >> wazuh
    win02 >> p1 >> wazuh
    linux >> p1 >> wazuh

    # Wazuh Manager vers TheHive.
    wazuh >> Edge(
        color="darkgreen",
        style="solid",
        penwidth="3",
        label="P1 • connecteur / webhook",
    ) >> thehive

    # Wazuh Manager vers Notifications.
    wazuh >> Edge(
        color="darkgreen",
        style="solid",
        penwidth="3",
        label="P1",
    ) >> notifications

    # TheHive vers Notifications.
    thehive >> Edge(
        color="darkgreen",
        style="solid",
        penwidth="3",
        label="P1",
    ) >> notifications

    # ==========================================================
    # P2 — ÉTENDU / OPTIONNEL
    # ==========================================================

    # Winlogbeat Windows et Filebeat Linux vers Logstash.
    win01 >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2",
    ) >> logstash

    win02 >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2",
    ) >> logstash

    linux >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2",
    ) >> logstash

    # Pipeline SIEM.
    logstash >> Edge(
        color="orange",
        style="solid",
        penwidth="2",
        label="P2",
    ) >> elasticsearch

    elasticsearch >> Edge(
        color="orange",
        style="solid",
        penwidth="2",
        label="P2",
    ) >> kibana

    # Flux Elastic vers TheHive — optionnel.
    elasticsearch >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2 • optionnel",
    ) >> thehive

    # TheHive <-> Cortex.
    thehive >> Edge(
        color="orange",
        style="solid",
        penwidth="2",
        label="P2",
    ) >> cortex

    cortex >> Edge(
        color="orange",
        style="solid",
        penwidth="2",
        label="P2",
    ) >> thehive

    # Cortex vers Threat Intelligence.
    cortex >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2",
    ) >> virustotal

    cortex >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2",
    ) >> urlhaus

    cortex >> Edge(
        color="orange",
        style="dashed",
        penwidth="2",
        label="P2 • optionnel",
    ) >> misp

    # ==========================================================
    # ANALYSTE SOC
    # ==========================================================

    # L'Analyste SOC consulte Kibana, Wazuh Manager et TheHive.
    analyst >> Edge(
        color="black",
        style="solid",
        label="Consultation",
    ) >> kibana

    analyst >> Edge(
        color="black",
        style="solid",
        label="Consultation",
    ) >> wazuh

    analyst >> Edge(
        color="black",
        style="solid",
        label="Consultation",
    ) >> thehive

    # ==========================================================
    # MITRE ATT&CK — fil rouge
    # ==========================================================

    mitre >> Edge(
        color="black",
        style="dashed",
        label="Catégorisation",
    ) >> wazuh

    mitre >> Edge(
        color="black",
        style="dashed",
        label="Catégorisation",
    ) >> kibana

    mitre >> Edge(
        color="black",
        style="dashed",
        label="Analyse",
    ) >> thehive