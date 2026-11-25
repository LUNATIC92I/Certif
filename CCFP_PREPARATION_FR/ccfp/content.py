"""Textes d'accompagnement du guide : présentation CCFP, objectifs, conseils, glossaire, bibliographie."""

TITLE = "CROWDSTRIKE CCFP – 250 QUESTIONS À CHOIX MULTIPLES POUR RÉUSSIR LA CERTIFICATION"
SUBTITLE = ("Guide avancé de préparation, d'évaluation et de maîtrise de la plateforme "
            "CrowdStrike Falcon")
EDITION = "Édition française – 2026"

DISCLAIMER = (
    "Ce guide est une ressource pédagogique indépendante. Toutes les questions sont originales et ont été "
    "rédigées à partir des objectifs publics de l'examen et de la documentation publique de CrowdStrike. "
    "Il ne s'agit en aucun cas de questions officielles, confidentielles ou divulguées de l'examen CCFP. "
    "Ce document n'est ni produit, ni approuvé par CrowdStrike. CrowdStrike, Falcon, Charlotte AI et les "
    "noms de modules cités sont des marques de CrowdStrike, Inc."
)

EXAM_FACTS = [
    ("Intitulé", "CrowdStrike Certified Falcon Practitioner (CCFP)"),
    ("Public visé", "Professionnels débutants en sécurité ou personnes ayant des bases en cybersécurité et une "
                    "pratique de la plateforme Falcon, avec une orientation SOC"),
    ("Format", "60 questions, 90 minutes"),
    ("Seuil de réussite", "Non indiqué dans le guide d'examen consulté (juillet 2026)"),
    ("Expérience recommandée", "3 à 6 mois de pratique de Falcon en production"),
    ("Formation recommandée", "Cours CrowdStrike Certified Falcon Practitioner de CrowdStrike University"),
    ("Inscription", "Bon d'examen (voucher) acheté via Pearson VUE ou le commercial CrowdStrike ; âge minimum "
                    "de 18 ans ; acceptation du CrowdStrike Certification Exam Agreement"),
    ("Passage", "En ligne ou en centre Pearson VUE ; examen en anglais (adapté aux non-anglophones)"),
    ("Nouvelle tentative", "48 heures après un premier échec, puis 7 jours entre les tentatives suivantes ; "
                           "au-delà de la 4e tentative, examen au cas par cas"),
    ("Validité", "3 ans ; recertification par la réussite de la version la plus récente de l'examen"),
    ("Contestation d'une question", "Dans les 3 jours suivant l'examen, auprès de l'équipe certification "
                                    "de CrowdStrike (adresse indiquée dans le guide officiel)"),
]

OFFICIAL_DOMAINS = [
    ("1", "Cybersecurity Fundamentals",
     "Types de menaces (malware, ransomware, phishing, mouvement latéral) ; tactiques et techniques MITRE "
     "ATT&CK ; EDR, NGAV, XDR, SIEM et cloud ; quotidien du SOC (triage, alert fatigue, dwell time) ; "
     "architectures mono et multi-tenant ; double rôle de l'IA."),
    ("2", "Falcon Platform Overview",
     "Principes d'architecture (cloud-native, capteur léger, console unique, multi-tenant) ; modules (Prevent, "
     "Insight XDR, Exposure Management, Next-Gen Identity Security, Next-Gen SIEM, Cloud Security, AIDR, "
     "Charlotte AI) ; phases d'adoption ; apport de la threat intelligence ; bénéfices opérationnels."),
    ("3", "Core Operational Workflows",
     "Navigation dans la console (menus, favoris, recherche universelle) ; présentation et priorisation des "
     "détections (MITRE, contexte) ; étapes d'une investigation ; cycle détection, investigation, réponse."),
    ("4", "AI and Automation in Falcon",
     "Rôle de l'IA dans la plateforme (Charlotte AI, Falcon AIDR, workflows agentiques, machine learning du "
     "Threat Graph) ; triage assisté par l'IA ; IA responsable : bénéfices et risques."),
]

MODULE_MAPPING = [
    (1, "Domaines 2 et 4 (architecture, modules, IA) ; domaine 1.5 (multi-tenant)", "Cœur CCFP"),
    (2, "Domaines 1.3 et 2.2 (NGAV, Falcon Prevent, politiques)", "Cœur CCFP, approfondi"),
    (3, "Domaine 3 (détections, investigation, cycle de réponse) ; domaine 4.2 (triage assisté)", "Cœur CCFP"),
    (4, "Domaine 3.3 (investigation) ; au-delà : chasse et requêtes", "Approfondissement (niveau CCFH)"),
    (5, "Domaines 1.1, 1.2 et 2.4 (menaces, MITRE, intelligence)", "Cœur CCFP"),
    (6, "Domaine 3.4 (réponse) ; au-delà : commandes RTR", "Approfondissement (niveau CCFR)"),
    (7, "Domaines 1.1 et 3.4 (menaces, réponse)", "Cœur CCFP, approfondi"),
    (8, "Domaines 1.3 et 2.2 (Next-Gen Identity Security, Cloud Security)", "Cœur CCFP"),
    (9, "Domaine 2.2 (Exposure Management, Device Control)", "Cœur CCFP"),
    (10, "Domaine 3.1 (console) ; au-delà : administration", "Approfondissement (niveau CCFA)"),
    (11, "Domaines 1 et 3 en situation", "Mise en pratique"),
]

OBJECTIVES = [
    "Décrire l'architecture cloud-native de Falcon (capteur, Threat Graph, console, clouds régionaux) et le rôle "
    "de chaque module.",
    "Configurer et expliquer les politiques de prévention, les exclusions et les groupes d'hôtes sans créer "
    "d'angles morts.",
    "Trier une détection : lire l'arbre de processus, la ligne de commande et le mapping MITRE ATT&CK, "
    "prioriser et escalader.",
    "Conduire une investigation et une chasse avec Advanced Event Search (CQL) et distinguer CQL de FQL.",
    "Exploiter la threat intelligence : IOC et IOA, profils d'adversaires, gestion des indicateurs.",
    "Répondre à distance avec Real Time Response et le confinement réseau, en respectant le moindre privilège.",
    "Mener une réponse à incident complète, du confinement au retour d'expérience, en préservant les preuves.",
    "Comprendre la protection des identités, la sécurité du cloud, l'Exposure Management et Device Control.",
    "Utiliser l'IA (Charlotte AI, AIDR) de façon responsable dans les opérations du SOC.",
]

TIPS = [
    ("Partir du guide officiel", "Le CCFP évalue d'abord les fondamentaux et la compréhension de la "
     "plateforme. Relisez les quatre domaines officiels et assurez-vous de maîtriser chaque objectif."),
    ("Pratiquer dans la console", "Trois à six mois de pratique sont recommandés : naviguez dans la console, "
     "ouvrez des détections, explorez l'arbre de processus, utilisez la recherche universelle et les favoris."),
    ("Suivre le parcours CrowdStrike University", "Les cours CCFP sont la préparation de référence. Les "
     "documentations recommandées sont accessibles depuis la console (Support and resources)."),
    ("Raisonner par scénario", "La plupart des questions exigent de choisir la meilleure action dans un "
     "contexte donné. Identifiez l'objectif (triage, confinement, preuve) avant de lire les propositions."),
    ("Se méfier des absolus", "Les propositions contenant « toujours », « jamais », « tout le parc » ou "
     "« sans vérification » sont souvent incorrectes en réponse à incident."),
    ("Connaître les noms des modules", "Les noms commerciaux évoluent (par exemple Falcon Identity Protection, "
     "désormais dans Next-Gen Identity Security). Retenez la fonction de chaque module plutôt que son seul nom."),
    ("S'entraîner en conditions réelles", "Passez l'examen blanc de 50 questions en 75 minutes, sans "
     "documentation, puis analysez chaque erreur à l'aide du corrigé et de la grille d'autoévaluation."),
    ("Gérer son temps", "Avec 60 questions en 90 minutes, visez environ 1 min 30 par question. Marquez les "
     "questions difficiles et revenez-y à la fin."),
]

SCORE_LEVELS = [
    ("90 – 100", "Excellente maîtrise", "Vous êtes prêt : entretenez vos acquis par la pratique."),
    ("80 – 89", "Bon niveau", "Revoyez les modules où se concentrent vos erreurs, puis refaites l'examen blanc."),
    ("70 – 79", "Connaissances à renforcer", "Reprenez les explications des questions manquées et les modules "
                                            "correspondants de la banque."),
    ("< 70", "Préparation supplémentaire recommandée", "Retravaillez la banque module par module et complétez "
                                                       "par la pratique de la console avant un nouvel essai."),
]

GLOSSARY = [
    ("Active Responder", "Rôle RTR intermédiaire autorisant la collecte (get) et des actions de remédiation (kill, rm, reg set/delete)."),
    ("Advanced Event Search", "Interface de recherche dans la télémétrie et les données Falcon, fondée sur LogScale et le langage CQL."),
    ("AID (Agent ID)", "Identifiant unique d'un capteur installé sur un hôte."),
    ("ASEP", "Auto-Start Extensibility Point : emplacement de démarrage automatique (clés Run, services…) utilisé pour la persistance."),
    ("BYOVD", "Bring Your Own Vulnerable Driver : chargement d'un pilote signé vulnérable pour agir au niveau du noyau."),
    ("Charlotte AI", "Analyste de sécurité IA agentique intégré à Falcon (résumés, questions en langage naturel, aide au triage)."),
    ("CID / CCID", "Customer ID : identifiant du tenant client ; le CCID inclut une somme de contrôle et sert à l'installation du capteur."),
    ("CQL", "CrowdStrike Query Language, langage de requête d'Advanced Event Search et de Next-Gen SIEM (filtres, regex, fonctions chaînées)."),
    ("CrowdScore", "Indicateur synthétique du niveau de menace observé sur l'environnement d'un client."),
    ("CSPM / IOM", "Gestion de la posture de sécurité cloud ; un IOM (Indicator of Misconfiguration) signale une configuration à risque."),
    ("Custom IOA", "Règle d'indicateur d'attaque personnalisée (critères sur image, ligne de commande, parent…) avec action de surveillance, détection ou blocage."),
    ("Device Control", "Module de contrôle des périphériques USB par classes, actions et exceptions."),
    ("Dwell time", "Durée de présence non détectée d'un adversaire dans l'environnement."),
    ("Event Streams", "API diffusant en continu les détections et les événements d'audit vers des outils tiers (SIEM)."),
    ("Exposure Management", "Ensemble de capacités d'inventaire des actifs, de gestion des vulnérabilités et de réduction de la surface d'attaque."),
    ("ExPRT.AI", "Notation de CrowdStrike estimant le risque réel d'exploitation d'une vulnérabilité."),
    ("Falcon AIDR", "AI Detection and Response : sécurisation de l'usage de l'IA et des agents IA (offre Falcon Guardian)."),
    ("Falcon Complete", "Service managé de détection et de réponse opéré par CrowdStrike."),
    ("Falcon Data Replicator (FDR)", "Export de la télémétrie brute des capteurs vers un stockage de type S3."),
    ("Falcon Fusion SOAR", "Moteur de workflows et d'automatisation de la plateforme."),
    ("Falcon Insight XDR", "Module EDR/XDR de détection, d'investigation et de réponse."),
    ("Falcon OverWatch", "Service de threat hunting managé 24/7 réalisé par des analystes CrowdStrike."),
    ("Falcon Prevent", "Module NGAV : machine learning, IOA, protection contre les exploits."),
    ("FQL", "Falcon Query Language : syntaxe de filtrage des API et de certaines vues (propriété:'valeur', + pour ET, virgule pour OU)."),
    ("Host group", "Groupe d'hôtes statique ou dynamique auquel sont attribuées les politiques."),
    ("IOA", "Indicator of Attack : comportement révélant une attaque en cours, indépendamment de l'outil utilisé."),
    ("IOC", "Indicator of Compromise : artefact technique observé (hash, IP, domaine)."),
    ("Jeton de maintenance", "Jeton requis pour désinstaller ou modifier le capteur lorsque la protection est activée."),
    ("Network containment", "Confinement réseau d'un hôte, qui conserve la communication avec le cloud CrowdStrike."),
    ("Next-Gen Identity Security", "Offre de protection des identités (ITDR, accès privilégiés), incluant l'ancienne Falcon Identity Protection."),
    ("Next-Gen SIEM", "SIEM de la plateforme Falcon, fondé sur LogScale, pour les données Falcon et tierces."),
    ("ProcessRollup2", "Événement de télémétrie décrivant le lancement d'un processus."),
    ("Real Time Response (RTR)", "Session de commandes à distance sur un hôte via le capteur."),
    ("Reduced Functionality Mode", "État d'un capteur fonctionnant avec des capacités limitées, souvent pour cause d'incompatibilité du noyau."),
    ("Response policy", "Politique définissant les fonctions RTR autorisées sur un groupe d'hôtes."),
    ("Sensor update policy", "Politique fixant la version du capteur et la protection contre la désinstallation."),
    ("Sensor Visibility Exclusion", "Exclusion qui supprime toute visibilité du capteur sur un chemin, à utiliser en dernier recours."),
    ("TargetProcessId / ContextProcessId", "Identifiants de processus Falcon permettant de relier un processus à ses événements."),
    ("Threat Graph", "Base de données graphe cloud de CrowdStrike qui corrèle les événements de tous les capteurs."),
    ("Tenant multi-CID (Flight Control)", "Architecture où un tenant parent supervise plusieurs tenants enfants."),
]

BIBLIO_PUBLIC = [
    ("CrowdStrike University – CCFP Certification Exam Guide (juillet 2026)",
     "https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/crowdstrike-university/ccfp-certification-exam-guide.pdf"),
    ("CrowdStrike – Falcon Certification Program",
     "https://www.crowdstrike.com/en-us/crowdstrike-university/crowdstrike-falcon-certification-program/"),
    ("CrowdStrike – Charlotte AI", "https://www.crowdstrike.com/en-us/platform/charlotte-ai/"),
    ("CrowdStrike – Falcon Guardian : AIDR et sécurité des agents IA",
     "https://www.crowdstrike.com/en-us/platform/falcon-guardian-aidr/"),
    ("CrowdStrike – Next-Gen Identity Security",
     "https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/"),
    ("CrowdStrike Tech Hub – Endpoint Security", "https://www.crowdstrike.com/tech-hub/endpoint-security/"),
    ("CrowdStrike Tech Hub – The Power of Real Time Response",
     "https://www.crowdstrike.com/en-us/resources/tech-hub/endpoint-security/the-power-of-real-time-response/"),
    ("CrowdStrike Developer Center – Falcon Query Language (FQL)",
     "https://developer.crowdstrike.com/api-reference/falcon-query-language/"),
    ("CrowdStrike Developer Center – Real Time Response API",
     "https://developer.crowdstrike.com/api-reference/collections/real-time-response/"),
    ("CrowdStrike Developer Center – Real Time Response Admin API",
     "https://developer.crowdstrike.com/api-reference/collections/real-time-response-admin/"),
    ("Falcon LogScale – CrowdStrike Query Language syntax",
     "https://library.humio.com/crowdstrike-query-language/syntax.html"),
    ("PSFalcon – Real-time Response (wiki)", "https://github.com/CrowdStrike/psfalcon/wiki/Real-time-Response"),
    ("CrowdStrike – Resources", "https://www.crowdstrike.com/resources/"),
    ("MITRE ATT&CK – Enterprise Matrix", "https://attack.mitre.org/"),
    ("NIST SP 800-61 Rev. 2 – Computer Security Incident Handling Guide", "https://csrc.nist.gov/pubs/sp/800/61/r2/final"),
    ("RFC 3227 – Guidelines for Evidence Collection and Archiving", "https://www.rfc-editor.org/rfc/rfc3227"),
    ("FIRST – Traffic Light Protocol 2.0", "https://www.first.org/tlp/"),
    ("CISA – Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
]

BIBLIO_AUTH = [
    ("Documentation Falcon (portail authentifié, accessible depuis la console : Support and resources > "
     "Documentation)", "https://falcon.crowdstrike.com/documentation/"),
]

SOURCES_NOTE = (
    "Les pages publiques listées ont été consultées en novembre 2026 pour vérifier les objectifs de l'examen et "
    "les éléments techniques. La documentation Falcon du portail client nécessite une authentification : elle n'a "
    "pas été consultée pour ce guide. Les éléments qui en dépendent (noms exacts des réglages, menus, limites "
    "de licence) sont signalés comme susceptibles de varier selon la version, le cloud et l'abonnement."
)
