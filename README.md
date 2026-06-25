# Advanced Honeypot Network - Hive

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev)
[![React Version](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Advanced Honeypot Network (Hive)** est une plateforme modulaire et hautement performante de Threat Intelligence et de déception réseau. Développée en **Go** pour le framework réseau et en **React 19** pour l'interface de contrôle, elle émule plusieurs protocoles (SSH, HTTP, MySQL, etc.) afin d'attirer les cyberattaquants, analyser leurs comportements en temps réel et cartographier leurs actions directement sur la matrice **MITRE ATT&CK**.

---

## 🚀 Fonctionnalités Principales

* **Multi-Émulation de Services :** Simulation intelligente de SSH (faux shell interactif), HTTP (mires WordPress/phpMyAdmin), FTP, SMB, MySQL et Redis.
* **Pipeline Événementiel (Event Bus) :** Centralisation asynchrone des interactions en tâche de fond pour une réactivité maximale.
* **Enrichissement Cyber :** Analyse GeoIP intégrée et moteur de détection basé sur la matrice MITRE ATT&CK (27 techniques couvertes).
* **Flux Temps Réel :** Transmission instantanée des logs d'attaques au Dashboard via WebSockets.
* **Renseignement sur les Menaces (CTI) :** Exportation automatisée des Indicateurs de Compromission (IOC) au format STIX 2.1 et génération de listes de blocage (`iptables`, Nginx).

---

## 🗺️ Architecture Technique

                  ┌─────────────────────────────────────────────┐
  Attackers       │              Hive Backend                   │
                  │                                             │
┌──────┐         │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐   │
│ SSH  │────2222──│──│ sshd │  │ httpd│  │ ftpd │  │ smbd │   │
│Client│         │  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘   │
└──────┘         │     │         │         │         │        │
                 │  ┌──┴───┐  ┌──┴───┐                        │
                 │  │mysqld│  │redisd│                        │
                 │  └──┬───┘  └──┬───┘                        │
                 │     │         │                             │
                 │     ▼         ▼                             │
                 │  ┌─────────────────┐                        │
                 │  │    Event Bus    │  (Canaux Go asynchrones)
                 │  └────────┬────────┘                        │
                 │           │                                 │
                 │     ┌─────┴─────┐                           │
                 │     │ Processor │  (Enrichissement GeoIP    │
                 │     │  MITRE    │   & Analyse ATT&CK)       │
                 │     │  Storage  │                           │
                 │     └───────────┘                           │
                 │                                             │
                 │  ┌─────────────────┐                        │
                 │  │   REST API      │  Routeur Chi           │
                 │  │   WebSocket     │  /ws/events             │
                 │  └─────────────────┘                        │
                 └──────────────┬──────────────────────────────┘
                                │
                 ┌──────────────┴──────────────────┐
                 │         Frontend                │
                 │   React 19 + TypeScript         │
                 │   Dashboard • Cartographie      │
                 │   MITRE Heatmap • Export CTI    │
                 └─────────────────────────────────┘

---

## 🛠️ Feuille de Route de Développement (8 Étapes)

Le projet est conçu de manière incrémentale à travers les étapes jalons suivantes :

### Étape 1 : Initialisation de l'Environnement
* Mise en place de l'arborescence standard (`cmd/`, `internal/`, `frontend/`, `pkg/`).
* Initialisation du module Go et configuration du binaire principal de démarrage.
* Préparation de l'orchestration Docker initiale pour l'infrastructure de données.

### Étape 2 : Le Premier Honeypot – SSH
* Émulation brute du protocole SSH avec la bibliothèque `golang.org/x/crypto/ssh`.
* Mécanisme de contournement d'authentification (`PasswordCallback`) acceptant les connexions pour forcer la capture des couples d'identifiants.
* Développement d'un faux Shell interactif simulant un environnement Ubuntu avec commandes standards (`ls`, `whoami`, `pwd`).

### Étape 3 : Le Pipeline d'Événements (Event Bus)
* Définition d'un schéma d'événement universel (`types.Event`) pour standardiser les structures de données.
* Développement d'un Event Bus centralisé asynchrone exploitant la puissance des canaux de Go (`channels`).
* Intégration d'un parseur GeoIP pour enrichir instantanément les adresses IP capturées avec leur localisation géographique.

### Étape 4 : Multiplication des Services Leurres
* Conception d'un Honeypot HTTP interceptant les scans automatisés sur les routes critiques (`/wp-login.php`, `/phpmyadmin`).
* Mise en place d'écouteurs de sockets bas niveau imitant les salutations réseau de MySQL et Redis (RESP protocol).

### Étape 5 : Moteur de Détection MITRE ATT&CK
* Écriture de filtres par correspondance de motifs (*pattern matching*) pour lier les actions aux techniques MITRE (ex: usage de `wget` -> T1105).
* Implémentation d'algorithmes à fenêtre glissante (*sliding windows*) via Redis pour détecter les attaques par force brute (T1110) et les scans de ports (T1046).

### Étape 6 : REST API & Flux Temps Réel
* Création d'une API REST performante (Chi Router) pour exposer les métriques, statistiques globales et historiques de sessions.
* Déploiement d'un serveur WebSocket dédié distribuant instantanément les événements du Bus vers l'extérieur.

### Étape 7 : Interface Utilisateur (React Dashboard)
* Création de l'application Single Page App en React 19 et TypeScript.
* Consommation du flux WebSocket pour mettre à jour en direct le tableau de bord.
* Intégration d'une cartographie mondiale interactive (`react-leaflet`) et d'une matrice thermique (*heatmap*) MITRE ATT&CK.

### Étape 8 : Exportations Cyber Threat Intelligence (CTI) & Industrialisation
* Module d'extraction automatique des indicateurs de compromission (IOC) au format standardisé STIX 2.1.
* Génération dynamique de listes de blocage réseau orientées pare-feu.
* Conteneurisation globale via Docker Compose avec builds multi-stages pour une mise en production instantanée.

---

## 🗂️ Structure du Projet

```text
advance-honeypot-network/
├── cmd/hive/              # Point d'entrée du binaire principal Go
├── pkg/types/             # Structures de données partagées (Event, Session, IOC)
├── internal/
│   ├── sshd/              # Honeypot SSH (Faux shell et gestionnaire de canaux)
│   ├── httpd/             # Honeypot HTTP (Pièges WordPress, phpMyAdmin)
│   ├── event/             # Pipeline Event Bus asynchrone
│   ├── mitre/             # Moteur de corrélation MITRE ATT&CK
│   ├── store/             # Gestion des connexions de données (PostgreSQL, Redis)
│   └── api/               # API REST & Serveur WebSockets
├── frontend/              # Application React 19 + TypeScript (Dashboard)
├── infra/                 # Configurations Docker, Nginx et bases de données
└── README.md              # Documentation technique
🛡️ Avertissement Légal / Legal Disclaimer
Cet outil est développé uniquement à des fins de recherche en sécurité et d'éducation. Le déploiement de honeypots sur des réseaux sans l'autorisation expresse de leur propriétaire ou de votre fournisseur d'infrastructure cloud est strictement interdit et peut violer les lois locales. Les auteurs déclinent toute responsabilité en cas de mauvaise utilisation de ce logiciel.