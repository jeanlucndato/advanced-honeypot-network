# Jeanluck Cyber Insights

**A cybersecurity portfolio focused on detection engineering, security labs, network infrastructure, and practical IT training.**

This repository publishes the static portfolio and technical case studies of [Jeanluck Ndato](https://github.com/jeanlucndato). Each project page describes its goals, design decisions, lab setup, and lessons learned, with screenshots that make the work easy to review.

**Portfolio:** [Website](https://jeanlucndato.github.io/404/) · [Résumé](https://jeanlucndato.github.io/resume/) · [LinkedIn](https://linkedin.com/in/jeanluckndato)

## Featured projects

| Project | What it demonstrates | Technologies and topics | Case study |
| --- | --- | --- | --- |
| **Hive — Interactive Honeypot Network** | A security engineering project that turns activity against decoy services into structured, searchable live telemetry. Four Go sensors observe SSH, HTTP, MySQL, and Redis activity and feed an operator dashboard. | Go, React, TypeScript, WebSockets, TCP/IP, JSONL, Docker Compose, STIX 2.1 | [Hive case study](hive.html) |
| **SOC home lab** | Building an instrumented enterprise-style environment to collect telemetry, investigate activity, and practice detection and response. | Windows Server, Active Directory, Sysmon, ELK, Wazuh, Ubuntu | [SOC overview](soc.html) · [Infrastructure details](ubuntu-server-details.html) |
| **Snort IDS/IPS lab** | Integrating firewall policy, intrusion detection, attack simulation, and alert review in a controlled lab. | OPNsense/pfSense, Snort, Kali Linux, ELK | [Snort case study](snort.html) |
| **InverseHacker** | Packaging reconnaissance and security-testing tools into a portable, containerized workflow. | Docker, Docker Compose, OSINT, web and network reconnaissance | [Case study](inversehacker.html) · [Source repository](https://github.com/jeanlucndato/inversehacker) |
| **IncidentForge** | An interactive helpdesk incident simulation focused on investigation, troubleshooting, and operational judgment. | GLPI, Docker, scenario-based IT training | [Project site](https://incident-forge.vercel.app/) · [Project write-up](IT.html) |
| **IP/MPLS network implementation** | Network architecture and routing concepts documented in a MikroTik-based ISP context. | IP/MPLS, MikroTik, OSPF, network design | [Network case study](orange.html) |
| **Security awareness lab** | Exploring social-engineering simulations as a way to support security awareness and defensive learning in authorized environments. | GoPhish, email security, incident analysis | [Case study](Phishing.html) |

Other pages cover Active Directory, Linux infrastructure, and a Kali Linux testing workstation. Browse the [portfolio homepage](index.html) for the full project index.

## Hive engineering highlights

Hive is a standout project in this portfolio. Its case study describes an end-to-end workflow from decoy interaction to operator review:

- **Protocol sensors:** separate Go sensors handle SSH, HTTP, MySQL handshakes, and Redis RESP interactions, normalizing observations into a shared event model.
- **Concurrent event delivery:** a typed event bus enriches, journals, retains, and distributes events through bounded subscriber queues so a slow dashboard client does not stall sensor handlers.
- **Operator workflow:** a React and TypeScript dashboard combines journal search with a reconnecting WebSocket feed, event details, health metrics, and CSV export.
- **Constrained deception:** the SSH shell is simulated; commands are recorded but never executed on the host. Passwords are discarded, form values are not retained by the demo endpoint, and redaction is best effort.
- **Reviewable threat intelligence:** heuristic ATT&amp;CK tags and STIX 2.1 indicators support investigation. Firewall suggestions are advisory and are never applied automatically.
- **Operational controls:** the documented local setup binds listeners to loopback by default, supports journal retention, and requires an API bearer token when the API binds beyond loopback.

The Hive case study includes [dashboard and decoy-site screenshots](hive.html). This repository contains the portfolio website and case-study material; it does not contain Hive’s Go backend or React application source.

## Skills represented

- **Blue Team and SOC:** log collection, endpoint telemetry, SIEM workflows, alert investigation, and IDS/IPS concepts.
- **Infrastructure and networking:** Active Directory, Windows and Linux servers, network segmentation, routing, and IP/MPLS.
- **Security research:** reconnaissance, web and network testing, threat modeling, and adversary-behavior analysis in lab settings.
- **Engineering and communication:** containerized environments, event-driven design, technical documentation, and clear case-study writing.

These are areas demonstrated by the projects documented here; the README does not imply certifications or production deployments. Review each case study for its scope and limitations.

## View the portfolio locally

This repository is a static HTML, CSS, and JavaScript website. It has no build step or package installation requirement.

```bash
git clone https://github.com/jeanlucndato/cyberinsights.git
cd cyberinsights
python3 -m http.server 8000
```

Open [http://localhost:8000](http://localhost:8000) in a browser. A local server handles relative assets consistently across the site.

## Repository guide

```text
.
├── index.html                   # Portfolio homepage and project index
├── hive.html                    # Hive honeypot and CTI case study
├── soc.html                     # SOC home-lab overview
├── snort.html                   # IDS/IPS lab case study
├── inversehacker.html           # InverseHacker case study
├── IT.html                      # IncidentForge write-up
├── orange.html                  # IP/MPLS network case study
├── Phishing.html                # Security awareness lab
├── *-details.html               # Supporting infrastructure and lab pages
└── assets/
    ├── css/                     # Site styles
    ├── js/                      # Navigation and interface behavior
    ├── img/                     # Project screenshots and illustrations
    └── vendor/                  # Front-end libraries
```

## Front-end stack

- Semantic HTML with custom CSS and JavaScript
- [Bootstrap](https://getbootstrap.com/) for responsive layout and interface utilities
- AOS, Swiper, GLightbox, and Isotope for motion, galleries, and filtering
- Static hosting; no server-side application is needed to browse this portfolio

## Responsible use

Offensive-security material is intended for learning and authorized testing in isolated labs or against systems for which you have explicit permission. Do not use techniques described here against third-party systems without authorization.

## Contact

- **GitHub:** [jeanlucndato](https://github.com/jeanlucndato)
- **LinkedIn:** [jeanluckndato](https://linkedin.com/in/jeanluckndato)
- **Résumé:** [jeanlucndato.github.io/resume](https://jeanlucndato.github.io/resume/)
- **Email:** [jeanlucndato@gmail.com](mailto:jeanlucndato@gmail.com)
