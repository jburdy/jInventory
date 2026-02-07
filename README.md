# jInventory

**Inventaire systeme automatise qui genere des rapports Markdown — concu pour etre analyse par une IA.**

Une commande, trois rapports — specs materiel, logiciels installes et etat du systeme en temps reel — le tout dans des fichiers `.md` lisibles. Le format Markdown est choisi volontairement pour pouvoir coller les rapports directement dans ChatGPT, Claude, Copilot ou n'importe quelle IA generative et demander :

- *"Quel upgrade materiel aurait le plus d'impact sur les performances ?"*
- *"Je veux faire X — est-ce que ma machine est prete ?"*

L'IA recoit une image complete et structuree de votre machine et peut donner des reponses precises et actionnables au lieu de conseils generiques.

---

## Rapports generes

| Fichier | Contenu | Change quand... |
|---------|---------|-----------------|
| `*-0-hardware.md` | CPU, barrettes RAM, stockage, GPU, interfaces reseau, peripheriques USB | Le materiel est ajoute/retire |
| `*-1-software.md` | Details OS, programmes installes, services, images Docker, ports en ecoute, utilisateurs | Un logiciel est installe/mis a jour |
| `*-2-state.md` | Utilisation CPU/RAM/disque, top processus, connexions actives, logs recents | A chaque execution (instantane) |

Les fichiers sont nommes `jInventory-<hostname>-<N>-<categorie>.md` pour une identification facile entre machines.

---

## Plateformes supportees

### Linux

**Prerequis :** Bash, coreutils standard

```bash
./Linux-Inventory.sh
```

### Windows

**Prerequis :** Python 3.14+, psutil

Double-cliquez sur le lanceur — il gere tout (creation du venv, installation des dependances, execution) :

```bat
Windows-Inventory.RUN.bat
```

Ou lancez manuellement :

```bash
pip install psutil
python Windows-Inventory.py
```

### macOS (Apple Silicon & Intel)

**Prerequis :** Python 3.14+, psutil

Lancez le script d'installation automatique :

```bash
chmod +x MacOS-Inventory.RUN.sh
./MacOS-Inventory.RUN.sh
```

Ou lancez manuellement :

```bash
pip install psutil
python3 MacOS-Inventory.py
```

> **Note :** Certaines sections (ports en ecoute, logs systeme) donnent plus d'informations avec `sudo`.

---

## Ce qui est collecte

<details>
<summary><strong>Rapport materiel</strong></summary>

- Fabricant, modele, numero de serie, BIOS/firmware
- CPU : modele, coeurs, threads, cache, support virtualisation
- Barrettes RAM (slot, taille, type DDR4/DDR5, frequence)
- Peripheriques de stockage et partitions
- GPU (modele, VRAM, version du driver)
- Interfaces reseau (MAC, driver, debit)
- Peripheriques USB et PCI
- Peripheriques audio
- Details SMART des disques (Linux)
- Inventaire firmware via fwupd (Linux)
- Details Apple Silicon : coeurs P/E, Neural Engine, Rosetta 2 (macOS)
- Peripheriques Thunderbolt et Bluetooth (macOS)

</details>

<details>
<summary><strong>Rapport logiciel</strong></summary>

- Version OS, build, architecture, date d'installation
- Locale et fuseau horaire
- Versions logicielles (Python, Node.js, Go, Git, Docker, Nginx, PostgreSQL, Redis...)
- Tous les programmes installes avec version et editeur (registre Windows / pacman / Homebrew+Applications macOS)
- Services actives et en demarrage automatique
- Taches planifiees / cron jobs / timers systemd / LaunchDaemons+Agents macOS
- Images, volumes et reseaux Docker
- Utilisateurs locaux
- Ports en ecoute
- Configuration DNS

</details>

<details>
<summary><strong>Rapport d'etat</strong></summary>

- Uptime, dernier demarrage, utilisateurs connectes
- Utilisation CPU (total + par coeur)
- Utilisation memoire et swap
- Utilisation disque par partition
- Compteurs d'E/S disque
- Etat de la batterie (portables)
- Top 15 processus par CPU et memoire
- Services en cours et en echec
- Etat des conteneurs Docker
- Connexions reseau actives
- Stats d'E/S reseau
- Evenements systeme recents / logs
- Mises a jour en attente (Linux)
- Temperatures et ventilateurs (Linux, avec lm-sensors)
- Etat securite : SIP, Gatekeeper, FileVault, Firewall (macOS)
- Pression memoire et infos Wi-Fi (macOS)
- Mises a jour macOS en attente (macOS)

</details>

---

## Outils optionnels

Les scripts detectent les outils disponibles et s'adaptent. Rien ne casse si un outil est absent — la section correspondante est simplement ignoree.

**Windows :** PowerShell, Docker, Git, WSL, Node.js, Go, psql, mysql, redis-server, nginx, VS Code

**Linux :** `smartctl`, `nvme`, `sensors`, `dmidecode`, `lshw`, `fwupdmgr`, `hostnamectl`, `timedatectl`, `localectl`, `expac`, `checkupdates`

**macOS :** `brew`, `mas`, Docker, Git, Node.js, Go, psql, mysql, redis-server, nginx, Tmux, VS Code, Xcode CLT

---

## Exemple de sortie

```
Generating Windows system inventory...

Tool detection:
  [OK]      git
  [OK]      python
  [OK]      node
  [OK]      docker
  [MISSING] go
  [MISSING] psql

  [OK] jInventory-DESKTOP-ABC-2-state.md
  [OK] jInventory-DESKTOP-ABC-0-hardware.md
  [OK] jInventory-DESKTOP-ABC-1-software.md

Done. 3 files generated:
  Hardware  : jInventory-DESKTOP-ABC-0-hardware.md (12.4 KB)
  Software  : jInventory-DESKTOP-ABC-1-software.md (45.2 KB)
  State     : jInventory-DESKTOP-ABC-2-state.md (8.7 KB)
```

---

## Analyse par IA generative

L'objectif principal de jInventory est de faire le pont entre votre systeme et l'IA generative. Les donnees systeme brutes sont difficiles a lire et eparpillees dans des dizaines de commandes. jInventory consolide tout en Markdown structure que les modeles d'IA comprennent parfaitement.

### Exemples de prompts

Une fois vos rapports generes, collez-les dans votre IA preferee et essayez :

| Objectif | Prompt |
|----------|--------|
| Nettoyage | *"Voici mon inventaire logiciel. Qu'est-ce qui semble inutile, redondant ou peut etre supprime sans risque ?"* |
| Upgrade | *"D'apres mon materiel, quel upgrade aurait le plus grand impact sur les performances ?"* |
| Securite | *"Examine mes ports en ecoute et mes services actifs. Y a-t-il des problemes de securite ?"* |
| Optimisation | *"Mon systeme utilise 85% de RAM au repos. D'apres la liste des processus, qu'est-ce qui consomme la memoire ?"* |
| Migration | *"Je change de machine. Genere une checklist de tout ce que je dois reinstaller."* |
| Comparaison | *"Voici les inventaires de deux machines. Quelles sont les differences ?"* |

### Pourquoi le Markdown ?

- Les modeles d'IA gerent nativement les tableaux et la structure Markdown — aucun parsing necessaire
- Les rapports sont assez legers pour tenir dans une seule fenetre de contexte
- Lisible aussi par un humain — consultable dans n'importe quel editeur, VS Code ou GitHub

---

## Autres cas d'usage

- **Documentation** — Conserver un instantane de la config machine a cote de vos projets
- **Audits** — Suivre ce qui est installe sur plusieurs machines
- **Depannage** — Partager rapidement les infos systeme lors d'un signalement de bug
- **Versionnage** — Committer les rapports dans Git et suivre les changements dans le temps
- **Migration** — Savoir exactement quoi reinstaller sur une nouvelle machine

---

## Licence

MIT
