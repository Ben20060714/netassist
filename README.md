# netassist

Console interactive Python 3.12+ pour lancer des scans Nmap dans un périmètre
explicitement autorisé et produire des rapports lisibles.

## Installation et lancement

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m netassist
```

`nmap` doit être installé sur le système. L’application reste ouverte jusqu’à
ce que l’utilisateur saisisse `exit` ou `quit`.

## Sorties

Chaque scan est placé dans `scans/<date>_<cible>_<profil>/` : XML Nmap, `.nmap`,
`.gnmap`, copie `.txt`, `report.md`, `report.json` et les sorties de commande.

## Limites de sécurité

Netassist ne contourne pas les IDS, IPS, pare-feu ou antivirus et ne fournit
aucune technique de furtivité, d’évasion, de brute force, d’exploitation ou de
persistance. Les scans actifs nécessitent une autorisation écrite et une
confirmation explicite dans l’application. Le profil `vulnerability` utilise
les scripts NSE `vuln` et doit être réservé à un laboratoire ou à un périmètre
validé.
