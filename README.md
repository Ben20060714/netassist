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

Pour les profils `service` et `vulnerability`, le périmètre de ports est
configurable dans l’interface : `top100` (défaut), `top1000`, `all` (`-p-`) ou
une liste/range validée comme `22,80,443,8000-8100`. Le choix est affiché dans
la commande exacte avant la confirmation.

Un export IDS/IPS facultatif peut être fourni après la confirmation du scan au
format JSON, JSONL/NDJSON ou CSV. Netassist le filtre sur la cible autorisée et
ajoute les alertes corrélées au rapport Markdown/JSON ainsi que dans
`ids-alerts.json`. Il ne se connecte pas directement à l’IDS/IPS et ne modifie
aucune alerte.

## Limites de sécurité

Netassist ne contourne pas les IDS, IPS, pare-feu ou antivirus et ne fournit
aucune technique de furtivité, d’évasion, de brute force, d’exploitation ou de
persistance. Les profils disponibles sont volontairement non furtifs :
`discovery` est une découverte d’hôtes à faible impact, `service` limite la
détection aux 100 ports courants et `vulnerability` est réservé à un périmètre
validé. Les scans actifs nécessitent une autorisation écrite et une confirmation
explicite dans l’application.
