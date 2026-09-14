# Użycie

`python app.py scan --profile quick --target 127.0.0.1` — plan.
`python app.py scan --profile lan-discovery --target 192.168.1.0/24 --authorized --apply`
`python app.py export --xml scan.xml --output reports`
`python app.py compare --xml before.xml --other after.xml --output reports`

Backend: osobno zainstalowany Nmap, na Windows Npcap dla wymagających go profili.
UDP wymaga administratora/root. Program nie instaluje backendów ani nie podnosi uprawnień.
MVP przyjmuje IP/CIDR, maks. 256 adresów; dla nazwy hosta podaj wcześniej ustalony IP.
Brak NSE, exploitów, evasion i automatycznego skanowania Internetu.
XML/TXT są wynikiem Nmap; --output dodatkowo eksportuje JSON/TXT/HTML parsowanych danych.
