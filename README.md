# PIVOTEER

Pivoteer helper script. It is designed to be your "sanity check" and automation partner during pivoting.
Setup Instructions

Create the directory:
```Bash
sudo mkdir -p /opt/pivoting-tools
sudo chown $USER:$USER /opt/pivoting-tools
```
Populate it with these exact filenames (rename your downloaded files):
```
- proxy (The Ligolo-ng server binary for Linux)

- agent (Ligolo-ng Linux agent)

- agent.exe (Ligolo-ng Windows agent)

- chisel (Chisel binary for Linux)

- chisel.exe (Chisel binary for Windows)
```
Save the script below as pivoteer.py and make it executable:
```Bash
chmod +x pivoteer.py
```
Run it:
```Bash

python3 pivoteer.py
```
