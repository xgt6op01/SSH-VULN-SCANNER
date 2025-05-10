Ultimate SSH Vulnerability Scanner
----------------------------------
This tool scans SSH servers for known vulnerabilities based on banner enumeration.
It checks CVE entries in a local database and links to corresponding GitHub/Exploit-DB exploits.

Features:
---------
- Scans a single IP or multiple IPs from a list.
- Supports custom ports (default is 22).
- Enumerates supported ciphers, key exchange algorithms, and MACs.
- Attempts SSH authentication bypass to detect SSH version leaks.
- Links to public exploits from GitHub and Exploit-DB.

Requirements:
-------------
- Python 3.8+
- Packages: paramiko, requests, argparse, colorama

Installation:
-------------
1. Clone the repository or download the files.
2. Install dependencies:

To run this script, please follow this setp,
####################Make sure to add a virtual environment#############
sudo apt-get install python3-venv

python3 -m venv ssh-scan

source ssh-scan/bin/activate

pip install -r requirements.txt

##########################################

Updating CVE Database:
-----------------------
1. Run the `update_cves.py` script to fetch the latest CVE information:

python3 update_cves.py

Usage:
------
### Scan a single IP:
To scan a specific IP for vulnerabilities, run the following command:

python3 scanner.py -i <IP_ADDRESS>

### Scan multiple IPs from a list:
To scan a list of IP addresses, specify a file containing the IPs (one per line):

python3 scanner.py -l targets.txt


### Specify a custom port (default is 22):
If you need to scan a non-default port (e.g., 2222), use the `-p` flag:

python3 scanner.py -i <IP_ADDRESS> -p 2222

Output:
-------
The output shows the SSH banner, enumerated supported ciphers, key exchange algorithms, and MACs.
It also displays any matched CVE vulnerabilities, with links to GitHub and Exploit-DB.

Example Output:
---------------
[+] 192.168.1.1:22 - SSH-2.0-OpenSSH_7.6p1 Debian-4+deb9u7
[!] Vulnerabilities found:
    CVE-2016-0777
        [GitHub] https://github.com/0x27/CVE-2016-0777
        [Exploit-DB] https://www.exploit-db.com/exploits/39169
    CVE-2019-6111
        [Exploit-DB] https://www.exploit-db.com/exploits/46516
[+] Supported Ciphers: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr']
[+] Supported Key Exchange Algorithms: ['diffie-hellman-group-exchange-sha256', 'ecdh-sha2-nistp256']
[+] Supported MACs: ['hmac-sha2-256', 'hmac-sha2-512']

Warning:
--------
This tool is intended for educational and research purposes only.
Do not scan IPs you do not own or have explicit permission to scan.

License:
--------
MIT License. Feel free to modify and distribute, but do so responsibly.

