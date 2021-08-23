# Description
Nmap script that searches for probable vulnerabilities based on services discovered in open ports.

# Requirements
- luasql
- nmap
- python
- git

# Run
### Prelaunch
In order to execute **cvescannerv2** script, it is necessary to generate the CVEs database.

The script **database.py** generates the database **cve.db** with all the required information.
It may take some time due to the high amount of vulnerabilities.

`pip install -r requirements.txt`

`python database.py`

**Note:** A semi-updated database is uploaded as .sql file in
[CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB) repository.

### Optional
Script **cvescannerv2.nse** can be placed in Nmap default script directory to execute
from anywhere.

- Linux location can be:
  - /usr/local/share/nmap/scripts/
  - /usr/share/nmap/scripts

- Windows location can be:
  - C:\Program Files\Nmap\Scripts
  - %APPDATA%\nmap

### Launch
After database has been created, it is necessary to specify the script to launch.

`nmap -sV <target_ip> --script=cvescannerv2.nse`
> If **cvescannerv2.nse** file was placed in Nmap default script directory

`nmap -sV <target_ip> --script=./cvescannerv2.nse`
> If **cvescannerv2.nse** file is in the current working directory

# Output
Nmap will show all CVEs related to every service-version discovered.
```
PORT      STATE SERVICE       VERSION
3306/tcp  open  mysql         MySQL 5.5.55
| cvescannerv2:
|   source: nvd.nist.gov
|   product: MySQL
|   version: 5.5.55
|   n_vulnerabilities: 5
|   vulnerabilities:
|     CVE ID           CVSSv2   CVSSv3   ExploitDB   Metasploit
|     CVE-2021-3278    7.5      9.8      Yes         No
|     CVE-2019-13401   6.8      8.8      No          No
|     CVE-2019-13402   6.5      8.8      No          No
|     CVE-2016-3976    5.0      7.5      Yes         Yes
|_    CVE-2014-3631    7.2      -        Yes         Yes
```

Also, a log file **cvescannerv2.log** will be generated, containing every exploit
related to CVEs.
```
#################################################
############## 2021-08-20 14:56:37 ##############
#################################################

[INFO] product: openview_storage_data_protector
[INFO] version: 6.00
[INFO] n_vulnerabilities: 2
[INFO] cve_id: CVE-2011-1866
[INFO] exploit_name: HP Data Protector 6.20 - EXEC_CMD Buffer Overflow - Windows dos Exploit
[INFO] metasploit_name: -
[INFO] exploit_url: https://www.exploit-db.com/exploits/17461
[INFO] cve_id: CVE-2011-1865
[INFO] exploit_name: HP Data Protector 6.20 - Multiple Vulnerabilities - Windows dos Exploit
[INFO] metasploit_name: -
[INFO] exploit_url: https://www.exploit-db.com/exploits/17458
[INFO] cve_id: CVE-2011-1865
[INFO] exploit_name: HP - 'OmniInet.exe' Opcode 27 Buffer Overflow (Metasploit) - Windows remote Exploit
[INFO] metasploit_name: HP OmniInet.exe Opcode 27 Buffer Overflow
[INFO] exploit_url: https://www.exploit-db.com/exploits/17467
[INFO] cve_id: CVE-2011-1865
[INFO] exploit_name: HP Data Protector 6.11 - Remote Buffer Overflow (DEP Bypass) - Windows remote Exploit
[INFO] metasploit_name: -
[INFO] exploit_url: https://www.exploit-db.com/exploits/17468
[INFO] cve_id: CVE-2011-1865
[INFO] exploit_name: HP OmniInet.exe Opcode 20 - Remote Buffer Overflow (Metasploit) - Windows remote Exploit
[INFO] metasploit_name: HP OmniInet.exe Opcode 20 Buffer Overflow
[INFO] exploit_url: https://www.exploit-db.com/exploits/17490

```



# Errors, causes and fixes
> Connection timeout/error during CRAWL phase when executing **database.py**
- Error caused by exploit-db WAF, your IP is flagged as DoS.

**Fix:** Wait 15 minutes before launching the **database.py** script again.

<br>

> cvescannerv2.nse:54: module 'luasql.sqlite3' not found:<br>
> NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
> ...
- Error caused because of missing luasql library.

**Fix:** Install lua-sql-sqlite3 and create a symlink to Nmap search path.

`sudo apt install lua-sql-sqlite3`

`sudo ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua`

# Acknowledgement

Based on [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner) script.

# License
    CVEScannerV2  Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](https://github.com/scmanjarrez/CVEScannerV2/blob/master/LICENSE)
