# Description
Nmap script that provides information about probable vulnerabilities based on discovered services.

**Contents:**
  - [Technical details](#technical-details)
  - [Requirements](#requirements)
  - [Run](#run)
    - [Pre-launch](#pre-launch)
      - [Optional](#optional)
    - [Launch](#launch)
  - [Output](#output)
  - [Errors and fixes](#errors-and-fixes)
    - [Blocked IP](#blocked-ip)
    - [Missing luasql](#missing-luasql)
  - [Docker container](#docker-container)
  - [Acknowledgements](#acknowledgements)
  - [License](#license)


# Technical details
The current implementation take care of the following cases:

- Nmap detection:
  - _Product cpe_ **AND** _version_: vulnerabilities affecting _version_ and
    vulnerabilities affecting a range of versions that include _version_.
  - _Product cpe_ **AND** _version range_: vulnerabilities affecting versions
    between _version range_ (included).
  - _product cpe_ but **NO** _version_: vulnerabilities that affect
    every version of the product.
  - If no vulnerabilities were found with _product cpe_ and _version_
    returned from Nmap, HTTP detection is used.
  - **NO** product _cpe_: HTTP detection is used.

- HTTP detection:
  - Used only if port matches HTTP/SSL.
  - An HTTP GET request is sent for every combination of _path_
    and _extension_ in **http-paths-vulnerscom.json**, comparing
    the request headers/body with the regexes in
    **http-regex-vulnerscom.json**.

> Nmap library shortport is used to detect if port matches HTTP/SSL.

# Requirements
- luasql
- nmap
- python

# Run
## Pre-launch
In order to execute **cvescannerv2.nse**, CVEs database, http-paths and http-regex files must be present.

The script **database.py** generates **cve.db** with the required information.

```bash
$ pip install -r requirements.txt
$ python database.py
```

> **Note:** For your convenience, a semi-updated database is offered as .sql format in **[CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB)**.

### Optional
**cvescannerv2.nse** can be placed in Nmap default script directory for global execution.

- Linux and OSX default script locations:
  - /usr/local/share/nmap/scripts/
  - /usr/share/nmap/scripts/
  - /opt/local/share/nmap/scripts/
  - /usr/local/Cellar/nmap/<i>&lt;version&gt;</i>/share/nmap/scripts/

- Windows default script locations:
  - C:\Program Files\Nmap\Scripts
  - %APPDATA%\nmap

> It's recommended to create a **symbolic link**, so changes in repository are reflected
> in global script.

## Launch
After database has been created, call the script:

- `nmap -sV <target_ip> --script cvescannerv2`

**Note**: cvescannerv2.nse accepts the following script-args: db, log, maxcve, path and regex.
<details>
    <summary><b>script-args default values</b></summary>

    db: cve.db
    log: cvescannerv2.log
    maxcve: 10
    path: http-paths-vulnerscom.json
    regex: http-regex-vulnerscom.json
</details>

<details>
    <summary><b>script-args examples</b></summary>

```bash
$ nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db
$ nmap -sV <target_ip> --script cvescannerv2 --script-args log=cvescannerv2.log
$ nmap -sV <target_ip> --script cvescannerv2 --script-args json=cvescannerv2.json
$ nmap -sV <target_ip> --script cvescannerv2 --script-args maxcve=10
$ nmap -sV <target_ip> --script cvescannerv2 --script-args path=http-paths-vulnerscom.json
$ nmap -sV <target_ip> --script cvescannerv2 --script-args regex=http-regex-vulnerscom.json

$ nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db,log=cvescannerv2.log,json=cvescannerv2.json,maxcve=10,path=http-paths-vulnerscom.json,regex=http-regex-vulnerscom.json
```

</details>

# Output
CVEScannerV2 will show all CVEs related to every _service-version_ discovered.

<details>
    <summary><b>cvescannerv2.nse output</b></summary>

    PORT      STATE    SERVICE        VERSION
    22/tcp    open  ssh                  OpenSSH 7.1 (protocol 2.0)
    | cvescannerv2:
    |   product: openssh
    |   version: 7.1
    |   vupdate: *
    |   cves: 27
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2008-3844       	9.3  	-    	No        	No
    |   	CVE-2016-8858       	7.8  	7.5  	No        	No
    |   	CVE-2016-6515       	7.8  	7.5  	Yes       	No
    |   	CVE-2016-1908       	7.5  	9.8  	No        	No
    |   	CVE-2016-10009      	7.5  	7.3  	Yes       	No
    |   	CVE-2015-8325       	7.2  	7.8  	No        	No
    |   	CVE-2016-10012      	7.2  	7.8  	No        	No
    |   	CVE-2016-10010      	6.9  	7.0  	Yes       	No
    |   	CVE-2020-15778      	6.8  	7.8  	No        	No
    |_  	CVE-2019-6111       	5.8  	5.9  	Yes       	No
    ...
    ...
    3306/tcp  open  mysql                MySQL 5.5.20-log
    | cvescannerv2:
    |   product: mysql
    |   version: 5.5.20
    |   vupdate: *
    |   cves: 541
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2012-2750       	10.0 	-    	No        	No
    |   	CVE-2016-6662       	10.0 	9.8  	Yes       	No
    |   	CVE-2012-3163       	9.0  	-    	No        	No
    |   	CVE-2020-14878      	7.7  	8.0  	No        	No
    |   	CVE-2013-1492       	7.5  	-    	No        	No
    |   	CVE-2014-0001       	7.5  	-    	No        	No
    |   	CVE-2018-2562       	7.5  	7.1  	No        	No
    |   	CVE-2014-6500       	7.5  	-    	No        	No
    |   	CVE-2014-6491       	7.5  	-    	No        	No
    |_  	CVE-2012-0553       	7.5  	-    	No        	No
    ...
    ...
</details>

Log file **cvescannerv2.log** contains every _exploit/metasploit_ found.

<details>
    <summary><b>cvescannerv2.log dump</b></summary>

    #################################################
    ############## 2021-11-05 14:01:01 ##############
    #################################################

    [*] host: 172.16.2.132
    [*] port: 22
    [+] protocol: tcp
    [+] service: ssh
    [+] product: openssh
    [+] version: 7.1
    [+] vupdate: *
    [+] cves: 27
    [-] 	id: CVE-2008-3844     	cvss_v2: 9.3  	cvss_v3: -
    [-] 	id: CVE-2016-8858     	cvss_v2: 7.8  	cvss_v3: 7.5
    [-] 	id: CVE-2016-6515     	cvss_v2: 7.8  	cvss_v3: 7.5
    [!] 		ExploitDB:
    [#] 			name: OpenSSH 7.2 - Denial of Service
    [#] 			id: 40888
    [#] 			url: https://www.exploit-db.com/exploits/40888
    [-] 	id: CVE-2016-1908     	cvss_v2: 7.5  	cvss_v3: 9.8
    [-] 	id: CVE-2016-10009    	cvss_v2: 7.5  	cvss_v3: 7.3
    [!] 		ExploitDB:
    [#] 			name: OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading
    [#] 			id: 40963
    [#] 			url: https://www.exploit-db.com/exploits/40963
    [-] 	id: CVE-2015-8325     	cvss_v2: 7.2  	cvss_v3: 7.8
    [-] 	id: CVE-2016-10012    	cvss_v2: 7.2  	cvss_v3: 7.8
    [-] 	id: CVE-2016-10010    	cvss_v2: 6.9  	cvss_v3: 7.0
    [!] 		ExploitDB:
    [#] 			name: OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation
    [#] 			id: 40962
    [#] 			url: https://www.exploit-db.com/exploits/40962
    [-] 	id: CVE-2020-15778    	cvss_v2: 6.8  	cvss_v3: 7.8
    ...
    ...
    -------------------------------------------------
    [*] host: 172.16.2.132
    [*] port: 3306
    [+] protocol: tcp
    [+] service: mysql
    [+] product: mysql
    [+] version: 5.5.20
    [+] vupdate: *
    [+] cves: 541
    [-] 	id: CVE-2012-2750     	cvss_v2: 10.0 	cvss_v3: -
    [-] 	id: CVE-2016-6662     	cvss_v2: 10.0 	cvss_v3: 9.8
    [!] 		ExploitDB:
    [#] 			name: MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Privilege Escalation
    [#] 			id: 40360
    [#] 			url: https://www.exploit-db.com/exploits/40360
    [-] 	id: CVE-2012-3163     	cvss_v2: 9.0  	cvss_v3: -
    [-] 	id: CVE-2020-14878    	cvss_v2: 7.7  	cvss_v3: 8.0
    [-] 	id: CVE-2013-1492     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2014-0001     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2018-2562     	cvss_v2: 7.5  	cvss_v3: 7.1
    [-] 	id: CVE-2014-6500     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2014-6491     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2012-0553     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2012-0882     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2012-3158     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2020-14760    	cvss_v2: 7.5  	cvss_v3: 5.5
    [-] 	id: CVE-2015-0411     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2016-0546     	cvss_v2: 7.2  	cvss_v3: -
    [-] 	id: CVE-2015-4819     	cvss_v2: 7.2  	cvss_v3: -
    [-] 	id: CVE-2016-3471     	cvss_v2: 7.1  	cvss_v3: 7.5
    [-] 	id: CVE-2016-6664     	cvss_v2: 6.9  	cvss_v3: 7.0
    [!] 		ExploitDB:
    [#] 			name: MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'root' System User Privilege Escalation
    [#] 			id: 40679
    [#] 			url: https://www.exploit-db.com/exploits/40679
    [-] 	id: CVE-2020-14866    	cvss_v2: 6.8  	cvss_v3: 4.9
    ...
    ...
</details>

Log file (json format) **cvescannerv2.json**.

<details>
    <summary><b>cvescannerv2.json dump</b></summary>

        {
          "192.168.45.128": {
            "ports": {
              "22/tcp": {
                "service": {
                  "vupdate": "p1",
                  "name": "ssh",
                  "version": "4.7",
                  "product": "openssh"
                },
                "vulnerabilities": {
                  "total": 36,
                  "cves": {
                    "CVE-2008-5161": {
                      "cvssv2": 2.6,
                      "cvssv3": "-"
                    },
                    "CVE-2016-6210": {
                      "cvssv3": 5.9,
                      "exploitdb": [
                        {
                          "name": "OpenSSHd 7.2p2 - Username Enumeration",
                          "url": "https://www.exploit-db.com/exploits/40113",
                          "id": 40113
                        },
                        {
                          "name": "OpenSSH 7.2p2 - Username Enumeration",
                          "url": "https://www.exploit-db.com/exploits/40136",
                          "id": 40136
                        }
                      ],
                      "metasploit": [
                        {
                          "name": "auxiliary/scanner/ssh/ssh_enumusers"
                        }
                      ],
                      "cvssv2": 4.3
                    },
                    ...
                    "CVE-2016-3115": {
                      "cvssv3": 6.4,
                      "exploitdb": [
                        {
                          "name": "OpenSSH 7.2p1 - (Authenticated) xauth Command Injection",
                          "url": "https://www.exploit-db.com/exploits/39569",
                          "id": 39569
                        }
                      ],
                      "cvssv2": 5.5
                    },
                    "CVE-2018-15473": {
                      "cvssv3": 5.3,
                      "exploitdb": [
                        {
                          "name": "OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)",
                          "url": "https://www.exploit-db.com/exploits/45210",
                          "id": 45210
                        },
                        {
                          "name": "OpenSSH 2.3 < 7.7 - Username Enumeration",
                          "url": "https://www.exploit-db.com/exploits/45233",
                          "id": 45233
                        },
                        {
                          "name": "OpenSSH < 7.7 - User Enumeration (2)",
                          "url": "https://www.exploit-db.com/exploits/45939",
                          "id": 45939
                        }
                      ],
                      "metasploit": [
                        {
                          "name": "auxiliary/scanner/ssh/ssh_enumusers"
                        }
                      ],
                      "cvssv2": 5.0
                    }
                  },
                  "cache": false
                }
              }
              ...
              ...
            },
            "timestamp": "2022-04-26 12:12:10"
          }
        }
</details>

> You can find the output from metasploitable2 and metasploitable3 in **example_data**.

# Errors and fixes
## Blocked IP
> Connection timeout/error during CRAWL phase (**database.py**)

**Fix:** Wait 15 minutes before re-running **database.py**.

## Missing luasql
> cvescannerv2.nse:54: module 'luasql.sqlite3' not found:<br>
> NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
> ...

**Fix:** Install lua-sql-sqlite3 and create a symlink to Nmap search path.
```bash
$ apt install lua-sql-sqlite3
$ ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua
```
> Above command may require super user permissions.

# Docker container
We have prepared a container with nmap, CVEScannerV2 and [netauditor](https://gitlab.gast.it.uc3m.es/schica/netauditor).
```bash
$ docker run --entrypoint nmap -v /tmp/CVEScannerV2:/tmp/CVEScannerV2 registry.gast.it.uc3m.es/kubernetesdockerimages/netauditor:latest -sV <ip> --script cvescannerv2 --script-args json=/tmp/CVEScannerV2/cvescannerv2.json,log=/tmp/CVEScannerV2/cvescannerv2.log
```
> **Note**: The entrypoint is set to **netauditor**.
> You need to change it to **nmap** and add the commands at the end.

> **Note2**: Script logs will be stored in /tmp/CVEScannerV2

# Acknowledgements
**This work has been supported by National R&D Project TEC2017-84197-C4-1-R and by
the Comunidad de Madrid project CYNAMON P2018/TCS-4566 and co-financed by European
Structural Funds (ESF and FEDER)**

- Based on [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner) script.

- Common server regexes and paths from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

- Modules cache generated from [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).
  > Can be found in **~/.msf4/store/modules_metadata.json** after running **msfconsole**

- CVE information gathered from [nvd.nist.gov](https://nvd.nist.gov).

# License
    CVEScannerV2  Copyright (C) 2022 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)
