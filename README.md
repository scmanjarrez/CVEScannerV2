# Description
Nmap script that provides information about probable vulnerabilities based on discovered services.

**Contents:**
  - [Technical details](#technical-details)
  - [Requirements](#requirements)
      - [Optional](#optional)
  - [Execution](#execution)
      - [Output](#output)
  - [Errors and fixes](#errors-and-fixes)
    - [Blocked IP](#blocked-ip)
    - [Missing luasql](#missing-luasql)
  - [Docker container](#docker-container)
  - [Acknowledgements](#acknowledgements)
  - [License](#license)


# Technical details
The current implementation take care of the following cases:

- If Nmap detects:
  - `cpe` **AND** `version`: vulnerabilities affecting `version` and
    vulnerabilities affecting a range of versions that include `version`.
  - `cpe` **AND** `version range`: vulnerabilities affecting versions
    between `version range` (included).
  - `cpe` but **NO** `version`: vulnerabilities that affect
    every version of the product.
  - If no vulnerabilities were found with `cpe` and `version`
    returned from Nmap, HTTP detection is used.
  - **NO** `cpe`: HTTP detection is used.

- HTTP detection:
  - Used only if port matches **HTTP**/**SSL**/**UPnP**.
  - An HTTP GET request is sent for every combination of _path_
    and _extension_ in `extra/http-paths-vulnerscom.json`, comparing
    the request headers/body with the regexes in
    `extra/http-regex-vulnerscom.json`.
  - Finally, the _home_ page html is analyzed in search for library paths.
    The script tries to obtain the name and version from library location;
    then does an HTTP GET to that path in order to inspect the code
    of the library and analyze the starting commenot looking for the version.

> Nmap library shortport is used to detect if port matches HTTP/SSL.

# Requirements
In order to run **cvescannerv2** script, you need the following files present
in your working directory
- CVE database: `cve.db`
- Paths file: `extra/http-paths-vulnerscom.json`
- Regex file: `extra/http-regex-vulnerscom.json`
- Product-aliases file: `extra/product-aliases.json`

In addition, you must have installed `lua-sql-sqlite3` (ubuntu)
or `lua5.4-sql-sqlite3` (alpine) packages

## Optional
If you don't have the database `cve.db`, you can build it
using the script `extra/database.py` or download a (semiupdated) copy
from [CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB) using `.sql` files
or under Actions->Latest->Summary->Artifacts

> This repository is updated every two weeks

```bash
pip install -r extra/requirements.txt
python extra/database.py
```

```bash
git clone https://github.com/scmanjarrez/CVEScannerV2DB
cd CVEScannerV2DB && sh build.sh
```

> **Note:** In order to execute `extra/database.py`, you need to
> [request an API key](https://nvd.nist.gov/developers/request-an-api-key)
> and save it to a file named `.api` on your current working directory
> or in the environment variable `NVD_KEY`.

# Execution
To run the script, use the following syntax
```
nmap -sV --script cvescannerv2 <TARGET>
nmap -sV --script cvescannerv2 --script-args log=logfile.log,json=logfile.json <TARGET>
```

It is possible to modify the behaviour to some extent using the
following arguments: db, maxcve, http, maxredirect, log, json,
path, regex, aliases, service and version.
<details>
    <summary><b>script-args default values</b></summary>

    db: cve.db
    maxcve: 10
    http: 1
    maxredirect: 1
    log: cvescannerv2.log
    json: cvescannerv2.json
    path: extra/http-paths-vulnerscom.json
    regex: extra/http-regex-vulnerscom.json
    aliases: extra/product-aliases.json
    service: all
    version: all
</details>

<details>
    <summary><b>script-args examples</b></summary>

    nmap -sV --script cvescannerv2 --script-args db=cve.db <TARGET>
    nmap -sV --script cvescannerv2 --script-args maxcve=5 <TARGET>

    # Change reports path
    nmap -sV --script cvescannerv2 --script-args log=scan2023.log,json=scan2023.json <TARGET>

    # Only scan certain service/version
    nmap -sV --script cvescannerv2 --script-args service=http_server,version=2.4.57 <TARGET>

    # Disable HTTP detection
    nmap -sV --script cvescannerv2 --script-args http=0 <TARGET>
</details>

> **Note**: `cvescannerv2.nse` can be placed in Nmap default script directory
> for global execution.
>
> - Linux and OSX default script locations:
>   - /usr/local/share/nmap/scripts/
>   - /usr/share/nmap/scripts/
>   - /opt/local/share/nmap/scripts/
>   - /usr/local/Cellar/nmap/<i>&lt;version&gt;</i>/share/nmap/scripts/
>
> - Windows default script locations:
>   - C:\Program Files\Nmap\Scripts
>   - %APPDATA%\nmap
>
> It's recommended to create a **symbolic link**, so changes in repository are reflected
> in the script.

## Output
CVEScannerV2 will show CVEs related to every `service-version` discovered.
> **Note**: This script depends on heuristics implemented in Nmap, so if it doesn't
> detect a service or is detected incorrectly, CVEScannerV2 will show an incorrect output.

<details>
    <summary><b>Nmap output</b></summary>

    PORT      STATE    SERVICE        VERSION
    22/tcp    open  ssh                  OpenSSH 7.1 (protocol 2.0)
    | cvescannerv2:
    |   product: openssh
    |   version: 4.7
    |   vupdate: p1
    |   cves: 38
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2016-1908       	7.5  	9.8  	No        	No
    |   	CVE-2023-38408      	nil  	9.8  	No        	No
    |       ...
    |   	CVE-2016-6515       	7.8  	7.5  	Yes       	No
    |_
    ...
    ...
    3306/tcp  open  mysql                MySQL 5.5.20-log
    | cvescannerv2:
    |   product: mysql
    |   version: 5.0.51
    |   vupdate: a
    |   cves: 212
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2009-2446       	8.5  	-    	No        	No
    |       ...
    |   	CVE-2009-4484       	7.5  	-    	No        	Yes
    |   	CVE-2008-0226       	7.5  	-    	No        	Yes
    |_
    ...
    ...
</details>

Log file **\*.log** contains every _exploit/metasploit_ found.

<details>
    <summary><b>cvescannerv2.log</b></summary>

    ## 2023-08-26T14:38:30+00:00

    [*] host: 192.168.69.129
    [*] port: 22
    [+] protocol: tcp
    [+] service: ssh
    [+] cpe: cpe:/a:openbsd:openssh:4.7p1
    [+] product: openssh
    [+] version: 4.7
    [+] vupdate: p1
    [+] cves: 38
    [-] 	id: CVE-2016-1908     	cvss_v2: 7.5  	cvss_v3: 9.8
    [-] 	id: CVE-2023-38408    	cvss_v2: nil  	cvss_v3: 9.8
    ...
    [-] 	id: CVE-2016-6515     	cvss_v2: 7.8  	cvss_v3: 7.5
    [!] 		ExploitDB:
    [#] 			name: nil
    [#] 			id: 40888
    [#] 			url: https://www.exploit-db.com/exploits/40888
    [-] 	id: CVE-2010-4478     	cvss_v2: 7.5  	cvss_v3: -
    ...
    -------------------------------------------------
    [*] host: 192.168.69.129
    [*] port: 3306
    [+] protocol: tcp
    [+] service: mysql
    [+] cpe: cpe:/a:mysql:mysql:5.0.51a-3ubuntu5
    [+] product: mysql
    [+] version: 5.0.51
    [+] vupdate: a
    [+] cves: 212
    [-] 	id: CVE-2009-2446     	cvss_v2: 8.5  	cvss_v3: -
    ...
    [-] 	id: CVE-2009-4484     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_getname
    [-] 	id: CVE-2008-0226     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_hello
    [#] 			name: exploit/windows/mysql/mysql_yassl_hello
    ...
</details>

Log file **\*.json** contains the same information but formatted as **json**

<details>
    <summary><b>cvescannerv2.json</b></summary>

    {
      "192.168.69.129": {
        "ports": {
          "22/tcp": {
            "services": [
              {
                "vupdate": "p1",
                "vulnerabilities": {
                  "total": 38,
                  "info": "scan",
                  "cves": {
                    "CVE-2014-1692": {
                      "cvssv2": 7.5,
                      "cvssv3": "-"
                    },
                    ...
                    "CVE-2016-6210": {
                      "cvssv3": 5.9,
                      "exploitdb": [
                        {
                          "id": 40113,
                          "url": "https://www.exploit-db.com/exploits/40113"
                        },
                        {
                          "id": 40136,
                          "url": "https://www.exploit-db.com/exploits/40136"
                        }
                      ],
                      "metasploit": [
                        {
                          "name": "auxiliary/scanner/ssh/ssh_enumusers"
                        }
                      ],
                      "cvssv2": 4.3
                    },
                  }
                  ...
                },
                "cpe": "cpe:/a:openbsd:openssh:4.7p1",
                "name": "ssh",
                "version": "4.7",
                "product": "openssh"
              }
            ]
          },
          ...
        "timestamp": "2023-08-26T14:38:30+00:00"
      }
    }
</details>

> You can find the full output of **metasploitable2/3** in `example_data`.

# Errors and fixes
## Blocked IP
> Connection timeout/error during CRAWL phase (`database.py`)

**Fix:** Wait 15 minutes before re-running `database.py`.

## Missing luasql
> cvescannerv2.nse:54: module 'luasql.sqlite3' not found:<br>
> NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
> ...

**Fix:** Install the library based on your OS (check [Requirements](#requirements))
and create a symlink to Nmap search path.
```bash
apt install lua-sql-sqlite3
ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua
```

```bash
apk add --no-cache lua5.4-sql-sqlite3
ln -s /usr/lib/lua /usr/local/lib/lua
```
> Above commands may require super user permissions.

# Docker container
We have prepared two containers configured and ready to be used, you can download them
from DockerHub
- Database embedded version: `scmanjarrez/cvescanner:db` or `scmanjarrez/cvescanner:latest`
- No database: `scmanjarrez/cvescannerv2:nodb`

```bash
docker run -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json <TARGET>

docker run -v ./cve.db:/CVEScannerV2/cve.db -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner:nodb --script-args log=/tmp/cvslogs/cvescannerv2.log,json=/tmp/cvslogs/cvescannerv2.json <TARGET>
```

> **Note**: You can find your logs in `/tmp/cvslogs` directory

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
    CVEScannerV2  Copyright (C) 2021-2024 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)
