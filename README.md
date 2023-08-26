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
  - Used only if port matches HTTP/SSL/UPnP.
  - An HTTP GET request is sent for every combination of _path_
    and _extension_ in **http-paths-vulnerscom.json**, comparing
    the request headers/body with the regexes in
    **http-regex-vulnerscom.json**.
  - Finally, the _home_ page html is analyzed in search for library paths.
    The script tries to obtain the name and version from library location;
    then does an HTTP GET to that path in order to inspect the code
    of the library and analyze the starting comment looking for the version.

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

> **Note:** In order to run database.py, due to the changes in the data feeds from NVD, now you
> need to [request an API key](https://nvd.nist.gov/developers/request-an-api-key) and store it in a file named `.api` in your current working directory.

> **Note2:** For your convenience, a semi-updated database is offered as .sql format in **[CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB)**.

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

**Note**: cvescannerv2.nse accepts the following script-args: db, log, maxcve, path, regex, service and version.
<details>
    <summary><b>script-args default values</b></summary>

    db: cve.db
    log: cvescannerv2.log
    maxcve: 10
    path: http-paths-vulnerscom.json
    regex: http-regex-vulnerscom.json
    service: all
    version: all
</details>

<details>
    <summary><b>script-args examples</b></summary>

```bash
$ nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db
$ nmap -sV <target_ip> --script cvescannerv2 --script-args log=scan2023.log
$ nmap -sV <target_ip> --script cvescannerv2 --script-args json=scan2023.json
$ nmap -sV <target_ip> --script cvescannerv2 --script-args maxcve=5
$ nmap -sV <target_ip> --script cvescannerv2 --script-args path=http-paths-vulnerscom.json
$ nmap -sV <target_ip> --script cvescannerv2 --script-args regex=http-regex-vulnerscom.json
$ nmap -sV <target_ip> --script cvescannerv2 --script-args service=http_server
$ nmap -sV <target_ip> --script cvescannerv2 --script-args version=2.4.57

$ nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db,log=scan2023.log,json=scan2023.json,maxcve=5,path=http-paths-vulnerscom.json,regex=http-regex-vulnerscom.json,service=http_server,version=2.4.57
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
    |   version: 4.7
    |   vupdate: p1
    |   cves: 38
    |   	CVE ID              	CVSSv2	CVSSv3	ExploitDB 	Metasploit
    |   	CVE-2016-1908       	7.5  	9.8  	No        	No
    |   	CVE-2023-38408      	nil  	9.8  	No        	No
    |   	CVE-2008-3844       	9.3  	-    	No        	No
    |   	CVE-2015-5600       	8.5  	-    	No        	No
    |   	CVE-2015-8325       	7.2  	7.8  	No        	No
    |   	CVE-2020-15778      	6.8  	7.8  	No        	No
    |   	CVE-2016-10012      	7.2  	7.8  	No        	No
    |   	CVE-2016-10708      	5.0  	7.5  	No        	No
    |   	CVE-2016-6515       	7.8  	7.5  	Yes       	No
    |   	CVE-2010-4478       	7.5  	-    	No        	No
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
    |   	CVE-2017-15945      	7.2  	7.8  	No        	No
    |   	CVE-2016-3440       	4.0  	7.7  	No        	No
    |   	CVE-2009-4484       	7.5  	-    	No        	Yes
    |   	CVE-2008-0226       	7.5  	-    	No        	Yes
    |   	CVE-2020-1967       	5.0  	7.5  	No        	No
    |   	CVE-2009-2942       	7.5  	-    	No        	No
    |   	CVE-2023-21980      	nil  	7.1  	No        	No
    |   	CVE-2013-2395       	6.8  	-    	No        	No
    |   	CVE-2009-5026       	6.8  	-    	No        	No
    |_
    ...
    ...
</details>

Log file **cvescannerv2.log** contains every _exploit/metasploit_ found.

<details>
    <summary><b>cvescannerv2.log dump</b></summary>

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
    [-] 	id: CVE-2008-3844     	cvss_v2: 9.3  	cvss_v3: -
    [-] 	id: CVE-2015-5600     	cvss_v2: 8.5  	cvss_v3: -
    [-] 	id: CVE-2015-8325     	cvss_v2: 7.2  	cvss_v3: 7.8
    [-] 	id: CVE-2020-15778    	cvss_v2: 6.8  	cvss_v3: 7.8
    [-] 	id: CVE-2016-10012    	cvss_v2: 7.2  	cvss_v3: 7.8
    [-] 	id: CVE-2016-10708    	cvss_v2: 5.0  	cvss_v3: 7.5
    [-] 	id: CVE-2016-6515     	cvss_v2: 7.8  	cvss_v3: 7.5
    [!] 		ExploitDB:
    [#] 			name: nil
    [#] 			id: 40888
    [#] 			url: https://www.exploit-db.com/exploits/40888
    [-] 	id: CVE-2010-4478     	cvss_v2: 7.5  	cvss_v3: -
    ...
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
    [-] 	id: CVE-2017-15945    	cvss_v2: 7.2  	cvss_v3: 7.8
    [-] 	id: CVE-2016-3440     	cvss_v2: 4.0  	cvss_v3: 7.7
    [-] 	id: CVE-2009-4484     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_getname
    [-] 	id: CVE-2008-0226     	cvss_v2: 7.5  	cvss_v3: -
    [!] 		Metasploit:
    [#] 			name: exploit/linux/mysql/mysql_yassl_hello
    [#] 			name: exploit/windows/mysql/mysql_yassl_hello
    [-] 	id: CVE-2020-1967     	cvss_v2: 5.0  	cvss_v3: 7.5
    [-] 	id: CVE-2009-2942     	cvss_v2: 7.5  	cvss_v3: -
    [-] 	id: CVE-2023-21980    	cvss_v2: nil  	cvss_v3: 7.1
    [-] 	id: CVE-2013-2395     	cvss_v2: 6.8  	cvss_v3: -
    [-] 	id: CVE-2009-5026     	cvss_v2: 6.8  	cvss_v3: -
    [-] 	id: CVE-2013-5882     	cvss_v2: 6.8  	cvss_v3: -
    [-] 	id: CVE-2009-4028     	cvss_v2: 6.8  	cvss_v3: -
    ...
    ...
</details>

Log file (json format) **cvescannerv2.json**.

<details>
    <summary><b>cvescannerv2.json dump</b></summary>

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
                "CVE-2015-8325": {
                  "cvssv2": 7.2,
                  "cvssv3": 7.8
                },
                "CVE-2012-0814": {
                  "cvssv2": 3.5,
                  "cvssv3": "-"
                },
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
      ...
    "timestamp": "2023-08-26T14:38:30+00:00"
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
    CVEScannerV2  Copyright (C) 2021-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)
