# Description
Nmap script that provides information about probable vulnerabilities based on discovered services.

**Contents:**
  - [Run](#run)
  - [Output](#output)
  - [Errors and fixes](#errors-and-fixes)
  - [Technical details](#technical-details)
  - [Acknowledgement](#acknowledgement)
  - [License](#license)

# Requirements
- luasql
- nmap
- python

# Run
### Prelaunch
In order to execute **cvescannerv2.nse** script, it is mandatory to generate CVEs database.

The script **database.py** generates **cve.db** with the required information.

- `pip install -r requirements.txt`
- `python database.py`
> **Note:** For your convinience, a semi-updated database is offered as .sql format in **[CVEScannerV2DB](https://github.com/scmanjarrez/CVEScannerV2DB)**.

### Optional
Script **cvescannerv2.nse** can be placed in Nmap default script directory for global execution.

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

### Launch
After database has been created, it is necessary to specify the script.

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
nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db
nmap -sV <target_ip> --script cvescannerv2 --script-args log=cvescannerv2.log
nmap -sV <target_ip> --script cvescannerv2 --script-args maxcve=10
nmap -sV <target_ip> --script cvescannerv2 --script-args path=http-paths-vulnerscom.json
nmap -sV <target_ip> --script cvescannerv2 --script-args regex=http-regex-vulnerscom.json

nmap -sV <target_ip> --script cvescannerv2 --script-args db=cve.db,log=cvescannerv2.log,maxcve=10,path=http-paths-vulnerscom.json,regex=http-regex-vulnerscom.json
```

</details>

# Output
Nmap will show all CVEs related to every service-version discovered.

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

Also, a log file **cvescannerv2.log** will be generated, with every
exploit/metasploit related to CVEs.

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

### Example outputs
You can find in **example_data** the output of the script for metasploitable2 and metasploitable3 machines.

# Errors and fixes
- Error due to block of your IP by the exploit-db WAF.
  > Connection timeout/error during CRAWL phase when executing **database.py**

  > **Fix:** Wait 15 minutes before launching the **database.py** script again.

- Error due to missing library (luasql).
  > cvescannerv2.nse:54: module 'luasql.sqlite3' not found:<br>
  > NSE failed to find nselib/luasql/sqlite3.lua in search paths.<br>
  > ...

  > **Fix:** Install lua-sql-sqlite3 and create a symlink to Nmap search path.<br>
  > - `sudo apt install lua-sql-sqlite3`<br>
  > - `sudo ln -s /usr/lib/x86_64-linux-gnu/lua /usr/local/lib/lua`

# Technical details
The current implementation take care of the following cases:

- Nmap detection:
  - Product _cpe_ **AND** _version_: we parse the cpe and
    compare the product and version with the database, retrieving
    results from vulnerabilities affecting the exact version (and vupdate)
    and vulnerabilities that affect a range of versions, this one included.
  - Product _cpe_ **AND** _version range_: we retrieve all vulnerabilities
    that affect all versions between _version range_ (included).
  - Product _cpe_ but **NO** _version_: we retrieve only vulnerabilities
    that affect all versions of the product.
  - If no vulnerabilities were found with the _cpe_ and _version_
    returned from Nmap, we use the HTTP detection if port is http or ssl.
  - **NO** product _cpe_: we use the HTTP detection  if port is http or ssl.

- HTTP detection:
  - We do an HTTP GET for every combination of _path_ and _extension_ in
  **http-paths-vulnerscom.json**, comparing the request headers/body with
  the regexes in **http-regexes-vulnerscom.json**.



# Acknowledgement

- Based on [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner) script.

- Common server regexes and paths from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

- Modules cache generated from [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).
  > Can be found in **~/.msf4/store/modules_metadata.json** after running **msfconsole**

- CVE information gathered from [nvd.nist.gov](https://nvd.nist.gov).

# License
    CVEScannerV2  Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](LICENSE)
