# Description
Nmap script that provides information about probable vulnerabilities based on discovered services.

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

### Launch
After database has been created, it is necessary to specify the script.

- `nmap -sV <target_ip> --script=cvescannerv2.nse`
  > **cvescannerv2.nse** placed in Nmap script directory

- `nmap -sV <target_ip> --script=./cvescannerv2.nse`
  > **cvescannerv2.nse** placed in the working directory

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
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args db=cve.db
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args log=cvescannerv2.log
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args maxcve=10
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args path=http-paths-vulnerscom.json
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args regex=http-regex-vulnerscom.json

nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args db=cve.db,log=cvescannerv2.log,maxcve=10,path=http-paths-vulnerscom.json,regex=http-regex-vulnerscom.json
```

</details>

# Output
Nmap will show all CVEs related to every service-version discovered.

<details>
    <summary><b>cvescannerv2.nse output</b></summary>

    PORT      STATE    SERVICE        VERSION
    53/tcp   open  domain      ISC BIND 9.4.2
    | cvescannerv2:
    |   source: nvd.nist.gov
    |   product: bind
    |   version: 9.4.2
    |   vupdate: *
    |   cves: 39
    |       CVE ID                  CVSSv2  CVSSv3  ExploitDB       Metasploit
    |       CVE-2008-0122           10.0    -       No              No
    |       CVE-2012-1667           8.5     -       No              No
    |       CVE-2014-8500           7.8     -       No              No
    |       CVE-2012-3817           7.8     -       No              No
    |       CVE-2012-4244           7.8     -       No              No
    |       CVE-2016-2776           7.8     7.5     Yes             Yes
    |       CVE-2015-5722           7.8     -       No              No
    |       CVE-2015-5477           7.8     -       Yes             Yes
    |       CVE-2012-5166           7.8     -       No              No
    |_      CVE-2010-0382           7.6     -       No              No
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    | cvescannerv2:
    |   source: nvd.nist.gov
    |   product: samba
    |   version: 3.X - 4.X
    |   vupdate: *
    |   cves: 91
    |       CVE ID                  CVSSv2  CVSSv3  ExploitDB       Metasploit
    |       CVE-2007-2446           10.0    -       No              Yes
    |       CVE-2015-0240           10.0    -       Yes             Yes
    |       CVE-2004-0600           10.0    -       No              No
    |       CVE-2004-1154           10.0    -       No              No
    |       CVE-2004-0882           10.0    -       No              No
    |       CVE-2012-1182           10.0    -       No              Yes
    |       CVE-2017-7494           10.0    9.8     Yes             Yes
    |       CVE-2007-4572           9.3     -       No              No
    |       CVE-2007-6015           9.3     -       No              No
    |_      CVE-2007-5398           9.3     -       No              No
    ...
    ...
</details>

Also, a log file **cvescannerv2.log** will be generated, with every
exploit/metasploit related to CVEs.

<details>
    <summary><b>cvescannerv2.log dump</b></summary>

    #################################################
    ############## 2021-08-20 14:56:37 ##############
    #################################################

    [+] product: openssh
    [+] version: 7.1
    [+] vupdate: *
    [+] cves: 25
    [+]     id: CVE-2008-3844       cvss_v2: 9.3    cvss_v3: nil
    [+]     id: CVE-2016-8858       cvss_v2: 7.8    cvss_v3: 7.5
    [+]     id: CVE-2016-6515       cvss_v2: 7.8    cvss_v3: 7.5
    [-]         ExploitDB:
    [!]             name: OpenSSH 7.2 - Denial of Service
    [*]             id: 40888
    [*]             url: https://www.exploit-db.com/exploits/40888
    [+]     id: CVE-2016-1908       cvss_v2: 7.5    cvss_v3: 9.8
    [+]     id: CVE-2016-10009      cvss_v2: 7.5    cvss_v3: 7.3
    [-]         ExploitDB:
    [!]             name: OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading
    [*]             id: 40963
    [*]             url: https://www.exploit-db.com/exploits/40963
    [+]     id: CVE-2016-10012      cvss_v2: 7.2    cvss_v3: 7.8
    [+]     id: CVE-2015-8325       cvss_v2: 7.2    cvss_v3: 7.8
    [+]     id: CVE-2016-10010      cvss_v2: 6.9    cvss_v3: 7.0
    [-]         ExploitDB:
    [!]             name: OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation
    [*]             id: 40962
    [*]             url: https://www.exploit-db.com/exploits/40962
    ...
    ...
    [+] product: mysql
    [+] version: 5.5.20
    [+] vupdate: *
    [+] cves: 541
    [+]     id: CVE-2012-2750       cvss_v2: 10.0   cvss_v3: nil
    [+]     id: CVE-2016-6662       cvss_v2: 10.0   cvss_v3: 9.8
    [-]         ExploitDB:
    [!]             name: MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Privilege Escalation
    [*]             id: 40360
    [*]             url: https://www.exploit-db.com/exploits/40360
    [+]     id: CVE-2012-3163       cvss_v2: 9.0    cvss_v3: nil
    [+]     id: CVE-2020-14878      cvss_v2: 7.7    cvss_v3: 8.0
    [+]     id: CVE-2014-0001       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2018-2562       cvss_v2: 7.5    cvss_v3: 7.1
    [+]     id: CVE-2012-0882       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2012-0553       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2020-14760      cvss_v2: 7.5    cvss_v3: 5.5
    [+]     id: CVE-2014-6491       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2014-6500       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2015-0411       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2013-1492       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2012-3158       cvss_v2: 7.5    cvss_v3: nil
    [+]     id: CVE-2015-4819       cvss_v2: 7.2    cvss_v3: nil
    [+]     id: CVE-2016-0546       cvss_v2: 7.2    cvss_v3: nil
    [+]     id: CVE-2016-3471       cvss_v2: 7.1    cvss_v3: 7.5
    [+]     id: CVE-2016-6664       cvss_v2: 6.9    cvss_v3: 7.0
    [-]         ExploitDB:
    [!]             name: MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'root' System User Privilege Escalation
    [*]             id: 40679
    [*]             url: https://www.exploit-db.com/exploits/40679
    ...
    ...
    [+] product: samba
    [+] version: 3.X - 4.X
    [+] vupdate: *
    [+] cves: 91
    [+]     id: CVE-2007-2446       cvss_v2: 10.0   cvss_v3: nil
    [-]         Metasploit:
    [!]             name: auxiliary/dos/samba/lsa_addprivs_heap
    [!]             name: auxiliary/dos/samba/lsa_transnames_heap
    [!]             name: exploit/linux/samba/lsa_transnames_heap
    [!]             name: exploit/osx/samba/lsa_transnames_heap
    [!]             name: exploit/solaris/samba/lsa_transnames_heap
    [+]     id: CVE-2015-0240       cvss_v2: 10.0   cvss_v3: nil
    [-]         ExploitDB:
    [!]             name: Samba < 3.6.2 (x86) - Denial of Service (PoC)
    [*]             id: 36741
    [*]             url: https://www.exploit-db.com/exploits/36741
    [-]         Metasploit:
    [!]             name: auxiliary/scanner/smb/smb_uninit_cred
    [+]     id: CVE-2004-0600       cvss_v2: 10.0   cvss_v3: nil
    [+]     id: CVE-2004-1154       cvss_v2: 10.0   cvss_v3: nil
    [+]     id: CVE-2004-0882       cvss_v2: 10.0   cvss_v3: nil
    [+]     id: CVE-2012-1182       cvss_v2: 10.0   cvss_v3: nil
    [-]         Metasploit:
    [!]             name: exploit/linux/samba/setinfopolicy_heap
    [+]     id: CVE-2017-7494       cvss_v2: 10.0   cvss_v3: 9.8
    [-]         ExploitDB:
    [!]             name: Samba 3.5.0 - Remote Code Execution
    [*]             id: 42060
    [*]             url: https://www.exploit-db.com/exploits/42060
    [!]             name: Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)
    [*]             id: 42084
    [*]             url: https://www.exploit-db.com/exploits/42084
    [-]         Metasploit:
    [!]             name: exploit/linux/samba/is_known_pipename
    [+]     id: CVE-2007-4572       cvss_v2: 9.3    cvss_v3: nil
    [+]     id: CVE-2007-6015       cvss_v2: 9.3    cvss_v3: nil
    [+]     id: CVE-2007-5398       cvss_v2: 9.3    cvss_v3: nil
    [+]     id: CVE-2009-1886       cvss_v2: 9.3    cvss_v3: nil
    [+]     id: CVE-2010-0728       cvss_v2: 8.5    cvss_v3: nil
    [+]     id: CVE-2014-8143       cvss_v2: 8.5    cvss_v3: nil
    [+]     id: CVE-2008-4314       cvss_v2: 8.5    cvss_v3: nil
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

# Acknowledgement

- Based on [alegr3/CVEscanner](https://github.com/alegr3/CVEscanner) script.

- Common server regexes and paths from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

- Modules cache generated from [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).
  > Can be found in **~/.msf4/store/modules_metadata.json** after running **msfconsole**

# License
    CVEScannerV2  Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](https://github.com/scmanjarrez/CVEScannerV2/blob/master/LICENSE)
