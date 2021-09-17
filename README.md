# Description
Nmap script that searches for probable vulnerabilities based on services discovered in open ports.

# Requirements
- luasql
- nmap
- python

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

**Note**: cvescannerv2.nse can accept the following script args: db, log, maxcve, path and regex. If
no arg received, default values are used.

```bash
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args db=cve.db
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args log=cvescannerv2.log
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args maxcve=10
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args path=http-paths-vulnerscom.json
nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args regex=http-regex-vulnerscom.json

nmap -sV <target_ip> --script=./cvescannerv2.nse --script-args db=cve.db,log=cvescannerv2.log
```

# Output
Nmap will show all CVEs related to every service-version discovered.

<details>
    <summary><b>cvescannerv2.nse output</b></summary>

    PORT      STATE    SERVICE        VERSION
    53/tcp    open     domain         ISC BIND 9.4.2
    | cvescannerv2:
    |   source: nvd.nist.gov
    |   product: bind
    |   version: 9.4.2
    |   vupdate: *
    |   cves: 24
    |       CVE ID          CVSSv2  CVSSv3  ExploitDB       Metasploit
    |       CVE-2012-1667   8.5     -       No              No
    |       CVE-2012-3817   7.8     -       No              No
    |       CVE-2014-8500   7.8     -       No              No
    |       CVE-2012-4244   7.8     -       No              No
    |       CVE-2012-5166   7.8     -       No              No
    |       CVE-2010-0382   7.6     -       No              No
    |       CVE-2015-8461   7.1     -       No              No
    |       CVE-2009-0025   6.8     -       No              No
    |       CVE-2015-8704   6.8     6.5     No              No
    |_      CVE-2015-8705   6.6     7.0     No              No
    445/tcp   open     netbios-ssn    Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    | cvescannerv2:
    |   source: nvd.nist.gov
    |   product: samba
    |   version: 3.X - 4.X
    |   vupdate: *
    |   cves: 91
    |       CVE ID          CVSSv2  CVSSv3  ExploitDB       Metasploit
    |       CVE-2017-7494   10.0    9.8     Yes             Yes
    |       CVE-2012-1182   10.0    -       No              No
    |       CVE-2004-0882   10.0    -       No              No
    |       CVE-2004-0600   10.0    -       No              No
    |       CVE-2007-2446   10.0    -       No              No
    |       CVE-2015-0240   10.0    -       Yes             No
    |       CVE-2004-1154   10.0    -       No              No
    |       CVE-2007-6015   9.3     -       No              No
    |       CVE-2009-1886   9.3     -       No              No
    |_      CVE-2007-5398   9.3     -       No              No
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

    [+] product: bind
    [+] version: 9.4.2
    [+] vupdate: *
    [+] cves: 24
    [+] 	id: CVE-2012-1667
    [+] 	id: CVE-2012-3817
    [+] 	id: CVE-2014-8500
    [+] 	id: CVE-2012-5166
    [+] 	id: CVE-2012-4244
    [+] 	id: CVE-2010-0382
    [+] 	id: CVE-2015-8461
    [+] 	id: CVE-2015-8704
    [+] 	id: CVE-2009-0025
    [+] 	id: CVE-2015-8705
    [+] 	id: CVE-2010-3614
    [+] 	id: CVE-2016-2848
    [+] 	id: CVE-2009-0265
    [+] 	id: CVE-2015-8000
    [+] 	id: CVE-2011-1910
    ...
    ...
    [+] product: mysql
    [+] version: 5.0.51
    [+] vupdate: a
    [+] cves: 2
    [+] 	id: CVE-2010-3677
    [+] 	id: CVE-2010-3682
    [+] product: http_server
    [+] version: 2.2.8
    [+] vupdate: *
    [+] cves: 32
    [+] 	id: CVE-2010-0425
    [-] 		ExploitDB:
    [!] 			name: Apache 2.2.14 mod_isapi - Dangling Pointer Remote SYSTEM
    [*] 			id: 11650
    [*] 			url: https://www.exploit-db.com/exploits/11650
    [-] 		Metasploit:
    [!] 			name: auxiliary/dos/http/apache_mod_isapi
    [+] 	id: CVE-2011-3192
    [-] 		ExploitDB:
    [!] 			name: Apache - Remote Memory Exhaustion (Denial of Service)
    [*] 			id: 17696
    [*] 			url: https://www.exploit-db.com/exploits/17696
    [-] 		Metasploit:
    [!] 			name: auxiliary/dos/http/apache_range_dos
    [+] 	id: CVE-2013-2249
    [+] 	id: CVE-2009-1891
    [+] 	id: CVE-2009-1890
    [+] 	id: CVE-2012-0883
    [+] 	id: CVE-2013-1862
    [+] 	id: CVE-2010-0408
    [+] 	id: CVE-2014-0098
    [+] 	id: CVE-2013-6438
    [+] 	id: CVE-2014-0231
    [+] 	id: CVE-2010-1452
    [+] 	id: CVE-2008-2364
    [+] 	id: CVE-2011-3368
    [-] 		ExploitDB:
    [!] 			name: Apache mod_proxy - Reverse Proxy Exposure
    [*] 			id: 17969
    [*] 			url: https://www.exploit-db.com/exploits/17969
    [-] 		Metasploit:
    [!] 			name: auxiliary/scanner/http/rewrite_proxy_bypass
    [+] 	id: CVE-2009-2699
    [+] 	id: CVE-2007-6750
    [-] 		Metasploit:
    [!] 			name: auxiliary/dos/http/slowloris
    [+] 	id: CVE-2009-1195
    [+] 	id: CVE-2012-0031
    [+] 	id: CVE-2011-3607
    ...
    ...
    [+] product: samba
    [+] version: 3.X - 4.X
    [+] vupdate: *
    [+] cves: 91
    [+] 	id: CVE-2004-1154
    [+] 	id: CVE-2007-2446
    [-] 		Metasploit:
    [!] 			name: auxiliary/dos/samba/lsa_addprivs_heap
    [!] 			name: auxiliary/dos/samba/lsa_transnames_heap
    [!] 			name: exploit/linux/samba/lsa_transnames_heap
    [!] 			name: exploit/osx/samba/lsa_transnames_heap
    [!] 			name: exploit/solaris/samba/lsa_transnames_heap
    [+] 	id: CVE-2012-1182
    [-] 		Metasploit:
    [!] 			name: exploit/linux/samba/setinfopolicy_heap
    [+] 	id: CVE-2015-0240
    [-] 		ExploitDB:
    [!] 			name: Samba < 3.6.2 (x86) - Denial of Service (PoC)
    [*] 			id: 36741
    [*] 			url: https://www.exploit-db.com/exploits/36741
    [-] 		Metasploit:
    [!] 			name: auxiliary/scanner/smb/smb_uninit_cred
    [+] 	id: CVE-2004-0882
    [+] 	id: CVE-2017-7494
    [-] 		ExploitDB:
    [!] 			name: Samba 3.5.0 - Remote Code Execution
    [*] 			id: 42060
    [*] 			url: https://www.exploit-db.com/exploits/42060
    [!] 			name: Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)
    [*] 			id: 42084
    [*] 			url: https://www.exploit-db.com/exploits/42084
    [-] 		Metasploit:
    [!] 			name: exploit/linux/samba/is_known_pipename
    [+] 	id: CVE-2004-0600
    [+] 	id: CVE-2007-4572
    [+] 	id: CVE-2007-5398
    ...
    ...
</details>



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

Common server regexes and paths from [vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners).

Metasploit-framework cache generated from msfconsole [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework).

# License
    CVEScannerV2  Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](https://github.com/scmanjarrez/CVEScannerV2/blob/master/LICENSE)
