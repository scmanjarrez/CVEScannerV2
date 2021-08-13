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

Based on [alegr3/CVEScanner](https://github.com/alegr3/CVEscanner) script.

# License
    CVEScannerV2  Copyright (C) 2021 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
    Universidad Carlos III de Madrid.
    This program comes with ABSOLUTELY NO WARRANTY; for details check below.
    This is free software, and you are welcome to redistribute it
    under certain conditions; check below for details.

[LICENSE](https://github.com/scmanjarrez/CVEScannerV2/blob/master/LICENSE)
