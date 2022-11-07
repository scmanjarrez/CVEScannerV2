#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# database - Database generator.

# Copyright (C) 2021-2022 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
# Universidad Carlos III de Madrid.

# This file is part of CVEScannerV2.

# CVEScannerV2 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# CVEScannerV2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from alive_progress import alive_bar, config_handler
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent
from threading import Thread, Event
from contextlib import closing
from queue import Queue
import requests as req
import dateutil.parser
import sqlite3 as sql
import argparse
import datetime
import zipfile
import shutil
import urllib
import html
import json
import time
import sys
import os
import re


TITLE = re.compile(
    r"""<meta property=(?P<quote>['"])og:title(?P=quote) """
    r"""content=(?P<quotex>['"])(.*?)(?P=quotex)""",
    re.IGNORECASE | re.DOTALL)
MSFNAME = re.compile(
    r"""['"]Name['"]\s+=>\s+(?P<quote>['"])((\\.|.)*?)(?P=quote)""",
    re.IGNORECASE | re.DOTALL)
CPE = re.compile(r'cpe:2.3:'
                 r'(.*?)(?<!:):(?!:)'
                 r'(.*?)(?<!:):(?!:)'
                 r'(.*?)(?<!:):(?!:)'
                 r'(.*?)(?<!:):(?!:)'
                 r'(.*?)(?<!:):(?!:)'
                 r'.*')
LAST_MOD = re.compile(r'lastModifiedDate:([\w\d:-]+).*?sha256:([\w\d]+)',
                      re.DOTALL)
EXPL_NAME = re.compile(r'https?://www.exploit-db.com/exploits/(\d+)')
REF_CVE = re.compile(r'CVE-\d+-\d+')

VER_TAG = ('versionStartIncluding', 'versionStartExcluding',
           'versionEndIncluding', 'versionEndExcluding')
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
NVD_NAME = "nvdcve-1.1-"
EXPL_DB_URL = "https://www.exploit-db.com/exploits"

UA = UserAgent()
BATCH = 25
# low requests per minute, but we need this to bypass WAF
THREADS = 3
DELAY = 5

COPYRIGHT = """
CVEScannerV2  Copyright (C) 2022 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
Universidad Carlos III de Madrid.
This program comes with ABSOLUTELY NO WARRANTY; for details check below.
This is free software, and you are welcome to redistribute it
under certain conditions; check below for details.
"""


def create_db(db):
    with closing(db.cursor()) as cur:
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS cached (
                year INTEGER PRIMARY KEY,
                last_update TEXT,
                sha256 TEXT
            );

            CREATE TABLE IF NOT EXISTS exploits (
                exploit_id INTEGER PRIMARY KEY,
                name TEXT
            );

            CREATE TABLE IF NOT EXISTS metasploits (
                metasploit_id INTEGER PRIMARY KEY,
                name TEXT
            );

            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                cvss_v2 REAL,
                cvss_v3 REAL,
                published INTEGER
            );

            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY,
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_update TEXT,
                UNIQUE (vendor, product, version, version_update)
            );

            CREATE TABLE IF NOT EXISTS affected (
                cve_id TEXT,
                product_id INT,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (product_id)
                    REFERENCES products (product_id),
                PRIMARY KEY (cve_id, product_id)
            );

            CREATE TABLE IF NOT EXISTS multiaffected (
                cve_id TEXT,
                product_id INT,
                versionStartIncluding TEXT,
                versionStartExcluding TEXT,
                versionEndIncluding TEXT,
                versionEndExcluding TEXT,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (product_id)
                    REFERENCES products (product_id),
                PRIMARY KEY (cve_id, product_id,
                             versionStartIncluding, versionStartExcluding,
                             versionEndIncluding, versionEndExcluding)
            );

            CREATE TABLE IF NOT EXISTS referenced_exploit (
                cve_id TEXT,
                exploit_id INTEGER,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (exploit_id)
                    REFERENCES exploits (exploit_id),
                PRIMARY KEY (cve_id, exploit_id)
            );

            CREATE TABLE IF NOT EXISTS referenced_metasploit (
                cve_id TEXT,
                metasploit_id INTEGER,
                FOREIGN KEY (cve_id)
                    REFERENCES cves (cve_id),
                FOREIGN KEY (metasploit_id)
                    REFERENCES metasploits (metasploit_id),
                PRIMARY KEY (cve_id, metasploit_id)
            );

            PRAGMA foreign_keys = ON;
            """
        )


def year_in_db(db, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS '
            '('
            'SELECT 1 '
            'FROM cached '
            'WHERE year = ?'
            ')',
            [year])
        return cur.fetchone()[0]


def cached_year(db, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT last_update '
            'FROM cached '
            'WHERE year = ?',
            [year])
        return cur.fetchone()[0]


def insert_year(db, year, last_update, sha256):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO cached '
            '(year, last_update, sha256) '
            'VALUES '
            '(?, ?, ?)',
            [year, last_update, sha256])
        db.commit()


def update_year(db, year, last_update, sha256):
    with closing(db.cursor()) as cur:
        cur.execute(
            'UPDATE cached '
            'SET '
            'last_update = ?, sha256 = ? '
            'WHERE year = ?',
            [last_update, sha256, year])
        db.commit()


def exploit_in_db(db, exploit, msf=False):
    with closing(db.cursor()) as cur:
        if not msf:
            cur.execute(
                'SELECT EXISTS '
                '('
                'SELECT 1 '
                'FROM exploits '
                'WHERE exploit_id = ?'
                ')',
                [exploit])
        else:
            cur.execute(
                'SELECT EXISTS '
                '('
                'SELECT 1 '
                'FROM metasploits '
                'WHERE name = ?'
                ')',
                [exploit])
        return cur.fetchone()[0]


def exploits_in_db(db):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT exploit_id '
            'FROM exploits '
            'WHERE name IS NULL')
        return [expl[0] for expl in cur.fetchall()]


def bulk_update_exploit_name(db, exploits_names):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'UPDATE exploits '
            'SET '
            'name = ? '
            'WHERE exploit_id = ?',
            exploits_names)
        db.commit()


def bulk_insert_exploits(db, exploits):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO exploits '
            '(exploit_id) '
            'VALUES '
            '(?)',
            exploits)
        db.commit()


def bulk_insert_metasploits(db, metasploits):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO metasploits '
            '(name) '
            'VALUES '
            '(?)',
            metasploits)
        db.commit()


def cve_in_db(db, cve):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS '
            '('
            'SELECT 1 '
            'FROM cves '
            'WHERE cve_id = ?'
            ')',
            [cve])
        return cur.fetchone()[0]


def bulk_insert_cve(db, cves):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO cves '
            '(cve_id, cvss_v2, cvss_v3, published) '
            'VALUES '
            '(?, ?, ?, ?)',
            cves)
        db.commit()


def bulk_update_cve(db, cves):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'UPDATE cves '
            'SET '
            'cvss_v2 = ?, cvss_v3 = ?, published = ? '
            'WHERE cve_id = ?',
            cves)
        db.commit()


def product_in_db(db, vendor, product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS '
            '('
            'SELECT 1 '
            'FROM products '
            'WHERE vendor = ? AND product = ? '
            'AND version = ? AND version_update = ?'
            ')',
            [vendor, product, version, update])
        return cur.fetchone()[0]


def bulk_insert_product(db, products):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO products '
            '(vendor, product, version, version_update) '
            'VALUES '
            '(?, ?, ?, ?)',
            products)
        db.commit()


def product_is_affected(db, cve, vendor, product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS '
            '('
            'SELECT 1 FROM affected '
            'WHERE cve_id = ? '
            'AND product_id = '
            '('
            'SELECT product_id FROM products '
            'WHERE vendor = ? AND product = ? '
            'AND version = ? AND version_update = ?'
            ')'
            ')',
            [cve, vendor, product, version, update])
        return cur.fetchone()[0]


def bulk_insert_affected(db, cves_products):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO affected '
            'VALUES '
            '(?, '
            '('
            'SELECT product_id FROM products '
            'WHERE vendor = ? AND product = ? '
            'AND version = ? AND version_update = ?'
            ')'
            ')',
            cves_products)
        db.commit()


def product_is_multiaffected(db, cve, vendor, product,
                             start_inc, start_exc, end_inc, end_exc):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS '
            '('
            'SELECT 1 FROM multiaffected '
            'WHERE cve_id = ? '
            'AND product_id = '
            '('
            'SELECT product_id FROM products '
            'WHERE vendor = ? AND product = ? '
            'AND version = "*"'
            ') '
            'AND versionStartIncluding = ? '
            'AND versionStartExcluding = ? '
            'AND versionEndIncluding = ? '
            'AND versionEndExcluding = ?'
            ')',
            [cve, vendor, product, start_inc, start_exc, end_inc, end_exc])
        return cur.fetchone()[0]


def bulk_insert_multiaffected(db, cves_products_versions):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO multiaffected '
            'VALUES '
            '(?, '
            '('
            'SELECT product_id FROM products '
            'WHERE vendor = ? AND product = ? '
            'AND version = "*"'
            '), '
            '?, ?, ?, ?)',
            cves_products_versions)
        db.commit()


def cve_is_referenced(db, cve, exploit, msf=False):
    with closing(db.cursor()) as cur:
        if not msf:
            cur.execute(
                'SELECT EXISTS '
                '('
                'SELECT 1 '
                'FROM referenced_exploit '
                'WHERE cve_id = ? AND exploit_id = ?'
                ')',
                [cve, exploit])
        else:
            cur.execute(
                'SELECT EXISTS '
                '('
                'SELECT 1 '
                'FROM referenced_metasploit '
                'WHERE cve_id = ? AND metastploit_id = ?'
                ')',
                [cve, exploit])
        return cur.fetchone()[0]


def bulk_insert_ereferenced(db, cves_exploits):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO referenced_exploit '
            'VALUES '
            '(?, ?)',
            cves_exploits)
        db.commit()


def bulk_insert_mreferenced(db, cves_metasploits):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO referenced_metasploit '
            'VALUES '
            '(?, '
            '('
            'SELECT metasploit_id '
            'FROM metasploits '
            'WHERE name = ?'
            ')'
            ')',
            cves_metasploits)
        db.commit()


def clean_db(args):
    print("[CLEAN] Removing exploit-db orphan references")
    with closing(sql.connect(args.database)) as db:
        with closing(db.cursor()) as cur:
            cur.execute(
                'DELETE FROM referenced_exploit '
                'WHERE exploit_id IN '
                '('
                'SELECT exploit_id '
                'FROM exploits '
                'WHERE name LIKE "404 Page %"'
                ')')
            cur.execute(
                'DELETE FROM exploits '
                'WHERE name LIKE "404 Page %"')
            db.commit()


def clean_temp(args):
    if not args.noclean:
        if os.path.exists(args.temp) and os.path.isdir(args.temp):
            print("[CLEAN] Removing temporary files")
            try:
                shutil.rmtree(args.temp)
            except FileNotFoundError:
                pass


class PopulateDBThread(Thread):
    def __init__(self, database, finished, new_year, in_queue, out_queue):
        Thread.__init__(self)
        self.database = database
        self.finished = finished
        self.new_year = new_year
        self.iqueue = in_queue
        self.oqueue = out_queue
        self.execmany = {
            0: bulk_insert_cve,
            1: bulk_update_cve,
            2: bulk_insert_product,
            3: bulk_insert_affected,
            4: bulk_insert_multiaffected,
            5: bulk_insert_exploits,
            6: bulk_insert_ereferenced,
            7: bulk_insert_metasploits,
            8: bulk_insert_mreferenced
        }
        self.datalist = {k: [] for k in self.execmany}

    def run(self):
        with closing(sql.connect(self.database)) as db:
            create_db(db)
            while True:
                if not self.iqueue.empty():
                    dtype, data = self.iqueue.get()
                    self.datalist[dtype].append(data)
                else:
                    if self.new_year.is_set():
                        self.new_year.clear()
                        for dt in range(len(self.execmany)):
                            self.execmany[dt](db, self.datalist[dt])
                            self.datalist[dt] = []
                        self.oqueue.put((1,))
                    elif self.finished.is_set():
                        break
                    else:
                        time.sleep(1)


def scrape_title(exploit):
    title = None
    try:
        with req.get(f'{EXPL_DB_URL}/{exploit}',
                     headers={'User-Agent': UA.random}) as page:
            decoded = html.unescape(page.text)
            title = TITLE.search(decoded).group(3)  # group 1 and 2 are quotes
    except (req.exceptions.ConnectionError,
            req.exceptions.ConnectTimeout) as e:
        print("Error ocurred:", exploit, e)
    finally:
        time.sleep(DELAY)
        return title, exploit


def exploit_batch(exploits):
    for i in range(0, len(exploits), BATCH):
        yield exploits[i:i + BATCH]


def _norm(string):
    return string.replace('\\', '')


def split(cpe23uri):
    return CPE.search(_norm(cpe23uri)).groups()


def parse_node(node):
    if node['operator'] == "AND":
        ret = []
        for child in node['children']:
            ret += parse_node(child)
        return ret
    else:
        return [(split(cpe['cpe23Uri']),
                 [_norm(cpe[vt]) if vt in cpe else None for vt in VER_TAG])
                for cpe in node['cpe_match']]


def check_updates(args):
    with closing(sql.connect(args.database)) as db:
        years = range(2002, datetime.datetime.now().year + 1)

        popu_finished = Event()
        popu_new_year = Event()
        popu_iqueue = Queue()
        popu_oqueue = Queue()
        popu_thread = PopulateDBThread(args.database, popu_finished,
                                       popu_new_year, popu_iqueue,
                                       popu_oqueue)
        popu_thread.start()
        time.sleep(1)

        for year in years:
            update = True
            if not year_in_db(db, year):
                insert_year(db, year, None, None)
            resp = req.get(f'{NVD_URL}{NVD_NAME}{year}.meta')
            last_update, sha256 = LAST_MOD.search(resp.text).groups()
            cached_upd = cached_year(db, year)
            if last_update == cached_upd:
                update = False

            tmpfile = f'{args.temp}/{NVD_NAME}{year}.json'
            if update:
                try:
                    os.makedirs(args.temp, exist_ok=True)
                except PermissionError:
                    print(f"[ERROR] Insufficient permission "
                          f"to create \"{args.temp}\" directory.")
                    sys.exit(-1)

                tmpurl = f'{NVD_URL}{NVD_NAME}{year}.json.zip'
                with alive_bar(1, title=f"[DWNLD] Year {year}:") as bar:
                    try:
                        urllib.request.urlretrieve(tmpurl, f'{tmpfile}.zip')
                    except urllib.error.ContentTooShortError:
                        print("[ERROR] Data downloaded less than expected.")
                        sys.exit(-1)
                    except urllib.error.URLError as e:
                        print(f"[ERROR] {e}")
                        sys.exit(-1)

                    with zipfile.ZipFile(f'{tmpfile}.zip', 'r') as zf:
                        try:
                            zf.extractall(args.temp)
                        except ValueError:
                            print("[ERROR] Unexpected close.")
                            sys.exit(-1)
                    bar()

                with open(tmpfile, 'r', encoding='utf8') as f:
                    data = json.load(f)

                with alive_bar(len(data['CVE_Items']),
                               title=f"[PARSE] Year {year}:") as bar:
                    for idx, cve_item in enumerate(data['CVE_Items']):
                        if '** REJECT **' in (
                                cve_item['cve']['description']
                                ['description_data'][0]
                                ['value']):
                            bar()
                            continue

                        cve_id = cve_item['cve']['CVE_data_meta']['ID']
                        try:
                            cvssv2 = (
                                cve_item['impact']['baseMetricV2']
                                ['cvssV2']['baseScore'])
                        except KeyError:
                            bar()
                            continue
                        cvssv3 = (cve_item['impact']
                                  ['baseMetricV3']['cvssV3']['baseScore']
                                  if 'baseMetricV3' in cve_item['impact']
                                  else None)
                        published = dateutil.parser.parse(
                            cve_item['publishedDate']).year
                        if not cve_in_db(db, cve_id):
                            try:
                                popu_iqueue.put(
                                    (0, (cve_id, cvssv2, cvssv3,
                                         published)))
                            except sql.IntegrityError:
                                print(f"[ERROR]: Integrity error: "
                                      f"{cve_id}, {cvssv2}, {cvssv3}, "
                                      f"{published}")
                                sys.exit(-1)
                        else:
                            popu_iqueue.put(
                                (1, (cve_id, cvssv2, cvssv3,
                                     published)))

                        nodes = cve_item['configurations']['nodes']
                        if nodes:
                            for node in nodes:
                                products = parse_node(node)
                                for (ptype, vend,
                                     prod, vers, vupd), tags in products:
                                    if ptype == 'a':
                                        if not product_in_db(
                                                db, vend, prod,
                                                vers, vupd):
                                            popu_iqueue.put(
                                                (2, (vend, prod,
                                                     vers, vupd)))
                                        if all(t is None
                                               for t in tags) and vers != '*':
                                            if not product_is_affected(
                                                    db, cve_id,
                                                    vend, prod, vers, vupd):
                                                popu_iqueue.put(
                                                    (3, (cve_id, vend,
                                                         prod, vers, vupd)))
                                        else:
                                            if not product_is_multiaffected(
                                                    db, cve_id, vend, prod,
                                                    tags[0], tags[1],
                                                    tags[2], tags[3]):
                                                popu_iqueue.put(
                                                    (4, (cve_id, vend, prod,
                                                         tags[0], tags[1],
                                                         tags[2], tags[3])))

                            references = (cve_item['cve']
                                          ['references']['reference_data'])
                            for reference in references:
                                if ('exploit-db' in reference['url'] and
                                    'Broken Link' not in reference['tags']):  # noqa
                                    expl_match = EXPL_NAME.match(
                                        reference['url'])
                                    if expl_match is not None:
                                        exploit, = expl_match.groups()
                                        if not exploit_in_db(
                                                db, exploit):
                                            popu_iqueue.put(
                                                (5, (exploit,)))
                                        if not cve_is_referenced(
                                                db, cve_id, exploit):
                                            popu_iqueue.put(
                                                (6, (cve_id, exploit)))
                        bar()
                popu_new_year.set()
                with alive_bar(1, title=f"[STORE] Year {year}:") as bar:
                    popu_oqueue.get()
                    bar()
                update_year(db, year, last_update, sha256)
            else:
                print(f"[CHECK] Year {year}: Already in DB ... skipping")

        if not os.path.isfile(args.metasploit):
            print("[Error] Metasploit cache file missing")
        else:
            with open(args.metasploit, 'r', encoding='utf8') as f:
                cache = json.load(f)

            with alive_bar(len(cache),
                           title="[PARSE] Reading Metastploit cache:") as bar:
                for meta in cache:
                    name = cache[meta]['fullname']
                    if not exploit_in_db(db, name, msf=True):
                        popu_iqueue.put((7, (name,)))
                    for ref in cache[meta]['references']:
                        match = REF_CVE.match(ref)
                        if match and cve_in_db(db, ref):
                            popu_iqueue.put((8, (ref, name)))
                    bar()
                popu_new_year.set()
        with alive_bar(1, title="[AWAIT] Populate threads") as bar:
            popu_finished.set()
            popu_thread.join()
            bar()

        if not args.noscrape:
            exploits = exploits_in_db(db)
            if len(exploits) > 0:
                expl_generator = exploit_batch(exploits)
                with ThreadPoolExecutor(max_workers=THREADS) as executor:
                    with alive_bar(len(exploits)//BATCH+1,
                                   title="[CRAWL] Exploit names") as bar:
                        for batch in expl_generator:
                            results = executor.map(scrape_title, batch)
                            bulk_update_exploit_name(db, list(results))
                            bar()


if __name__ == "__main__":
    config_handler.set_global(bar='classic', spinner='classic')
    parser = argparse.ArgumentParser(description="Tool to generate cve.db.")

    parser.add_argument('-d', '--database',
                        default='cve.db',
                        help="Database generated.")

    parser.add_argument('-m', '--metasploit',
                        default='modules_cache_msf.json',
                        help="Metasploit cache file.")

    parser.add_argument('-t', '--temp',
                        default='temp',
                        help="Temporary download directory.")

    parser.add_argument('-ns', '--noscrape',
                        action='store_true',
                        help="Do not scrape exploit-db.")

    parser.add_argument('-nc', '--noclean',
                        action='store_true',
                        help="Do not remove temporary directory.")

    args = parser.parse_args()

    print(COPYRIGHT)

    msg = "[START] Creating database ..."
    if os.path.isfile(args.database):
        msg = "[START] Updating database ..."
    print(msg)
    check_updates(args)
    clean_db(args)
    clean_temp(args)
