#!/usr/bin/env python

from alive_progress import alive_bar, config_handler
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent
from threading import Thread, Event
from contextlib import closing
from queue import Queue
import requests as req
import dateutil.parser
import sqlite3 as sql
import datetime
import zipfile
import shutil
import urllib
import json
import time
import sys
import os
import re


DB = 'cve.db'
TMP_DIR = 'temp'
TITLE = re.compile("<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
PAGE_CHUNK = 4096
UA = UserAgent()
BATCH = 50
THREADS = 6
DELAY = 0.5


def create_db(db):
    with closing(db.cursor()) as cur:
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS Years (
                Year INTEGER PRIMARY KEY,
                LastUpdate TEXT,
                SHA256 TEXT
            );

            CREATE TABLE IF NOT EXISTS Exploits (
                Exploit INTEGER PRIMARY KEY,
                Name TEXT
            );

            CREATE TABLE IF NOT EXISTS CVEs (
                CVE TEXT PRIMARY KEY,
                CVSSV2 REAL,
                CVSSV3 REAL,
                Year INTEGER,
                Exploit TEXT,
                FOREIGN KEY (Year) REFERENCES Years (Year),
                FOREIGN KEY (Exploit) REFERENCES Exploits (Exploit)
            );

            CREATE TABLE IF NOT EXISTS ProductTypes (
                ProductType TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS Vendors (
                Vendor TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS Products (
                ProductID INTEGER PRIMARY KEY,
                ProductType TEXT,
                Vendor TEXT,
                Product TEXT,
                Version TEXT,
                VUpdate TEXT,
                FOREIGN KEY (Vendor) REFERENCES Vendors (Vendor),
                FOREIGN KEY (ProductType) REFERENCES ProductTypes (ProductType),
                UNIQUE (ProductType, Vendor, Product, Version, VUpdate)
            );

            CREATE TABLE IF NOT EXISTS Affected (
                CVE TEXT,
                ProductID INT,
                FOREIGN KEY (CVE) REFERENCES CVEs (CVE),
                FOREIGN KEY (ProductID) REFERENCES Products (ProductID),
                PRIMARY KEY (CVE, ProductID)
            );

            CREATE TABLE IF NOT EXISTS Referenced (
                CVE TEXT,
                Exploit INTEGER,
                FOREIGN KEY (CVE) REFERENCES CVEs (CVE),
                FOREIGN KEY (Exploit) REFERENCES Exploits (Exploit),
                PRIMARY KEY (CVE, Exploit)
            );

            PRAGMA foreign_keys = ON;
            """
        )


def year_in_db(db, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Years '
            'WHERE Year = ?'
            ')',
            [year])
        return cur.fetchone()[0]


def cached_year(db, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT LastUpdate FROM Years '
            'WHERE Year = ?',
            [year])
        return cur.fetchone()[0]


def insert_year(db, year, last_update, sha256):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO Years (Year, LastUpdate, SHA256) '
            'VALUES (?, ?, ?)',
            [year, last_update, sha256])
        db.commit()


def bulk_insert_year(db, year_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Years (Year, LastUpdate, SHA256) '
            'VALUES (?, ?, ?)',
            year_list)
        db.commit()


def update_year(db, year, last_update, sha256):
    with closing(db.cursor()) as cur:
        cur.execute(
            ('UPDATE Years '
             'SET LastUpdate = ?, SHA256 = ? '
             'WHERE Year = ?'),
            [last_update, sha256, year])
        db.commit()


def bulk_update_year(db, year_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'UPDATE Years '
            'SET LastUpdate = ?, SHA256 = ? '
            'WHERE Year = ?',
            year_list)
        db.commit()


def exploit_in_db(db, exploit):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Exploits '
            'WHERE Exploit = ?'
            ')',
            [exploit])
        return cur.fetchone()[0]


def exploits_in_db(db):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT Exploit FROM Exploits '
            'WHERE Name IS NULL')
        return [expl[0] for expl in cur.fetchall()]


def update_exploit_name(db, exploit_name):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'UPDATE Exploits '
            'SET Name = ? '
            'WHERE Exploit = ?',
            exploit_name)
        db.commit()


def bulk_insert_exploit(db, exploit_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Exploits (Exploit) VALUES (?)',
            exploit_list)
        db.commit()


def cve_in_db(db, cve):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM CVEs '
            'WHERE CVE = ?)',
            [cve])
        return cur.fetchone()[0]


def insert_cve(db, cve, cvssv2, cvssv3, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO CVEs (CVE, CVSSV2, CVSSV3, Year) '
            'VALUES (?, ?, ?, ?)',
            [cve, cvssv2, cvssv3, year])
    db.commit()


def bulk_insert_cve(db, cve_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO CVEs (CVE, CVSSV2, CVSSV3, Year) '
            'VALUES (?, ?, ?, ?)',
            cve_list)
        db.commit()


def update_cve(db, cve, cvssv2, cvssv3, year):
    with closing(db.cursor()) as cur:
        cur.execute(
            'UPDATE CVEs '
            'SET CVSSV2 = ?, CVSSV3 = ?, Year = ? '
            'WHERE CVE = ?',
            [cvssv2, cvssv3, year, cve])
        db.commit()


def bulk_update_cve(db, cve_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'UPDATE CVEs '
            'SET CVSSV2 = ?, CVSSV3 = ?, Year = ? '
            'WHERE CVE = ?',
            cve_list)
        db.commit()


def product_type_in_db(db, product_type):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM ProductTypes '
            'WHERE ProductType = ?)',
            [product_type])
        return cur.fetchone()[0]


def insert_product_type(db, product_type):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO ProductTypes VALUES (?)',
            [product_type])
        db.commit()


def bulk_insert_product_type(db, ptype_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO ProductTypes VALUES (?)',
            ptype_list)
        db.commit()


def vendor_in_db(db, vendor):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Vendors '
            'WHERE Vendor = ?)',
            [vendor])
        return cur.fetchone()[0]


def insert_vendor(db, vendor):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO Vendors VALUES (?)',
            [vendor])
        db.commit()


def bulk_insert_vendor(db, vendor_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Vendors VALUES (?)',
            vendor_list)
        db.commit()


def product_in_db(db, product_type, vendor, product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Products '
            'WHERE ProductType = ? AND '
            'Vendor = ? AND Product = ? AND '
            'Version = ? AND VUpdate = ?)',
            [product_type, vendor, product, version, update])
        return cur.fetchone()[0]


def insert_product(db, product_type, vendor, product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO Products ('
            'ProductType, Vendor, Product, Version, VUpdate) '
            'VALUES (?, ?, ?, ?, ?)',
            [product_type, vendor, product, version, update])
        db.commit()


def bulk_insert_product(db, product_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Products ('
            'ProductType, Vendor, Product, Version, VUpdate) '
            'VALUES (?, ?, ?, ?, ?)',
            product_list)
        db.commit()


def product_is_affected(db, cve, product_type, vendor,
                        product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Affected '
            'WHERE ProductID = ('
            'SELECT ProductID FROM Products '
            'WHERE ProductType = ? AND Vendor = ? AND '
            'Product = ? AND Version = ? AND VUpdate = ?) AND CVE = ?)',
            [product_type, vendor, product, version, update, cve])
        return cur.fetchone()[0]


def insert_affected(db, cve, product_type, vendor,
                    product, version, update):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO Affected '
            'VALUES (?, ('
            'SELECT ProductID FROM Products '
            'WHERE ProductType = ? AND Vendor = ? AND '
            'Product = ? AND Version = ? AND VUpdate = ?))',
            [cve, product_type, vendor, product, version, update])
        db.commit()


def bulk_insert_affected(db, product_cve_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Affected '
            'VALUES (?, ('
            'SELECT ProductID FROM Products '
            'WHERE ProductType = ? AND Vendor = ? AND '
            'Product = ? AND Version = ? AND VUpdate = ?))',
            product_cve_list)
        db.commit()


def cve_has_reference(db, cve, exploit):
    with closing(db.cursor()) as cur:
        cur.execute(
            'SELECT EXISTS('
            'SELECT 1 FROM Referenced '
            'WHERE CVE = ? AND Exploit = ?)',
            [cve, exploit])
        return cur.fetchone()[0]


def insert_referenced(db, cve, exploit):
    with closing(db.cursor()) as cur:
        cur.execute(
            'INSERT INTO Referenced '
            'VALUES (?, ?)',
            [cve, exploit])
        db.commit()


def bulk_insert_referenced(db, cve_exploit_list):
    with closing(db.cursor()) as cur:
        cur.executemany(
            'INSERT or IGNORE INTO Referenced '
            'VALUES (?, ?)',
            cve_exploit_list)
        db.commit()


class PopulateDBThread(Thread):
    def __init__(self, finished, changed, in_queue, out_queue):
        Thread.__init__(self)
        self.finished = finished
        self.changed = changed
        self.iqueue = in_queue
        self.oqueue = out_queue
        self.execmany = {
            0: bulk_insert_exploit,
            1: bulk_insert_cve,
            2: bulk_update_cve,
            3: bulk_insert_vendor,
            4: bulk_insert_product,
            5: bulk_insert_affected,
            6: bulk_insert_referenced
        }
        self.datalist = {
            0: [], 1: [], 2: [], 3: [],
            4: [], 5: [], 6: []
        }

    def run(self):
        with closing(sql.connect(DB)) as db:
            create_db(db)
            while True:
                if not self.iqueue.empty():
                    dtype, data = self.iqueue.get()
                    self.datalist[dtype].append(data)
                else:
                    if self.changed.is_set():
                        self.changed.clear()
                        for dt in range(0, 7):
                            self.execmany[dt](db, self.datalist[dt])
                            self.datalist[dt] = []
                        self.oqueue.put((1,))
                    elif self.finished.is_set():
                        break
                    else:
                        time.sleep(1)


def scrape_title(exploit):
    unquoted = None
    try:
        with req.get(f'https://www.exploit-db.com/exploits/{exploit}',
                     stream=True, headers={'User-Agent': UA.random}
                     ) as page:
            buff = ""
            for chk in page.iter_content(chunk_size=PAGE_CHUNK):
                buff += chk.decode('utf-8')
                match = TITLE.search(buff)
                if match:
                    unquoted = match.group(1).replace("&#039;", "'")
                    break
    except (req.exceptions.ConnectionError,
            req.exceptions.ConnectTimeout) as e:
        print("Error ocurred:", exploit, e)
    finally:
        time.sleep(DELAY)
        return (unquoted, exploit)


def exploit_batch(exploits):
    for i in range(0, len(exploits), BATCH):
        yield exploits[i:i + BATCH]


def check_updates():
    with closing(sql.connect(DB)) as db:
        url = "https://nvd.nist.gov/feeds/json/cve/1.1/"
        filename = "nvdcve-1.1-"
        meta = re.compile(r'lastModifiedDate:([\w\d:-]+).*?sha256:([\w\d]+)',
                          re.DOTALL)
        cpeuri = re.compile(r'cpe:2.3:(.*?):(.*?):(.*?):(.*?):(.*?):.*')
        expl_name = re.compile(r'https?://www.exploit-db.com/exploits/(\d+)')
        product_type = {'a': 'Application',
                        'o': 'Operating System',
                        'h': 'Hardware'}
        nvd_years = range(2002, datetime.datetime.now().year + 1)
        # 2002 data feed includes prior vulnerabilities, first cve from 1988
        vuln_years = range(1988, datetime.datetime.now().year + 1)

        populate_ychanged = Event()
        populate_finished = Event()
        populate_iqueue = Queue()
        populate_oqueue = Queue()
        populate_thread = PopulateDBThread(populate_finished,
                                           populate_ychanged,
                                           populate_iqueue,
                                           populate_oqueue)
        populate_thread.start()
        time.sleep(1)

        for vy in vuln_years:
            if not year_in_db(db, vy):
                insert_year(db, vy, None, None)

        for year in nvd_years:
            resp = req.get(f"{url}{filename}{year}.meta")
            matched = meta.match(resp.text)
            update = True
            if matched is not None:
                last_update, sha256 = matched.groups()
                cached_lu = cached_year(db, year)
                if last_update == cached_lu:
                    update = False

                tmpfile = f"{TMP_DIR}/{filename}{year}.json"
                if update:
                    try:
                        os.makedirs(TMP_DIR, exist_ok=True)
                    except PermissionError:
                        print(f"[ERROR] Insufficient permission "
                              f"to create \"{TMP_DIR}\" directory.")
                        sys.exit(-1)

                    tmpurl = f"{url}{filename}{year}.json.zip"
                    with alive_bar(total=1,
                                   title=f"[DWNLD] Year {year}:") as bar:
                        try:
                            urllib.request.urlretrieve(tmpurl,
                                                       f"{tmpfile}.zip")
                        except urllib.error.ContentTooShortError:
                            print("[ERROR] Data downloaded "
                                  "is less than expected.")
                            sys.exit(-1)
                        except urllib.error.URLError as e:
                            print(f"[ERROR] {e}")
                            sys.exit(-1)

                        with zipfile.ZipFile(f"{tmpfile}.zip", 'r') as zf:
                            try:
                                zf.extractall(TMP_DIR)
                            except ValueError:
                                print("[ERROR] Unexpected close.")
                                sys.exit(-1)
                        bar()

                    with open(tmpfile, 'r') as f:
                        data = json.load(f)

                    with alive_bar(total=len(data['CVE_Items']),
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
                            cve_year = dateutil.parser.parse(
                                cve_item['publishedDate']).year
                            vendors = cve_item['configurations']['nodes']
                            if not vendors:
                                bar()
                                continue

                            references = (cve_item['cve']
                                          ['references']['reference_data'])
                            if not cve_in_db(db, cve_id):
                                try:
                                    populate_iqueue.put((1,
                                                         (cve_id,
                                                          cvssv2,
                                                          cvssv3,
                                                          cve_year)))
                                except sql.IntegrityError:
                                    print(cve_id, cvssv2, cvssv3, cve_year)
                                    sys.exit(-1)
                            else:
                                populate_iqueue.put((2,
                                                     (cve_id, cvssv2, cvssv3,
                                                      cve_year)))

                            for vendor in vendors:
                                products = ([ch['cpe_match'][0]
                                             for ch in vendor['children']]
                                            if 'children' in vendor
                                            else vendor['cpe_match'])
                                for product in products:
                                    uri = cpeuri.match(product['cpe23Uri'])
                                    if uri is not None:
                                        groups = uri.groups()
                                        ptype, vend, prod, vers, upd = groups
                                        ptype = product_type[ptype]
                                        if not product_type_in_db(db,
                                                                  ptype):
                                            insert_product_type(db,
                                                                ptype)
                                        if not vendor_in_db(db,
                                                            vend):
                                            populate_iqueue.put((3,
                                                                 (vend,)))
                                        if not product_in_db(db,
                                                             ptype, vend,
                                                             prod, vers,
                                                             upd):
                                            populate_iqueue.put((4, (ptype,
                                                                     vend,
                                                                     prod,
                                                                     vers,
                                                                     upd)))
                                        if not product_is_affected(db,
                                                                   cve_id,
                                                                   ptype,
                                                                   vend,
                                                                   prod,
                                                                   vers,
                                                                   upd):
                                            populate_iqueue.put((5,
                                                                 (cve_id,
                                                                  ptype,
                                                                  vend,
                                                                  prod,
                                                                  vers,
                                                                  upd)))
                                    else:
                                        print(f"[ERROR] Can't parse "
                                              f"{product['cpe23Uri']}")
                                        continue

                            for reference in references:
                                if ('exploit-db' in reference['url'] and
                                    'Broken Link' not in reference['tags']):
                                    expl_match = expl_name.match(
                                        reference['url'])
                                    if expl_match is not None:
                                        exploit, = expl_match.groups()
                                        if not exploit_in_db(db, exploit):
                                            populate_iqueue.put((0,
                                                                 (exploit,)))
                                        if not cve_has_reference(db, cve_id,
                                                                 exploit):
                                            populate_iqueue.put((6,
                                                                 (cve_id,
                                                                  exploit)))
                            bar()
                    populate_ychanged.set()
                    with alive_bar(total=1,
                                   title=f"[STORE] Year {year}:") as bar:
                        populate_oqueue.get()
                        bar()
                    update_year(db, year, last_update, sha256)
                else:
                    print(f"[CHECK] Year {year}: Already in DB ... skipping")
            else:
                print(f"[ERROR] Year {year}: Cannot retrieve metadata")

        with alive_bar(total=1,
                       title="[AWAIT] Populate threads") as bar:
            populate_finished.set()
            populate_thread.join()
            bar()

        exploits = exploits_in_db(db)
        if len(exploits) > 0:
            expl_generator = exploit_batch(exploits)
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                with alive_bar(
                        total=len(exploits)//BATCH+1,
                        title="[CRAWL] Exploit names") as bar:
                    for batch in expl_generator:
                        results = executor.map(scrape_title, batch)
                        update_exploit_name(db, list(results))
                        bar()


def clean_temp():
    if os.path.exists(TMP_DIR) and os.path.isdir(TMP_DIR):
        with alive_bar(
                total=1, title="[CLEAN] Temporary files") as bar:
            try:
                shutil.rmtree(TMP_DIR)
            except FileNotFoundError:
                pass
            finally:
                bar()


if __name__ == "__main__":
    config_handler.set_global(bar='classic', spinner='classic')
    check_updates()
    clean_temp()
