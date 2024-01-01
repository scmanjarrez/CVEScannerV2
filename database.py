#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# database - Database generator.

# Copyright (C) 2021-2024 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
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

import argparse
import html
import json
import os
import re
import sqlite3 as sql
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from queue import Queue
from threading import Event, Thread

import httpx
from fake_useragent import UserAgent

from pyrate_limiter import Limiter, RequestRate
from tqdm import tqdm


# 50 requests in a 30-seconds window
LIMITER = Limiter(RequestRate(48, 30))
UA = UserAgent()
KEY = ""
RE = {
    "tit": re.compile(
        r"""<meta property=(?P<quote>['"])og:title(?P=quote) """
        r"""content=(?P<quotex>['"])(.*?)(?P=quotex)""",
        re.IGNORECASE | re.DOTALL,
    ),
    "msf": re.compile(
        r"""['"]Name['"]\s+=>\s+(?P<quote>['"])((\\.|.)*?)(?P=quote)""",
        re.IGNORECASE | re.DOTALL,
    ),
    "cpe": re.compile(
        r"cpe:2.3:"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r"(.*?)(?<!:):(?!:)"
        r".*"
    ),
    "v3": re.compile(r"(cvssMetricV3.+)"),
    "exp": re.compile(r"https?://www.exploit-db.com/exploits/(\d+)"),
    "cve": re.compile(r"CVE-\d+-\d+"),
}
VTAGS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)
URL = {
    "nvd": "https://services.nvd.nist.gov/rest/json/{}/2.0?startIndex={}",
    "expdb": "https://www.exploit-db.com/exploits",
}
CONST = {
    "cpe": 10000,  # max results per page
    "cve": 2000,
    "bat": 25,
}
COPYRIGHT = """
CVEScannerV2  Copyright (C) 2022-2024 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
Universidad Carlos III de Madrid.
This program comes with ABSOLUTELY NO WARRANTY; for details check below.
This is free software, and you are welcome to redistribute it
under certain conditions; check below for details.
"""  # noqa


class Database:
    def __init__(self, database):
        self.path = database

    def __enter__(self):
        self.conn = sql.connect(self.path)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_class, exc, traceback):
        self.conn.commit()
        self.conn.close()

    def setup(self):
        self.cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY,
                last_mod TEXT
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

    def cached_metadata(self):
        self.cursor.execute("SELECT last_mod FROM metadata")
        return self.cursor.fetchone()[0]

    def cached_cve(self, cve):
        self.cursor.execute(
            "SELECT EXISTS "
            "("
            "SELECT 1 "
            "FROM cves "
            "WHERE cve_id = ?"
            ")",
            [cve],
        )
        return self.cursor.fetchone()[0]

    def cached_exploits(self):
        self.cursor.execute(
            "SELECT exploit_id FROM exploits WHERE name IS NULL"
        )
        return [expl[0] for expl in self.cursor.fetchall()]

    def insert_products(self, products):
        self.cursor.executemany(
            "INSERT or IGNORE INTO products "
            "(vendor, product, version, version_update) "
            "VALUES (?, ?, ?, ?)",
            products,
        )
        self.conn.commit()

    def insert_cves(self, cves):
        self.cursor.executemany(
            "INSERT or REPLACE INTO cves VALUES (?, ?, ?, ?)",
            cves,
        )
        self.conn.commit()

    def insert_exploits(self, exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO exploits (exploit_id) VALUES (?)",
            exploits,
        )
        self.conn.commit()

    def insert_metasploits(self, metasploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO metasploits (name) VALUES (?)",
            metasploits,
        )
        self.conn.commit()

    def insert_affected(self, cves_products):
        self.cursor.executemany(
            "INSERT or IGNORE INTO affected "
            "VALUES "
            "(?, "
            "("
            "SELECT product_id FROM products "
            "WHERE vendor = ? AND product = ? "
            "AND version = ? AND version_update = ?"
            ")"
            ")",
            cves_products,
        )
        self.conn.commit()

    def insert_multiaffected(self, cves_products_versions):
        self.cursor.executemany(
            "INSERT or IGNORE INTO multiaffected "
            "VALUES "
            "(?, "
            "("
            "SELECT product_id FROM products "
            "WHERE vendor = ? AND product = ? "
            "AND version = '*'"
            "), "
            "?, ?, ?, ?)",
            cves_products_versions,
        )
        self.conn.commit()

    def insert_referenced(self, cves_exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO referenced_exploit VALUES (?, ?)",
            cves_exploits,
        )
        self.conn.commit()

    def insert_referencedm(self, cves_exploits):
        self.cursor.executemany(
            "INSERT or IGNORE INTO referenced_metasploit "
            "VALUES "
            "(?, "
            "("
            "SELECT metasploit_id "
            "FROM metasploits "
            "WHERE name = ?"
            ")"
            ")",
            cves_exploits,
        )
        self.conn.commit()

    def update_metadata(self):
        self.cursor.execute(
            "INSERT or REPLACE INTO metadata VALUES (1, ?)", [now()]
        )
        self.conn.commit()

    def update_exploits(self, exploits):
        self.cursor.executemany(
            "UPDATE exploits SET name = ? WHERE exploit_id = ?",
            exploits,
        )
        self.conn.commit()

    def remove_cves(self, cves):
        self.cursor.executemany(
            "DELETE FROM referenced_exploit WHERE cve_id = ?", cves
        )
        self.cursor.executemany(
            "DELETE FROM referenced_metasploit WHERE cve_id = ?", cves
        )
        self.cursor.executemany("DELETE FROM affected WHERE cve_id = ?", cves)
        self.cursor.executemany(
            "DELETE FROM multiaffected WHERE cve_id = ?", cves
        )
        self.cursor.executemany("DELETE FROM cves WHERE cve_id = ?", cves)
        self.conn.commit()

    def clean(self):
        self.cursor.execute(
            "DELETE FROM referenced_exploit "
            "WHERE exploit_id IN "
            "("
            "SELECT exploit_id "
            "FROM exploits "
            "WHERE name LIKE '404 Page %'"
            ")"
        )
        self.cursor.execute(
            "DELETE FROM exploits WHERE name LIKE '404 Page %'"
        )
        self.conn.commit()


def now():
    return datetime.isoformat(datetime.utcnow())


def _norm(string):
    return string.replace("\\", "")


def split(cpe_uri):
    return RE["cpe"].match(_norm(cpe_uri)).groups()


def parse_node(node, cve_id):
    return [
        (
            split(cpe["criteria"]),
            [_norm(cpe[vt]) if vt in cpe else None for vt in VTAGS],
        )
        for cpe in node["cpeMatch"]
    ]


class PopulateDBThread(Thread):
    def __init__(self, path, finished, insert, queue):
        Thread.__init__(self)
        self.path = path
        self.finished = finished
        self.insert = insert
        self.queue = queue

    def setup_execm(self, db):
        self.execmany = {
            0: db.insert_products,
            1: db.insert_cves,
            2: db.remove_cves,
            3: db.insert_exploits,
            4: db.insert_metasploits,
            5: db.insert_affected,
            6: db.insert_multiaffected,
            7: db.insert_referenced,
            8: db.insert_referencedm,
        }
        self.datalist = {k: [] for k in self.execmany}

    def run(self):
        with Database(self.path) as db:
            db.setup()
            self.setup_execm(db)
            try:
                while True:
                    if not self.queue.empty():
                        dtype, data = self.queue.get()
                        self.datalist[dtype].append(data)
                    else:
                        if self.insert.is_set():
                            self.insert.clear()
                            for dt in range(len(self.execmany)):
                                self.execmany[dt](set(self.datalist[dt]))
                                self.datalist[dt] = []
                        elif self.finished.is_set():
                            break
                        else:
                            time.sleep(1)
            except Exception:
                print(traceback.format_exc())


@LIMITER.ratelimit("identity", delay=True)
def query_api(args):
    try:
        url, database, cl, bar, thread_objs, batch, populate = args
        ev_fin, ev_ins, queue = thread_objs
        try:
            resp = cl.get(url)
        except httpx.TimeoutException:
            print(traceback.format_exc())
            return
        data = resp.json()
        if "cpes" in url:
            idy = 0
            for prod in data["products"]:
                ptype, ven, pro, ver, vup = split(prod["cpe"]["cpeName"])
                idy += 1
                if ptype == "a":
                    queue.put((0, (ven, pro, ver, vup)))
        else:
            for vuln in data["vulnerabilities"]:
                cve_id = vuln["cve"]["id"]
                if vuln["cve"]["vulnStatus"].lower() in (
                    "deferred",
                    "rejected",
                ):
                    if not populate:
                        #print(f"sending {cve_id} to remove")
                        queue.put((2, (cve_id,)))
                    continue
                cvssv2 = (
                    None
                    if "cvssMetricV2" not in vuln["cve"]["metrics"]
                    else vuln["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"][
                        "baseScore"
                    ]
                )
                cvssv3keys = [
                    key
                    for key in vuln["cve"]["metrics"].keys()
                    if RE["v3"].match(key) is not None
                ]
                cvssv3 = (
                    None
                    if not cvssv3keys
                    else vuln["cve"]["metrics"][cvssv3keys[0]][0]["cvssData"][
                        "baseScore"
                    ]
                )
                year = int(vuln["cve"]["published"][:4])
                queue.put((1, (cve_id, cvssv2, cvssv3, year)))
                if "configurations" in vuln["cve"]:
                    for config in vuln["cve"]["configurations"]:
                        for node in config["nodes"]:
                            products = parse_node(node, cve_id)
                            for (
                                ptype,
                                ven,
                                pro,
                                ver,
                                vup,
                            ), tags in products:
                                if ptype == "a":
                                    queue.put((0, (ven, pro, ver, vup)))
                                    if (
                                        all(t is None for t in tags)
                                        and ver != "*"
                                    ):
                                        queue.put(
                                            (
                                                5,
                                                (
                                                    cve_id,
                                                    ven,
                                                    pro,
                                                    ver,
                                                    vup,
                                                ),
                                            )
                                        )
                                    else:
                                        queue.put(
                                            (6, (cve_id, ven, pro, *tags))
                                        )
                if "references" in vuln["cve"]:
                    for reference in vuln["cve"]["references"]:
                        if "exploit-db" in reference["url"] and (
                            "tags" not in reference
                            or (
                                "tags" in reference
                                and "Broken Link" not in reference["tags"]
                            )
                        ):
                            match = RE["exp"].match(reference["url"])
                            if match is not None:
                                exp_id = match.group(1)
                                queue.put((3, (exp_id,)))
                                queue.put((7, (cve_id, exp_id)))
    except Exception:
        print(url)
        print(traceback.format_exc())
    ev_ins.set()
    bar.update(batch)


def update_db(args, thread_objs, populate=False):
    extra = ""
    if not populate:
        print("[*] Updating database...")
        with Database(args.database) as db:
            try:
                last = db.cached_metadata()
                extra = f"&lastModStartDate={last}&lastModEndDate={now()}"
            except TypeError:
                pass
    else:
        print("[+] Creating database...")

    with httpx.Client(timeout=120, headers={"apiKey": KEY}) as cl:
        print("[*] Retrieving CVEs/CPEs metadata...")
        resp = cl.get(
            f"{URL['nvd'].format('cpes', 0)}" f"&resultsPerPage=1{extra}"
        )
        if resp.status_code != 200:
            print("[!] Error retrieving information from NVD API")
            os._exit(-1)
        cpes = resp.json()["totalResults"]
        resp = cl.get(
            f"{URL['nvd'].format('cves', 0)}" f"&resultsPerPage=1{extra}"
        )
        cves = resp.json()["totalResults"]
        print(f"[+] Metadata: {cpes} CPEs | {cves} CVEs")
        cve_q, cpe_q = -(-cves // CONST["cve"]), -(-cpes // CONST["cpe"])
        cve_l, cpe_l = cves % CONST["cve"], cpes % CONST["cpe"]
        time.sleep(5)

        if cpes:
            with tqdm(
                total=cpes, ascii=" =", desc="[+] Retrieving CPEs"
            ) as bar:
                q_args = []
                idx = 0
                with ThreadPoolExecutor() as tpe:
                    for _ in range(cpe_q):
                        q_args.append(
                            [
                                f"{URL['nvd'].format('cpes', idx)}{extra}",
                                args.database,
                                cl,
                                bar,
                                thread_objs,
                                CONST["cpe"],
                                populate,
                            ]
                        )
                        idx += CONST["cpe"]
                    q_args[-1][-2] = cpe_l  # last batch
                    tpe.map(query_api, q_args)

        if cves:
            with tqdm(
                total=cves, ascii=" =", desc="[+] Retrieving CVEs"
            ) as bar:
                q_args = []
                idx = 0
                with ThreadPoolExecutor() as tpe:
                    for _ in range(cve_q):
                        q_args.append(
                            [
                                f"{URL['nvd'].format('cves', idx)}{extra}",
                                args.database,
                                cl,
                                bar,
                                thread_objs,
                                CONST["cve"],
                                populate,
                            ]
                        )
                        idx += CONST["cve"]
                    q_args[-1][-2] = cve_l  # last batch
                    tpe.map(query_api, q_args)


def update_metasploit(args, thread_objs):
    meta = Path(args.metasploit)
    if not meta.is_file():
        print("[-] Metasploit cache file missing")
    else:
        with meta.open() as f:
            cache = json.load(f)
        with Database(args.database) as db:
            for vuln in tqdm(
                cache, ascii=" =", desc="[+] Retrieving metastploit data"
            ):
                name = cache[vuln]["fullname"]
                thread_objs[2].put((4, (name,)))
                for ref in cache[vuln]["references"]:
                    match = RE["cve"].match(ref)
                    if match is not None:
                        while True:
                            try:
                                if db.cached_cve(ref):
                                    thread_objs[2].put((8, (ref, name)))
                            except sql.OperationalError:
                                time.sleep(2)
                            else:
                                break
        thread_objs[1].set()


def scrape_title(exploit):
    title = None
    delay = 5
    try:
        page = httpx.get(
            f"{URL['expdb']}/{exploit}",
            headers={"User-Agent": UA.random},
            timeout=120,
        )
        decoded = html.unescape(page.text)
        title = RE["tit"].search(decoded).group(3)  # group 1 and 2 are quotes
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        print("Error ocurred:", exploit, e)
    finally:
        time.sleep(delay)
        return title, exploit


def exploit_batch(exploits):
    for i in range(0, len(exploits), CONST["bat"]):
        yield exploits[i : i + CONST["bat"]]


def update_exploitdb(args, thread_objs):
    with Database(args.database) as db:
        db.clean()
        if not args.noscrape:
            exps = db.cached_exploits()
            # low requests per minute, but we need this to bypass WAF
            threads = 3
            if len(exps) > 0:
                exp_gen = exploit_batch(exps)
                with ThreadPoolExecutor(max_workers=threads) as tpe:
                    with tqdm(
                        total=len(exps) // CONST["bat"] + 1,
                        ascii=" =",
                        desc="[+] Retrieving exploit-db names",
                    ) as bar:
                        for batch in exp_gen:
                            res = list(tpe.map(scrape_title, batch))
                            db.update_exploits(list(res))
                            bar.update()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to generate CVEScannerV2 database"
    )

    parser.add_argument(
        "-d", "--database", default="cve.db", help="Database file path"
    )

    parser.add_argument(
        "-m",
        "--metasploit",
        default="modules_cache_msf.json",
        help="Metasploit cache file path",
    )

    parser.add_argument(
        "-ns",
        "--noscrape",
        action="store_true",
        help="Disable exploit-db name scraping",
    )
    args = parser.parse_args()

    print(COPYRIGHT)

    api = Path(".api")
    if api.is_file():
        with api.open() as f:
            KEY = f.read().strip()
    else:
        print(
            "[!] NVD API key required in order to retrieve data. "
            "Check README.md for more information"
        )
        os._exit(-1)

    thread_objs = (Event(), Event(), Queue())
    thread = PopulateDBThread(args.database, *thread_objs)
    thread.start()

    update_db(args, thread_objs, populate=not Path(args.database).is_file())

    with Database(args.database) as db:
        db.update_metadata()

    update_metasploit(args, thread_objs)
    update_exploitdb(args, thread_objs)

    with tqdm(total=1, ascii=" =", desc="[*] Awaiting database thread") as bar:
        thread_objs[0].set()
        thread.join()
        bar.update()
