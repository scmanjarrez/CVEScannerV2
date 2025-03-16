import sqlite3 as sql
from contextlib import closing
import argparse
from texttable import Texttable
import logging


def related(args):
    with closing(sql.connect(args.cve)) as db:
        with closing(db.cursor()) as cur:
            cur.execute(
                """
                SELECT affected.cve_id, cves.cvss_v2, cves.cvss_v3,
                products.vendor, products.product, products.version, products.version_update,
                (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = affected.cve_id)) as edb,
                (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = affected.cve_id)) as msf
                FROM products
                INNER JOIN affected ON products.product_id = affected.product_id
                INNER JOIN cves ON affected.cve_id = cves.cve_id
                WHERE products.product = ?;
                """,
                [args.product],
            )
            return cur.fetchall()


def related_multi(args):
    with closing(sql.connect(args.cve)) as db:
        with closing(db.cursor()) as cur:
            cur.execute(
                """
                SELECT multiaffected.cve_id, cves.cvss_v2, cves.cvss_v3,
                products.vendor, products.product,
                multiaffected.versionStartIncluding, multiaffected.versionStartExcluding,
                multiaffected.versionEndIncluding, multiaffected.versionEndExcluding,
                (SELECT EXISTS (SELECT 1 FROM referenced_exploit WHERE cve_id = multiaffected.cve_id)) as edb,
                (SELECT EXISTS (SELECT 1 FROM referenced_metasploit WHERE cve_id = multiaffected.cve_id)) as msf
                FROM multiaffected
                INNER JOIN cves ON multiaffected.cve_id = cves.cve_id
                INNER JOIN products ON multiaffected.product_id = products.product_id
                WHERE multiaffected.product_id IN (SELECT product_id FROM products WHERE product = ?)
                """,
                [args.product],
            )
            return cur.fetchall()


def clean(data):
    final = []
    for row in data:
        tmp = []
        for elem in row:
            if elem is None:
                tmp.append("")
            elif elem in [0, 1]:
                val = "Yes"
                if elem == 0:
                    val = "No"
                tmp.append(val)
            elif elem == "-":
                tmp.append("*")
            else:
                tmp.append(elem)
        final.append(tmp)
    return final


def default_table(header_size):
    table = Texttable()
    table.set_precision(1)
    table.set_cols_align(["c"] * header_size)
    table.set_cols_valign(["m"] * header_size)
    table.set_max_width(0)
    return table


def print_affected(data):
    if data:
        header = [
            "CVE", "CVSSv2", "CVSSv3",
            "Vendor", "Product",
            "Version", "V.Update",
            "EDB", "MSF"
        ]
        table = default_table(len(header))
        table.header(header)
        table.add_rows(data, header=False)
        print(table.draw())
    else:
        print("No data found")


def print_multi(data):
    if data:
        header = [
            "CVE", "CVSSv2", "CVSSv3",
            "Vendor", "Product",
            "StartInclude", "StartExclude",
            "EndInclude", "EndExclude",
            "EDB", "MSF"
        ]
        table = default_table(len(header))
        table.header(header)
        table.add_rows(data, header=False)
        print(table.draw())


def compare_version(user_version, db_version, user_update, db_update):
    if db_version == "-":
        db_version = "*"
    if ((user_update is None or db_update == "*" or user_update == db_update)
        and user_version == db_version):
            return 0
    user_version = user_version.split(".")
    db_version = db_version.split(".")
    res = 0
    for user_v, db_v in zip(user_version, db_version):
        try:
            u_v = int(user_v)
            d_v = int(db_v)
        except ValueError:
            u_v = user_v
            d_v = db_v
        if u_v < d_v:
            res = -1
        elif u_v > d_v:
            res = 1
        else:
            res = 0
        if res: # if lower or higher, just exit
            return res
    if user_update is not None and user_update != db_update:
        return -2
    return res


def main(args):
    cve = clean(related(args))
    cve_multi = clean(related_multi(args))
    if args.raw:
        print_affected(cve)
        print()
        print_multi(cve_multi)
        print()

    res = []
    user_version = args.version
    user_update = args.update
    for c in cve:
        db_version = c[5]
        db_update = c[6]
        if user_version is None:
            res.append(c)
        else:
            if db_version == "*":
                res.append(c)
                continue
            cmp = compare_version(
                user_version, db_version,
                user_update, db_update,
            )
            if not cmp: # same version?
                res.append(c)
            else:
                if args.debug:
                    if cmp == -1:
                        logging.info(f"ERR: {c[0]}: {user_version}(u) < {db_version}(d)")
                    elif cmp == 1:
                        logging.info(f"ERR: {c[0]}: {user_version}(u) > {db_version}(d)")
                    else:
                        logging.info(f"ERR: {c[0]}: {user_version}(u) == {db_version}(d), {user_update}(u) != {db_update}(d)")

    res_multi = []
    for c in cve_multi:
        startinc_version = c[5]
        startexc_version = c[6]
        endinc_version = c[7]
        endexc_version = c[8]
        if startinc_version:
            cmp = compare_version(user_version, startinc_version, None, None)
            if cmp == -1:
                if args.debug:
                    logging.info(f"ERR: {c[0]}: StInc: {user_version}(u) < {startinc_version}(d)")
                continue
        elif startexc_version:
            cmp = compare_version(user_version, startexc_version, None, None)
            if cmp in [-1, 0]:
                if args.debug:
                    logging.info(f"ERR: {c[0]}: StInc: {user_version}(u) <= {startexc_version}(d)")
                continue

        if endinc_version:
            cmp = compare_version(user_version, endinc_version, None, None)
            if cmp == 1:
                if args.debug:
                    logging.info(f"ERR: {c[0]}: EndInc: {user_version}(u) > {endinc_version}(d)")
                continue
        elif endexc_version:
            cmp = compare_version(user_version, endexc_version, None, None)
            if cmp in [1, 0]:
                if args.debug:
                    logging.info(f"ERR: {c[0]}: EndExc: {user_version}(u) >= {endexc_version}(d)")
                continue
        res_multi.append(c)

    print("Exact match:")
    print_affected(res)
    if res_multi:
        print()
        print("Multi match:")
        print_multi(res_multi)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Command line utility to query related CVEs"
    )
    parser.add_argument("-c", "--cve", help="Path to CVE db", default="./cve.db")
    parser.add_argument("-p", "--product", help="Product name to query", required=True)
    parser.add_argument("-v", "--version", help="Version of the product")
    parser.add_argument("-u", "--update", help="Version update of the product")
    parser.add_argument("-r", "--raw", action="store_true", help="Output raw data (no filters applied)")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug messages")
    args = parser.parse_args()
    logging.basicConfig(
        format=("%(asctime)s - %(message)s"),
        level=logging.INFO,
    )
    main(args)
