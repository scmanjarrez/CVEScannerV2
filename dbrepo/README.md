# CVEScannerV2DB

Data store for [CVEScannerV2](https://github.com/scmanjarrez/CVEScannerV2).
It holds the CVEScannerV2 SQLite database as a `sqlite3 .dump` split into
`dump.p00` ... `dump.pNN` parts of 25 MiB each.

**Do not edit by hand.** The `database.yaml` workflow of
[CVEScannerV2](https://github.com/scmanjarrez/CVEScannerV2) generates this
content and force-pushes it as an orphan commit to `master` on days 1 and 15
of each month.

## Rebuild the database

```sh
git clone https://github.com/scmanjarrez/CVEScannerV2DB
cd CVEScannerV2DB
sh build.sh
```

Requires `sqlite3`. Options:

- `-o FILE`: output database file.
- `--remove`: overwrite an existing output file. Without it, the script fails
  if the destination already exists.

The script ends by running `PRAGMA quick_check`.

## Compatibility

The database follows the CVEScannerV2 v4 schema (`conditions` table,
`cves.cvss_v4` column and checkpoint tables). For the old v3 NSE scripts, use
the `v3-final` tag.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
