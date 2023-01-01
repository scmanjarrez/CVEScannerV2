#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-3.0-or-later

# splitter - Database splitter.

# Copyright (C) 2021-2023 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
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

from pathlib import Path

import argparse


def generate_splits(args):
    inp = Path(args.input)
    n_files = int(inp.stat().st_size / 1024 / 1024 // args.size)
    padding = len(str(n_files))
    idx = 0
    empty = False
    with inp.open() as f:
        while not empty:
            out = Path(
                f'{args.output}/{inp.stem}_{idx:0{padding}d}{inp.suffix}')
            with out.open('w') as ff:
                while (out.stat().st_size / 1024 / 1024) < args.size:
                    nxt = f.readline()
                    if not nxt:
                        empty = True
                        break
                    ff.write(nxt)
                idx += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Split big sqlite dump into small scripts")

    parser.add_argument('-s', '--size', type=int,
                        default=25,
                        help="Size (MiB). Default: 25")
    parser.add_argument('-i', '--input', required=True,
                        help="Input sql to be splitted.")
    parser.add_argument('-o', '--output',
                        default='.',
                        help="Output directory.")
    args = parser.parse_args()

    generate_splits(args)
