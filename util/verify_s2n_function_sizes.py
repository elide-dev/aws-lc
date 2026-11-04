#!/usr/bin/env python3
"""Assemble the s2n Ed25519 routines and check their live ELF function ranges."""

import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--readelf', default='readelf')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    imported = root / 'third_party/s2n-bignum/s2n-bignum-imported'
    with tempfile.TemporaryDirectory(prefix='s2n-size-') as temp:
        for name in ['edwards25519_scalarmuldouble', 'edwards25519_scalarmuldouble_alt']:
            obj = Path(temp) / (name + '.o')
            subprocess.run([args.cc, '-g', '-gdwarf-4', '-I' + str(root / 'include'),
                            '-I' + str(imported / 'include'), '-c',
                            str(imported / 'x86_att/curve25519' / (name + '.S')),
                            '-o', str(obj)], check=True)
            rows = subprocess.check_output([args.readelf, '-Ws', str(obj)], text=True)
            functions = {}
            for row in rows.splitlines():
                fields = row.split()
                if len(fields) == 8 and fields[3] == 'FUNC':
                    functions[fields[7]] = (int(fields[1], 16), int(fields[2]))
            start, size = functions[name]
            helpers = [value for symbol, value in functions.items() if symbol.startswith('L' + name + '_')]
            assert len(helpers) == 4, functions
            assert size > 0
            assert start + size <= min(address for address, _ in helpers), functions
            assert all(length > 0 for _, length in helpers)
            print(name, 'outer range ends before all four helpers')


if __name__ == '__main__':
    main()
