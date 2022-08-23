#!/usr/bin/env python3
from __future__ import annotations

from sx import Struct, parse, dump


class Boot2(Struct):
    header_size:  Fixed(16, uint32be)
    loader_size:  uint32be
    payload_size: uint32be
    unk0C:        uint32be

    loader:       Data(self.loader_size)
    payload:      Data(self.payload_size)


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)

    subcommands = parser.add_subparsers()

    def do_pack(args, parser):
        boot2 = Boot2(
            loader=args.loader.read(),
            payload=args.payload.read(),
        )
        dump(Boot2, boot2, args.outfile)

    pack_cmd = subcommands.add_parser('pack')
    pack_cmd.set_defaults(func=do_pack)
    pack_cmd.add_argument('loader', type=argparse.FileType('rb'))
    pack_cmd.add_argument('payload', type=argparse.FileType('rb'))
    pack_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    def do_unpack(args, parser):
        boot2 = parse(Boot2, args.infile)
        args.loader.write(boot2.loader)
        args.payload.write(boot2.payload)

    unpack_cmd = subcommands.add_parser('unpack')
    unpack_cmd.set_defaults(func=do_unpack)
    unpack_cmd.add_argument('infile', type=argparse.FileType('rb'))
    unpack_cmd.add_argument('loader', type=argparse.FileType('wb'))
    unpack_cmd.add_argument('payload', type=argparse.FileType('wb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')
    sys.exit(args.func(args, parser))
