#!/usr/bin/env python3
from __future__ import annotations
from sx import Struct, Arr, parse, dump
import hashlib
from tweezer import (
    Certificate, Ticket, TitleMetadata, TitleID, ContentType,
)


class WADv0(Struct):
    header_size:      Fixed(32, uint32be)
    data_offset:      uint32be
    cert_chain_size:  uint32be
    tik_size:         uint32be
    tmd_size:         uint32be
    _unk14:           Data(12)

    cert_chain:       Sized(Arr(Certificate), self.cert_chain_size)
    tik:              Sized(Ticket, self.tik_size)
    tmd:              Sized(TitleMetadata, self.tmd_size)

    data:             Ref(Data(), self.data_offset)

    def extract_chunks(self):
        chunks = []
        n = 0

        for chunk in self.tmd.content.version_content.content_chunks:
            data_size = chunk.calc_data_size()
            chunks.append(self.data[n:n + data_size])
            n += data_size

        return chunks


class InstallWAD(Struct):
    cert_chain_size:    uint32be
    _unk04:             Fixed(0, uint32be)
    tik_size:           uint32be
    tmd_size:           uint32be
    data_size:          uint32be
    footer_size:        uint32be

    cert_chain:         AlignedTo(Sized(Arr(Certificate), self.cert_chain_size), 0x40)
    tik:                AlignedTo(Sized(Ticket, self.tik_size), 0x40)
    tmd:                AlignedTo(Sized(TitleMetadata, self.tmd_size), 0x40)
    data:               AlignedTo(Data(self.data_size), 0x40)
    footer:             AlignedTo(Data(self.footer_size), 0x40)

class BackupWAD(Struct):
    console_id:         uint32be
    savegame_count:     uint32be
    savegame_size:      uint32be
    tmd_size:           uint32be
    data_size:          uint32be
    total_size:         uint32be
    present_contents:   Data(0x40)
    title_id:           TitleID
    savegame_mac:       Data(6)
    _pad66:             Data(2)

    tmd:                AlignedTo(Sized(TitleMetadata, self.tmd_size), 0x40)

class WADv1(Struct):
    size:    uint32be
    type:    Str(length=2)
    version: uint16be
    content: Switch(selector=self.type, options={
        'ib': InstallWAD,
        'Is': InstallWAD,
        'Bk': BackupWAD,
    })


if __name__ == '__main__':
    import argparse
    import sys
    import os.path

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)

    subcommands = parser.add_subparsers()

    def do_extract(args, parser):
        if args.boot:
            wad = parse(WADv0, args.infile)
            cert_chain = wad.cert_chain
            tmd = wad.tmd
            tik = wad.tik
            data = wad.data
        else:
            wad = parse(WADv1, args.infile)
            if isinstance(wad.content, (InstallWAD, BackupWAD)):
                tmd = wad.content.tmd
            else:
                tmd = None
            if isinstance(wad.content, InstallWAD):
                cert_chain = wad.content.cert_chain
                tik = wad.content.tik
                data = wad.content.data
            else:
                cert_chain = tik = data = None

        out_prefix = os.path.join(args.outdir, os.path.basename(os.path.splitext(args.infile.name)[0]))
        if cert_chain is not None:
            with open(out_prefix + '.crt', 'wb') as f:
                dump(Arr(Certificate), cert_chain, f)
        if tmd:
            with open(out_prefix + '.tmd', 'wb') as f:
                dump(TitleMetadata, tmd, f)
        if tik:
            with open(out_prefix + '.tik', 'wb') as f:
                dump(Ticket, tik, f)
        if data is not None:
            with open(out_prefix + '.bin', 'wb') as f:
                f.write(data)

    extract_cmd = subcommands.add_parser('extract')
    extract_cmd.set_defaults(func=do_extract)
    extract_cmd.add_argument('-b', '--boot', action='store_true', help='input file is a boot2 WAD')
    extract_cmd.add_argument('infile', type=argparse.FileType('rb'))
    extract_cmd.add_argument('outdir', nargs='?', default='.')

    def do_dump(args, parser):
        if args.boot:
            wad = parse(WADv0, args.infile)
        else:
            wad = parse(WADv1, args.infile)
        print(wad)

    dump_cmd = subcommands.add_parser('dump')
    dump_cmd.set_defaults(func=do_dump)
    dump_cmd.add_argument('-b', '---boot', action='store_true', help='input file is a boot2 WAD')
    dump_cmd.add_argument('infile', type=argparse.FileType('rb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')
    sys.exit(args.func(args, parser))
