#!/usr/bin/env python3
from __future__ import annotations
import os
from collections import Counter
from Crypto.Cipher import AES

from sx import Struct, Arr, uint32be, parse, dump, sizeof
from tweezer import Certificate, TitleMetadata, Ticket
from texel import WADv0


NAND_PAGE_SIZE = 2048
NAND_SPARE_SIZE = 64

nand_parity_counts = bytes(
    bin(x).count('1') for x in range(256)
)

def nand_calc_ecc(data: bytes) -> int:
    e = [[0, 0] for _ in range(3 + 9)]

    for i, x in enumerate(data):
        for j in range(9):
            e[3 + j][(i >> j) & 1] ^= x

    x = e[3][0] ^ e[3][1]
    e[0] = [x & 0b01010101, x & 0b10101010]
    e[1] = [x & 0b00110011, x & 0b11001100]
    e[2] = [x & 0b00001111, x & 0b11110000]

    pa = pb = 0
    for i, (a, b) in enumerate(e):
        pa |= (nand_parity_counts[a] & 1) << i
        pb |= (nand_parity_counts[b] & 1) << i

    return (pa | (pb << 16))

def nand_check_ecc(data: bytearray, ecc: bytes) -> bool:
    if ecc == b'\xff' * 16:
        return True

    for i in range(4):
        ecc_read = int.from_bytes(ecc[4 * i:4 * i + 4], 'little')
        ecc_calc = nand_calc_ecc(data[512 * i:512 * i + 512])
        ecc_diff = ecc_read ^ ecc_calc
        if ecc_diff:
            # ECC error, try to correct it
            if not (ecc_diff - 1) & ecc_diff:
                # single-bit ECC error
                pass
            else:
                # single-bit data error
                if False:
                    # correctable
                    pass
                else:
                    # uncorrectable
                    return False

    return True

def nand_calc_hmac(data: bytes) -> bytes:
    # TODO
    return b''

def nand_check_hmac(data: bytearray, hmac: bytes, key: bytes) -> bool:
    if hmac == b'\x00' * 48:
        return True

    return nand_calc_hmac(data, key) == hmac

def nand_check_spare(data: bytearray, spare: bytes, hmac_key: bytes = None) -> None:
    ecc = spare[48:]
    if not nand_check_ecc(data, ecc):
        return False

    if hmac_key:
        hmac = spare[:48]
        if not nand_check_hmac(data, hmac, hmac_key):
            return False

    return True

def nand_read_pages(infile, offset: int, count: int, hmac_key: bytes = None) -> bytes:
    data = bytearray(count * NAND_PAGE_SIZE)
    infile.seek(offset * (NAND_PAGE_SIZE + NAND_SPARE_SIZE), os.SEEK_SET)
    for i in range(count):
        page_data = bytearray(infile.read(NAND_PAGE_SIZE))
        page_spare = infile.read(NAND_SPARE_SIZE)
        if not nand_check_spare(page_data, page_spare, hmac_key=hmac_key):
            raise ValueError
        data[i * NAND_PAGE_SIZE:(i + 1) * NAND_PAGE_SIZE] = page_data
    return data

def nand_calc_spare(data: bytes, hmac_key: bytes = None) -> bytes:
    spare = bytearray(64)

    for i in range(4):
        ecc = nand_calc_ecc(data[512 * i:512 * i + 512])
        spare[48 + 4 * i:48 + 4 * i + 4] = ecc.to_bytes(4, 'little')

    if hmac_key:
        spare[0:48] = nand_calc_hmac(data, hmac_key)

    return spare

def nand_write_pages(outfile, offset: int, data: bytes, hmac_key: bytes = None) -> None:
    assert len(data) % NAND_PAGE_SIZE == 0

    outfile.seek(offset * (NAND_PAGE_SIZE + NAND_SPARE_SIZE), os.SEEK_SET)
    for i in range(len(data) // NAND_PAGE_SIZE):
        page_data = data[i * NAND_PAGE_SIZE:(i + 1) * NAND_PAGE_SIZE]
        page_spare = nand_calc_spare(page_data, hmac_key=hmac_key)
        outfile.write(page_data)
        outfile.write(page_spare)

NAND_BLOCK_PAGES = 64

def nand_read_blocks(infile, offset: int, count: int) -> bytes:
    return nand_read_pages(infile, offset * NAND_BLOCK_PAGES, count * NAND_BLOCK_PAGES)

def nand_write_blocks(infile, offset: int, data: bytes) -> None:
    return nand_write_pages(infile, offset * NAND_BLOCK_PAGES, data)


BOOT1_PAGE_OFFSET = 0
BOOT1_PAGE_SIZE = 47

def extract_boot1(infile, key: bytes) -> bytes:
    enc_data = nand_read_pages(infile, BOOT1_PAGE_OFFSET, BOOT1_PAGE_SIZE)
    data = AES.new(key, AES.MODE_CBC, iv=bytes(16)).decrypt(enc_data)
    return data.rstrip(b'\x00')

def insert_boot1(infile, key: bytes, data: bytes) -> None:
    data = data.ljust(BOOT1_PAGE_SIZE * NAND_PAGE_SIZE, b'\x00')
    enc_data = AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(data)
    nand_write_pages(infile, BOOT1_PAGE_OFFSET, enc_data)


class BlockMapping(Struct):
    signature:  Fixed(0x26f29a401ee684cf, uint64be)
    generation: uint32be
    blocks:     Data(64)

def extract_block_mapping(infile, block_num_hints: list[int], reverse=False) -> tuple[int | None, list[int], list[int]]:
    top_generation = -1
    top_blocks = []
    map_blocks = []

    if reverse:
        block_num_hints = block_num_hints[::-1]

    for block_num in block_num_hints:
        block = nand_read_blocks(infile, block_num, 1)
        map_data = block[-NAND_PAGE_SIZE:]
        map_size = sizeof(BlockMapping)
        mappings = []
        while map_data:
            try:
                mapping = parse(BlockMapping, map_data)
            except Exception as e:
                break
            map_data = map_data[map_size:]
            mappings.append((mapping.generation, tuple(mapping.blocks)))

        if mappings:
            map_blocks.append(block_num)
            counter = Counter(mappings)
            ((common_generation, common_blocks), best_count), = counter.most_common(1)
            if best_count > 1 and common_generation > top_generation:
                top_generation = common_generation
                top_blocks = list(common_blocks)

    if top_generation > -1:
        block_iter = enumerate(top_blocks)
        if reverse:
            block_iter = reversed(list(block_iter))
        content_blocks = [i for i, value in block_iter if value == 0]
        return (top_generation, content_blocks, map_blocks)
    else:
        return (None, [], [])

def extract_mapped_blocks(infile, block_num_hints: list[int], reversed=False):
    generation, content_blocks, map_blocks = extract_block_mapping(infile, block_num_hints, reversed)
    data = b''
    for block_num in content_blocks:
        block = nand_read_blocks(infile, block_num, 1)
        if block_num in map_blocks:
            block = block[:-NAND_PAGE_SIZE]
        data += block
    return data


BOOT2_BLOCK_NUMBERS = [1, 2, 3, 4, 5, 6, 7]

def extract_boot2(infile, backup=False) -> WADv0:
    data = extract_mapped_blocks(infile, BOOT2_BLOCK_NUMBERS, reversed=backup)
    return parse(WADv0, data)

def insert_boot2(infile, content: WADv0, backup=False) -> None:
    data = dump(WADv0, content)
    insert_mapped_blocks(infile, BOOT2_BLOCK_NUMBERS, reversed=backup)


if __name__ == '__main__':
    import argparse
    import sys
    import os.path

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)
    parser.add_argument('-d', '--key-dir', default=os.path.expanduser('~/.wii'))
    parser.add_argument('-p', '--profile', default='retail')

    subcommands = parser.add_subparsers()

    def do_extract_boot1(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'boot1.key'), 'rb') as f:
            boot1_key = f.read()
        args.boot1file.write(extract_boot1(args.nandfile, boot1_key))

    extract_boot1_cmd = subcommands.add_parser('extract-boot1')
    extract_boot1_cmd.set_defaults(func=do_extract_boot1)
    extract_boot1_cmd.add_argument('nandfile', type=argparse.FileType('rb'))
    extract_boot1_cmd.add_argument('boot1file', type=argparse.FileType('wb'))

    def do_insert_boot1(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'boot1.key'), 'rb') as f:
            boot1_key = f.read()
        insert_boot1(args.nandfile, boot1_key, args.boot1file.read())

    insert_boot1_cmd = subcommands.add_parser('insert-boot1')
    insert_boot1_cmd.set_defaults(func=do_insert_boot1)
    insert_boot1_cmd.add_argument('nandfile', type=argparse.FileType('r+b'))
    insert_boot1_cmd.add_argument('boot1file', type=argparse.FileType('rb'))

    def do_extract_boot2(args, parser):
        boot2 = extract_boot2(args.nandfile, backup=args.backup)
        prefix = os.path.basename(os.path.splitext(args.nandfile.name)[0])

        if not args.chainfile:
            args.chainfile = open(prefix + '.boot2.crt', 'wb')
        dump(Arr(Certificate), boot2.cert_chain, args.chainfile)
        if not args.metafile:
            args.metafile = open(prefix + '.boot2.tmd', 'wb')
        dump(TitleMetadata, boot2.tmd, args.metafile)
        if not args.ticketfile:
            args.ticketfile = open(prefix + '.boot2.tik', 'wb')
        dump(Ticket, boot2.tik, args.ticketfile)
        if not args.appfile:
            args.appfile = open(prefix + '.boot2.app', 'wb')
        args.appfile.write(boot2.data[:boot2.tmd.content.calc_data_size()])

    extract_boot2_cmd = subcommands.add_parser('extract-boot2')
    extract_boot2_cmd.set_defaults(func=do_extract_boot2)
    extract_boot2_cmd.add_argument('-b', '--backup', action='store_true', help='extract from backup boot2 slot')
    extract_boot2_cmd.add_argument('nandfile', type=argparse.FileType('rb'))
    extract_boot2_cmd.add_argument('chainfile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('metafile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('ticketfile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('appfile', nargs='?', type=argparse.FileType('wb'))

    def do_insert_boot2(args, parser):
        cert_chain = parse(Arr(Certificate), args.chainfile)
        tmd = parse(TitleMetadata, args.metafile)
        tik = parse(Ticket, args.ticketfile)
        app = args.appfile.read()
        boot2 = WADv0(
            cert_chain=cert_chain,
            tmd=tmd,
            tik=tik,
            data=app,
        )
        insert_boot2(args.nandfile, boot2, backup=args.backup)

    insert_boot2_cmd = subcommands.add_parser('insert-boot2')
    insert_boot2_cmd.set_defaults(func=do_insert_boot2)
    insert_boot2_cmd.add_argument('-b', '--backup', action='store_true', help='insert into backup boot2 slot')
    insert_boot2_cmd.add_argument('nandfile', type=argparse.FileType('r+b'))
    insert_boot2_cmd.add_argument('chainfile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('metafile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('ticketfile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('appfile', nargs='?', type=argparse.FileType('rb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')
    sys.exit(args.func(args, parser))
