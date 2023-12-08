#!/usr/bin/env python3
from __future__ import annotations
import os
from collections import Counter
from Crypto.Cipher import AES

from sx import Struct, parse, dump, sizeof
from texel import WADv0


NAND_PAGE_SIZE = 2048
NAND_SPARE_SIZE = 64

nand_parity_counts = bytes(
    bin(x).count('1') for x in range(256)
)

def nand_calc_ecc(data: bytes) -> tuple[int, int]:
    # these orders are NOT, in fact, rabbits
    bit_order = 3
    byte_order = (len(data) - 1).bit_length()

    e = [[0, 0] for _ in range(bit_order + byte_order)]

    for pos, x in enumerate(data):
        for i in range(byte_order):
            e[bit_order + i][(pos >> i) & 1] ^= x

    x = e[bit_order][0] ^ e[bit_order][1]
    e[0] = [x & 0b01010101, x & 0b10101010]
    e[1] = [x & 0b00110011, x & 0b11001100]
    e[2] = [x & 0b00001111, x & 0b11110000]

    peven = podd = 0
    for i, (even, odd) in enumerate(e):
        peven |= (nand_parity_counts[even] & 1) << i
        podd |= (nand_parity_counts[odd] & 1) << i

    return peven, podd

def nand_check_ecc(data: bytearray, ecc: bytes) -> bool:
    if ecc == b'\xff' * 16:
        return True

    for i in range(4):
        data_chunk = data[512 * i:512 * i + 512]
        ecc_chunk = ecc[4 * i:4 * i + 4]

        ecc_diff_even, ecc_diff_odd = nand_calc_ecc(data_chunk)
        ecc_diff_even ^= int.from_bytes(ecc_chunk[0:2], 'little')
        ecc_diff_odd ^= int.from_bytes(ecc_chunk[2:4], 'little')
        if ecc_diff_even or ecc_diff_odd:
            # ECC error, try to correct it
            if ecc_diff_even.bit_count() + ecc_diff_odd.bit_count() == 1:
                # single-bit checksum error: correctable
                print('ecc:', 'ignored checksum error')
            elif ecc_diff_even ^ ecc_diff_odd == 0xFFF:
                # single-bit data error: correctable
                bit_pos = ecc_diff_odd & 0b111
                byte_pos = ecc_diff_odd >> 3
                data[byte_pos] ^= 1 << bit_pos
                print('ecc:', 'corrected data error')
            else:
                # uncorrectable data error
                print('ecc:', 'uncorrectable data error')
                return False

    return True

def nand_calc_hmac(data: bytes, key: bytes) -> bytes:
    # TODO
    return bytes(48)

def nand_check_hmac(data: bytearray, hmac: bytes, key: bytes) -> bool:
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
            raise ValueError('incorrect spare data on NAND page {}'.format(offset + i))
        data[i * NAND_PAGE_SIZE:(i + 1) * NAND_PAGE_SIZE] = page_data
    return data

def nand_calc_spare(data: bytes, hmac_key: bytes = None) -> bytes:
    spare = bytearray(64)

    for i in range(4):
        ecc_even, ecc_odd = nand_calc_ecc(data[512 * i:512 * i + 512])
        spare[48 + 4 * i:48 + 4 * i + 4] = ecc_even.to_bytes(2, 'little') + ecc_odd.to_bytes(2, 'little')

    if hmac_key:
        spare[0:48] = nand_calc_hmac(data, hmac_key)
    else:
        spare[0] = 0xFF

    return spare

def nand_write_pages(outfile, offset: int, data: bytes, hmac_key: bytes = None) -> None:
    assert len(data) % NAND_PAGE_SIZE == 0

    outfile.seek(offset * (NAND_PAGE_SIZE + NAND_SPARE_SIZE), os.SEEK_SET)
    for i in range(len(data) // NAND_PAGE_SIZE):
        page_data = data[i * NAND_PAGE_SIZE:(i + 1) * NAND_PAGE_SIZE]
        page_spare = nand_calc_spare(page_data, hmac_key=hmac_key)
        outfile.write(page_data)
        outfile.write(page_spare)

def nand_check_pages(infile, hmac_key: bytes = None):
    i = 1
    while True:
        page_data = bytearray(infile.read(NAND_PAGE_SIZE))
        if not page_data:
            break
        page_spare = infile.read(NAND_SPARE_SIZE)
        yield (i, nand_check_spare(page_data, page_spare, hmac_key=hmac_key))
        i += 1


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

def insert_mapped_blocks(outfile, block_num_hints: list[int], data: bytes, reversed=False) -> None:
    generation, content_blocks, map_blocks = extract_block_mapping(outfile, block_num_hints, reversed)
    n = 0
    for block_num in content_blocks:
        block_pages = NAND_BLOCK_PAGES
        if block_num in map_blocks:
            block_pages -= 1
        block_size = block_pages * NAND_PAGE_SIZE
        chunk = data[n:n + block_size].ljust(block_size, b'\x00')
        n += block_size
        nand_write_blocks(outfile, block_num, chunk)
        if n >= len(data):
            break


BOOT2_BLOCK_NUMBERS = [1, 2, 3, 4, 5, 6, 7]

def extract_boot2(infile, backup=False) -> WADv0:
    data = extract_mapped_blocks(infile, BOOT2_BLOCK_NUMBERS, reversed=backup)
    return parse(WADv0, data)

def insert_boot2(outfile, content: WADv0, backup=False) -> None:
    data = dump(WADv0, content).getvalue()
    insert_mapped_blocks(outfile, BOOT2_BLOCK_NUMBERS, data, reversed=backup)


if __name__ == '__main__':
    import argparse
    import sys
    import os.path
    from tweezer import CertificateChain, Signed
    from tong import TitleMetadata, Ticket

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)
    parser.add_argument('-d', '--key-dir', default=os.path.expanduser('~/.wii'))
    parser.add_argument('-p', '--profile', default='retail')

    subcommands = parser.add_subparsers()

    def do_verify(args, parser, key_dir):
        bad_pages = []
        for (page_no, check) in nand_check_pages(args.nandfile):
            if not check:
                bad_pages.append(page_no)
            sys.stderr.write('\rchecking page {}...'.format(page_no))
            if bad_pages:
                sys.stderr.write(' [bad: {}]'.format(', '.join(str(x) for x in bad_pages)))

        sys.stderr.write('\rchecked all pages!        ')
        if bad_pages:
            sys.stderr.write('[bad: {}]\n'.format(', '.join(str(x) for x in bad_pages)))
        else:
            sys.stderr.write('[no bad pages]\n')

    verify_cmd = subcommands.add_parser('verify')
    verify_cmd.set_defaults(func=do_verify)
    verify_cmd.add_argument('nandfile', type=argparse.FileType('rb'))

    def do_extract_boot1(args, parser, key_dir):
        with open(os.path.join(key_dir, 'boot1.key'), 'rb') as f:
            boot1_key = f.read()
        args.boot1file.write(extract_boot1(args.nandfile, boot1_key))

    extract_boot1_cmd = subcommands.add_parser('extract-boot1')
    extract_boot1_cmd.set_defaults(func=do_extract_boot1)
    extract_boot1_cmd.add_argument('nandfile', type=argparse.FileType('rb'))
    extract_boot1_cmd.add_argument('boot1file', type=argparse.FileType('wb'))

    def do_insert_boot1(args, parser, key_dir):
        with open(os.path.join(key_dir, 'boot1.key'), 'rb') as f:
            boot1_key = f.read()
        insert_boot1(args.nandfile, boot1_key, args.boot1file.read())

    insert_boot1_cmd = subcommands.add_parser('insert-boot1')
    insert_boot1_cmd.set_defaults(func=do_insert_boot1)
    insert_boot1_cmd.add_argument('nandfile', type=argparse.FileType('r+b'))
    insert_boot1_cmd.add_argument('boot1file', type=argparse.FileType('rb'))

    def do_extract_boot2(args, parser, key_dir):
        boot2 = extract_boot2(args.nandfile, backup=args.backup)
        prefix = os.path.basename(os.path.splitext(args.nandfile.name)[0])
        chunks = boot2.extract_chunks()
        for i in range(len(args.chunkfiles), len(chunks)):
            args.chunkfiles.append(open(prefix + '.boot2.{}.bin'.format(i), 'wb'))

        if not args.chainfile:
            args.chainfile = open(prefix + '.boot2.crt', 'wb')
        dump(CertificateChain, boot2.cert_chain, args.chainfile)
        if not args.metafile:
            args.metafile = open(prefix + '.boot2.tmd', 'wb')
        dump(Signed[TitleMetadata], boot2.tmd, args.metafile)
        if not args.ticketfile:
            args.ticketfile = open(prefix + '.boot2.tik', 'wb')
        dump(Signed[Ticket], boot2.tik, args.ticketfile)
        for (chunk, chunkfile) in zip(chunks, args.chunkfiles):
            chunkfile.write(chunk)

    extract_boot2_cmd = subcommands.add_parser('extract-boot2')
    extract_boot2_cmd.set_defaults(func=do_extract_boot2)
    extract_boot2_cmd.add_argument('-b', '--backup', action='store_true', help='extract from backup boot2 slot')
    extract_boot2_cmd.add_argument('nandfile', type=argparse.FileType('rb'))
    extract_boot2_cmd.add_argument('chainfile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('metafile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('ticketfile', nargs='?', type=argparse.FileType('wb'))
    extract_boot2_cmd.add_argument('chunkfiles', nargs='*', type=argparse.FileType('wb'))

    def do_insert_boot2(args, parser, key_dir):
        cert_chain = parse(CertificateChain, args.chainfile)
        tmd = parse(Signed[TitleMetadata], args.metafile)
        tik = parse(Signed[Ticket], args.ticketfile)
        data = b''
        for chunk in args.chunkfiles:
            data += chunk.read()
        boot2 = WADv0(
            cert_chain=cert_chain,
            tmd=tmd,
            tik=tik,
            data=data,
        )
        insert_boot2(args.nandfile, boot2, backup=args.backup)

    insert_boot2_cmd = subcommands.add_parser('insert-boot2')
    insert_boot2_cmd.set_defaults(func=do_insert_boot2)
    insert_boot2_cmd.add_argument('-b', '--backup', action='store_true', help='insert into backup boot2 slot')
    insert_boot2_cmd.add_argument('nandfile', type=argparse.FileType('r+b'))
    insert_boot2_cmd.add_argument('chainfile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('metafile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('ticketfile', nargs='?', type=argparse.FileType('rb'))
    insert_boot2_cmd.add_argument('chunkfiles', nargs='*', type=argparse.FileType('rb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')

    key_dir = os.path.join(args.key_dir, 'keys', args.profile)
    sys.exit(args.func(args, parser, key_dir))
