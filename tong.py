from __future__ import annotations
import enum
import hashlib
from Crypto.Cipher import AES
from sx import Struct, parse, dump
from tweezer import Signed


def align_to(value, n):
    return value + (n - value % n) % n

def get_root_cert_name(profile: str) -> str:
    return 'Root'

def get_ca_cert_name(profile: str) -> str:
    return {
        'retail': 'CA00000001',
        'dev': 'CA00000002',
    }[profile]

def get_ticket_cert_name(profile: str) -> str:
    return {
        'retail': 'XS00000003',
        'dev': 'XS00000006',
    }[profile]

def get_ticket_cert_chain(profile: str) -> tuple[str]:
    return (
        get_root_cert_name(profile),
        get_ca_cert_name(profile),
        get_ticket_cert_name(profile),
    )

def get_metadata_cert_name(profile: str) -> str:
    return {
        'retail': 'CP00000004',
        'dev': 'CP00000007'
    }[profile]

def get_metadata_cert_chain(profile: str) -> tuple[str]:
    return (
        get_root_cert_name(profile),
        get_ca_cert_name(profile),
        get_metadata_cert_name(profile),
    )

def get_device_cert_name(profile: str) -> str:
    return {
        'retail': 'MS00000002',
        'dev': 'MS00000003',
    }[profile]

def get_device_cert_chain(profile: str) -> tuple[str]:
    return (
        get_root_cert_name(profile),
        get_ca_cert_name(profile),
        get_device_cert_name(profile),
    )


# Title metadata structures, ref:
# - https://wiibrew.org/wiki/TMD
# - https://www.3dbrew.org/wiki/Title_metadata
# - https://dsibrew.org/wiki/Title_metadata

class TitlePlatform(enum.Enum):
    Raw       = 0
    Wii       = 1
    DSi       = 3
    _3DS      = 4
    WiiU      = 5
    WiiOnWiiU = 7

class TitleCategoryV0(enum.Flag):
    Downloaded   = (1 << 0)
    System       = (1 << 1)
    AddOn        = (1 << 2)
    Hidden       = (1 << 3)
    ArcadeSystem = (1 << 16)
    ArcadeGame   = (1 << 18)

class TitleCategoryV1(enum.Flag):
    Downloaded         = (1 << 0)
    Demo               = (1 << 1)
    AddOn              = (1 << 2)
    Hidden             = (1 << 3)
    System             = (1 << 4)
    RequireBatchUpdate = (1 << 5)
    AutoApproved       = (1 << 6)
    AutoMounted        = (1 << 7)
    SkipConvertJumpID  = (1 << 8)
    IsConversion       = (1 << 9)

class TitleID(Struct):
    platform: Enum(TitlePlatform, uint16be)
    category: Switch(selector=self.platform, options={
        TitlePlatform.Raw:       Enum(TitlePlatform, uint16be),
        TitlePlatform.Wii:       Enum(TitleCategoryV0, uint16be),
        TitlePlatform.DSi:       Enum(TitleCategoryV1, uint16be),
        TitlePlatform._3DS:      Enum(TitleCategoryV1, uint16be),
        TitlePlatform.WiiU:      Enum(TitleCategoryV1, uint16be),
        TitlePlatform.WiiOnWiiU: Enum(TitleCategoryV0, uint16be),
    })
    id:       Data(4)

class ContentType(enum.Flag):
    Encrypted = 1
    Disc = 2
    CFM = 4
    Optional = 0x4000
    Shared = 0x8000

class TitleContentChunkV0(Struct):
    id:     uint32be
    index:  uint16be
    type:   Enum(ContentType, uint16be)
    size:   uint64be
    digest: Data(20)

    def calc_data_size(self):
        size = self.size
        if self.type & ContentType.Encrypted:
            size = align_to(size, 16)
        return size

    def update(self, content: bytes) -> bytes:
        self.size = len(content)
        self.digest = hashlib.sha1(content).digest()

class TitleContentChunkV1(Struct):
    id:     uint32be
    index:  uint16be
    type:   Enum(ContentType, uint16be)
    size:   uint64be
    digest: Data(32)

class Region(enum.Enum):
    JPN = 0
    USA = 1
    EUR = 2
    ALL = 3
    KOR = 4

class TitleMetadataV0Content(Struct):
    _unk1A:         Data(2)
    region:         Enum(Region, uint16be)
    ratings:        Data(16)
    _unk2E:         Data(12)
    ipc_perms_mask: Data(12)
    _unk46:         Data(18)
    perms:          uint32be
    title_ver:      uint16be
    content_count:  uint16be
    boot_slot:      uint16be
    _unk62:         uint16be
    content_chunks: Arr(TitleContentChunkV0, count=self.content_count)

class TitleContentInfo(Struct):
    index_offset:  uint16be
    chunk_count:   uint16be
    chunk_digest:  Data(32)

class TitleMetadataV1Content(Struct):
    save_data_size:      uint32le
    srl_save_data_size:  uint32le
    _unk22:              Data(4)
    srl_flags:           uint8
    _unk27:              Data(0x31)
    perms:               uint32be
    title_ver:           uint16be
    content_count:       uint16be
    boot_slot:           uint16be
    _unk62:              uint16be
    content_info_digest: Data(32)
    content_infos:       Arr(TitleContentInfo, count=64)
    content_chunks:      Arr(TitleContentChunkV1, count=self.content_count)

class TitleMetadataContent(Struct):
    version:         uint8
    ca_crl_version:  uint8
    crl_version:     uint8
    system_type:     uint8
    system_version:  uint64be
    title_id:        TitleID
    title_type:      uint32be
    group_id:        uint16be
    version_content: Switch(selector=self.version, options={
        0: TitleMetadataV0Content,
        1: TitleMetadataV1Content,
    })

TitleMetadata = Signed[TitleMetadataContent]


# Ticket structures; ref:
# - https://wiibrew.org/wiki/Ticket
# - https://www.3dbrew.org/wiki/Ticket

class LimitType(enum.Enum):
    NoTime = 0
    Time = 1
    NoRunCount = 3
    RunCount = 4

class TicketLimit(Struct):
    type:  Enum(LimitType, uint32be)
    value: uint32be

class TicketContent(Struct):
    ec_key:         Data(60)
    version:        uint8
    ca_crl_version: uint8
    crl_version:    uint8
    enc_title_key:  Data(16)
    _unk4F:         Data(1)
    id:             uint64be
    console_id:     uint32be
    title_id:       TitleID
    _unk65:         uint16be
    title_ver:      uint16be
    perms:          uint32be
    perm_mask:      uint32be
    exportable:     uint8
    key_slot:       uint8
    _unk72:         Data(47)
    audit:          uint8
    content_perms:  Data(64)
    _unk2E:         Data(2)
    limits:         Arr(TicketLimit, count=8)

    def calc_title_key(self, common_keys: list[bytes]) -> bytes:
        if self.console_id:
            title_key_iv = dump(uint64be, self.id).getvalue() + bytes(8)
        else:
            title_key_iv = dump(TitleID, self.title_id).getvalue() + bytes(8)
        return AES.new(common_keys[self.key_slot], AES.MODE_CBC, iv=title_key_iv).decrypt(self.enc_title_key)

    def encrypt(self, common_keys: list[bytes], metadata: TitleMetadataContent, index: int, content: bytes) -> bytes:
        title_key = self.calc_title_key(common_keys)

        chunk = metadata.version_content.content_chunks[index]
        size = chunk.calc_data_size()
        dec_data = content.ljust(size, b'\x00')

        if chunk.type & ContentType.Encrypted:
            iv = chunk.index.to_bytes(2, byteorder='big') + bytes(14)
            data = AES.new(title_key, AES.MODE_CBC, iv=iv).encrypt(dec_data)

        return data

    def decrypt(self, common_keys: list[bytes], metadata: TitleMetadataContent, index: int, content: bytes) -> bytes:
        title_key = self.calc_title_key(common_keys)

        chunk = metadata.version_content.content_chunks[index]
        size = chunk.calc_data_size()
        data = content[:size]

        if chunk.type & ContentType.Encrypted:
            iv = chunk.index.to_bytes(2, byteorder='big') + bytes(14)
            data = AES.new(title_key, AES.MODE_CBC, iv=iv).decrypt(data)[:chunk.size]

        return data

Ticket = Signed[TicketContent]


if __name__ == '__main__':
    import argparse
    import sys
    import os.path

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)
    parser.add_argument('-d', '--key-dir', default=os.path.expanduser('~/.wii'))
    parser.add_argument('-p', '--profile', default='retail')

    subcommands = parser.add_subparsers()

    def do_encrypt(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'common.key'), 'rb') as f:
            common_keys = [f.read()]

        metadata = parse(TitleMetadataContent, args.metafile)
        ticket = parse(TicketContent, args.ticketfile)
        dec_data = args.infile.read()
        args.chunkfile.write(ticket.encrypt(common_keys, metadata, args.index, dec_data))

    encrypt_cmd = subcommands.add_parser('encrypt')
    encrypt_cmd.set_defaults(func=do_encrypt)
    encrypt_cmd.add_argument('-i', '--index', type=int, default=0)
    encrypt_cmd.add_argument('metafile', type=argparse.FileType('rb'))
    encrypt_cmd.add_argument('ticketfile', type=argparse.FileType('rb'))
    encrypt_cmd.add_argument('infile', type=argparse.FileType('rb'))
    encrypt_cmd.add_argument('chunkfile', type=argparse.FileType('wb'))

    def do_decrypt(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'common.key'), 'rb') as f:
            common_keys = [f.read()]

        metadata = parse(TitleMetadataContent, args.metafile)
        ticket = parse(TicketContent, args.ticketfile)
        enc_data = args.chunkfile.read()
        args.outfile.write(ticket.decrypt(common_keys, metadata, args.index, enc_data))

    decrypt_cmd = subcommands.add_parser('decrypt')
    decrypt_cmd.set_defaults(func=do_decrypt)
    decrypt_cmd.add_argument('-i', '--index', type=int, default=0)
    decrypt_cmd.add_argument('metafile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('ticketfile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('chunkfile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    def do_update(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'common.key'), 'rb') as f:
            common_keys = [f.read()]

        metadata = parse(TitleMetadataContent, args.metafile)

        data = args.chunkfile.read()
        metadata.version_content.content_chunks[args.index].update(data)

        dump(TitleMetadataContent, metadata, args.outfile)

    update_cmd = subcommands.add_parser('update')
    update_cmd.set_defaults(func=do_update)
    update_cmd.add_argument('-i', '--index', type=int, default=0)
    update_cmd.add_argument('metafile', type=argparse.FileType('r+b'))
    update_cmd.add_argument('chunkfile', type=argparse.FileType('rb'))
    update_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')
    sys.exit(args.func(args, parser))
