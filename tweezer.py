#!/usr/bin/env python3
from __future__ import annotations
from typing import Any, Generic
import enum
import os
import os.path
import hashlib
import itertools

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sx import Struct, Generic as SxGeneric, Arr, Data, Nothing, parse, dump


# Crypto stuff, ref: https://wiibrew.org/wiki/Certificate_chain, https://www.3dbrew.org/wiki/Ticket

T = Generic()
SxCT = SxGeneric('SxCT')

class Algorithm(enum.Enum):
    RSA4096_SHA1           = 0x0000
    RSA2048_SHA1           = 0x0001
    ECDSA_SECT233R1_SHA1   = 0x0002
    RSA4096_SHA256         = 0x0003
    RSA2048_SHA256         = 0x0004
    ECDSA_SECT233R1_SHA256 = 0x0005

KEY_SIZES = {
    Algorithm.RSA4096_SHA1:           512 + 4,
    Algorithm.RSA2048_SHA1:           256 + 4,
    Algorithm.ECDSA_SECT233R1_SHA1:   60,
    Algorithm.RSA4096_SHA256:         512 + 4,
    Algorithm.RSA2048_SHA256:         256 + 4,
    Algorithm.ECDSA_SECT233R1_SHA256: 60,
}

DATA_SIZES = {
    Algorithm.RSA4096_SHA1:           (20, 512),
    Algorithm.RSA2048_SHA1:           (20, 256),
    Algorithm.ECDSA_SECT233R1_SHA1:   (20, 60),
    Algorithm.RSA4096_SHA256:         (32, 512),
    Algorithm.RSA2048_SHA256:         (32, 256),
    Algorithm.ECDSA_SECT233R1_SHA256: (32, 60),
}

class PublicKey(Struct):
    entry_type: Fixed(0, uint16be)
    algorithm:  Enum(Algorithm, uint16be)
    subject:    Sized(cstr, 64, hard=True)
    unk44:      Data(4)
    value:      Switch(selector=self.algorithm, options={
        algo: Data(KEY_SIZES[algo]) for algo in Algorithm
    })
    _pad48_X:   Data(52)

    def make_key(self) -> RSA:
        if self.algorithm in (Algorithm.RSA4096_SHA1, Algorithm.RSA2048_SHA1, Algorithm.RSA4096_SHA256, Algorithm.RSA2048_SHA256):
            modulus, exponent = self.value[:-4], self.value[-4:]
            return RSA.construct((int.from_bytes(modulus, byteorder='big'), int.from_bytes(exponent, byteorder='big')))
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        if len(data) > len(self.value):
            raise ValueError('key of type {} cannot encrypt data larger than {} bytes (found {} bytes)'.format(
                self.algorithm.name, len(self.value.value), len(data),
            ))
        key = self.make_key()
        return key.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) > len(self.value):
            raise ValueError('key of type {} cannot encrypt data larger than {} bytes (found {} bytes)'.format(
                self.algorithm.name, len(self.value.value), len(data),
            ))
        key = self.make_key()
        nval = bytes_to_long(data)
        ndec = key._encrypt(nval)
        return long_to_bytes(ndec, key.size_in_bytes())

class Signature(Struct):
    entry_type: Fixed(1, uint16be)
    algorithm:  Enum(Algorithm, uint16be)
    value:      Switch(selector=self.algorithm, options={
        algo: Data(DATA_SIZES[algo][1]) for algo in Algorithm
    })
    _pad4_X:    Data(60)
    issuer:     Sized(cstr, 64, hard=True)

    def digest(self, content: bytes) -> bytes:
        if self.algorithm in (Algorithm.RSA4096_SHA1, Algorithm.RSA2048_SHA1, Algorithm.ECDSA_SECT233R1_SHA1):
            return hashlib.sha1(content).digest()
        elif self.algorithm in (Algorithm.RSA4096_SHA256, Algorithm.RSA2048_SHA256, Algorithm.ECDSA_SECT233R1_SHA256):
            return hashlib.sha256(content).digest()
        else:
            raise ValueError('no known digest algorithm for {}'.format(self.algorithm))

    def verify_key(self, root: PublicKey, chain: list[Certificate]) -> bool:
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])
        return chain[-1].algorithm == self.algorithm and issuer == self.issuer

    def verify(self, root: PublicKey, chain: list[Certificate], content: bytes) -> bool:
        for i, cert in enumerate(chain):
            if not cert.verify(root, chain[:i]):
                return False
        if not self.verify_key(root, chain):
            return False
        return chain[-1].content.decrypt(self.value).startswith(content)

    def verify_buggy(self, root: PublicKey, chain: list[Certificate], content: bytes) -> bool:
        for i, cert in enumerate(chain):
            if not cert.verify_buggy(root, chain[:i]):
                return False
        if not self.verify_key(root, chain):
            return False
        return value[zero_pos] == 0 and value[:zero_pos] == content[:zero_pos]

    @classmethod
    def calc(cls, root: PublicKey, chain: list[Certificate], key: PrivateKey, content: bytes) -> Signature:
        assert key.subject == chain[-1].subject
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])

        sig = cls(
            algorithm=key.algorithm,
            value=b'',
            issuer=issuer,
        )
        sig.value = key.encrypt(sig.digest(content))
        assert sig.verify(root, chain, content)
        return sig

    @classmethod
    def forge(cls, root: PublicKey, chain: list[PublicKey], content: bytes) -> Signature:
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])
        # all-zero ciphertexts decrypt to all-zero plaintexts in RSA, since (m^e mod n) = 0 if m = 0
        value = bytes(DATA_SIZES[key.algorithm][1])
        forged_sig = cls(
            algorithm=key.algorithm,
            value=value,
            issuer=issuer,
        )
        assert forged_sig.verify_buggy(root, chain, content)
        return forged_sig

def is_forgeable_data(key: PublicKey, content: (bytes, bytearray)) -> bool:
    return Signature(algorithm=key.algorithm, value=b'').digest(content)[0] == 0

class Signed(Struct, generics={SxCT}):
    signature: Signature
    content:   SxCT

    def digest(self) -> bytes:
        data = dump(type(self.content), self.content).getvalue()
        return self.signature.digest(data)

    def verify(self, root: PublicKey, chain: list[Certificate]) -> bool:
        return self.signature.verify(root, chain, self.digest())

    def verify_buggy(self, root: PublicKey, chain: list[Certificate]) -> bool:
        return self.signature.verify_buggy(root, chain, self.digest())

    @classmethod
    def calc(cls, root: PublicKey, chain: list[Certificate], key: PrivateKey, content: T) -> Signed[T]:
         data = dump(type(content), content).getvalue()
         return cls(
            signature=Signature.calc(root, chain, key, data),
            content=data,
         )

    @classmethod
    def forge(cls, root: PublicKey, chain: list[Certificate], content: T, tweakable_positions: list[int] = None) -> Signed[T]:
        data = dump(type(content), content).getvalue()
        public_key = chain[-1].content
        if tweakable_positions is None:
            tweakable_positions = [len(data) + i for i in range(256)]

        # create forged data
        for i in range(len(tweakable_positions)):
            for positions in itertools.permutations(tweakable_positions, i):
                forged_data = bytearray(data)
                for pos in positions:
                    if len(forged_data) <= pos:
                        forged_data.extend(b'\x00' * (pos - len(forged_data) + 1))
                for values in itertools.product(*(range(256) for _ in range(len(positions)))):
                    for (pos, val) in zip(positions, values):
                        forged_data[pos] = val
                    if is_forgeable_data(public_key, forged_data):
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            raise ValueError('could not find data permutation that is forgeable')

        forgery = cls(
            signature=Signature(algorithm=public_key.algorithm, value=b''),
            content=parse(type(content), forged_data),
        )
        forgery.signature = Signature.forge(root, chain, forgery.digest())
        return forgery

Certificate = Signed[PublicKey]
SignedData = Signed[Data()]

def align_to(value, n):
    return value + (n - value % n) % n

def save_public_key(basedir: str, key: PublicKey) -> None:
    with open(os.path.join(basedir, key.subject + '.pub'), 'wb') as f:
        dump(PublicKey, key, f)

def save_private_key(basedir: str, key: PrivateKey) -> None:
    with open(os.path.join(basedir, key.subject + '.key'), 'wb') as f:
        dump(PrivateKey, key, f)

def save_sig(basedir: str, name: str, sig: Signature) -> None:
    with open(os.path.join(basedir, sig.issuer + '-' + name + '.sig'), 'wb') as f:
        dump(Signature, sig, f)

def save_cert(basedir: str, cert: Certificate) -> None:
    save_public_key(basedir, cert.content)
    save_sig(basedir, cert.content.subject, cert.signature)

def save_chains(basedir: str, chain: list[Certificate]) -> None:
    avail = {('Root',)}
    for c in chain:
        issuer = tuple(c.signature.issuer.split('-'))
        assert issuer in avail
        save_cert(basedir, c)
        subject = issuer + (c.content.subject,)
        avail.add(subject)

def load_public_key(basedir: str, name: str) -> PublicKey:
    with open(os.path.join(basedir, name + '.pub'), 'rb') as f:
        return parse(PublicKey, f)

def load_private_key(basedir: str, name: str) -> PrivateKey:
    with open(os.path.join(basedir, name + '.key'), 'rb') as f:
        return parse(PrivateKey, f)

def load_sig(basedir: str, name: str, issuer: str) -> Signature:
    with open(os.path.join(basedir, issuer + '-' + name + '.sig'), 'rb') as f:
        return parse(Signature, f)

def load_cert(basedir: str, issuer: tuple[str, ...], subject: str) -> Certificate:
    key = load_public_key(basedir, subject)
    sig = load_sig(basedir, subject, '-'.join(issuer))
    return Certificate(
        signature=sig,
        content=key,
    )

def load_chain(basedir: str, names: tuple[str, ...]) -> tuple[PublicKey, list[Certificate]]:
    root = load_public_key(basedir, names[0])
    chain = []
    for i, name in enumerate(names[1:], start=1):
        chain.append(load_cert(basedir, names[:i], name))
    return root, chain

def load_chains(basedir: str, names: list[tuple[str, ...], str]) -> list[Certificate]:
    loaded = set()
    chain = []
    for name in names:
        _, certs = load_chain(basedir, name)
        for c in certs:
            issuer = tuple(c.signature.issuer.split('-'))
            if (issuer, c.content.subject) in loaded:
                continue
            chain.append(c)
            loaded.add((issuer, c.content.subject))
    return chain

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

    def calc_data_size(self):
        size = 0
        for chunk in self.version_content.content_chunks:
            size += chunk.calc_data_size()
        return size

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

    def decrypt(self, common_keys: list[bytes], metadata: TitleMetadataContent, content: bytes) -> bytes:
        title_key = self.calc_title_key(common_keys)

        data = b''
        n = 0
        for chunk in metadata.version_content.content_chunks:
            chunk_size = chunk.calc_data_size()
            chunk_data = content[n:n + chunk_size]
            n += chunk_size

            if chunk.type & ContentType.Encrypted:
                iv = chunk.index.to_bytes(2, byteorder='big') + bytes(14)
                chunk_data = AES.new(title_key, AES.MODE_CBC, iv=iv).decrypt(chunk_data)[:chunk.size]
            data += chunk_data

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

    def do_import(args, parser):
        cert_dir = os.path.join(args.key_dir, 'certs', args.profile)
        chain = parse(Arr(Certificate), args.infile)
        save_chains(cert_dir, chain)

    import_cmd = subcommands.add_parser('import')
    import_cmd.set_defaults(func=do_import)
    import_cmd.add_argument('infile', type=argparse.FileType('rb'))

    def do_sign(args, parser):
        cert_dir = os.path.join(args.key_dir, 'certs', args.profile)
        root, chain = load_chain(cert_dir, tuple(args.key_chain.split('-')))
        try:
            sign_key = load_private_key(cert_dir, chain[-1].content.subject)
        except:
            if not args.forge:
                print('{}: error loading private key "{}", and -f/--forge not specified'.format(
                    parser.prog, sign_pub_key.subject
                ), file=sys.stderr)
                return 1
            sign_key = None

        data = args.infile.read()
        if sign_key:
            signed_data = SignedData.calc(root, chain, sign_key, data)
        else:
            signed_data = SignedData.forge(root, chain, data, args.tweakable_offset)
        dump(SignedData, signed_data, args.outfile)

    sign_cmd = subcommands.add_parser('sign')
    sign_cmd.set_defaults(func=do_sign)
    sign_cmd.add_argument('-k', '--key-chain', required=True, help='key chain (separated by `-`) to use for signing')
    sign_cmd.add_argument('-f', '--forge', action='store_true', help='forge signature if no private key is present')
    sign_cmd.add_argument('-t', '--tweakable-offset', type=int, action='append', help='input offsets that are tweakable for signature forging')
    sign_cmd.add_argument('infile', type=argparse.FileType('rb'))
    sign_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    def do_verify(args, parser):
        cert_dir = os.path.join(args.key_dir, 'certs', args.profile)

        signed_data = parse(SignedData, args.infile)
        if args.key_chain and args.key_chain != signed_data.signature.issuer:
            sys.exit(1)
        root, chain = load_chain(cert_dir, tuple(signed_data.signature.issuer.split('-')))

        if not signed_data.verify(root, chain):
            if not args.forged:
                sys.exit(1)
            if not signed_data.verify_buggy(root, chain):
                sys.exit(1)

        if args.outfile:
            args.outfile.write(signed_data.content)

    verify_cmd = subcommands.add_parser('verify')
    verify_cmd.set_defaults(func=do_verify)
    verify_cmd.add_argument('-k', '--key-chain', required=True, help='key chain (separated by `-`) to use for verification')
    verify_cmd.add_argument('-f', '--forged', action='store_true', help='allow forged signature if signature does not verify otherwise')
    verify_cmd.add_argument('infile', type=argparse.FileType('rb'))
    verify_cmd.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))

    def do_extract(args, parser):
        signed_data = parse(SignedData, args.infile)
        args.outfile.write(signed_data.content)

    extract_cmd = subcommands.add_parser('extract')
    extract_cmd.set_defaults(func=do_extract)
    extract_cmd.add_argument('infile', type=argparse.FileType('rb'))
    extract_cmd.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))

    def do_decrypt(args, parser):
        key_dir = os.path.join(args.key_dir, 'keys', args.profile)
        with open(os.path.join(key_dir, 'common.key'), 'rb') as f:
            common_keys = [f.read()]

        try:
            metadata = parse(TitleMetadata, args.metafile).content
        except:
            args.metafile.seek(0, os.SEEK_SET)
            metadata = parse(TitleMetadataContent, args.metafile).content
        try:
            ticket = parse(Ticket, args.ticketfile).content
        except:
            args.ticketfile.seek(0, os.SEEK_SET)
            ticket = parse(TicketContent, args.ticketfile)
        enc_data = args.appfile.read()
        args.outfile.write(ticket.decrypt(common_keys, metadata, enc_data))

    decrypt_cmd = subcommands.add_parser('decrypt')
    decrypt_cmd.set_defaults(func=do_decrypt)
    decrypt_cmd.add_argument('metafile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('ticketfile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('appfile', type=argparse.FileType('rb'))
    decrypt_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')
    sys.exit(args.func(args, parser))
