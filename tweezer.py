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
from sx import Struct, Generic as SxGeneric, Arr, Data, parse, dump, to_type


# Ref: https://wiibrew.org/wiki/Certificate_chain, https://www.3dbrew.org/wiki/Ticket

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
    Algorithm.RSA4096_SHA1:           (512 + 4, 512),
    Algorithm.RSA2048_SHA1:           (256 + 4, 256),
    Algorithm.ECDSA_SECT233R1_SHA1:   (60,      60),
    Algorithm.RSA4096_SHA256:         (512 + 4, 512),
    Algorithm.RSA2048_SHA256:         (256 + 4, 256),
    Algorithm.ECDSA_SECT233R1_SHA256: (60,      60),
}

CRYPT_ALGOS = {
    Algorithm.RSA4096_SHA1:           'rsa',
    Algorithm.RSA2048_SHA1:           'rsa',
    Algorithm.ECDSA_SECT233R1_SHA1:   'ecdsa_sect233r1',
    Algorithm.RSA4096_SHA256:         'rsa',
    Algorithm.RSA2048_SHA256:         'rsa',
    Algorithm.ECDSA_SECT233R1_SHA256: 'ecdsa_sect233r1',
}

DIGEST_ALGOS = {
    Algorithm.RSA4096_SHA1:           'sha1',
    Algorithm.RSA2048_SHA1:           'sha1',
    Algorithm.ECDSA_SECT233R1_SHA1:   'sha1',
    Algorithm.RSA4096_SHA256:         'sha256',
    Algorithm.RSA2048_SHA256:         'sha256',
    Algorithm.ECDSA_SECT233R1_SHA256: 'sha256',
}

DATA_SIZES = {
    Algorithm.RSA4096_SHA1:           512,
    Algorithm.RSA2048_SHA1:           256,
    Algorithm.ECDSA_SECT233R1_SHA1:   60,
    Algorithm.RSA4096_SHA256:         512,
    Algorithm.RSA2048_SHA256:         60,
    Algorithm.ECDSA_SECT233R1_SHA256: 60,
}

DIGEST_SIZES = {
    'sha1':   20,
    'sha256': 32,
}

DIGEST_SIG_PREFIXES = {
    # OID 1.3.14.3.2.26, 0x14-length hash
    'sha1': bytes.fromhex("""
30 21
  30 09
     06 05 2B0E03021A
     05 00
  04 14
"""),
    # OID 1.2.840.113549.1.1.11, 0x20-length hash
    'sha256': bytes.fromhex("""
30 31
  30 0D
     06 09 2A864886F70D01010B
     05 00
  04 20
"""),
}


# https://www.rfc-editor.org/rfc/rfc2313#section-8.1

def pkcs1_pad_private(data: bytes, blocksize: int) -> bytes:
    space = blocksize - (len(data) % blocksize)
    if space < 3:
        space += blocksize
    ps = b'\xff' * (space - 3)
    return b'\x00\x01' + ps + b'\x00' + data

def pkcs1_unpad_private(data: bytes) -> bytes | None:
    if len(data) < 3 or data[0] != 0 or data[1] != 1:
        return None
    data = data[2:].lstrip(b'\xff')
    if not data or data[0] != 0:
        return None
    return data[1:]

def pkcs1_pad_sig_private(data: bytes, algorithm: Algorithm) -> bytes:
    prefix = DIGEST_SIG_PREFIXES[DIGEST_ALGOS[algorithm]]
    return pkcs1_pad_private(prefix + data, DATA_SIZES[algorithm])

def pkcs1_unpad_sig_private(data: bytes, algorithm: Algorithm) -> bytes | None:
    unpadded = pkcs1_unpad_private(data)
    if not unpadded:
        return None
    prefix = DIGEST_SIG_PREFIXES[DIGEST_ALGOS[algorithm]]
    if not unpadded.startswith(prefix):
        return None
    return unpadded[len(prefix):]

def pkcs1_pad_public(data: bytes, blocksize: int) -> bytes:
    space = blocksize - (len(data) % blocksize)
    if space < 3:
        space += blocksize
    ps = b''
    while len(ps) < space - 3:
        ps += os.urandom(space - 3 - len(ps)).replace(b'\x00', b'')
    return b'\x00\x02' + ps + b'\x00' + data

def pkcs1_unpad_public(data: bytes) -> bytes | None:
    if len(data) < 3 or data[0] != 0 or data[1] != 2:
        return None
    data = data[2:]
    while data[0] != 0:
        data = data[1:]
    if not data or data[0] != 0:
        return None
    return data[1:]

def pkcs1_pad_sig_public(data: bytes, algorithm: Algorithm) -> bytes:
    return pkcs1_pad_public(data, DATA_SIZES[algorithm])

def pkcs1_unpad_sig_public(data: bytes, algorithm: Algorithm) -> bytes | None:
    return pkcs1_unpad_public(data)


class PublicKey(Struct):
    entry_type: Fixed(0, uint16be)
    algorithm:  Enum(Algorithm, uint16be)
    subject:    Sized(cstr, 64, hard=True)
    unk44:      Data(4)
    value:      Switch(selector=self.algorithm, options={
        algo: Data(KEY_SIZES[algo][0]) for algo in Algorithm
    })
    _pad48_X:   Data(52)

    @classmethod
    def generate(cls, algorithm: Algorithm, subject: str, key: Any) -> PublicKey:
        crypt_algo = CRYPT_ALGOS.get(algorithm, None)
        if crypt_algo == 'rsa':
            value = key.n.to_bytes(key.size_in_bytes(), byteorder='big') + key.e.to_bytes(4, byteorder='big')
        else:
            raise NotImplementedError('unknown crypt algorithm for {}: {}'.format(self.algorithm, crypt_algo))
        return cls(
            algorithm=algorithm,
            subject=subject,
            value=value,
        )

    def make_key(self) -> Any:
        crypt_algo = CRYPT_ALGOS.get(self.algorithm, None)
        if crypt_algo == 'rsa':
            modulus, exponent = self.value[:-4], self.value[-4:]
            return RSA.construct((int.from_bytes(modulus, byteorder='big'), int.from_bytes(exponent, byteorder='big')))
        else:
            raise NotImplementedError('unknown crypt algorithm for {}: {}'.format(self.algorithm, crypt_algo))

    def encrypt(self, data: bytes) -> bytes:
        if len(data) > len(self.value):
            raise ValueError('key of type {} cannot encrypt data larger than {} bytes (found {} bytes)'.format(
                self.algorithm.name, len(self.value), len(data),
            ))
        key = self.make_key()
        nval = bytes_to_long(data)
        ndec = key._encrypt(nval)
        return long_to_bytes(ndec, key.size_in_bytes())

    def decrypt_sig(self, data: bytes) -> bytes:
        return self.encrypt(data)

# Complete fabrication
class PrivateKey(Struct):
    public_key:  PublicKey
    value:       Switch(selector=self.public_key.algorithm, options={
        algo: Data(KEY_SIZES[algo][1]) for algo in Algorithm
    })

    @classmethod
    def generate(cls, algorithm: Algorithm, subject: str) -> PrivateKey:
        crypt_algo = CRYPT_ALGOS.get(algorithm, None)
        public_size, private_size = KEY_SIZES.get(algorithm, (0, 0))
        if crypt_algo == 'rsa':
            key = RSA.generate(private_size * 8)
            value = key.d.to_bytes(key.size_in_bytes(), byteorder='big')
        else:
            raise NotImplementedError('unknown crypt algorithm for {}: {}'.format(self.algorithm, crypt_algo))
        return cls(
            public_key=PublicKey.generate(algorithm, subject, key.public_key()),
            value=value
        )

    def make_key(self) -> RSA:
        public_key = self.public_key.make_key()
        crypt_algo = CRYPT_ALGOS.get(self.algorithm, None)
        if crypt_algo == 'rsa':
            return RSA.construct((public_key.n, public_key.e, int.from_bytes(self.value, byteorder='big')))
        else:
            raise NotImplementedError('unknown crypt algorithm for {}: {}'.format(self.algorithm, crypt_algo))

    def encrypt(self, data: bytes) -> bytes:
        return self.public_key.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) > len(self.value):
            raise ValueError('key of type {} cannot encrypt data larger than {} bytes (found {} bytes)'.format(
                self.algorithm.name, len(self.value), len(data),
            ))
        key = self.make_key()
        nval = bytes_to_long(data)
        ndec = key._decrypt(nval)
        return long_to_bytes(ndec, key.size_in_bytes())

    def encrypt_sig(self, data: bytes) -> bytes:
        return self.decrypt(data)

    def decrypt_sig(self, data: bytes) -> bytes:
        return self.public_key.decrypt_sig(data)

class Signature(Struct):
    entry_type: Fixed(1, uint16be)
    algorithm:  Enum(Algorithm, uint16be)
    value:      Switch(selector=self.algorithm, options={
        algo: Data(DATA_SIZES[algo]) for algo in Algorithm
    })
    _pad4_X:    Data(60)
    issuer:     Sized(cstr, 64, hard=True)

    def digest(self, content: bytes) -> bytes:
        digest_algo = DIGEST_ALGOS.get(self.algorithm, None)
        if digest_algo == 'sha1':
            return hashlib.sha1(self.issuer.encode('ascii').ljust(64, b'\x00') + content).digest()
        elif digest_algo == 'sha256':
            return hashlib.sha256(self.issuer.encode('ascii').ljust(64, b'\x00') + content).digest()
        else:
            raise NotImplementedError('unknown digest algorithm for {}: {}'.format(self.algorithm, digest_algo))

    def verify_key(self, root: PublicKey, chain: list[Certificate]) -> PublicKey | None:
        for i, cert in enumerate(chain):
            if not cert.verify(root, chain[:i]):
                return None
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])
        if issuer != self.issuer:
            return None
        if chain:
            key = chain[-1].content
        else:
            key = root
        if key.algorithm != self.algorithm:
            return None
        return key

    def verify(self, root: PublicKey, chain: list[Certificate], content: bytes) -> bool:
        key = self.verify_key(root, chain)
        if not key:
            return False
        raw_signature = key.decrypt_sig(self.value)
        signature = pkcs1_unpad_sig_private(raw_signature, key.algorithm)
        if not signature:
            signature = pkcs1_unpad_sig_public(raw_signature, key.algorithm)
        if not signature:
            return False
        return signature == self.digest(content)

    def verify_buggy(self, root: PublicKey, chain: list[Certificate], content: bytes) -> bool:
        key = self.verify_key(root, chain)
        if not key:
            return False
        # who needs padding, anyway?
        digest = self.digest(content)
        signature = key.decrypt_sig(self.value)[-len(digest):]
        zero_pos = signature.index(b'\x00')
        return signature[:zero_pos + 1] == digest[:zero_pos + 1]

    def calc(self, key: PrivateKey, content: bytes, public=False) -> None:
        content = self.digest(content)
        if public:
            content = pkcs1_pad_sig_public(content, key.public_key.algorithm)
        else:
            content = pkcs1_pad_sig_private(content, key.public_key.algorithm)
        self.value = key.encrypt_sig(content)

    def forge(self, key: PublicKey, content: bytes, public=False) -> None:
        assert self.is_forgeable_data(content)
        # all-zero ciphertexts decrypt to all-zero plaintexts in RSA, since (m^e mod n) = 0 if m = 0
        self.value = bytes(DATA_SIZES[key.algorithm])

    def is_forgeable_data(self, content: bytes) -> bool:
        return self.digest(content)[0] == 0

class Signed(Struct, generics={SxCT}):
    signature: Signature
    content:   SxCT

    def raw_content(self) -> bytes:
        return dump(to_type(self.content), self.content).getvalue()

    def verify(self, root: PublicKey, chain: list[Certificate]) -> bool:
        return self.signature.verify(root, chain, self.raw_content())

    def verify_buggy(self, root: PublicKey, chain: list[Certificate]) -> bool:
        return self.signature.verify_buggy(root, chain, self.raw_content())

    @classmethod
    def calc(cls, root: PublicKey, chain: list[Certificate], key: PrivateKey, content: T, public=False) -> Signed[T]:
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])
        self = cls(
            signature=Signature(algorithm=key.algorithm, value=b'', issuer=issuer),
            content=content,
         )
        self.signature.calc(key, self.content, public=public)
        assert self.verify(root, chain)
        return self

    @classmethod
    def forge(cls, root: PublicKey, chain: list[Certificate], content: T, tweakable_positions: list[int] = None, public=False) -> Signed[T]:
        issuer = '-'.join([root.subject] + [c.content.subject for c in chain])
        public_key = chain[-1].content
        signature = Signature(algorithm=public_key.algorithm, value=b'', issuer=issuer)
        forgery = cls(
            signature=signature,
            content=content,
        )
        data = forgery.raw_content()

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
                    if signature.is_forgeable_data(forged_data):
                        break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            raise ValueError('could not find data permutation that is forgeable')

        forgery.content = parse(to_type(content), forged_data)
        forgery.signature.forge(public_key, forgery.raw_content(), public=public)
        assert forgery.verify_buggy(root, chain)
        return forgery

Certificate = Signed[PublicKey]
CertificateChain = Arr(Certificate)
SignedData = Signed[Data()]


def save_public_key(basedir: str, key: PublicKey) -> None:
    with open(os.path.join(basedir, key.subject + '.pub'), 'wb') as f:
        dump(PublicKey, key, f)

def save_private_key(basedir: str, key: PrivateKey) -> None:
    with open(os.path.join(basedir, key.public_key.subject + '.key'), 'wb') as f:
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


if __name__ == '__main__':
    import argparse
    import sys
    import os.path

    parser = argparse.ArgumentParser()
    parser.set_defaults(func=None)
    parser.add_argument('-d', '--key-dir', default=os.path.expanduser('~/.wii'))
    parser.add_argument('-p', '--profile', default='retail')

    subcommands = parser.add_subparsers()

    def do_import_chains(args, parser, cert_dir):
        for infile in args.infile:
            chain = parse(CertificateChain, infile)
            save_chains(cert_dir, chain)

    import_chains_cmd = subcommands.add_parser('import-chains')
    import_chains_cmd.set_defaults(func=do_import_chains)
    import_chains_cmd.add_argument('infile', nargs='*', type=argparse.FileType('rb'))

    def do_export_chains(args, parser, cert_dir):
        certs = {}
        for chain in args.chain:
            _, chain_certs = load_chain(cert_dir, tuple(chain.split('-')))
            for cert in chain_certs:
                certs[cert.signature.issuer, cert.content.subject] = cert
        ordered_certs = [cert for key, cert in sorted(certs.items())]
        dump(CertificateChain, ordered_certs, args.outfile)

    export_chains_cmd = subcommands.add_parser('export-chains')
    export_chains_cmd.set_defaults(func=do_export_chains)
    export_chains_cmd.add_argument('outfile', type=argparse.FileType('wb'))
    export_chains_cmd.add_argument('chain', nargs='*', help='chain name')

    def do_create(args, parser, cert_dir):
        crypt_candidates = {algo for algo, value in CRYPT_ALGOS.items() if value.lower() == args.crypt_algo.lower()}
        digest_candidates = {algo for algo, value in DIGEST_ALGOS.items() if value.lower() == args.digest_algo.lower()}
        candidates = crypt_candidates & digest_candidates

        if args.size:
            size_candidates = {algo for algo, (public_size, private_size) in KEY_SIZES.items() if args.size // 8 in (public_size, private_size)}
            candidates &= size_candidates

        if not candidates:
            parser.error('could not find algorithm for given algos and size')
        if len(candidates) > 1:
            parser.error('ambiguous algorithm choice (have you specified -s/--size?): {}'.format(', '.join(c.name for c in candidates)))
        algo = next(iter(candidates))

        private_key = PrivateKey.generate(algo, args.subject)
        save_private_key(cert_dir, private_key)
        save_public_key(cert_dir, private_key.public_key)

    create_cmd = subcommands.add_parser('generate')
    create_cmd.set_defaults(func=do_create)
    create_cmd.add_argument('-c', '--crypt-algo', required=True, help='(en/de)cryption algorithm')
    create_cmd.add_argument('-d', '--digest-algo', required=True, help='digest algorithm')
    create_cmd.add_argument('-s', '--size', type=int, help='size in bits')
    create_cmd.add_argument('subject', help='public key subject')

    def do_sign(args, parser, cert_dir):
        root, chain = load_chain(cert_dir, tuple(args.key_chain.split('-')))
        if chain:
            public_key = chain[-1].content
        else:
            public_key = root
        try:
            sign_key = load_private_key(cert_dir, public_key.subject)
        except:
            if not args.forge:
                print('{}: error loading private key "{}", and -f/--forge not specified'.format(
                    parser.prog, public_key.subject
                ), file=sys.stderr)
                return 1
            sign_key = None

        data = args.infile.read()
        if sign_key:
            signed_data = SignedData.calc(root, chain, sign_key, data, public=args.public)
        else:
            signed_data = SignedData.forge(root, chain, data, args.tweakable_offset, public=args.public)
        dump(SignedData, signed_data, args.outfile)

    sign_cmd = subcommands.add_parser('sign')
    sign_cmd.set_defaults(func=do_sign)
    sign_cmd.add_argument('-k', '--key-chain', required=True, help='key chain (separated by `-`) to use for signing')
    sign_cmd.add_argument('-f', '--forge', action='store_true', help='forge signature if no private key is present')
    sign_cmd.add_argument('-P', '--public', action='store_true', default=False, help='use public key padding (type 2) instead of private key (type 1)')
    sign_cmd.add_argument('-t', '--tweakable-offset', type=int, action='append', help='input offsets that are tweakable for signature forging')
    sign_cmd.add_argument('infile', type=argparse.FileType('rb'))
    sign_cmd.add_argument('outfile', type=argparse.FileType('wb'))

    def do_verify(args, parser, cert_dir):
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
    verify_cmd.add_argument('-k', '--key-chain', help='key chain (separated by `-`) to use for verification')
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

    args = parser.parse_args()
    if not args.func:
        parser.error('must specify subcommand')

    cert_dir = os.path.join(args.key_dir, 'certs', args.profile)
    sys.exit(args.func(args, parser, cert_dir))
