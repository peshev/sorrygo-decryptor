#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
from typing import Iterable, Callable, BinaryIO, Tuple, Optional, Union

import tqdm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = {
    0x66: "java",
    0xFF: "csharp",
    0x99: "golang",
    0x11: "rust",
}


def read_var_length_block(f: BinaryIO, header: bool = False) -> Optional[bytes]:
    block_type = "header" if header else "block"
    length_bytes = f.read(4)
    if len(length_bytes) == 0 and not header:
        # clean EOF while trying to read the length of a new block is ok (although in practice, all files end with a zero-length block, so this should never happen)
        return None
    if len(length_bytes) != 4:
        # EOF while trying to read the header length, or some garbage at the end of the file is not ok
        raise ValueError(
            f"Expected to read 4 bytes (length), actually read {len(length_bytes)} bytes while reading {block_type}")

    length = int.from_bytes(length_bytes)
    if (length == 0 and header) or length > 0x10010:
        raise ValueError(f"Unexpected {block_type.capitalize()} length: {length}")

    data = f.read(length)
    if len(data) != length:
        raise ValueError(
            f"Expected to read {length} bytes (data), actually read {len(data)} bytes while reading {block_type}")

    return data


def read_fixed_length_block(f: BinaryIO, length: int) -> Optional[bytes]:
    if length == 0:
        return b""
    data = f.read(length)
    if len(data) == 0:
        return None
    return data


def read_blocks(f: BinaryIO, read_block_fn: Callable[[BinaryIO], Optional[bytes]]) -> Iterable[bytes]:
    while True:
        block = read_block_fn(f)
        if block is None:
            return
        yield block


def decrypt_aes_gcm_blocks(key, blocks: Iterable[bytes]) -> Iterable[bytes]:
    aes_gcm = AESGCM(key)
    chunk_index = 0

    for block in blocks:
        if len(block) > 0:
            yield aes_gcm.decrypt(chunk_index.to_bytes(12), block, None)
        chunk_index += 1


def decrypt_aes_cfb_blocks(key, iv, blocks: Iterable[bytes]) -> Iterable[bytes]:
    aes_cfb = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = aes_cfb.decryptor()

    for block in blocks:
        yield decryptor.update(block)
    yield decryptor.finalize()


def write_blocks(path: str, blocks: Iterable[bytes]):
    with open(path, "wb") as f:
        for block in blocks:
            f.write(block)


def decrypt_rsa_header(private_key: RSAPrivateKey, enc_header: bytes) -> bytes:
    key_size = private_key.key_size // 8
    if len(enc_header) % key_size != 0:
        raise ValueError(
            "RSA header size is not a multiple of the private key size: "
            f"header={len(enc_header)} bytes, key={key_size} bytes"
        )
    return b"".join(
        private_key.decrypt(enc_header[offset: offset + key_size], padding.PKCS1v15())
        for offset in
        range(0, len(enc_header), key_size)
    )


def decrypt_to_file(enc_path: str, private_key: RSAPrivateKey, out_path: Optional[str]= None) -> str:
    if out_path is None:
        out_path = default_output_path(enc_path)
    if os.path.exists(out_path):
        raise FileExistsError(f"Decrypted file {out_path} exists. Not decrypting.")
    write_blocks(out_path, decrypt_file(enc_path, private_key))
    return out_path


def decrypt_file(enc_path: str, private_key: RSAPrivateKey) -> Iterable[bytes]:
    with open(enc_path, "rb") as f:
        magic_byte = f.read(1)
        if len(magic_byte) != 1:
            raise ValueError(f"Encrypted file {enc_path} is empty")

        fmt = MAGIC.get(magic_byte[0], "unknown")
        if fmt == "unknown":
            raise ValueError(f"Unknown magic byte: 0x{magic_byte:02x}")

        _ = read_var_length_block(f, header=True)  # TODO: What's in this first header?

        encrypted_header = read_var_length_block(f, header=True)
        assert encrypted_header is not None
        header = decrypt_rsa_header(private_key, encrypted_header)

        if fmt == "java" and len(header) == 0x20:
            return decrypt_aes_cfb_blocks(
                header[16:32], header[:16],
                read_blocks(f, lambda fp: read_fixed_length_block(fp, 64 * 1024)))
        elif fmt in ("golang", "csharp", "rust") and len(header) >= 0x20:
            return decrypt_aes_gcm_blocks(
                header[:32],
                read_blocks(f, read_var_length_block))
        else:
            raise ValueError(f"Unknown decrypt format {fmt} or incorrect header length ({len(header)} bytes)")


def default_output_path(path: str, strip_suffix: str = ".sorry") -> str:
    if path.endswith(strip_suffix):
        return path[:-len(strip_suffix)]
    return path + ".dec"


def load_private_key(path, password: Optional[Union[str,bytes]]= None) -> RSAPrivateKey:
    if isinstance(password, str):
        password = password.encode()
    private_key = serialization.load_pem_private_key(Path(path).read_bytes(), password=password)
    assert isinstance(private_key, RSAPrivateKey)
    return private_key


def find_encrypted_files(dir_path: str, output_dir_path: str = None, extension: str = ".sorry") \
        -> Iterable[Tuple[str, str]]:
    for root, dirs, files in os.walk(dir_path):
        if output_dir_path is not None:
            output_path = os.path.join(output_dir_path, os.path.relpath(root, dir_path))
        else:
            output_path = root
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(extension):
                yield file_path, default_output_path(os.path.join(output_path, file), extension)


def main():
    parser = argparse.ArgumentParser(description="Decrypt .sorry files")
    parser.add_argument("encrypted_file")
    parser.add_argument("-k", "--key", default="private.pem", help="private key PEM path")
    parser.add_argument("-o", "--output", help="output path")
    parser.add_argument("--password", help="private key passphrase")
    args = parser.parse_args()

    private_key = load_private_key(args.key, password=args.password)

    if os.path.isdir(args.encrypted_file):
        if args.output is not None:
            if os.path.exists(args.output) and not os.path.isdir(args.output):
                raise ValueError(f"{args.output} exists but it's not a directory")
            else:
                os.makedirs(args.output)
        encrypted_files = list(tqdm.tqdm(find_encrypted_files(args.encrypted_file, args.output),
                                         desc=f"Finding encrypted files in {args.encrypted_file}"))
        for encrypted_file, output_path in tqdm.tqdm(encrypted_files, desc="Decrypting files"):
            try:
                decrypt_to_file(encrypted_file, private_key, output_path)
                print(f"Wrote decrypted file to {output_path}")
            except FileExistsError as e:
                print(e.args[0])
    elif os.path.isfile(args.encrypted_file):
        try:
            output_file_path = decrypt_to_file(args.encrypted_file, private_key, args.output)
            print(f"Wrote decrypted file to {output_file_path}")
        except FileExistsError as e:
            print(e.args[0])


if __name__ == "__main__":
    main()
