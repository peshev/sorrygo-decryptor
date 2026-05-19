#!/usr/bin/env python3

import argparse
import concurrent
import os
import urllib
from asyncio import as_completed
from concurrent.futures import ThreadPoolExecutor
from io import SEEK_CUR, SEEK_SET
from pathlib import Path
from typing import Iterable, Callable, BinaryIO, Tuple, Optional, Union
import urllib.parse

import boto3
from botocore.exceptions import ClientError
from smart_open import open

import tqdm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import multitqdm
from multitqdm import ProgressBar, ProgressBarExecutor

MAGIC = {
    0x66: "java",
    0xFF: "csharp",
    0x99: "golang",
    0x11: "rust",
}


def get_aes_gcm_ciphertext_size(f: BinaryIO) -> int:
    restore_pos = f.tell()
    plaintext_size = 0
    while True:
        length_bytes = f.read(4)
        if len(length_bytes) == 0:
            break
        if len(length_bytes) != 4:
            raise ValueError(
                f"Expected to read 4 bytes (length), actually read {len(length_bytes)} bytes while calculating plaintext size")

        length = int.from_bytes(length_bytes, "big")
        if length > 0x10010:
            raise ValueError(f"Unexpected block length: {length}")
        if length == 0:
            break

        plaintext_size += length
        f.seek(length, SEEK_CUR)

    f.seek(restore_pos, SEEK_SET)
    return plaintext_size


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

    length = int.from_bytes(length_bytes, "big")
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
            yield aes_gcm.decrypt(chunk_index.to_bytes(12, "big"), block, None)
        chunk_index += 1


def decrypt_aes_cfb_blocks(key, iv, blocks: Iterable[bytes]) -> Iterable[bytes]:
    aes_cfb = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = aes_cfb.decryptor()

    for block in blocks:
        yield decryptor.update(block)
    yield decryptor.finalize()


def progress_blocks(progressbar: ProgressBar, blocks: Iterable[bytes]) -> Iterable[bytes]:
    for block in blocks:
        progressbar.progress(len(block))
        yield block


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


def decrypt_to_file(progressbar: ProgressBar, enc_path: str, private_key: RSAPrivateKey, out_path: str):
    write_blocks(out_path, decrypt_file(progressbar, enc_path, private_key))


def read_header(f):
    magic_byte = f.read(1)
    if len(magic_byte) != 1:
        raise ValueError(f"Encrypted file is empty")

    fmt = MAGIC.get(magic_byte[0], "unknown")
    if fmt == "unknown":
        raise ValueError(f"Unknown magic byte: 0x{magic_byte:02x}")

    _ = read_var_length_block(f, header=True)  # TODO: What's in this first header?

    encrypted_header = read_var_length_block(f, header=True)
    assert encrypted_header is not None
    return fmt, encrypted_header


def decrypt_file(progressbar: ProgressBar, enc_path: str, private_key: RSAPrivateKey) -> Iterable[
    bytes]:
    with open(enc_path, "rb") as f:
        fmt, encrypted_header = read_header(f)
        header = decrypt_rsa_header(private_key, encrypted_header)

        if fmt == "java" and len(header) == 0x20:
            yield from decrypt_aes_cfb_blocks(
                header[16:32], header[:16],
                read_blocks(f, lambda fp: read_fixed_length_block(fp, 64 * 1024)))
        elif fmt in ("golang", "csharp", "rust") and len(header) >= 0x20:
            plaintext_size = get_aes_gcm_ciphertext_size(f)
            progressbar.start(desc=enc_path, total=plaintext_size, unit="B", unit_scale=True)
            yield from decrypt_aes_gcm_blocks(header[:32],
                                              progress_blocks(progressbar,
                                                              read_blocks(f, read_var_length_block)))
            progressbar.complete()
        else:
            raise ValueError(f"Unknown decrypt format {fmt} or incorrect header length ({len(header)} bytes)")


def default_output_path(path: str, strip_suffix: str = ".sorry") -> str:
    if path.endswith(strip_suffix):
        return path[:-len(strip_suffix)]
    return path + ".dec"


def load_private_key(path, password: Optional[Union[str, bytes]] = None) -> RSAPrivateKey:
    if isinstance(password, str):
        password = password.encode()
    private_key = serialization.load_pem_private_key(Path(path).read_bytes(), password=password)
    assert isinstance(private_key, RSAPrivateKey)
    return private_key


def find_encrypted_files(dir_path: str, output_dir_path: str = None, extension: str = ".sorry") \
        -> Iterable[Tuple[str, str]]:
    for root, dirs, files in os.walk(dir_path):
        if output_dir_path is not None:
            relpath = os.path.relpath(root, dir_path)
            if relpath != ".":
                output_path = os.path.join(output_dir_path, relpath)
            else:
                output_path = output_dir_path
        else:
            output_path = root
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith(extension):
                yield file_path, default_output_path(os.path.join(output_path, file), extension)


class FilesystemInterface(object):
    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def isfile(self, path: str) -> bool:
        raise NotImplementedError

    def isdir(self, path: str) -> bool:
        raise NotImplementedError

    def makedirs(self, path: str, exists_ok: bool = True) -> None:
        raise NotImplementedError


class LocalFilesystemInterface(FilesystemInterface):

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def isfile(self, path: str) -> bool:
        return os.path.isfile(path)

    def isdir(self, path: str) -> bool:
        return os.path.isdir(path)

    def makedirs(self, path: str, exist_ok: bool = True) -> None:
        os.makedirs(path, exist_ok)


class S3FilesystemInterface(FilesystemInterface):
    def __init__(self):
        self.client = boto3.client("s3")

    def exists(self, path: str) -> bool:
        parsed = urllib.parse.urlparse(path)
        assert parsed.scheme == "s3"
        return bool(self.client.list_objects_v2(Bucket=parsed.hostname, Prefix=parsed.path.lstrip("/")).get("Contents"))

    def isfile(self, path: str) -> bool:
        parsed = urllib.parse.urlparse(path)
        assert parsed.scheme == "s3"
        try:
            self.client.head_object(Bucket=parsed.hostname, Key=parsed.path.lstrip("/"))
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            else:
                raise e

    def isdir(self, path: str) -> bool:
        return self.exists(path) and not self.isfile(path)

    def makedirs(self, path: str, exists_ok: bool = True) -> None:
        pass


def main():
    parser = argparse.ArgumentParser(description="Decrypt .sorry files")
    parser.add_argument("encrypted_file")
    parser.add_argument("-k", "--key", default="private.pem", help="private key PEM path")
    parser.add_argument("-o", "--output", help="output path")
    parser.add_argument("--password", help="private key passphrase")
    parser.add_argument("-w", "--workers", help="parallel workers to decrypt with", default=4, type=int)
    args = parser.parse_args()

    private_key = load_private_key(args.key, password=args.password)
    src_fs = LocalFilesystemInterface()
    if args.output and args.output.startswith("s3://"):
        dest_fs = S3FilesystemInterface()
    else:
        dest_fs = LocalFilesystemInterface()

    if src_fs.isdir(args.encrypted_file):
        if args.output is not None and not args.output.startswith("s3:"):
            if dest_fs.exists(args.output) and not dest_fs.isdir(args.output):
                raise ValueError(f"{args.output} exists but it's not a directory")
            else:
                dest_fs.makedirs(args.output)
        encrypted_files = list(tqdm.tqdm(find_encrypted_files(args.encrypted_file, args.output),
                                         desc=f"Enumerating encrypted files in {args.encrypted_file}"))
        with ProgressBarExecutor(ThreadPoolExecutor(max_workers=args.workers),
                                 total_completed=True,
                                 total=len(encrypted_files),
                                 desc="Decrypting files") as executor:
            futures = []
            for encrypted_file, output_path in encrypted_files:
                if not dest_fs.exists(output_path):
                    futures.append(executor.submit(decrypt_to_file, encrypted_file, private_key, output_path))
                else:
                    print(f"Decrypted file {output_path} exists. Not decrypting.")
            for future in concurrent.futures.as_completed(futures):
                future.result()
    elif src_fs.isfile(args.encrypted_file):
        if args.output and (args.output.endswith("/") or dest_fs.isdir(args.output)):
            output_path = args.output
            if not output_path.endswith("/"):
                output_path += "/"
            output_path += default_output_path(os.path.basename(args.encrypted_file))
        else:
            output_path = args.output
        if output_path is None:
            output_path = default_output_path(args.encrypted_file)
        if dest_fs.exists(output_path):
            print(f"Decrypted file {output_path} exists. Not decrypting.")
        else:
            decrypt_to_file(multitqdm.SimpleProgressBar(), args.encrypted_file, private_key, output_path)


if __name__ == "__main__":
    main()
