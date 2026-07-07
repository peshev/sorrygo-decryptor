import os
from io import SEEK_CUR, SEEK_SET, SEEK_END
from typing import BinaryIO, Optional, Union, Iterable, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# noinspection PyUnresolvedReferences
from multitqdm import ProgressBar
from utils import read_blocks, ProgressBarFileReader, Decryptor

MAGIC = {
    0x66: "java",
    0xFF: "csharp",
    0x99: "golang",
    0x11: "rust",
}
MAGIC_SIZE = 1
FIXED_BLOCK_SIZE = 64 * 1024
AES_GCM_TAG_SIZE = 0x10
VAR_BLOCK_LENGTH_SIZE = 4
FULL_VAR_BLOCK_PLAINTEXT_SIZE = 0x10000
FULL_VAR_BLOCK_CIPHERTEXT_SIZE = FULL_VAR_BLOCK_PLAINTEXT_SIZE + AES_GCM_TAG_SIZE
FULL_VAR_BLOCK_SIZE = VAR_BLOCK_LENGTH_SIZE + FULL_VAR_BLOCK_CIPHERTEXT_SIZE


def read_var_length_block_length(f: BinaryIO, header: bool = False) -> Optional[int]:
    block_type = "header" if header else "block"
    length_bytes = f.read(VAR_BLOCK_LENGTH_SIZE)
    if len(length_bytes) == 0 and not header:
        # clean EOF while trying to read the length of a new block is ok (although in practice, all files end with a zero-length block, so this should never happen)
        return None
    if len(length_bytes) != VAR_BLOCK_LENGTH_SIZE:
        # EOF while trying to read the header length, or some garbage at the end of the file is not ok
        raise ValueError(
            f"Expected to read {VAR_BLOCK_LENGTH_SIZE} bytes (length), actually read {len(length_bytes)} bytes while reading {block_type}")

    length = int.from_bytes(length_bytes, "big")
    if (length == 0 and header) or length > FULL_VAR_BLOCK_CIPHERTEXT_SIZE:
        raise ValueError(f"Unexpected {block_type} length: {length}")
    return length


def read_var_length_block(f: BinaryIO, header: bool = False) -> Optional[bytes]:
    block_type = "header" if header else "block"
    length = read_var_length_block_length(f, header)
    if length is None:
        return None

    data = f.read(length)
    if len(data) != length:
        raise ValueError(
            f"Expected to read {length} bytes (data), actually read {len(data)} bytes while reading {block_type}")

    return data


def skip_var_length_block(f: BinaryIO) -> Optional[int]:
    length = read_var_length_block_length(f)
    if length is None:
        return None
    f.seek(length, SEEK_CUR)
    return length


def read_fixed_length_block(f: BinaryIO, length: int = FIXED_BLOCK_SIZE) -> Optional[bytes]:
    if length == 0:
        return b""
    data = f.read(length)
    if len(data) == 0:
        return None
    return data


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


def read_header(f: BinaryIO) -> Tuple[str, bytes]:
    magic_byte = f.read(MAGIC_SIZE)
    if len(magic_byte) != MAGIC_SIZE:
        raise ValueError(f"Encrypted file is empty")

    fmt = MAGIC.get(magic_byte[0], "unknown")
    if fmt == "unknown":
        raise ValueError(f"Unknown magic byte: 0x{magic_byte:02x}")

    _ = read_var_length_block(f)  # TODO: What's in this first header?

    encrypted_header = read_var_length_block(f, header=True)
    if encrypted_header is None:
        raise ValueError(f"Could not read encrypted header")

    return fmt, encrypted_header


def get_var_length_block_plaintext_size(f: BinaryIO) -> int:
    original_pos = f.tell()
    try:
        return sum(l - AES_GCM_TAG_SIZE for l in read_blocks(f, skip_var_length_block))
    finally:
        f.seek(original_pos, SEEK_SET)


def get_fixed_block_plaintext_size(f: BinaryIO, block_size: int = FIXED_BLOCK_SIZE) -> int:
    original_pos = f.tell()
    try:
        f.seek(0, SEEK_END)
        size = f.tell() - original_pos
        if size % block_size != 0:
            raise ValueError(f"Ciphertext size is not a multiple of FIXED_BLOCK_SIZE ({block_size})")
        return size
    finally:
        f.seek(original_pos, SEEK_SET)


def calculate_plaintext_size(f: BinaryIO, fmt: str) -> int:
    if fmt == "java":
        return get_fixed_block_plaintext_size(f)
    elif fmt in ("golang", "csharp", "rust"):
        return get_var_length_block_plaintext_size(f)
    else:
        raise ValueError(f"Unknown decrypt format {fmt}")


def calculate_file_plaintext_size(enc_path: str):
    with open(enc_path, "rb") as f:
        fmt, encrypted_header = read_header(f)
        return calculate_plaintext_size(f, fmt)


def estimate_plaintext_size(file_size: int) -> int:
    """
    Assumes:
        * 1st block is 2048-byte block with fixed header
        * 2nd block is 256-byte block key header
        * All blocks are full-size except for the second-to-last one
        * Last block is empty
    :param file_size:
    :return:
    """
    size_without_header = (
            file_size
            - MAGIC_SIZE  # magic byte
            - (VAR_BLOCK_LENGTH_SIZE + 2048)  # header 1
            - (VAR_BLOCK_LENGTH_SIZE + 256)  # key header
            - (VAR_BLOCK_LENGTH_SIZE + 0)  # empty block at the end
    )
    full_blocks_count = size_without_header // FULL_VAR_BLOCK_SIZE
    partial_block_plaintext_size = size_without_header % FULL_VAR_BLOCK_SIZE
    if partial_block_plaintext_size > 0:
        partial_block_plaintext_size -= (VAR_BLOCK_LENGTH_SIZE + AES_GCM_TAG_SIZE)

    return full_blocks_count * FULL_VAR_BLOCK_PLAINTEXT_SIZE + partial_block_plaintext_size


def decrypt_file(progressbar: ProgressBar, enc_path: str, private_key: RSAPrivateKey, size: Optional[int] = None) -> \
        Iterable[bytes]:
    if size is None:
        size = os.path.getsize(enc_path)

    with progressbar.start(desc=enc_path, total=size, unit="B", unit_scale=True) as pb, \
            ProgressBarFileReader(open(enc_path, "rb"), pb) as f:
        fmt, encrypted_header = read_header(f)
        header = decrypt_rsa_header(private_key, encrypted_header)

        if fmt == "java":
            yield from decrypt_aes_cfb_blocks(
                header[16:32], header[:16],
                read_blocks(f, read_fixed_length_block))
        elif fmt in ("golang", "csharp", "rust"):
            yield from decrypt_aes_gcm_blocks(
                header[:32],
                read_blocks(f, read_var_length_block))
        else:
            raise ValueError(f"Unknown decrypt format {fmt}")


def load_private_key(path, password: Optional[Union[str, bytes]] = None) -> RSAPrivateKey:
    if isinstance(password, str):
        password = password.encode()
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=password)
    assert isinstance(private_key, RSAPrivateKey)
    return private_key


class SorryGoDecryptor(Decryptor):
    def __init__(self, private_key_path: str, private_key_password: Optional[Union[str, bytes]] = None):
        self.private_key = load_private_key(private_key_path, private_key_password)

    def decrypt(self, progressbar: ProgressBar, enc_path: str, size: Optional[int] = None) -> Iterable[bytes]:
        return decrypt_file(progressbar, enc_path, self.private_key, size)

    def estimate_plaintext_size(self, file_size: int) -> int:
        return estimate_plaintext_size(file_size)

    def calculate_plaintext_size(self, enc_path: str) -> int:
        return calculate_file_plaintext_size(enc_path)
