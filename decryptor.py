#!/usr/bin/env python3

import argparse
import concurrent
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Tuple, Optional, List

# noinspection PyPackageRequirements
import tqdm

# noinspection PyUnresolvedReferences
from multitqdm import ProgressBar, ProgressBarExecutor, SimpleProgressBar
from utils import FilesystemInterface, write_blocks, LocalFilesystemInterface, S3FilesystemInterface, Decryptor
from sorrygo import SorryGoDecryptor


class EncryptedFile(object):
    def __init__(self, decryptor: Decryptor, encrypted_path: str, decrypted_path: str,
                 src_fs: FilesystemInterface, dest_fs: FilesystemInterface):
        self.decryptor = decryptor
        self.encrypted_path = encrypted_path
        self.decrypted_path = decrypted_path
        self.dest_fs = dest_fs
        self.src_fs = src_fs
        self._encrypted_file_size = None
        self._decrypted_file_size = None

    def encrypted_file_size(self, force: bool = False) -> int:
        if self._encrypted_file_size is None or force:
            self._encrypted_file_size = self.src_fs.getsize(self.encrypted_path)
        return self._encrypted_file_size

    def decrypted_file_size(self, force: bool = False) -> int:
        if self._decrypted_file_size is None or force:
            self._decrypted_file_size = self.dest_fs.getsize(self.decrypted_path)
        return self._decrypted_file_size

    def estimate_plaintext_size(self):
        return self.decryptor.estimate_plaintext_size(self.encrypted_file_size())

    def is_decrypted(self) -> bool:
        try:
            return self.decrypted_file_size(True) == self.estimate_plaintext_size()
        except FileNotFoundError:
            return False

    def delete(self, force=False):
        if self.is_decrypted() or force:
            self.src_fs.unlink(self.encrypted_path)
            return True
        else:
            return False

    def _decrypt_blocks(self, progressbar: ProgressBar):
        return self.decryptor.decrypt(progressbar, self.encrypted_path, self.encrypted_file_size())

    def decrypt(self, progressbar: ProgressBar):
        return write_blocks(self.decrypted_path, self._decrypt_blocks(progressbar))


def default_output_path(path: str, strip_suffix: str = ".sorry") -> str:
    if path.endswith(strip_suffix):
        return path[:-len(strip_suffix)]
    return path + ".dec"


def find_encrypted_files(dir_path: str, output_dir_path: Optional[str] = None, extension: str = ".sorry") \
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


def assert_directory(path: str, fs: FilesystemInterface):
    if path is not None:
        if fs.exists(path):
            if not fs.isdir(path):
                raise ValueError(f"{path} exists but it's not a directory")
        else:
            fs.makedirs(path)


class EncryptedFilePreProcessor(object):
    def __init__(self, delete: bool = False):
        self.encrypted_files = []
        self.exceptions = []
        self.encrypted_files_total_size = 0
        self.delete = delete

    def __call__(self, encrypted_file: EncryptedFile):
        try:
            if encrypted_file.is_decrypted():
                if self.delete:
                    encrypted_file.delete()
            else:
                self.encrypted_files_total_size += encrypted_file.encrypted_file_size()
                self.encrypted_files.append(encrypted_file)
        except Exception as e:
            self.exceptions.append((e, encrypted_file))

    def print_summary(self):
        for e, ef in self.exceptions:
            print(f"Exception while processing {ef.encrypted_path}: {e}")


class EncryptedFileProcessor(object):
    def __init__(self, delete: bool = False):
        self.exceptions: List[Tuple[Exception, EncryptedFile]] = []
        self.delete = delete

    def __call__(self, progressbar: ProgressBar, encrypted_file: EncryptedFile):
        try:
            decrypted_plaintext_size = encrypted_file.decrypt(progressbar)
            assert decrypted_plaintext_size == encrypted_file.estimate_plaintext_size(), (
                f"Unable to correctly estimate the plaintext size for {encrypted_file.encrypted_path}. "
                f"Expected {encrypted_file.estimate_plaintext_size()}, "
                f"but got {decrypted_plaintext_size}"
            )
            assert encrypted_file.is_decrypted(), (
                f"Unexpected plaintext file size for {encrypted_file.encrypted_path}. "
                f"Expected {encrypted_file.estimate_plaintext_size()}, "
                f"but got {encrypted_file.decrypted_file_size()}")
            if self.delete:
                encrypted_file.delete()
        except Exception as e:
            self.exceptions.append((e, encrypted_file))

    def print_summary(self):
        for e, ef in self.exceptions:
            print(f"Exception while processing {ef.encrypted_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt .sorry files")
    parser.add_argument("encrypted_file", nargs="+")
    parser.add_argument("-k", "--key", help="private key PEM path",
                        default="private.pem")
    parser.add_argument("-o", "--output", help="output path")
    parser.add_argument("--password", help="private key passphrase")
    parser.add_argument("-w", "--workers", help="parallel workers to decrypt with",
                        default=4, type=int)
    parser.add_argument("-d", "--delete", help="Delete encrypted files after successful encryption",
                        action="store_true")
    args = parser.parse_args()
    decryptor = SorryGoDecryptor(args.key, args.password)

    src_fs = LocalFilesystemInterface()
    if args.output and args.output.startswith("s3://"):
        dest_fs = S3FilesystemInterface()
    else:
        dest_fs = LocalFilesystemInterface()

    if args.output and (args.output.endswith("/") or dest_fs.isdir(args.output)):
        output_path = args.output
        if not output_path.endswith("/"):
            output_path += "/"
    else:
        output_path = args.output

    # Step 1: Find files that have the encrypted file extension
    found_encrypted_files = []
    for encfile in args.encrypted_file:
        if src_fs.isdir(encfile):
            assert_directory(output_path, dest_fs)
            found_encrypted_files.extend(find_encrypted_files(encfile, output_path))
        elif src_fs.isfile(encfile):
            if len(args.encrypted_files) > 1:
                assert_directory(output_path, dest_fs)
                if output_path is not None:
                    output_path += default_output_path(os.path.basename(encfile))
            if output_path is None:
                output_path = default_output_path(encfile)
            found_encrypted_files.append((encfile, output_path))

    encrypted_files = [
        EncryptedFile(decryptor, encrypted_path, decrypted_path, src_fs, dest_fs)
        for encrypted_path, decrypted_path in
        found_encrypted_files
    ]

    # Step 2: Figure out which of these files have already been decrypted, optionally delete the encrypted versions
    # of already decrypted files, and collect the size of all files to be decrypted
    preprocessor = EncryptedFilePreProcessor(args.delete)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for future in tqdm.tqdm(
                concurrent.futures.as_completed(
                    executor.submit(preprocessor, encrypted_file)
                    for encrypted_file in
                    encrypted_files
                ),
                desc=f"Calculating size of encrypted files in {args.encrypted_file}",
                total=len(encrypted_files)):
            future.result()
    preprocessor.print_summary()

    # Step 3: If any files that need to be decrypted have been identified, decrypt and optionally delete them
    # after verifying that they've successfully been decrypted
    if preprocessor.encrypted_files:
        processor = EncryptedFileProcessor(delete=args.delete)
        with ProgressBarExecutor(ThreadPoolExecutor(max_workers=args.workers),
                                 desc="Decrypting files",
                                 total=preprocessor.encrypted_files_total_size, unit="B",
                                 unit_scale=True) as executor:
            for future in concurrent.futures.as_completed(
                    executor.submit(processor, encrypted_file)
                    for encrypted_file in
                    preprocessor.encrypted_files
            ):
                future.result()
        processor.print_summary()
    else:
        print("All files were already decrypted.")


if __name__ == "__main__":
    main()
    pass
