import os
import urllib
import urllib.parse
from io import SEEK_SET
from typing import Iterable, Callable, BinaryIO, Optional, Union

import boto3
import smart_open
from botocore.exceptions import ClientError, HTTPClientError
from smart_open import open

# noinspection PyUnresolvedReferences
from multitqdm import ProgressBar


class FilesystemInterface(object):
    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def isfile(self, path: str) -> bool:
        raise NotImplementedError

    def isdir(self, path: str) -> bool:
        raise NotImplementedError

    def makedirs(self, path: str, exists_ok: bool = True) -> None:
        raise NotImplementedError

    def getsize(self, path: str) -> int:
        raise NotImplementedError

    def unlink(self, path: str):
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

    def getsize(self, path: str) -> int:
        return os.path.getsize(path)

    def unlink(self, path: str):
        os.unlink(path)


class S3FilesystemInterface(FilesystemInterface):
    def __init__(self):
        self.client = boto3.client("s3")
        self.cache = {}

    @staticmethod
    def _parse_s3_url(url):
        parsed = urllib.parse.urlparse(url)
        assert parsed.scheme == "s3", f"S3 URL with an unexpected schema {parsed.scheme}"
        assert not parsed.query, f"S3 URL with a query {parsed.query}"
        assert not parsed.fragment, f"S3 URL with a fragment {parsed.fragment}"

        return parsed.netloc, parsed.path.lstrip("/")

    def _cache_contents(self, list_objects_response: dict):
        bucket_cache = self.cache.setdefault(list_objects_response['Name'], {})
        for c in list_objects_response['Contents']:
            dir_cache = bucket_cache
            path = c['Key'].split("/")
            current_path = ""
            for p in path[:-1]:
                dir_cache = dir_cache.setdefault("Contents", {}).setdefault(p, {})
                current_path += "/" + p
                if list_objects_response.get("Prefix"):
                    if current_path.startswith(list_objects_response['Prefix']):
                        dir_cache['Complete'] = True
            dir_cache.setdefault("Contents", {})[path[-1]] = c

    def _cache_get(self, bucket, key):
        bucket_cache = self.cache[bucket]
        dir_cache = bucket_cache
        path = key.split("/")
        for p in path[:-1]:
            dir_cache = dir_cache[p]
        return dir_cache[path[-1]]

    def get(self, path):
        bucket, key = self._parse_s3_url(path)
        try:
            return self._cache_get(bucket, key)
        except KeyError:
            self._cache_contents(self.client.list_objects_v2(Bucket=bucket, Prefix=os.path.dirname(key)))
        return self._cache_get(bucket, key)

    def _list_dir(self):
        pass

    def exists(self, path: str) -> bool:
        bucket, key = self._parse_s3_url(path)
        return bool(self.client.list_objects_v2(Bucket=bucket, Prefix=os.path.dirname(key)).get("Contents"))

    def isfile(self, path: str) -> bool:
        bucket, key = self._parse_s3_url(path)
        try:
            self.client.head_object(Bucket=bucket, Key=key)
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

    def getsize(self, path: str) -> int:
        bucket, key = self._parse_s3_url(path)
        retries = 3
        while True:
            try:
                resp = self.client.head_object(Bucket=bucket, Key=key)
                return int(resp['ContentLength'])
            except ClientError as e:
                if e.response["Error"]["Code"] == "404":
                    raise FileNotFoundError(path)
                else:
                    raise e
            except HTTPClientError:
                # botocore.exceptions.HTTPClientError: An HTTP Client raised an unhandled exception: unknown encoding: idna
                retries -= 1
                if retries <= 0:
                    raise FileNotFoundError(path)


# noinspection PyAbstractClass
class ProgressBarFileReader(BinaryIO):
    def __init__(self, f: BinaryIO, pb: ProgressBar):
        self.f = f
        self.pb = pb

    def read(self, n=-1, /) -> bytes:
        result = self.f.read(n)
        self.pb.progress(len(result))
        return result

    def seek(self, offset: int, whence: int = SEEK_SET):
        return self.f.seek(offset, whence)

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.f.__exit__(exc_type, exc_val, exc_tb)


def read_blocks(f: BinaryIO, read_block_fn: Callable[[BinaryIO], Optional[Union[bytes, int]]]) \
        -> Iterable[Union[bytes, int]]:
    while True:
        block = read_block_fn(f)
        if block is None:
            return
        yield block


def progress_blocks(progressbar, blocks: Iterable[bytes]) -> Iterable[bytes]:
    for block in blocks:
        progressbar.progress(len(block))
        yield block


def write_blocks(path: str, blocks: Iterable[bytes]):
    length = 0
    with open(path, "wb", compression=smart_open.compression.NO_COMPRESSION) as f:
        for block in blocks:
            length += f.write(block)
    return length


class Decryptor(object):
    def decrypt(self, progressbar: ProgressBar, enc_path: str, size: Optional[int] = None) -> Iterable[bytes]:
        raise NotImplementedError()

    def estimate_plaintext_size(self, file_size: int) -> int:
        raise NotImplementedError()

    def calculate_plaintext_size(self, enc_path: str) -> int:
        raise NotImplementedError()
