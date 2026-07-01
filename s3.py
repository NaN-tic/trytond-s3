# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import gzip
import hashlib
import logging
import os
import queue
import threading
import time
from functools import cache
from io import BytesIO
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from minio import Minio
from minio.error import S3Error

from trytond.config import config
from trytond.exceptions import UserError
from trytond.filestore import FileStore
from trytond.pool import PoolMeta
from trytond.transaction import Transaction

logger = logging.getLogger(__name__)


PRODUCTION_ENV = config.getboolean('database', 'production', default=False)
PRODUCTION_ENV = True
access_key = config.get('database', 'access_key', default='')
secret_key = config.get('database', 'secret_key', default='')
bucket = config.get('database', 'bucket')
endpoint = config.get('database', 'endpoint', default=None)
max_file_life_cache = config.getint(
    'database', 'max_file_life_cache', default=-1)
max_file_life_count = config.getint(
    'database', 'max_file_life_count', default=-1)
s3_workers = config.getint('database', 's3_workers', default=50)


def get_default_storage_class():
    if max_file_life_cache == -1 and max_file_life_count == -1:
        return 'GLACIER_IR'
    return 'STANDARD_IA'


# Usual values for storage_class:
#
# - GLACIER_IR: Glacier Instant Retrieval
# - STANDARD: Standard
# - STANDARD_IA: Standard - Infrequent Access
# - INTELLIGENT_TIERING: Intelligent-Tiering

storage_class = config.get(
    'database', 'storage_class', default=get_default_storage_class())


@cache
def get_fernet_key():
    fernet_key = config.get('cryptography', 'fernet_key', default=None)
    if not fernet_key:
        return None
    return Fernet(fernet_key)


def decrypt(data):
    fernet = get_fernet_key()
    if not fernet:
        return data
    if not data:
        return data
    return fernet.decrypt(bytes(data))


def encrypt(data):
    fernet = get_fernet_key()
    if not fernet:
        if PRODUCTION_ENV:
            raise UserError(
                'You must configure cryptography/fernet_key before saving '
                'files in the S3 filestore.')
        return data
    return fernet.encrypt(bytes(data))


def compress(data):
    output = BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb') as gz_file:
        gz_file.write(data)
    compressed = output.getvalue()
    if len(compressed) >= len(data):
        return data
    return compressed


def decompress(data):
    if not data or data[:2] != b'\x1f\x8b':
        return data
    with gzip.GzipFile(fileobj=BytesIO(data), mode='rb') as gz_file:
        return gz_file.read()


def name(file_id, prefix=''):
    return '/'.join(filter(None, [prefix, file_id]))


def check_cache(filename):
    if os.path.exists(filename):
        with open(filename, 'rb') as cache_file:
            return cache_file.read()
    return None


def save_cache(data, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'wb') as cache_file:
        cache_file.write(data)


def local_files(path, prefix=''):
    root = os.path.join(path, prefix) if prefix else path
    root = os.path.normpath(root)
    if not os.path.isdir(root):
        return
    for current_root, _, filenames in os.walk(root):
        for filename in filenames:
            full_path = os.path.join(current_root, filename)
            yield filename, full_path


def is_not_found_error(exception):
    code = getattr(exception, 'code', None)
    if code in {'404', 'NoSuchKey', 'NotFound'}:
        return True
    response = getattr(exception, 'response', {})
    error = response.get('Error', {})
    return error.get('Code') in {'404', 'NoSuchKey', 'NotFound'}


class ProcessClock:

    def __init__(self):
        self.started_at = time.monotonic()
        self.last_at = self.started_at
        self.lock = threading.Lock()

    def format(self, message):
        now = time.monotonic()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with self.lock:
            elapsed_since_last = now - self.last_at
            elapsed_since_start = now - self.started_at
            self.last_at = now
        return (
            '[%s] [last=%.3fs] [total=%.3fs] %s'
            % (timestamp, elapsed_since_last, elapsed_since_start, message))


class Cron(metaclass=PoolMeta):
    __name__ = 'ir.cron'

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls.method.selection.extend([
            ('ir.cron|sync_s3_filestore_cache', 'S3 - Synchronize Cache'),
        ])

    @classmethod
    def sync_s3_filestore_cache(cls):
        process_clock = ProcessClock()
        result = FileStoreS3().ensure_uploaded(Transaction().database.name)
        logger.info(
            process_clock.format('S3 cache synchronization result: %s'),
            result)

        crons = cls.search([
            ('method', '=', 'ir.cron|sync_s3_filestore_cache'),
            ('active', '=', True),
        ])
        if crons:
            cls.write(crons, {'active': False})


class FileStoreS3(FileStore):
    _client = None

    @property
    def client(self):
        if FileStoreS3._client is None:
            secure = True
            client_endpoint = endpoint or 's3.amazonaws.com'
            if '://' in client_endpoint:
                parsed = urlparse(client_endpoint)
                secure = parsed.scheme == 'https'
                client_endpoint = parsed.netloc or parsed.path
            FileStoreS3._client = Minio(
                client_endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=secure,
                )
        return FileStoreS3._client

    def _put_s3_data(self, key, data):
        payload = encrypt(compress(data))
        self.client.put_object(bucket, key, BytesIO(payload), len(payload))

    def _get_s3_data(self, file_id, prefix=''):
        key = name(file_id, prefix)
        response = self.client.get_object(bucket, key)
        try:
            return decompress(decrypt(response.read()))
        finally:
            response.close()
            response.release_conn()

    def _stat_s3_data(self, key):
        return self.client.stat_object(bucket, key)

    def _delete_s3_data(self, key):
        self.client.remove_object(bucket, key)

    def _id(self, data):
        return hashlib.md5(data).hexdigest()

    def prune_cache_files(self):
        cache_files = []
        if os.path.isdir(self.path):
            for root, _, filenames in os.walk(self.path):
                for filename in filenames:
                    path = os.path.join(root, filename)
                    try:
                        mtime = os.path.getmtime(path)
                    except OSError:
                        continue
                    cache_files.append((path, mtime))

        removed = []
        now = time.time()
        remaining = []
        for path, mtime in cache_files:
            if max_file_life_cache >= 0 and now - mtime > max_file_life_cache:
                try:
                    os.remove(path)
                except OSError:
                    continue
                removed.append(path)
            else:
                remaining.append((path, mtime))

        if max_file_life_count >= 0 and len(remaining) > max_file_life_count:
            to_remove_count = len(remaining) - max_file_life_count
            to_remove = sorted(remaining, key=lambda item: item[1])[:to_remove_count]
            for path, _ in to_remove:
                try:
                    os.remove(path)
                except OSError:
                    continue
                removed.append(path)
        return removed

    def get(self, file_id, prefix=''):
        process_clock = ProcessClock()
        filename = self._filename(file_id, prefix)
        cache_file = check_cache(filename)
        if cache_file is not None:
            os.utime(filename, None)

            if PRODUCTION_ENV:
                removed_files = self.prune_cache_files()
                if removed_files:
                    logger.info(
                        process_clock.format('Removed %d cache files: %s'),
                        len(removed_files),
                        ', '.join(removed_files))

            return cache_file

        data = self._get_s3_data(file_id, prefix)
        save_cache(data, filename)
        return data

    def size(self, file_id, prefix=''):
        filename = self._filename(file_id, prefix)
        if os.path.exists(filename):
            return super().size(file_id, prefix)
        key = name(file_id, prefix)
        return self._stat_s3_data(key).size

    def set(self, data, prefix=''):
        file_id = self._id(data)
        filename = self._filename(file_id, prefix)
        os.makedirs(os.path.dirname(filename), mode=0o770, exist_ok=True)
        collision = 0
        while True:
            basename = os.path.basename(filename)
            if PRODUCTION_ENV:
                try:
                    if data != self._get_s3_data(basename, prefix):
                        collision += 1
                        filename = self._filename(
                            '%s-%s' % (file_id, collision), prefix)
                        continue
                except S3Error as exc:
                    if not is_not_found_error(exc):
                        raise
                    key = name(basename, prefix)
                    self._put_s3_data(key, data)
                    save_cache(data, filename)
                else:
                    save_cache(data, filename)
            elif os.path.exists(filename):
                if data != check_cache(filename):
                    collision += 1
                    filename = self._filename(
                        '%s-%s' % (file_id, collision), prefix)
                    continue
            else:
                save_cache(data, filename)
            return basename

    def list(self, prefix=''):
        for obj in self.client.list_objects(
                bucket, prefix=prefix, recursive=True, use_api_v1=False):
            yield obj.object_name

    def ensure_encrypted(self, prefix=''):
        if not PRODUCTION_ENV:
            return {
                'scanned': 0,
                'encrypted': 0,
                'skipped': 0,
            }
        process_clock = ProcessClock()
        task_queue = queue.Queue(maxsize=max(s3_workers * 2, 1))
        stop_event = threading.Event()
        lock = threading.Lock()
        sentinel = object()
        counters = {'scanned': 0, 'encrypted': 0, 'skipped': 0}
        errors = []

        def worker():
            while True:
                key = task_queue.get()
                try:
                    if key is sentinel:
                        return
                    response = self.client.get_object(bucket, key)
                    try:
                        data = response.read()
                        try:
                            decrypt(data)
                        except InvalidToken:
                            self._put_s3_data(key, data)
                            outcome = 'encrypted'
                        else:
                            outcome = 'skipped'
                    finally:
                        response.close()
                        response.release_conn()
                    with lock:
                        counters[outcome] += 1
                except Exception as exc:
                    with lock:
                        errors.append(exc)
                    stop_event.set()
                finally:
                    task_queue.task_done()

        workers = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(max(s3_workers, 1))
            ]
        for thread in workers:
            thread.start()

        try:
            for key in self.list(prefix):
                if stop_event.is_set():
                    break
                with lock:
                    counters['scanned'] += 1
                    scanned = counters['scanned']
                task_queue.put(key)
                if scanned % 100 == 0:
                    with lock:
                        message = process_clock.format(
                            'S3 ensure encrypted progress: scanned=%d '
                            'encrypted=%d skipped=%d') % (
                                counters['scanned'],
                                counters['encrypted'],
                                counters['skipped'])
                        logger.info(message)
                        print(message)
            if errors:
                raise errors[0]
            task_queue.join()
            if errors:
                raise errors[0]
        finally:
            for _ in workers:
                task_queue.put(sentinel)
            for thread in workers:
                thread.join()

        message = process_clock.format(
            'S3 ensure encrypted result: scanned=%d encrypted=%d skipped=%d'
            ) % (
                counters['scanned'],
                counters['encrypted'],
                counters['skipped'])
        logger.info(message)
        print(message)
        return counters

    def ensure_uploaded(self, prefix=''):
        if not PRODUCTION_ENV:
            return {
                'scanned': 0,
                'uploaded': 0,
                'skipped': 0,
            }
        process_clock = ProcessClock()
        task_queue = queue.Queue(maxsize=max(s3_workers * 2, 1))
        stop_event = threading.Event()
        lock = threading.Lock()
        sentinel = object()
        counters = {'scanned': 0, 'uploaded': 0, 'skipped': 0}
        errors = []

        def worker():
            while True:
                file_info = task_queue.get()
                try:
                    if file_info is sentinel:
                        return
                    file_id, filename = file_info
                    key = name(file_id, prefix)
                    try:
                        self._stat_s3_data(key)
                    except S3Error as exc:
                        if not is_not_found_error(exc):
                            raise
                        with open(filename, 'rb') as local_file:
                            data = local_file.read()
                        self._put_s3_data(key, data)
                        outcome = 'uploaded'
                    else:
                        outcome = 'skipped'
                    with lock:
                        counters[outcome] += 1
                except Exception as exc:
                    with lock:
                        errors.append(exc)
                    stop_event.set()
                finally:
                    task_queue.task_done()

        workers = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(max(s3_workers, 1))
            ]
        for thread in workers:
            thread.start()

        try:
            for file_info in local_files(self.path, prefix):
                if stop_event.is_set():
                    break
                with lock:
                    counters['scanned'] += 1
                    scanned = counters['scanned']
                task_queue.put(file_info)
                if scanned % 100 == 0:
                    with lock:
                        logger.info(process_clock.format(
                            'S3 cache upload progress: scanned=%d '
                            'uploaded=%d skipped=%d') % (
                                counters['scanned'],
                                counters['uploaded'],
                                counters['skipped']))
            if errors:
                raise errors[0]
            task_queue.join()
            if errors:
                raise errors[0]
        finally:
            for _ in workers:
                task_queue.put(sentinel)
            for thread in workers:
                thread.join()

        logger.info(process_clock.format(
            'S3 cache upload result: scanned=%d uploaded=%d skipped=%d') % (
                counters['scanned'],
                counters['uploaded'],
                counters['skipped']))
        return counters

    def delete(self, file_id, prefix=''):
        filename = self._filename(file_id, prefix)
        if os.path.exists(filename):
            os.remove(filename)
        if not PRODUCTION_ENV:
            return
        key = name(file_id, prefix)
        self._delete_s3_data(key)

    def set_with_id(self, file_id, data, prefix=''):
        filename = self._filename(file_id, prefix)
        save_cache(data, filename)
        if not PRODUCTION_ENV:
            return file_id
        key = name(file_id, prefix)
        self._put_s3_data(key, data)
        return file_id
