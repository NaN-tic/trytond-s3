# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
import datetime
import os
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from cryptography.fernet import Fernet

from trytond.exceptions import UserError
from trytond.modules.s3 import s3
from trytond.pool import Pool
from trytond.tests.test_tryton import ModuleTestCase, with_transaction
from trytond.transaction import Transaction


class FakeS3Error(s3.S3Error):

    def __init__(self, code):
        Exception.__init__(self, code)
        self.code = code


class FakeObjectResponse:

    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return self.payload

    def close(self):
        return None

    def release_conn(self):
        return None


class FakeListedObject:

    def __init__(self, object_name):
        self.object_name = object_name


class S3TestCase(ModuleTestCase):
    'Test S3 module'
    module = 's3'

    def _create_sync_cron(self, Cron):
        cron = Cron(
            method='ir.cron|sync_s3_filestore_cache',
            interval_number=1,
            interval_type='hours')
        cron.save()
        return cron

    def test_s3_filestore_cache_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            s3.get_fernet_key.cache_clear()
            payload = b'nantic'

            with patch.object(
                    s3.config, 'get',
                    side_effect=lambda section, option, default=None: {
                        ('cryptography', 'fernet_key'):
                            '8BwFmKMykS2X2-gmwEwgfmA9hPN-pb4Ua5N2XyqAlh4=',
                        }.get((section, option), default)):
                encrypted = s3.encrypt(payload)
                self.assertNotEqual(encrypted, payload)
                self.assertEqual(s3.decrypt(encrypted), payload)
                compressed = s3.compress(payload)
                self.assertEqual(compressed, payload)
                self.assertEqual(s3.decompress(compressed), payload)
                self.assertEqual(s3.decompress(payload), payload)
                repeated = b'a' * 1024
                smaller = s3.compress(repeated)
                self.assertLess(len(smaller), len(repeated))
                self.assertEqual(s3.decompress(smaller), repeated)
            self.assertIsInstance(s3.get_fernet_key(), (type(None), Fernet))

            target = os.path.join(tmpdir, 'ab', 'cd', 'file')
            s3.save_cache(payload, target)
            self.assertEqual(s3.check_cache(target), payload)

            filestore = s3.FileStoreS3()
            cache_dir = os.path.join(tmpdir, 'cache')
            os.makedirs(cache_dir)
            old_path = os.path.join(cache_dir, 'old')
            new_path = os.path.join(cache_dir, 'new')
            for path in [old_path, new_path]:
                with open(path, 'wb') as cache_file:
                    cache_file.write(payload)
            now = datetime.datetime.now().timestamp()
            os.utime(old_path, (now - 20, now - 20))
            os.utime(new_path, (now - 10, now - 10))

            with patch.object(
                    s3.FileStoreS3, 'path',
                    new_callable=PropertyMock, return_value=cache_dir), \
                    patch.object(s3, 'max_file_life_cache', 15), \
                    patch.object(s3, 'max_file_life_count', 1):
                removed = filestore.prune_cache_files()
            self.assertEqual(removed, [old_path])
            self.assertFalse(os.path.exists(old_path))
            self.assertTrue(os.path.exists(new_path))

    def test_s3_filestore_prune_cache_files_removes_by_count(self):
        filestore = s3.FileStoreS3()
        with tempfile.TemporaryDirectory() as cache_dir:
            old_path = os.path.join(cache_dir, 'old')
            new_path = os.path.join(cache_dir, 'new')
            for path in [old_path, new_path]:
                with open(path, 'wb') as cache_file:
                    cache_file.write(b'nantic')
            now = datetime.datetime.now().timestamp()
            os.utime(old_path, (now - 20, now - 20))
            os.utime(new_path, (now - 10, now - 10))

            with patch.object(
                    s3.FileStoreS3, 'path',
                    new_callable=PropertyMock, return_value=cache_dir), \
                    patch.object(s3, 'max_file_life_cache', -1), \
                    patch.object(s3, 'max_file_life_count', 1):
                removed = filestore.prune_cache_files()

        self.assertEqual(removed, [old_path])

    def test_s3_filestore_prune_cache_files_disabled(self):
        filestore = s3.FileStoreS3()
        with tempfile.TemporaryDirectory() as cache_dir:
            path = os.path.join(cache_dir, 'file')
            with open(path, 'wb') as cache_file:
                cache_file.write(b'nantic')
            with patch.object(
                    s3.FileStoreS3, 'path',
                    new_callable=PropertyMock, return_value=cache_dir), \
                    patch.object(s3, 'max_file_life_cache', -1), \
                    patch.object(s3, 'max_file_life_count', -1):
                removed = filestore.prune_cache_files()

        self.assertEqual(removed, [])

    def test_s3_filestore_non_production_is_local_only(self):
        class Client:
            def list_objects(self, bucket, prefix=None, recursive=False,
                    use_api_v1=False):
                return iter([FakeListedObject('attachments/from-s3')])

        with tempfile.TemporaryDirectory() as tmpdir:
            filestore = s3.FileStoreS3()
            payload = b'only-local'
            with patch.object(s3, 'PRODUCTION_ENV', False), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=Client()):
                file_id = filestore.set(payload, 'attachments')
                filename = filestore._filename(file_id, 'attachments')
                self.assertTrue(os.path.exists(filename))
                self.assertEqual(filestore.get(file_id, 'attachments'), payload)
                self.assertEqual(filestore.size(file_id, 'attachments'),
                    len(payload))
                self.assertEqual(
                    list(filestore.list('attachments')),
                    ['attachments/from-s3'])
                filestore.delete(file_id, 'attachments')
                self.assertFalse(os.path.exists(filename))

    def test_s3_filestore_list_uses_pagination(self):
        filestore = s3.FileStoreS3()

        class Client:
            def __init__(self):
                self.calls = []

            def list_objects(self, bucket, prefix=None, recursive=False,
                    use_api_v1=False):
                self.calls.append({
                        'bucket': bucket,
                        'prefix': prefix,
                        'recursive': recursive,
                        'use_api_v1': use_api_v1,
                        })
                return iter([
                    FakeListedObject('attachments/first'),
                    FakeListedObject('attachments/second'),
                ])

        client = Client()
        with patch.object(
                s3.FileStoreS3, 'client',
                new_callable=PropertyMock, return_value=client):
            keys = list(filestore.list('attachments'))

        self.assertEqual(keys, ['attachments/first', 'attachments/second'])
        self.assertEqual(client.calls, [
                {'bucket': s3.bucket, 'prefix': 'attachments',
                    'recursive': True, 'use_api_v1': False},
                ])

    def test_s3_filestore_non_production_get_can_read_from_s3(self):
        filestore = s3.FileStoreS3()
        file_id = 'abcd1234'

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = os.path.join(
                tmpdir, 'attachments', file_id[0:2], file_id[2:4], file_id)
            with patch.object(s3, 'PRODUCTION_ENV', False), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, '_get_s3_data',
                        return_value=b'from-s3') as get_s3_mock:
                data = filestore.get(file_id, 'attachments')

        self.assertEqual(data, b'from-s3')
        self.assertEqual(get_s3_mock.call_count, 1)
        self.assertFalse(os.path.exists(filename))

    def test_s3_filestore_requires_fernet_in_production_to_save(self):
        filestore = s3.FileStoreS3()

        class Client:
            def put_object(self, **kwargs):
                return None

        with patch.object(s3, 'PRODUCTION_ENV', True), \
                patch.object(s3, 'get_fernet_key', return_value=None), \
                patch.object(
                    s3.FileStoreS3, '_get_s3_data',
                    side_effect=FakeS3Error('404')), \
                patch.object(
                    s3.FileStoreS3, 'client',
                    new_callable=PropertyMock, return_value=Client()):
            with self.assertRaises(UserError):
                filestore.set(b'data', 'attachments')

    def test_s3_filestore_production_set_saves_local_cache(self):
        filestore = s3.FileStoreS3()

        class Client:
            def __init__(self):
                self.put_calls = []

            def put_object(self, *args):
                self.put_calls.append(args)

        client = Client()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(s3, 'PRODUCTION_ENV', True), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=client), \
                    patch.object(
                        s3.FileStoreS3, '_get_s3_data',
                        side_effect=FakeS3Error('404')), \
                    patch.object(
                        s3, 'get_fernet_key',
                        return_value=Fernet(
                            '8BwFmKMykS2X2-gmwEwgfmA9hPN-pb4Ua5N2XyqAlh4=')):
                file_id = filestore.set(b'payload', 'attachments')
                filename = filestore._filename(file_id, 'attachments')
                self.assertTrue(os.path.exists(filename))
                with open(filename, 'rb') as cache_file:
                    self.assertEqual(cache_file.read(), b'payload')
        self.assertEqual(len(client.put_calls), 1)

    def test_s3_filestore_production_size_uses_local_cache_first(self):
        filestore = s3.FileStoreS3()

        class Client:
            def stat_object(self, bucket, key):
                raise AssertionError('S3 should not be queried when cache exists')

        client = Client()
        with tempfile.TemporaryDirectory() as tmpdir:
            file_id = 'abcd1234'
            filename = os.path.join(
                tmpdir, 'attachments', file_id[0:2], file_id[2:4], file_id)
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'wb') as cache_file:
                cache_file.write(b'cached-size')

            with patch.object(s3, 'PRODUCTION_ENV', True), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=client):
                size = filestore.size(file_id, 'attachments')

        self.assertEqual(size, len(b'cached-size'))

    def test_s3_filestore_production_set_reuses_existing_content(self):
        filestore = s3.FileStoreS3()
        payload = b'same-data'

        class Client:
            def __init__(self):
                self.put_calls = []

            def put_object(self, *args):
                self.put_calls.append(args)

        client = Client()
        with tempfile.TemporaryDirectory() as tmpdir:
            expected_id = filestore._id(payload)
            filename = os.path.join(
                tmpdir, 'attachments', expected_id[0:2], expected_id[2:4],
                expected_id)
            with patch.object(s3, 'PRODUCTION_ENV', True), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=client), \
                    patch.object(
                        s3.FileStoreS3, '_get_s3_data',
                        return_value=payload) as get_s3_mock:
                file_id = filestore.set(payload, 'attachments')
                self.assertTrue(os.path.exists(filename))

        self.assertEqual(file_id, expected_id)
        self.assertEqual(get_s3_mock.call_count, 1)
        self.assertEqual(client.put_calls, [])

    def test_s3_filestore_production_set_uses_s3_as_source_of_truth(self):
        filestore = s3.FileStoreS3()
        payload = b'same-data'

        class Client:
            def __init__(self):
                self.put_calls = []

            def put_object(self, *args):
                self.put_calls.append(args)

        client = Client()
        with tempfile.TemporaryDirectory() as tmpdir:
            expected_id = filestore._id(payload)
            filename = os.path.join(
                tmpdir, 'attachments', expected_id[0:2], expected_id[2:4],
                expected_id)
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'wb') as cache_file:
                cache_file.write(b'stale-cache')

            with patch.object(s3, 'PRODUCTION_ENV', True), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=client), \
                    patch.object(
                        s3.FileStoreS3, '_get_s3_data',
                        return_value=payload) as get_s3_mock:
                file_id = filestore.set(payload, 'attachments')

            with open(filename, 'rb') as cache_file:
                cached_payload = cache_file.read()

        self.assertEqual(file_id, expected_id)
        self.assertEqual(cached_payload, payload)
        self.assertEqual(get_s3_mock.call_count, 1)
        self.assertEqual(client.put_calls, [])

    def test_s3_filestore_ensure_encrypted(self):
        filestore = s3.FileStoreS3()
        fernet = Fernet('8BwFmKMykS2X2-gmwEwgfmA9hPN-pb4Ua5N2XyqAlh4=')
        encrypted_body = fernet.encrypt(b'already-encrypted')
        plain_body = b'plain'

        class Client:
            def __init__(self):
                self.put_calls = []

            def get_object(self, bucket, key):
                payloads = {
                    'prefix/encrypted': encrypted_body,
                    'prefix/plain': plain_body,
                }
                return FakeObjectResponse(payloads[key])

            def put_object(self, *args):
                self.put_calls.append(args)

        client = Client()
        with patch.object(s3, 'PRODUCTION_ENV', True), \
                patch.object(
                    s3.FileStoreS3, 'client',
                    new_callable=PropertyMock, return_value=client), \
                patch.object(
                    s3.FileStoreS3, 'list',
                    return_value=iter(['prefix/encrypted', 'prefix/plain'])), \
                patch.object(s3, 'get_fernet_key', return_value=fernet):
            result = filestore.ensure_encrypted('prefix')

        self.assertEqual(result, {
                'scanned': 2,
                'encrypted': 1,
                'skipped': 1,
                })
        self.assertEqual(len(client.put_calls), 1)
        self.assertEqual(client.put_calls[0][0], s3.bucket)
        self.assertEqual(client.put_calls[0][1], 'prefix/plain')
        self.assertEqual(
            s3.decompress(fernet.decrypt(client.put_calls[0][2].getvalue())),
            plain_body)

    def test_s3_filestore_ensure_encrypted_uses_multiple_threads(self):
        filestore = s3.FileStoreS3()
        fernet = Fernet('8BwFmKMykS2X2-gmwEwgfmA9hPN-pb4Ua5N2XyqAlh4=')
        barrier = threading.Barrier(2)
        thread_ids = set()

        class Client:
            def get_object(self, bucket, key):
                thread_ids.add(threading.get_ident())
                barrier.wait(timeout=1)
                return FakeObjectResponse(b'plain')

            def put_object(self, *args):
                return None

        with patch.object(s3, 'PRODUCTION_ENV', True), \
                patch.object(s3, 's3_workers', 2), \
                patch.object(
                    s3.FileStoreS3, 'client',
                    new_callable=PropertyMock, return_value=Client()), \
                patch.object(
                    s3.FileStoreS3, 'list',
                    return_value=iter(['prefix/first', 'prefix/second'])), \
                patch.object(s3, 'get_fernet_key', return_value=fernet):
            result = filestore.ensure_encrypted('prefix')

        self.assertEqual(result, {
                'scanned': 2,
                'encrypted': 2,
                'skipped': 0,
                })
        self.assertEqual(len(thread_ids), 2)

    def test_s3_filestore_ensure_uploaded(self):
        filestore = s3.FileStoreS3()
        fernet = Fernet('8BwFmKMykS2X2-gmwEwgfmA9hPN-pb4Ua5N2XyqAlh4=')

        class Client:
            def __init__(self):
                self.put_calls = []

            def stat_object(self, bucket, key):
                if key == 'attachments/missing-id':
                    raise FakeS3Error('404')
                return SimpleNamespace(size=1)

            def put_object(self, *args):
                self.put_calls.append(args)

        client = Client()
        with tempfile.TemporaryDirectory() as tmpdir:
            attachments = os.path.join(tmpdir, 'attachments')
            os.makedirs(os.path.join(attachments, 'aa', 'bb'))
            os.makedirs(os.path.join(attachments, 'cc', 'dd'))
            missing_path = os.path.join(
                attachments, 'aa', 'bb', 'missing-id')
            existing_path = os.path.join(
                attachments, 'cc', 'dd', 'existing-id')
            with open(missing_path, 'wb') as output:
                output.write(b'missing')
            with open(existing_path, 'wb') as output:
                output.write(b'existing')

            with patch.object(s3, 'PRODUCTION_ENV', True), \
                    patch.object(
                        s3.FileStoreS3, 'path',
                        new_callable=PropertyMock, return_value=tmpdir), \
                    patch.object(
                        s3.FileStoreS3, 'client',
                        new_callable=PropertyMock, return_value=client), \
                    patch.object(s3, 'get_fernet_key', return_value=fernet):
                result = filestore.ensure_uploaded('attachments')

        self.assertEqual(result, {
                'scanned': 2,
                'uploaded': 1,
                'skipped': 1,
                })
        self.assertEqual(len(client.put_calls), 1)
        self.assertEqual(client.put_calls[0][0], s3.bucket)
        self.assertEqual(client.put_calls[0][1], 'attachments/missing-id')
        self.assertEqual(
            s3.decompress(fernet.decrypt(client.put_calls[0][2].getvalue())),
            b'missing')

    def test_s3_filestore_ensure_uploaded_processes_more_than_100_files(self):
        filestore = s3.FileStoreS3()
        local_entries = [
            (f'file-{index:03d}', f'/tmp/file-{index:03d}')
            for index in range(101)
            ]

        class Client:
            def stat_object(self, bucket, key):
                return SimpleNamespace(size=1)

        with patch.object(s3, 'PRODUCTION_ENV', True), \
                patch.object(s3, 's3_workers', 2), \
                patch.object(
                    s3.FileStoreS3, 'client',
                    new_callable=PropertyMock, return_value=Client()), \
                patch.object(s3, 'local_files', return_value=iter(local_entries)):
            result = filestore.ensure_uploaded('attachments')

        self.assertEqual(result, {
                'scanned': 101,
                'uploaded': 0,
                'skipped': 101,
                })

    @with_transaction()
    def test_cron_sync_s3_filestore_cache_deactivates_after_execution(self):
        Cron = Pool().get('ir.cron')
        cron = self._create_sync_cron(Cron)

        self.assertTrue(cron.active)

        with Transaction().set_user(0), \
                patch.object(
                    s3.FileStoreS3, 'ensure_uploaded',
                    return_value={'scanned': 2, 'uploaded': 1, 'skipped': 1}
                    ) as ensure_uploaded:
            Cron.sync_s3_filestore_cache()

        ensure_uploaded.assert_called_once_with(Transaction().database.name)
        cron = Cron(cron.id)
        self.assertFalse(cron.active)

    @with_transaction()
    def test_cron_sync_s3_filestore_cache_deactivates_on_manual_run(self):
        Cron = Pool().get('ir.cron')
        cron = self._create_sync_cron(Cron)

        self.assertTrue(cron.active)

        with patch.object(
                s3.FileStoreS3, 'ensure_uploaded',
                return_value={'scanned': 0, 'uploaded': 0, 'skipped': 0}
                ) as ensure_uploaded:
            Cron.sync_s3_filestore_cache()

        ensure_uploaded.assert_called_once_with(Transaction().database.name)
        cron = Cron(cron.id)
        self.assertFalse(cron.active)

    @with_transaction()
    def test_cron_sync_s3_filestore_cache_deactivates_on_run_once(self):
        Cron = Pool().get('ir.cron')
        cron = self._create_sync_cron(Cron)

        self.assertTrue(cron.active)

        with patch.object(
                s3.FileStoreS3, 'ensure_uploaded',
                return_value={'scanned': 1, 'uploaded': 1, 'skipped': 0}
                ) as ensure_uploaded:
            Cron.run_once([cron])

        ensure_uploaded.assert_called_once_with(Transaction().database.name)
        cron = Cron(cron.id)
        self.assertFalse(cron.active)


del ModuleTestCase
