r"""
#=================================================================
# BlockLoader Tests (includes LimitReader)
# Ensure attempt to read more than 100 bytes, reads exactly 100 bytes
>>> len(BlockLoader().load(test_cdx_dir + 'iana.cdx', 0, 100).read(400))
100

# no length specified, read full amount requested
>>> len(BlockLoader().load(to_file_url(test_cdx_dir + 'example.cdx'), 0, -1).read(400))
400

# no such file
#>>> len(BlockLoader().load('_x_no_such_file_', 0, 100).read(400))  # doctest: +IGNORE_EXCEPTION_DETAIL
Traceback (most recent call last):
IOError: [Errno 2] No such file or directory: '_x_no_such_file_'

# Disable for now
# HMAC Cookie Maker
#>>> print_str(BlockLoader(cookie_maker=HMACCookieMaker('test', 'test', 5), decode_content=False).load('https://example.com', 41, 14).read())
#'Example Domain'

# fixed cookie, range request
#>>> print_str(BlockLoader(cookie='some=value', decode_content=True).load('https://example.com', 41, 14).read())
'Example Domain'

# range request
#>>> print_str(BlockLoader(decode_content=True).load('https://example.com', 1248).read())
'</html>\n'

# custom profile
#>>> print_str(BlockLoader(decode_content=True).load('local+https://example.com', 1248).read())
'</html>\n'

# unknown loader error
#>>> BlockLoader().load('foo://example.com', 10).read()  # doctest: +IGNORE_EXCEPTION_DETAIL
#Traceback (most recent call last):
#IOError: No Loader for type: foo

# test with extra id, ensure 4 parts of the A-B=C-D form are present
>>> len(re.split('[-=]', HMACCookieMaker('test', 'test', 5).make('extra')))
4

# cookie extract tests
>>> extract_client_cookie(dict(HTTP_COOKIE='a=b; c=d'), 'a')
'b'

>>> extract_client_cookie(dict(HTTP_COOKIE='a=b; c=d'), 'c')
'd'

>>> extract_client_cookie(dict(HTTP_COOKIE='a=b; c=d'), 'x')

>>> extract_client_cookie(dict(HTTP_COOKIE='x'), 'x')

>>> extract_client_cookie({}, 'y')

# test read_last_line
>>> print_str(read_last_line(BytesIO(b'A\nB\nC')))
'C'

>>> print_str(read_last_line(BytesIO(b'Some Line\nLonger Line\nLongest Last Line LL'), offset=8))
'Longest Last Line LL'

>>> print_str(read_last_line(BytesIO(b'A\nBC')))
'BC'

>>> print_str(read_last_line(BytesIO(b'A\nBC\n')))
'BC\n'

>>> print_str(read_last_line(BytesIO(b'ABC')))
'ABC'

"""


#=================================================================
import re
import os
import pytest

from io import StringIO
from io import BytesIO
import requests
import yaml
from yaml import Loader

from pywb.utils.loaders import BlockLoader, HMACCookieMaker, to_file_url
from pywb.utils.loaders import extract_client_cookie
from pywb.utils.loaders import read_last_line

from pywb.utils.canonicalize import canonicalize

from mock import patch
from unittest.mock import Mock

import pywb.utils.loaders as loaders

from warcio.bufferedreaders import DecompressingBufferedReader

from pywb import get_test_dir

test_cdx_dir = get_test_dir() + 'cdx/'

def s3_authenticated_access_verification(bucket):
    import boto3, botocore
    s3_client = boto3.client('s3')
    try:
        s3_client.head_bucket(Bucket=bucket)
    except botocore.exceptions.NoCredentialsError:
        pytest.skip("Skipping S3Loader test for authenticated reads: no credentials configured")

@pytest.mark.live
def test_s3_read_authenticated_1():
    pytest.importorskip('boto3')
    pytest.skip("credentials issue, to fix later")

    s3_authenticated_access_verification('commoncrawl')

    res = BlockLoader().load('s3://commoncrawl/crawl-data/CC-MAIN-2015-11/segments/1424936462700.28/warc/CC-MAIN-20150226074102-00159-ip-10-28-5-156.ec2.internal.warc.gz',
                             offset=53235662,
                             length=2526)

    buff = res.read()
    assert len(buff) == 2526

    reader = DecompressingBufferedReader(BytesIO(buff))
    assert reader.readline() == b'WARC/1.0\r\n'
    assert reader.readline() == b'WARC-Type: response\r\n'

@pytest.mark.live
def test_s3_read_authenticated_2():
    pytest.importorskip('boto3')
    pytest.skip("credentials issue, to fix later")

    s3_authenticated_access_verification('commoncrawl')

    res = BlockLoader().load('s3://commoncrawl/crawl-data/CC-MAIN-2015-11/index.html')

    buff = res.read()
    assert len(buff) == 2330

    reader = DecompressingBufferedReader(BytesIO(buff))
    assert reader.readline() == b'<!DOCTYPE html>\n'

def mock_load(expected):
    def mock(self, url, offset, length):
        assert canonicalize(url) == canonicalize(expected)
        assert offset == 0
        assert length == -1
        return None

    return mock

def test_mock_webhdfs_load_1():
    expected = 'http://remote-host:1234/webhdfs/v1/some/file.warc.gz?op=OPEN&offset=10&length=50'
    with patch('pywb.utils.loaders.HttpLoader.load', mock_load(expected)):
        res = BlockLoader().load('webhdfs://remote-host:1234/some/file.warc.gz', 10, 50)

def test_mock_webhdfs_load_2():
    expected = 'http://remote-host/webhdfs/v1/some/file.warc.gz?op=OPEN&offset=10'
    with patch('pywb.utils.loaders.HttpLoader.load', mock_load(expected)):
        res = BlockLoader().load('webhdfs://remote-host/some/file.warc.gz', 10, -1)

def test_mock_webhdfs_load_3_username():
    os.environ['WEBHDFS_USER'] = 'someuser'
    expected = 'http://remote-host/webhdfs/v1/some/file.warc.gz?op=OPEN&offset=10&user.name=someuser'
    with patch('pywb.utils.loaders.HttpLoader.load', mock_load(expected)):
        res = BlockLoader().load('webhdfs://remote-host/some/file.warc.gz', 10, -1)

def test_mock_webhdfs_load_4_token():
    os.environ['WEBHDFS_USER'] = ''
    os.environ['WEBHDFS_TOKEN'] = 'ATOKEN'
    expected = 'http://remote-host/webhdfs/v1/some/file.warc.gz?op=OPEN&offset=10&delegation=ATOKEN'
    with patch('pywb.utils.loaders.HttpLoader.load', mock_load(expected)):
        res = BlockLoader().load('webhdfs://remote-host/some/file.warc.gz', 10, -1)


# Error
def test_err_no_such_file():
    # no such file
    with pytest.raises(IOError):
        len(BlockLoader().load('_x_no_such_file_', 0, 100).read('400'))


def test_err_unknown_loader():
    # unknown loader error
    with pytest.raises(IOError):
        BlockLoader().load('foo://example.com', 10).read()
#IOError: No Loader for type: foo



def test_yaml_resolve_env():
    os.environ['PYWB_PATH'] = './test'
    os.environ['PYWB_FOO'] = 'bar'

    config = """\
collection:
    coll:
        index: ${PYWB_PATH}/index
        archive: ${PYWB_PATH}/archive/${PYWB_FOO}
        other: ${PYWB_NOT}/archive/${PYWB_FOO}
"""

    config_data = yaml.load(config, Loader=Loader)

    assert config_data['collection']['coll']['index'] == './test/index'
    assert config_data['collection']['coll']['archive'] == './test/archive/bar'
    assert config_data['collection']['coll']['other'] == '${PYWB_NOT}/archive/bar'

    del os.environ['PYWB_PATH']
    del os.environ['PYWB_FOO']

def print_str(string):
    return string.decode('utf-8')


########################
# AzureBlobLoader tests
########################

def make_azure_loader(monkeypatch, config=None):
    """Build an AzureBlobLoader using a controlled config.yaml result."""
    if config is None:
        config = {}

    monkeypatch.setattr(loaders, 'load_yaml_config', lambda _filename: config)
    return loaders.AzureBlobLoader()


@pytest.fixture
def azure_sdk(monkeypatch):
    """Mock Azure SDK symbols, including when the optional SDK is absent."""
    sdk_mocks = {
        'BlobServiceClient': Mock(name='BlobServiceClient'),
        'AzureNamedKeyCredential': Mock(name='AzureNamedKeyCredential'),
        'AzureSasCredential': Mock(name='AzureSasCredential'),
        'ClientSecretCredential': Mock(name='ClientSecretCredential'),
        'ManagedIdentityCredential': Mock(name='ManagedIdentityCredential'),
        'DefaultAzureCredential': Mock(name='DefaultAzureCredential'),
    }

    for name, mock_obj in sdk_mocks.items():
        # raising=False also supports test environments without Azure SDKs,
        # where these names are not defined by pywb.utils.loaders.
        monkeypatch.setattr(loaders, name, mock_obj, raising=False)

    monkeypatch.setattr(loaders, 'azure_blob_avail', True)
    return sdk_mocks


class TestAzureBlobLoader:
    def test_load_full_blob(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'anonymous'})
        service_client = Mock(name='service_client')
        azure_sdk['BlobServiceClient'].return_value = service_client
        blob_client = service_client.get_blob_client.return_value
        blob_client.download_blob.return_value.chunks.return_value = iter(
            [b'hello ', b'azure ', b'blob']
        )

        reader = loader.load('azure://mystorage/warcs/example.warc.gz')

        assert reader.read() == b'hello azure blob'
        azure_sdk['BlobServiceClient'].assert_called_once_with(
            account_url='https://mystorage.blob.core.windows.net',
            credential=None,
        )
        service_client.get_blob_client.assert_called_once_with(
            container='warcs', blob='example.warc.gz'
        )
        blob_client.download_blob.assert_called_once_with()

    @pytest.mark.parametrize(
        ('offset', 'length', 'expected_download_args'),
        [
            (0, -1, {}),
            (128, -1, {'offset': 128}),
            (128, 64, {'offset': 128, 'length': 64}),
            (0, None, {}),
        ],
    )
    def test_load_blob_with_range(
        self, monkeypatch, azure_sdk, offset, length, expected_download_args
    ):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'anonymous'})
        service_client = Mock(name='service_client')
        azure_sdk['BlobServiceClient'].return_value = service_client
        blob_client = service_client.get_blob_client.return_value
        blob_client.download_blob.return_value.chunks.return_value = iter([b'data'])

        reader = loader.load(
            'azure://mystorage/warcs/example.warc.gz',
            offset=offset,
            length=length,
        )

        assert reader.read() == b'data'
        blob_client.download_blob.assert_called_once_with(**expected_download_args)

    def test_blob_name_can_contain_nested_path(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'anonymous'})
        service_client = Mock(name='service_client')
        azure_sdk['BlobServiceClient'].return_value = service_client

        loader.load('azure://mystorage/warcs/2024/01/example.warc.gz')

        service_client.get_blob_client.assert_called_once_with(
            container='warcs', blob='2024/01/example.warc.gz'
        )

    def test_account_url_can_be_overridden(self, monkeypatch, azure_sdk):
        custom_url = 'https://custom-storage.example.test'
        loader = make_azure_loader(
            monkeypatch,
            {'azure_auth': 'anonymous', 'azure_account_url': custom_url},
        )

        loader.load('azure://mystorage/container/blob')

        azure_sdk['BlobServiceClient'].assert_called_once_with(
            account_url=custom_url, credential=None
        )

    def test_access_key_auth(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(
            monkeypatch, {'azure_account_key': 'storage-account-key'}
        )

        credential = loader._make_credential('mystorage', 'access_key')

        azure_sdk['AzureNamedKeyCredential'].assert_called_once_with(
            'mystorage', 'storage-account-key'
        )
        assert credential is azure_sdk['AzureNamedKeyCredential'].return_value

    def test_sas_auth_uses_configured_token_and_strips_question_mark(
        self, monkeypatch, azure_sdk
    ):
        loader = make_azure_loader(
            monkeypatch, {'azure_sas_token': '?sv=configured&sig=secret'}
        )

        credential = loader._make_credential('mystorage', 'sas')

        azure_sdk['AzureSasCredential'].assert_called_once_with(
            'sv=configured&sig=secret'
        )
        assert credential is azure_sdk['AzureSasCredential'].return_value

    def test_sas_in_url_takes_precedence_over_configured_token(
        self, monkeypatch, azure_sdk
    ):
        loader = make_azure_loader(
            monkeypatch,
            {'azure_auth': 'sas', 'azure_sas_token': 'configured-token'},
        )
        service_client = Mock(name='service_client')
        azure_sdk['BlobServiceClient'].return_value = service_client

        loader.load(
            'azure://mystorage/container/blob?sv=url-token&sig=url-signature'
        )

        azure_sdk['AzureSasCredential'].assert_called_once_with(
            'sv=url-token&sig=url-signature'
        )
        azure_sdk['BlobServiceClient'].assert_called_once_with(
            account_url='https://mystorage.blob.core.windows.net',
            credential=azure_sdk['AzureSasCredential'].return_value,
        )

    def test_service_principal_auth(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(
            monkeypatch,
            {
                'azure_tenant_id': 'tenant-id',
                'azure_client_id': 'client-id',
                'azure_client_secret': 'client-secret',
            },
        )

        credential = loader._make_credential('mystorage', 'service_principal')

        azure_sdk['ClientSecretCredential'].assert_called_once_with(
            tenant_id='tenant-id',
            client_id='client-id',
            client_secret='client-secret',
        )
        assert credential is azure_sdk['ClientSecretCredential'].return_value

    @pytest.mark.parametrize(
        ('managed_identity_client_id', 'expected_args'),
        [
            ('user-assigned-client-id', {'client_id': 'user-assigned-client-id'}),
            (None, {}),
        ],
    )
    def test_managed_identity_auth(
        self, monkeypatch, azure_sdk, managed_identity_client_id, expected_args
    ):
        loader = make_azure_loader(
            monkeypatch,
            {'azure_managed_identity_client_id': managed_identity_client_id},
        )

        credential = loader._make_credential('mystorage', 'managed_identity')

        azure_sdk['ManagedIdentityCredential'].assert_called_once_with(
            **expected_args
        )
        assert credential is azure_sdk['ManagedIdentityCredential'].return_value

    @pytest.mark.parametrize(
        ('managed_identity_client_id', 'expected_args'),
        [
            (
                'user-assigned-client-id',
                {'managed_identity_client_id': 'user-assigned-client-id'},
            ),
            (None, {}),
        ],
    )
    def test_default_auth(
        self, monkeypatch, azure_sdk, managed_identity_client_id, expected_args
    ):
        loader = make_azure_loader(
            monkeypatch,
            {'azure_managed_identity_client_id': managed_identity_client_id},
        )

        credential = loader._make_credential('mystorage', 'default')

        azure_sdk['DefaultAzureCredential'].assert_called_once_with(
            **expected_args
        )
        assert credential is azure_sdk['DefaultAzureCredential'].return_value

    def test_anonymous_auth_returns_no_credential(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch)

        assert loader._make_credential('mystorage', 'anonymous') is None

    def test_client_is_cached_for_same_account_and_sas(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'sas'})
        clients = [Mock(name='client1'), Mock(name='client2'), Mock(name='client3')]
        azure_sdk['BlobServiceClient'].side_effect = clients

        first_client = loader._get_client('mystorage', 'sv=one')
        cached_client = loader._get_client('mystorage', 'sv=one')
        second_sas_client = loader._get_client('mystorage', 'sv=two')
        second_account_client = loader._get_client('anotherstorage', 'sv=one')

        assert first_client is cached_client
        assert second_sas_client is not first_client
        assert second_account_client is not first_client
        assert azure_sdk['BlobServiceClient'].call_count == 3

    def test_missing_auth_configuration_raises(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch)

        with pytest.raises(IOError, match='azure_auth to be set'):
            loader.load('azure://mystorage/container/blob')

    def test_invalid_auth_type_raises(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'unknown'})

        with pytest.raises(IOError, match='Invalid Azure Blob auth type'):
            loader.load('azure://mystorage/container/blob')

    def test_access_key_auth_requires_key(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'access_key'})

        with pytest.raises(IOError, match='azure_account_key'):
            loader.load('azure://mystorage/container/blob')

    def test_sas_auth_requires_token(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'sas'})

        with pytest.raises(IOError, match='azure_sas_token'):
            loader.load('azure://mystorage/container/blob')

    def test_service_principal_requires_all_credentials(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(
            monkeypatch,
            {
                'azure_auth': 'service_principal',
                'azure_tenant_id': 'tenant-id',
                'azure_client_id': 'client-id',
                # client secret intentionally omitted
            },
        )

        with pytest.raises(IOError, match='azure_tenant_id, azure_client_id'):
            loader.load('azure://mystorage/container/blob')

    def test_url_must_include_storage_account(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'anonymous'})

        with pytest.raises(IOError, match='include storage account name'):
            loader.load('azure:///container/blob')

    def test_url_must_include_container_and_blob(self, monkeypatch, azure_sdk):
        loader = make_azure_loader(monkeypatch, {'azure_auth': 'anonymous'})

        with pytest.raises(IOError, match='<container>/<blob>'):
            loader.load('azure://mystorage/container-only')


class TestAzureBlobIteratorReader:
    def test_read_in_sizes_across_chunk_boundaries(self):
        reader = loaders.AzureBlobIteratorReader(iter([b'abc', b'def', b'gh']))

        assert reader.read(2) == b'ab'
        assert reader.read(3) == b'cde'
        assert reader.read(1) == b'f'
        assert reader.read() == b'gh'
        assert reader.read() == b''

    def test_read_larger_than_remaining_data(self):
        reader = loaders.AzureBlobIteratorReader(iter([b'abc', b'def']))

        assert reader.read(20) == b'abcdef'
        assert reader.read(1) == b''


if __name__ == "__main__":
    import doctest
    doctest.testmod()


