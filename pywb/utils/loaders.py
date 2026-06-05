from __future__ import absolute_import

"""
This module provides loaders for local file system and over http
local and remote access
"""

import os
import hmac
import hashlib
import requests
import yaml

import six
from six.moves.urllib.parse import unquote_plus, urlsplit, urlencode

import time
import pkgutil
import base64
import cgi
import re

from io import open, BytesIO
from warcio.limitreader import LimitReader
from pywb.utils.io import no_except_close, StreamClosingReader

try:
    import boto3
    from botocore import UNSIGNED
    from botocore.client import Config

    s3_avail = True
except ImportError:  # pragma: no cover
    s3_avail = False

try:
    from azure.storage.blob import BlobServiceClient
    from azure.core.credentials import AzureNamedKeyCredential, AzureSasCredential
    from azure.identity import (
        ClientSecretCredential,
        DefaultAzureCredential,
        ManagedIdentityCredential,
    )
    azure_blob_avail = True
except ImportError:  # pragma: no cover
    azure_blob_avail = False


# ============================================================================
def init_yaml_env_vars():
    """Initializes the yaml parser to be able to set
    the value of fields from environment variables

    :rtype: None
    """
    env_rx = re.compile(r'\$\{[^}]+\}')

    yaml.add_implicit_resolver('!envvar', env_rx)

    def envvar_constructor(loader, node):
        value = loader.construct_scalar(node)
        value = os.path.expandvars(value)
        return value

    yaml.add_constructor('!envvar', envvar_constructor)


# ============================================================================
def load_py_name(string):
    import importlib

    string = string.split(':', 1)
    mod = importlib.import_module(string[0])
    return getattr(mod, string[1])


# =================================================================
def is_http(filename):
    return filename.startswith(('http://', 'https://'))


# =================================================================
def to_file_url(filename):
    """ Convert a filename to a file:// url
    """
    url = 'file://' + os.path.abspath(filename).replace(os.path.sep, '/')
    return url


# =================================================================
def from_file_url(url):
    """ Convert from file:// url to file path
    """
    if url.startswith('file://'):
        url = url[len('file://'):].replace('/', os.path.sep)

    return url


# =================================================================
def load(filename):
    return BlockLoader().load(filename)


# =============================================================================
def load_yaml_config(config_file):
    config = None
    configdata = None
    try:
        configdata = load(config_file)
        config = yaml.load(configdata, Loader=yaml.Loader)
    finally:
        no_except_close(configdata)

    return config


# =============================================================================
def load_overlay_config(main_env_var, main_default_file='',
                        overlay_env_var='', overlay_file=''):
    configfile = os.environ.get(main_env_var, main_default_file)
    config = None

    if configfile:
        configfile = os.path.expandvars(configfile)

        config = load_yaml_config(configfile)

    config = config or {}

    overlay_configfile = os.environ.get(overlay_env_var, overlay_file)

    if overlay_configfile:
        overlay_configfile = os.path.expandvars(overlay_configfile)
        config.update(load_yaml_config(overlay_configfile))

    return config


# =================================================================
def extract_client_cookie(env, cookie_name):
    cookie_header = env.get('HTTP_COOKIE')
    if not cookie_header:
        return None

    # attempt to extract cookie_name only
    inx = cookie_header.find(cookie_name)
    if inx < 0:
        return None

    end_inx = cookie_header.find(';', inx)
    if end_inx > 0:
        value = cookie_header[inx:end_inx]
    else:
        value = cookie_header[inx:]

    value = value.split('=')
    if len(value) < 2:
        return None

    value = value[1].strip()
    return value


# =================================================================
def read_last_line(fh, offset=256):
    """ Read last line from a seekable file. Start reading
    from buff before end of file, and double backwards seek
    until line break is found. If reached beginning of file
    (no lines), just return whole file
    """
    fh.seek(0, 2)
    size = fh.tell()

    while offset < size:
        fh.seek(-offset, 2)
        lines = fh.readlines()
        if len(lines) > 1:
            return lines[-1]
        offset *= 2

    fh.seek(0, 0)
    return fh.readlines()[-1]


# =================================================================
class BaseLoader(object):
    def __init__(self, **kwargs):
        pass

    def load(self, url, offset=0, length=-1):
        raise NotImplemented()


# =================================================================
class BlockLoader(BaseLoader):
    """
    a loader which can stream blocks of content
    given a uri, offset and optional length.
    Currently supports: http/https, file/local file system,
    pkg, WebHDFS, S3
    """

    loaders = {}
    profile_loader = None

    def __init__(self, **kwargs):
        super(BlockLoader, self).__init__()
        self.cached = {}
        self.kwargs = kwargs

    def load(self, url, offset=0, length=-1):
        loader, url = self._get_loader_for_url(url)
        return loader.load(url, offset, length)

    def _get_loader_for_url(self, url):
        """
        Determine loading method based on uri
        """
        parts = url.split('://', 1)
        if len(parts) < 2:
            type_ = 'file'
        else:
            type_ = parts[0]

        if '+' in type_:
            profile_name, scheme = type_.split('+', 1)
            if len(parts) == 2:
                url = scheme + '://' + parts[1]
        else:
            profile_name = ''
            scheme = type_

        loader = self.cached.get(type_)
        if loader:
            return loader, url

        loader_cls = self._get_loader_class_for_type(scheme)

        if not loader_cls:
            raise IOError('No Loader for type: ' + scheme)

        profile = self.kwargs

        if self.profile_loader:
            profile = self.profile_loader(profile_name, scheme)

        loader = loader_cls(**profile)

        self.cached[type_] = loader
        return loader, url

    def _get_loader_class_for_type(self, type_):
        loader_cls = self.loaders.get(type_)
        return loader_cls

    @staticmethod
    def init_default_loaders():
        BlockLoader.loaders['http'] = HttpLoader
        BlockLoader.loaders['https'] = HttpLoader
        BlockLoader.loaders['s3'] = S3Loader
        BlockLoader.loaders['azure'] = AzureBlobLoader
        BlockLoader.loaders['file'] = LocalFileLoader
        BlockLoader.loaders['pkg'] = PackageLoader
        BlockLoader.loaders['webhdfs'] = WebHDFSLoader

    @staticmethod
    def set_profile_loader(src):
        BlockLoader.profile_loader = src

    @staticmethod
    def _make_range_header(offset, length):
        if length > 0:
            range_header = 'bytes={0}-{1}'.format(offset, offset + length - 1)
        else:
            range_header = 'bytes={0}-'.format(offset)

        return range_header


# =================================================================
class PackageLoader(BaseLoader):
    def load(self, url, offset=0, length=-1):
        if url.startswith('pkg://'):
            url = url[len('pkg://'):]

        # then, try as package.path/file
        pkg_split = url.split('/', 1)
        if len(pkg_split) == 1:
            raise

        data = pkgutil.get_data(pkg_split[0], pkg_split[1])
        if offset > 0:
            data = data[offset:]

        if length > -1:
            data = data[:length]

        buff = BytesIO(data)
        buff.name = url
        return buff

        # afile = pkg_resources.resource_stream(pkg_split[0],
        #                                      pkg_split[1])


# =================================================================
class LocalFileLoader(PackageLoader):
    def load(self, url, offset=0, length=-1):
        """
        Load a file-like reader from the local file system
        """

        # if starting with . or /, can only be a file path..
        file_only = url.startswith(('/', '.'))

        # convert to filename
        filename = from_file_url(url)
        if filename != url:
            file_only = True
            url = filename

        afile = None
        try:
            # first, try as file
            afile = open(url, 'rb')

        except IOError:
            no_except_close(afile)
            if file_only:
                raise

            return super(LocalFileLoader, self).load(url, offset, length)

        if offset > 0:
            afile.seek(offset)

        if length >= 0:
            return LimitReader(afile, length)
        else:
            return afile


# =================================================================
class HttpLoader(BaseLoader):
    def __init__(self, **kwargs):
        super(HttpLoader, self).__init__()
        self.cookie_maker = kwargs.get('cookie_maker')
        if not self.cookie_maker:
            self.cookie_maker = kwargs.get('cookie')
        self.session = None
        self.decode_content = kwargs.get('decode_content', False)

    def load(self, url, offset, length):
        """
        Load a file-like reader over http using range requests
        and an optional cookie created via a cookie_maker
        """
        headers = {}
        if offset != 0 or length != -1:
            headers['Range'] = BlockLoader._make_range_header(offset, length)

        if self.cookie_maker:
            if isinstance(self.cookie_maker, six.string_types):
                headers['Cookie'] = self.cookie_maker
            else:
                headers['Cookie'] = self.cookie_maker.make()

        if not self.session:
            self.session = requests.Session()

        r = self.session.get(url, headers=headers, stream=True)
        r.raise_for_status()
        if self.decode_content:
            r.raw.decode_content = True
        return StreamClosingReader(r.raw)


# =================================================================
class S3Loader(BaseLoader):
    def __init__(self, **kwargs):
        super(S3Loader, self).__init__()
        self.client = None
        self.aws_access_key_id = kwargs.get('aws_access_key_id')
        self.aws_secret_access_key = kwargs.get('aws_secret_access_key')

    def load(self, url, offset, length):
        if not s3_avail:  # pragma: no cover
            raise IOError('To load from s3 paths, ' +
                          'you must install boto3: pip install boto3')

        aws_access_key_id = self.aws_access_key_id
        aws_secret_access_key = self.aws_secret_access_key

        parts = urlsplit(url)

        if parts.username and parts.password:
            aws_access_key_id = unquote_plus(parts.username)
            aws_secret_access_key = unquote_plus(parts.password)
            bucket_name = parts.netloc.split('@', 1)[-1]
        else:
            bucket_name = parts.netloc

        key = parts.path[1:]

        if offset == 0 and length == -1:
            range_ = ''
        else:
            range_ = BlockLoader._make_range_header(offset, length)

        def s3_load(anon=False):
            if not self.client:
                s3_client_args = {}
                if anon:
                    s3_client_args['config'] = Config(signature_version=UNSIGNED)
                if aws_access_key_id:
                    s3_client_args['aws_access_key_id'] = aws_access_key_id
                    s3_client_args['aws_secret_access_key'] = aws_secret_access_key

                client = boto3.client('s3', **s3_client_args)

            else:
                client = self.client

            res = client.get_object(Bucket=bucket_name,
                                    Key=key,
                                    Range=range_)

            if not self.client:
                self.client = client

            return res

        try:
            obj = s3_load(anon=False)

        except Exception:
            if not self.client:
                obj = s3_load(anon=True)
            else:
                raise

        return obj['Body']


# ============================================================================
class AzureBlobLoader(BaseLoader):

    DEFAULT_SUFFIX = 'blob.core.windows.net'

    def __init__(self, **kwargs):
        super(AzureBlobLoader, self).__init__()

        self.clients = {}

        config = load_yaml_config('./config.yaml')
        self.auth = config['azure_auth']
        self.account_key = config['azure_account_key']
        self.sas_token = config['azure_sas_token']
        self.tenant_id = config['azure_tenant_id']
        self.client_id = config['azure_client_id']
        self.client_secret = config['azure_client_secret']
        self.managed_identity_client_id = config['azure_managed_identity_client_id']
        self.account_url = config['azure_account_url']
        self.endpoint_suffix = config['azure_endpoint_suffix']

    def load(self, url, offset=0, length=-1):
        if not azure_blob_avail:  # pragma: no cover
            raise IOError(
                'To load from Azure Blob paths, you must install Azure SDKs: '
                'pip install azure-storage-blob azure-identity'
            )

        parts = urlsplit(url)

        account_name = parts.netloc
        path = parts.path[1:]

        if not account_name:
            raise IOError('Azure Blob URL must include storage account name')

        path_parts = path.split('/', 1)
        if len(path_parts) != 2:
            raise IOError(
                'Azure Blob URL must be of the form '
                'azure://<account>/<container>/<blob>'
            )

        container_name, blob_name = path_parts

        # SAS can be supplied in the URI query string.
        sas_from_url = parts.query or None

        client = self._get_client(account_name, sas_from_url)

        blob_client = client.get_blob_client(
            container=container_name,
            blob=blob_name
        )

        if length is not None and length >= 0:
            downloader = blob_client.download_blob(offset=offset, length=length)
        elif offset:
            downloader = blob_client.download_blob(offset=offset)
        else:
            downloader = blob_client.download_blob()

        return AzureBlobIteratorReader(downloader.chunks())

    def _get_client(self, account_name, sas_from_url=None):
        auth = self._resolve_auth()

        # Cache per account/auth/SAS. SAS in URL may vary by request.
        cache_key = (account_name, auth, sas_from_url)
        client = self.clients.get(cache_key)
        if client:
            return client

        account_url = self._make_account_url(account_name)

        credential = self._make_credential(account_name, auth, sas_from_url)

        client = BlobServiceClient(
            account_url=account_url,
            credential=credential
        )

        self.clients[cache_key] = client
        return client

    def _make_account_url(self, account_name):
        if self.account_url:
            return self.account_url

        return 'https://{0}.{1}'.format(account_name, self.endpoint_suffix)
    
    def _resolve_auth(self):
        if not self.auth:
            raise IOError(
                'Azure Blob auth requires azure_auth to be set. '
                'Valid values are: access_key, sas, service_principal, '
                'managed_identity, default, anonymous'
            )

        return self.auth

    def _make_credential(self, account_name, auth, sas_from_url=None):
        auth = auth.lower()

        valid_auth_options = ('access_key', 'sas', 'service_principal', 'managed_identity', 'default', 'anonymous')

        if auth not in valid_auth_options:
            raise IOError(
                'Invalid Azure Blob auth type: {0}. '
                'Valid values are: {1}'.format(
                    auth,
                    ', '.join(valid_auth_options)
                )
            )

        if auth == 'anonymous':
            return None

        if auth == 'access_key':
            if not self.account_key:
                raise IOError('Azure Blob access key auth requires azure_account_key')
            return AzureNamedKeyCredential(account_name, self.account_key)

        if auth == 'sas':
            sas = sas_from_url or self.sas_token
            if not sas:
                raise IOError('Azure Blob SAS auth requires azure_sas_token or URL query SAS')

            # AzureSasCredential expects the raw token without leading '?'.
            if sas.startswith('?'):
                sas = sas[1:]

            return AzureSasCredential(sas)

        if auth == 'service_principal':
            if not (self.tenant_id and self.client_id and self.client_secret):
                raise IOError(
                    'Azure Blob service principal auth requires '
                    'azure_tenant_id, azure_client_id, and azure_client_secret'
                )

            return ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )

        if auth == 'managed_identity':
            if self.managed_identity_client_id:
                return ManagedIdentityCredential(
                    client_id=self.managed_identity_client_id
                )

            return ManagedIdentityCredential()

        if auth == 'default':
            kwargs = {}

            if self.managed_identity_client_id:
                kwargs['managed_identity_client_id'] = self.managed_identity_client_id

            return DefaultAzureCredential(**kwargs)
        

# =================================================================
class WebHDFSLoader(HttpLoader):
    """Loader class specifically for loading webhdfs content"""

    HTTP_URL = 'http://{host}/webhdfs/v1{path}?'

    def load(self, url, offset, length):
        """Loads the supplied web hdfs content

        :param str url: The URL to the web hdfs content to be loaded
        :param int|float|double offset: The offset of the content to be loaded
        :param int|float|double length: The length of the content to be loaded
        :return: The raw response content
        """
        parts = urlsplit(url)

        http_url = self.HTTP_URL.format(host=parts.netloc,
                                        path=parts.path)

        params = {'op': 'OPEN',
                  'offset': str(offset)
                 }

        if length > 0:
            params['length'] = str(length)

        if os.environ.get('WEBHDFS_USER'):
            params['user.name'] = os.environ.get('WEBHDFS_USER')

        if os.environ.get('WEBHDFS_TOKEN'):
            params['delegation'] = os.environ.get('WEBHDFS_TOKEN')

        http_url += urlencode(params)

        return super(WebHDFSLoader, self).load(http_url, 0, -1)


# =================================================================
# Signed Cookie-Maker
# =================================================================

class HMACCookieMaker(object):
    """
    Utility class to produce signed HMAC digest cookies
    to be used with each http request
    """

    def __init__(self, key, name, duration=10):
        self.key = key
        self.name = name
        # duration in seconds
        self.duration = duration

    def make(self, extra_id=''):
        expire = str(int(time.time() + self.duration))

        if extra_id:
            msg = extra_id + '-' + expire
        else:
            msg = expire

        hmacdigest = hmac.new(self.key.encode('utf-8'), msg.encode('utf-8'), digestmod=hashlib.md5)
        hexdigest = hmacdigest.hexdigest()

        if extra_id:
            cookie = '{0}-{1}={2}-{3}'.format(self.name, extra_id,
                                              expire, hexdigest)
        else:
            cookie = '{0}={1}-{2}'.format(self.name, expire, hexdigest)

        return cookie


# =================================================================
# Wrapper for Azure StorageStreamDownloader
# =================================================================

class AzureBlobIteratorReader(object):
    """A minimal file-like reader over an iterator of byte chunks."""

    def __init__(self, iterator):
        self.iterator = iterator
        self.buff = b''
        self.closed = False

    def read(self, size=-1):
        if self.closed:
            return b''

        if size is None or size < 0:
            chunks = [self.buff]
            self.buff = b''
            chunks.extend(self.iterator)
            return b''.join(chunks)

        while len(self.buff) < size:
            try:
                self.buff += next(self.iterator)
            except StopIteration:
                break

        result = self.buff[:size]
        self.buff = self.buff[size:]
        return result

    def close(self):
        self.closed = True
        self.buff = b''

# ============================================================================
BlockLoader.init_default_loaders()

init_yaml_env_vars()
