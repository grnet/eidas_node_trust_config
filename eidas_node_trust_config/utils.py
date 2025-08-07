import os
import datetime
import json
from io import BytesIO
from binascii import hexlify
from pathlib import Path
from urllib.parse import urldefrag
from xmlsec.crypto import _cert_fingerprint as xmlsec_cert_fingerprint
from cryptography.hazmat.primitives.serialization import Encoding as CryptoSerializationEncoding
from cryptography.hazmat.primitives.hashes import SHA256
from jsonschema.validators import validator_for as jsonschema_validator_for
from jsonpointer import resolve_pointer as jsonpointer_resolve_pointer
from lxml import etree
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
import yaml

try:
    import importlib.resources as importlib_resources
    pkg_resources = None
except ImportError:
    importlib_resources = None
    try:
        import pkg_resources
    except ImportError:
        raise ImportError("No module named 'importlib.resources' or 'pkg_resources'")

def is_cert_expired(cert):
    if hasattr(cert, 'not_valid_after_utc'):
        return cert.not_valid_after_utc < datetime.datetime.now(datetime.UTC)
    else:
        return cert.not_valid_after < datetime.datetime.now()

def update_fp_pem_mapping(certificates, cert, filter_expired=True):
    fp, cert = xmlsec_cert_fingerprint(cert)
    if filter_expired and is_cert_expired(cert):
        return
    fp = hexlify(cert.fingerprint(SHA256())).lower().decode('ascii')
    cert = cert.public_bytes(CryptoSerializationEncoding.PEM).decode('ascii')
    certificates.update({fp: cert})

# def b64_slugify(s):
#     return s.replace('/', '_').replace('+', '-')

class ResourceCache:
    """
    A singleton class that provides a cache for package resources.

    The ResourceCache class retrieves and caches package file resources.
    It ensures that only one instance of the class is created, making it a singleton.

    This class utilizes either the `importlib.resources` or `pkg_resources` module to fetch and cache resources
    from a python package, defaulting to the current package. It first checks if `importlib.resources` is available,
    and if not, falls back to `pkg_resources`.

    Attributes:
        _cache (dict): A dictionary that stores the cached resources.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._cache = getattr(self, '_cache', {})

    def _load_resource(self, package, filename):
        if importlib_resources is not None:
            ref = importlib_resources.files(package).joinpath(filename)
            if not ref.is_file():
                raise FileNotFoundError(f"Resource not found: {package}/{filename}")
            with importlib_resources.as_file(ref) as schema_file:
                return Path(schema_file).read_text()
        elif pkg_resources is not None:
            ref = (package, filename)
            if not pkg_resources.resource_exists(*ref) or pkg_resources.resource_isdir(*ref):
                raise FileNotFoundError(f"Resource not found or is a directory: {package}/{filename}")
            schema_file = pkg_resources.resource_filename(*ref)
            return Path(schema_file).read_text()

    def get_package_resource_as_text(self, filename):
        """
        Retrieve the contents of a resource file from this package as text.

        Args:
            filename (str): The name of the resource file.

        Returns:
            str: The contents of the resource file as text.
        """
        k = (__package__, filename)
        return self._cache[k] if k in self._cache else self._cache.setdefault(k, self._load_resource(*k))

    def get_package_resource_as_bytes(self, filename):
        """
        Retrieve the contents of a resource file from this package as bytes.

        Args:
            filename (str): The name of the file to retrieve.

        Returns:
            bytes: The contents of the file as bytes.
        """
        return self.get_package_resource_as_text(filename).encode()

class ResourceCacheResolver(etree.Resolver):
    """
    A custom resolver that uses a cache to resolve system URLs from resources of this package.

    Attributes:
        _resource_cache (ResourceCache): An instance of the ResourceCache class used for fetching and caching package resources.
    """

    def __init__(self, return_bytes=False):
        self._resource_cache = ResourceCache()
        self._return_bytes = return_bytes
        super().__init__()

    def resolve(self, system_url, _, context, *args, **kwargs):
        """
        Resolves the given system URL and returns the resolved XML as a string.

        The system URL is prefixed with the directory holding the schema resources. If the system URL contains a scheme, no attempt
        is made to resolve it.

        Args:
            system_url (str): The system URL to resolve.
            _: The public ID associated with the system URL.
            context: The context object.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            str: The resolved XML as a string.

        Raises:
            None
        """
        if '://' in system_url:
            return
        if not system_url.startswith('schemas/'):
            system_url = f"schemas/{system_url}"
        res = self._resource_cache.get_package_resource_as_bytes(system_url) if self._return_bytes \
            else self._resource_cache.get_package_resource_as_text(system_url)
        if res:
            return self.resolve_file(BytesIO(res), context, **kwargs) if self._return_bytes \
            else self.resolve_string(res, context, **kwargs)

def validate_etree_with_xml_schema(data, schema):
    if not schema.startswith('schemas/'):
        schema = f"schemas/{schema}"
    parser = etree.XMLParser()
    parser.resolvers.add(ResourceCacheResolver(return_bytes=True))
    schema = etree.fromstring(ResourceCache().get_package_resource_as_bytes(schema), parser=parser)
    xsd = etree.XMLSchema(schema)
    # TODO: raise or return
    xsd.assertValid(data)

# def print_schema_properties(schema, parents=[]):
#     if isinstance(schema, str):
#         return
#     if isinstance(schema, list):
#         for idx, item in enumerate(schema):
#             print_schema_properties(item, parents=parents + [idx])
#         return
#     for prop in list(schema.keys()):
#         value = schema[prop]
#         if prop == "properties":
#             keys = list(value.keys())
#             print(f"{'/'.join(str(p) for p in parents)}: {keys}")
#         print_schema_properties(value, parents=parents + [prop])

def traverse_schema(schema, func, orig_schema=None):
    if orig_schema is None:
        orig_schema = schema
    # if isinstance(schema, str):
    #     return
    if isinstance(schema, list):
        i = 0
        while i < len(schema):
            remove, value = func(schema[i], orig_schema=orig_schema)
            if remove:
                del schema[i]
                continue
            if schema[i] != value:
                schema[i] = value
            else:
                traverse_schema(schema[i], func, orig_schema=orig_schema)
            i += 1
    elif isinstance(schema, dict):
        for prop in list(schema.keys()):
            remove, value = func(schema[prop], orig_schema=orig_schema, prop=prop)
            if remove:
                del schema[prop]
                continue
            if schema[prop] != value:
                schema[prop] = value
            else:
                traverse_schema(schema[prop], func, orig_schema=orig_schema)

def remove_required_properties(item, prop=None, **_):
    if prop == 'required':
        return True, item
    if isinstance(item, dict) and 'required' in item:
        del item['required']
    return False, item

def dereference_refs(item, orig_schema=None, **_):
    if not isinstance(item, dict) or '$ref' not in item:
        return False, item
    ref, ptr = urldefrag(item['$ref'])
    if ref:
        ref = item['$ref'][:len(ref)] # guard against urlparse case normalization
        ref = get_json_schema_from_registry(ref)
        traverse_schema(ref, dereference_refs)
    if ptr:
        return False, jsonpointer_resolve_pointer(ref if ref else orig_schema, ptr)
    return False, ref

JSON_SCHEMAS_PREFIX = 'urn:pypi:eidas_node_trust_config:schemas:'
JSON_SCHEMAS_POSTPROC = {
    'norequired': remove_required_properties,
    'dereference': dereference_refs,
}

def retrieve_from_filesystem(uri):
    if uri.startswith(JSON_SCHEMAS_PREFIX):
        uri = uri.removeprefix(JSON_SCHEMAS_PREFIX)
    if "::" in uri:
        _uri = uri
        uri, *procs = uri.split('::')
        for idx, proc in enumerate(procs):
            if proc not in JSON_SCHEMAS_POSTPROC:
                raise NoSuchResource(ref=_uri) # FIXME: better exception or ignore?
            procs[idx] = JSON_SCHEMAS_POSTPROC[proc]
    else:
        procs = []
    if ":" in uri:
        raise NoSuchResource(ref=uri)
    schema_path = f"schemas/{uri}.json"
    # if not system_url.startswith('schemas/'):
    #     system_url = f"schemas/{system_url}"
    contents = json.loads(ResourceCache().get_package_resource_as_text(schema_path))
    for proc in procs:
        if callable(proc):
            traverse_schema(contents, proc)
        # TODO: implement importing?
    return Resource.from_contents(contents)

JSON_SCHEMAS_REGISTRY = Registry(retrieve=retrieve_from_filesystem)

def get_json_schema_from_registry(schema):
    return JSON_SCHEMAS_REGISTRY.get_or_retrieve(schema).value.contents

def validate_data_with_json_schema(data, schema):
    # if isinstance(data, str):
    #     if not os.path.exists(data):
    #         raise FileNotFoundError(f"File not found: {data}")
    #     with open(data, 'r') as fd:
    #         data = json.load(fd)
    schema_registry = JSON_SCHEMAS_REGISTRY
    schema_retrieved = get_json_schema_from_registry(schema)
    validator_cls = jsonschema_validator_for(schema_retrieved)
    validator = validator_cls(schema_retrieved, registry=schema_registry)
    # TODO: raise or return
    validator.validate(data)
    return validator.is_valid(data)

def load_config_file_and_merge_with_args(config_file, config_args):
    if config_file is None:
        return config_args
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"File not found: {config_file}")
    from eidas_node_trust_config.configuration import country_data_merge as config_data_merge, MergeableList
    yaml.SafeLoader.add_constructor('!seq_merge', lambda loader, node: MergeableList(loader.construct_sequence(node, deep=loader.deep_construct)))
    with open(config_file, 'r') as fd:
        config_data = yaml.safe_load(fd)
    return config_data_merge(config_data, config_args)

def write_json_schema_to_file(schema, filename):
    # if os.path.exists(filename):
    #     raise FileNotFoundError(f"Schema output file exists: {filename}")
    with open(filename, 'w') as fd:
        json.dump(get_json_schema_from_registry(schema), fd)
