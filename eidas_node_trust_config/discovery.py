import os
import requests
from lxml import etree
from xmlsec import verify as xmlsec_verify
from xmlsec.exceptions import XMLSigException, XMLSigAlgoKeyTypeException
from eidas_node_trust_config.utils import update_fp_pem_mapping, validate_etree_with_xml_schema, validate_data_with_json_schema

EDFA_API_V2_BASE_URL = 'https://eidas.ec.europa.eu/efda/api/v2'

def get_edfa_session():
    cookie_var = get_edfa_session.ENV_COOKIE
    if cookie_var not in os.environ:
        raise Exception(f"{cookie_var} environment variable is not set")
    cookie_name, *cookie_value = os.environ.get(cookie_var).split('=', 1)
    if not cookie_name or not cookie_value:
        raise Exception(f"{cookie_var} environment variable should be in the form 'cookie_name=cookie_value'")
    cookie_value = cookie_value[0]
    session = requests.Session()
    session.cookies.set(cookie_name, cookie_value)
    return session
get_edfa_session.ENV_COOKIE = 'EDFA_API_COOKIE'

class EdfaApiV2EidasNodeDetails:
    SCHEMA_ID = 'urn:pypi:eidas_node_trust_config:schemas:edfaApiV2EidasNodeDetails'
    class Environment:
        PRODUCTION = 'productionNode'
        PROD = PRODUCTION
        TESTING = 'testingNode'
        TEST = TESTING
    class Entity:
        MDSL = 'mdsl'
        PS = 'eidasService'
        CONNECTORS = 'eidasConnectors'
        MIDDLEWARES_HOSTED = 'middlewareServiceHosted'
    entity_to_common_signing_certificate_key = {
        Entity.MDSL: Entity.MDSL,
        Entity.PS: 'service',
        Entity.CONNECTORS: 'connector',
        Entity.MIDDLEWARES_HOSTED: 'middlewareHosted',
    }

    def __init__(self, country_code, session=None, schema_validate=True):
        self.country_code = country_code
        self.url = f"{EDFA_API_V2_BASE_URL}/eidas-node/details/{self.country_code}"
        self.session = session or get_edfa_session()
        self.data = self.get_data()
        if schema_validate:
            self.validate_data()

    def get_data(self):
        response = self.session.get(self.url)
        response.raise_for_status()
        data = response.json()
        if data.get('countryCode') != self.country_code:
            raise Exception(f"Response countryCode does not match: {data.get('countryCode')} != {self.country_code}")
        return data

    def validate_data(self):
        # TODO: handle errors?
        validate_data_with_json_schema(self.data, self.SCHEMA_ID)

    def get_country_name(self, environment=Environment.PROD):
        return self.data[environment]['country']['countryName']

    def has_middleware_service_provided(self, environment=Environment.PROD):
        entity_data = self.get_entity_data(self.Entity.PS, environment=environment)
        if entity_data is None:
            return
        return entity_data['middlewareServiceProvided'] is not None

    def get_environment_data(self, environment, only_active=True, **_):
        if environment not in self.data or not self.data[environment]:
            raise Exception(f"Invalid environment: {environment}")
        # if not self.data[environment]:
        #     return [] # TODO or exception? or log warning?
        if only_active and self.data[environment]['status'] != 'ACTIVE':
            return {} # TODO or exception?
        return self.data[environment]

    def get_entity_data(self, entity, environment=Environment.PROD, only_active=True, **_):
        environment_data = self.get_environment_data(environment, only_active=only_active)
        if entity not in environment_data:
            raise Exception(f"Invalid entity: {entity}")
        return environment_data[entity]

    def get_entity_data_as_list(self, entity, environment=Environment.PROD, only_active=True, mwsh_provider_country_code=None, **_):
        entity_data = self.get_entity_data(entity, environment=environment, only_active=only_active)
        if entity_data is None:
            return []
        if not isinstance(entity_data, list): # mdsl or eidasService
            if entity == self.Entity.PS:
                entity_data = entity_data['proxyService']
            entity_data = [entity_data]
        if mwsh_provider_country_code is not None and entity == self.Entity.MIDDLEWARES_HOSTED:
            for item in entity_data:
                if item['countryProvider'] != mwsh_provider_country_code:
                    entity_data.remove(item)
        for item in entity_data:
            if item is None or (only_active and item['status'] != 'ACTIVE'):
                entity_data.remove(item)
        return entity_data

    def get_metadata_urls(self, entity, **kwargs):
        return [item['metadataUrl'] for item in self.get_entity_data_as_list(entity, **kwargs)]

    def get_signing_certificates(self, entity, environment=Environment.PROD, filter_expired=True, **kwargs):
        def append_valid_certificate(cert):
            if filter_expired and not cert['expirationDays']:
                return
            update_fp_pem_mapping(certificates, cert['base64'], filter_expired=filter_expired)
        certificates = {}
        for cert in self.get_environment_data(environment, **kwargs).get('commonSigningCertificates', []):
            if cert[self.entity_to_common_signing_certificate_key[entity]]:
                append_valid_certificate(cert)
        for item in self.get_entity_data_as_list(entity, environment=environment, **kwargs):
            for cert in item['signingCertificates']:
                append_valid_certificate(cert)
        return certificates

class ManualEidasNodeDetails(EdfaApiV2EidasNodeDetails):
    def __init__(self, country_code, data, schema_validate=True):
        self.country_code = country_code
        self.data = data
        if schema_validate:
            self.validate_data()

NS = {
 'ser': 'http://eidas.europa.eu/metadata/servicelist',
 'ds': 'http://www.w3.org/2000/09/xmldsig#',
}

class MetadataServiceList:
    SCHEMA_ID = 'eidas-metadata-servicelist-1.0.xsd'
    XMLSIG_EXEMPT_COUNTRY_CODES = []
    class EndpointType:
        PROXY_SERVICE = 'http://eidas.europa.eu/metadata/ept/ProxyService'
        CONNECTOR = 'http://eidas.europa.eu/metadata/ept/Connector'

    def __init__(self, url, country_code=None, mds=None, xinclude=True):
        self.url = url
        self.country_code = country_code
        self.mds = mds
        self.xinclude = xinclude
        self.data = self.get_data()
        self.validate()
        self.verify_signature()

    def get_data(self):
        response = requests.get(self.url)
        response.raise_for_status()
        tree = etree.fromstring(
            response.content, parser=etree.XMLParser(resolve_entities=False, collect_ids=False)).getroottree()
        if self.xinclude:
            tree.xinclude()
        return tree

    def validate(self):
        # TODO: handle errors?
        validate_etree_with_xml_schema(self.data, self.SCHEMA_ID)

    def verify_signature(self, country_code=None):
        if not self.mds: # None or empty list or dict_values
            return
        mds = self.mds if isinstance(self.mds, (list, type({}.values()))) else [self.mds]
        _name_exempt = 'XMLSIG_EXEMPT_COUNTRY_CODES'
        xmlsig_exempt_cc = _name_exempt in os.environ and os.environ.get(_name_exempt).split(',') or getattr(self, _name_exempt)
        xmlsig_required = (country_code or self.country_code) not in xmlsig_exempt_cc
        verified = False
        errors = []
        for mds_cert in mds:
            try:
                if xmlsec_verify(self.data, mds_cert):
                    verified = True
                    break
            except XMLSigAlgoKeyTypeException as e:
                errors.append(e.args[0])
                continue
            except XMLSigException as e:
                if "No valid ds:Signature elements found" in e.args[0] and xmlsig_required:
                    raise
        if not verified:
            msg = "Signature verification failed"
            if errors:
                msg = f"{msg}: {errors}"
            raise Exception(msg)

    def get_metadata_locations(self, country_code=None, endpoint_type=None, filter_expired_certificates=True):
        if country_code is None:
            country_code = self.country_code
        root = self.data.getroot()
        for mdlist in root.iter(f'{{{NS["ser"]}}}MetadataList'):
            territory = mdlist.get('Territory')
            if country_code is not None and country_code != territory:
                continue # TODO: or exception?
            for mdloc in mdlist.iter(f'{{{NS["ser"]}}}MetadataLocation'):
                location = mdloc.get('Location')
                endpoint = mdloc.find(f'{{{NS["ser"]}}}Endpoint')
                mdloc_endpoint_type = endpoint is not None and endpoint.get('EndpointType')
                if endpoint_type is not None and endpoint_type != mdloc_endpoint_type:
                    continue
                entity_id = endpoint is not None and endpoint.get('EntityID')
                if entity_id is not None and entity_id != location:
                    continue # TODO: or exception?
                certificates = [elem.text.strip() for elem in
                                mdloc.findall(f'{{{NS["ds"]}}}KeyInfo/{{{NS["ds"]}}}X509Data/{{{NS["ds"]}}}X509Certificate')]
                certs = {}
                for cert in certificates:
                    update_fp_pem_mapping(certs, cert, filter_expired=filter_expired_certificates)
                yield {
                    'territory': territory,
                    'location': location,
                    'endpoint_type': mdloc_endpoint_type,
                    'certificates': certs,
                }
    
    def get_location_urls(self, **kwargs):
        return [entry['location'] for entry in self.get_metadata_locations(**kwargs)]

    def get_certificates(self, location=None, **kwargs):
        return {k: v for entry in self.get_metadata_locations(**kwargs)
                for k, v in entry['certificates'].items() if location is None or entry['location'] == location}

    # def get_certificates_by_location(self, **kwargs):
    #     return {entry['location']: entry['certificates'] for entry in self.get_metadata_locations(**kwargs)}

