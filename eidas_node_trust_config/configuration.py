import os
from io import StringIO
from collections import defaultdict
from enum import Enum
import configparser
from jinja2 import Environment, FileSystemLoader
from lxml import etree
from eidas_node_trust_config.discovery import get_edfa_session, EdfaApiV2EidasNodeDetails, ManualEidasNodeDetails, MetadataServiceList

class MergeableList(list):
    pass

def country_data_merge(dict1, dict2, override_with_none_values=True):
    for key, value in dict2.items():
        if isinstance(value, dict):
            node = dict1.get(key, {})
            if node is None: # case eidasService.proxyService = None
                node = {}
            dict1[key] = country_data_merge(node, value, override_with_none_values=override_with_none_values)
        elif not override_with_none_values and value is None and key in dict1 and dict1[key] is not None:
            pass # do not override with None
        elif (isinstance(value, MergeableList) and key in dict1 and isinstance(dict1[key], list)) or \
            (isinstance(value, list) and key in dict1 and isinstance(dict1[key], MergeableList)):
            for item in value:
                if item not in dict1[key]:
                    dict1[key].append(item)
            if not isinstance(dict1[key], MergeableList):
                dict1[key] = MergeableList(dict1[key])
        else: # lists without !seq_merge tag are overridden
            dict1[key] = value
    return dict1

class EidasNodeTrustAggregator:
    class Environment(Enum):
        PRODUCTION = EdfaApiV2EidasNodeDetails.Environment.PRODUCTION
        PROD = PRODUCTION
        TESTING = EdfaApiV2EidasNodeDetails.Environment.TESTING
        PREPROD = TESTING
        PRE_PROD = TESTING
        PREPRODUCTION = TESTING
        PRE_PRODUCTION = TESTING
    class Component(Enum):
        PS = EdfaApiV2EidasNodeDetails.Entity.PS
        PROXY_SERVICE = PS
        PROXYSERVICE = PS
        CONNECTOR = EdfaApiV2EidasNodeDetails.Entity.CONNECTORS
        MIDDLEWARE_HOSTED = EdfaApiV2EidasNodeDetails.Entity.MIDDLEWARES_HOSTED
    component_to_mdsl_endpoint_type = {
        Component.PROXY_SERVICE: MetadataServiceList.EndpointType.PROXY_SERVICE,
        Component.CONNECTOR: MetadataServiceList.EndpointType.CONNECTOR,
        Component.MIDDLEWARE_HOSTED: False,
    }

    def __init__(self, node_country_code, api_countries=None, manual_countries=None, metadata_service_lists=None, **edfa_kwargs):
        self.node_country_code = node_country_code
        self.country_data = self._create_country_data(api_countries or [], manual_countries or {})
        self.mdsl_data = self._create_mdsl_data(metadata_service_lists or {}, **edfa_kwargs)

    def _create_country_data(self, api_countries, manual_countries):
        country_data = {}
        edfa_session = None
        for country_code in api_countries:
            if edfa_session is None:
                edfa_session = get_edfa_session()
            country_code_in_manual_countries = country_code in manual_countries
            country = EdfaApiV2EidasNodeDetails(country_code, session=edfa_session, schema_validate=not(country_code_in_manual_countries))
            if country_code_in_manual_countries:
                country = ManualEidasNodeDetails(country_code, country_data_merge(country.data, manual_countries[country_code]))
            country_data[country_code] = country
        for country_code in manual_countries:
            if country_code not in country_data:
                country_data[country_code] = ManualEidasNodeDetails(country_code, manual_countries[country_code])
        return country_data

    def _create_mdsl_data(self, mdservicelists, **edfa_kwargs):
        mdsl_data = {}
        MDSL = EdfaApiV2EidasNodeDetails.Entity.MDSL
        for country_code in self.country_data:
            for env in self.Environment:
                try:
                    mdsl_mds = self.country_data[country_code].get_signing_certificates(MDSL, environment=env.value, **edfa_kwargs)
                    for mdsl_url in self.country_data[country_code].get_metadata_urls(MDSL, environment=env.value, **edfa_kwargs):
                        mdsl_data[(env.name, mdsl_url)] = MetadataServiceList(mdsl_url, country_code=country_code, mds=mdsl_mds.values())
                except Exception as e:
                    if "Invalid environment:" in e.args[0]:
                        continue
                    raise
        for env in self.Environment:
            for mdsl in mdservicelists.get(env.value, []):
                mdsl_mds = [item.get('base64') if isinstance(item, dict) else item for item in mdsl.get('signingCertificates', [])]
                mdsl_url = mdsl['metadataUrl']
                mdsl_data[(env.name, mdsl_url)] = MetadataServiceList(mdsl_url, mds=mdsl_mds)
        return mdsl_data

    def get_metadata_endpoints(self, environment, component, only_active=True, detailed_proxyservice=True, require_single_proxyservice_endpoint=True):
        if component == self.Component.PS:
            endpoints = defaultdict(dict)
        elif component == self.Component.CONNECTOR:
            endpoints = set()
        else:
            raise Exception(f"Unknown component: {component}")
        for country_code, data in self.country_data.items():
            if component == self.Component.PS:
                if data.has_middleware_service_provided(environment=environment.value):
                    ps_endpoints = self.country_data[self.node_country_code].get_metadata_urls(
                        self.Component.MIDDLEWARE_HOSTED.value, environment=environment.value, only_active=only_active, mwsh_provider_country_code=country_code)
                else:
                    ps_endpoints = data.get_metadata_urls(component.value, environment=environment.value, only_active=only_active)
                endpoints[country_code] = {
                    'country_name': data.get_country_name(environment=environment.value),
                    'endpoints': set(ps_endpoints),
                }
            elif component == self.Component.CONNECTOR:
                endpoints.update(data.get_metadata_urls(component.value, environment=environment.value, only_active=only_active))
        for (env, _), data in self.mdsl_data.items():
            if env != environment.name:
                continue
            if component == self.Component.PS:
                country_code = data.country_code
                for mdloc in data.get_metadata_locations(endpoint_type=self.component_to_mdsl_endpoint_type[component]):
                    if country_code is None:
                        country_code = mdloc['territory']
                    ps_endpoints = endpoints[country_code].setdefault('endpoints', set())
                    ps_endpoints.add(mdloc['location'])
            elif component == self.Component.CONNECTOR:
                endpoints.update(data.get_location_urls(endpoint_type=self.component_to_mdsl_endpoint_type[component]))
        if component == self.Component.PS:
            for country_code in list(endpoints.keys()):
                data = endpoints[country_code]
                num_endpoints = len(data['endpoints'])
                if require_single_proxyservice_endpoint and num_endpoints != 1:
                    country_name = data.get('country_name')
                    country = f"{country_name} ({country_code})" if country_name else country_code
                    raise Exception(f"{country} has {num_endpoints} ProxyService endpoints")
                elif num_endpoints == 0:
                    del endpoints[country_code]
            if not detailed_proxyservice:
                endpoints = set(endpoint for data in endpoints.values() for endpoint in data['endpoints'])
        return endpoints

    def get_signing_certificates(self, environment, component=None, only_active=True, filter_expired=True):
        certs = {}
        cert_fp_to_cc_mapping = defaultdict(set)
        def update_cert_fp_to_cc_mapping(cert_fps, country_code):
            for cert_fp in cert_fps:
                cert_fp_to_cc_mapping[cert_fp].add(country_code)
        if component is None:
            # hosted middlewares are looked up through the PS component of the providing country
            components = [c for c in self.Component if c is not self.Component.MIDDLEWARE_HOSTED]
        else:
            components = [component]
        for component in components:
            for country_code, data in self.country_data.items():
                if component == self.Component.PS and data.has_middleware_service_provided(environment=environment.value):
                    cc_certs = self.country_data[self.node_country_code].get_signing_certificates(
                        self.Component.MIDDLEWARE_HOSTED.value, environment=environment.value, filter_expired=filter_expired, only_active=only_active, mwsh_provider_country_code=country_code)
                else:
                    cc_certs = data.get_signing_certificates(component.value, environment=environment.value, filter_expired=filter_expired, only_active=only_active)
                certs.update(cc_certs)
                update_cert_fp_to_cc_mapping(cc_certs.keys(), country_code)
            for (env, _), data in self.mdsl_data.items():
                if env != environment.name:
                    continue
                country_code = data.country_code
                for mdloc in data.get_metadata_locations(endpoint_type=self.component_to_mdsl_endpoint_type[component], filter_expired_certificates=filter_expired):
                    cc_certs = mdloc['certificates']
                    certs.update(cc_certs)
                    if country_code is None:
                        country_code = mdloc['territory']
                    update_cert_fp_to_cc_mapping(cc_certs.keys(), country_code)
        return certs, cert_fp_to_cc_mapping

JAVA_PROPERTIES_DTD = etree.DTD(StringIO(
"""<!ELEMENT properties ( comment?, entry* ) >
<!ATTLIST properties version CDATA #FIXED "1.0">
<!ELEMENT comment (#PCDATA) >
<!ELEMENT entry (#PCDATA) >
<!ATTLIST entry key CDATA #REQUIRED>
"""))

def validate_template_output(rendered_template, output_path):
    file_type = os.path.splitext(output_path)[1][1:].lower()
    if file_type == 'properties':
        config = configparser.ConfigParser()
        try:
            config.read_string(rendered_template)
        except configparser.ParsingError as e:
            try:
                rendered_template = "[dummy section]\n" + rendered_template
                config.read_string(rendered_template)
            except configparser.ParsingError as e:
                raise Exception(f"Java properties INI syntax is invalid: {e}")
    elif file_type == 'xml':
        # dtd_url = "http://java.sun.com/dtd/properties.dtd"
        # dtd = etree.DTD(requests.get(dtd_url).text)
        # dtd_file_path = os.path.join(os.path.dirname(__file__), 'java_properties.dtd')
        # with open(dtd_file_path, 'r') as dtd_fd:
        #     dtd = etree.DTD(dtd_fd)
        # dtd = etree.DTD(StringIO(JAVA_PROPERTIES_DTD))

        try:
            try:
                xml = etree.fromstring(rendered_template)
            except ValueError:
                xml = etree.fromstring(rendered_template.encode())
            assert JAVA_PROPERTIES_DTD.validate(xml)
        except (etree.DocumentInvalid, AssertionError) as e:
            raise Exception(f"XML syntax is invalid or Java properties DTD validation failed: {e}")
    else:
        raise Exception("Unknown file type. Please choose either 'properties' or 'xml'.")

def render_and_validate_template(template_path, data):
    env = Environment(loader=FileSystemLoader(['/', '.']), keep_trailing_newline=True)
    template = env.get_template(template_path)
    rendered_template = template.render({'data': data})
    output_path = os.path.splitext(template_path)[0]
    validate_template_output(rendered_template, output_path)
    with open(output_path, 'w') as f:
        f.write(rendered_template)

def write_certs_to_dir(directory, fp_cert_mapping, file_extension, fp_cc_mapping=None):
    fp_cc_mapping = fp_cc_mapping or {}
    if file_extension == 'pem':
        symlink_extension = 'crt'
    elif file_extension == 'crt':
        symlink_extension = 'pem'
    else:
        raise ValueError("Unknown file extension. Please choose either 'pem' or 'crt'.")
    for fingerprint, pem in fp_cert_mapping.items():
        file_path = os.path.join(directory, f"{fingerprint}.{file_extension}")
        with open(file_path, 'w') as fd:
            fd.write(pem)
        for country_code in fp_cc_mapping.get(fingerprint, set()):
            symlink_path = os.path.join(directory, f"{country_code}_{fingerprint}.{symlink_extension}")
            if os.path.exists(symlink_path):
                os.remove(symlink_path)
            os.symlink(os.path.basename(file_path), symlink_path)
