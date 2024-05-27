import sys
import os
import glob
import re
from pathlib import Path
import itertools
import unittest
from unittest.mock import patch, Mock
import json

sys.path.append(str(Path(__file__).resolve().parent.parent))
from eidas_node_trust_config.discovery import EdfaApiV2EidasNodeDetails, get_edfa_session, update_fp_pem_mapping

class TestEdfaApiV2EidasNodeDetails(unittest.TestCase):
    TEST_DATA_FN_PREFIX = 'edfa_api_v2_eidas-node_details_'
    TEST_ENVS = ['productionNode', 'testingNode']
    TEST_ENTITIES = ['mdsl', 'eidasService', 'eidasConnectors']

    @classmethod
    def setUpClass(cls):
        os.environ[get_edfa_session.ENV_COOKIE] = 'dummy_cookie=dummy_value'

        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(current_dir, 'data')
        json_files = glob.glob(os.path.join(data_dir, f"{cls.TEST_DATA_FN_PREFIX}*.json"))
        cls.test_data = {}
        for f in json_files:
            country_code = re.search(r'%s(\w+).json' % cls.TEST_DATA_FN_PREFIX, os.path.basename(f)).group(1)
            with open(f, 'r') as fd:
                cls.test_data[country_code] = json.load(fd)

    def get_side_effect(self, country_code):
        return lambda: self.test_data[country_code]

    def run_test(self, method_name, mock_get_data, callback=None, **method_kwargs):
        for country_code in self.test_data:
            mock_get_data.side_effect = self.get_side_effect(country_code)
            edfa = EdfaApiV2EidasNodeDetails(country_code)
            for environment, entity, only_active, filter_expired in itertools.product(self.TEST_ENVS, self.TEST_ENTITIES, (True, False), (True, False)):
                kwargs = {'environment': environment, 'only_active': only_active, 'filter_expired': filter_expired}
                result = getattr(EdfaApiV2EidasNodeDetails, method_name)(edfa, entity, **{**method_kwargs, **kwargs})

                entity_data = self.test_data[country_code][environment][entity]
                if entity_data is None:
                    entity_data = []
                elif not isinstance(entity_data, list): # mdsl or eidasService
                    if entity == 'eidasService':
                        entity_data = entity_data['proxyService']
                    entity_data = [entity_data]
                for item in entity_data:
                    if item is None or (only_active and item['status'] != 'ACTIVE'):
                        entity_data.remove(item)

                if callable(callback):
                    test_params = {'country_code': country_code, 'entity': entity, **kwargs}
                    entity_data = callback(entity_data, **test_params)
                self.assertEqual(result, entity_data)

    @patch('eidas_node_trust_config.discovery.EdfaApiV2EidasNodeDetails.get_data')
    def test_get_entity_data_as_list(self, mock_get_data):
        self.run_test('get_entity_data_as_list', mock_get_data)

    @patch('eidas_node_trust_config.discovery.EdfaApiV2EidasNodeDetails.get_data')
    def test_get_metadata_urls(self, mock_get_data):
        callback = lambda entity_data, **_: [item['metadataUrl'] for item in entity_data]
        self.run_test('get_metadata_urls', mock_get_data, callback=callback)

    @patch('eidas_node_trust_config.discovery.EdfaApiV2EidasNodeDetails.get_data')
    def test_get_signing_certificates(self, mock_get_data):
        test_data = self.test_data
        def callback(entity_data, **test_params):
            filter_expired=test_params.get('filter_expired', True)
            cert_data = {}
            for cert in test_data[test_params['country_code']][test_params['environment']]['commonSigningCertificates']:
                if cert[EdfaApiV2EidasNodeDetails.entity_to_common_signing_certificate_key[test_params['entity']]] and cert['expirationDays']:
                    update_fp_pem_mapping(cert_data, cert['base64'], filter_expired=filter_expired)
            for item in entity_data:
                for cert in item['signingCertificates']:
                    if cert['expirationDays']:
                        update_fp_pem_mapping(cert_data, cert['base64'], filter_expired=filter_expired)
            return cert_data
        self.run_test('get_signing_certificates', mock_get_data, callback=callback)

# Run the tests
if __name__ == '__main__':
    unittest.main()
