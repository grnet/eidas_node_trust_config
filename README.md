# eIDAS node trust configuration

Aggregate trust data (metadata endpoints and certificates) for configuring eIDAS node from the [eIDAS dashboard](https://eidas.ec.europa.eu/efda/browse/notification/eid-chapter-contacts), Metadata Service Lists (MDSL) and manual configuration.

## Installation

To install the package, run the following command:

```sh
pip install git+https://github.com/grnet/eidas_node_trust_config.git
```

Some required changes to dependency [pyXMLSecurity](https://github.com/IdentityPython/pyXMLSecurity/) need to be resolved upstream before this package can be published to PyPi. Until that happens the dependency points to a patched fork of this library; you may install the package from this repository.

## Usage

```sh
usage: eidas_node_trust_config [-h] [--config CONFIG.yml] [--write-config-schema SCHEMA.json] [--node-country-code CC] [--environment {productionNode,testingNode}]
                               [--api-countries CC [CC ...]] [--eidas-node-props-template TEMPLATE] [--eidas-node-props-component {PS,PROXY_SERVICE,PROXYSERVICE,CONNECTOR}]
                               [--eidas-node-props-detailed-proxyservice | --no-eidas-node-props-detailed-proxyservice] [--eidas-node-mds-certs-dir DIR]
                               [--eidas-node-mds-certs-component {None,PS,PROXY_SERVICE,PROXYSERVICE,CONNECTOR}]
                               [--eidas-node-mds-certs-cc-links | --no-eidas-node-mds-certs-cc-links]
                               [--single-proxyservice-endpoint-per-country | --no-single-proxyservice-endpoint-per-country] [--only-active | --no-only-active]
                               [--filter-expired | --no-filter-expired]

eIDAS node trust configuration

options:
  -h, --help            show this help message and exit
  --config CONFIG.yml   Path to the YAML configuration file
  --write-config-schema SCHEMA.json
                        Path to the file where the configuration JSON schema (self-contained, after dereferencing) should be written
  --node-country-code CC
                        Country code of this eIDAS node
  --environment {productionNode,testingNode}
                        Environment of this eIDAS node
  --api-countries CC [CC ...]
                        Country codes to fetch from the API
  --single-proxyservice-endpoint-per-country, --no-single-proxyservice-endpoint-per-country
                        Require a single ProxyService endpoint per country
  --only-active, --no-only-active
                        Only consider environments/entities in country data which have status=ACTIVE
  --filter-expired, --no-filter-expired
                        Filter out expired certificates

eidas_node_props:
  Render eIDAS node properties file templates (repeat for multiple templates)

  --eidas-node-props-template TEMPLATE
                        Path to jinja2 template file; the output file is derived by stripping the extension from TEMPLATE
  --eidas-node-props-component {PS,PROXY_SERVICE,PROXYSERVICE,CONNECTOR}
                        Component to source data for rendering the template
  --eidas-node-props-detailed-proxyservice, --no-eidas-node-props-detailed-proxyservice
                        Provide detailed ProxyService data to the template

eidas_node_mds_certs:
  Export eIDAS node signing certificates to a directory (repeat for multiple directories)

  --eidas-node-mds-certs-dir DIR
                        Directory to write signing certificates (PEM files)
  --eidas-node-mds-certs-component {None,PS,PROXY_SERVICE,PROXYSERVICE,CONNECTOR}
                        Component to source certificate data (optional)
  --eidas-node-mds-certs-cc-links, --no-eidas-node-mds-certs-cc-links
                        Create '<country_code>_<fingerprint>.crt' symbolic links to certificates
```

Command line arguments override options provided in the YAML configuration file, with the exception of `manual_countries` and `metadata_service_lists` which are exclusive to the latter.

### Configuration file example

```yaml
$schema: "urn:pypi:eidas_node_trust_config:schemas:configuration" # optional
node_country_code: CC
environment: testingNode # or productionNode
api_countries:
  - CC
  - CA
  - CB
  # ...
manual_countries:
  # it is possible to only provide some keys to override country data from the API
  # unlike merging for objects, providing an array completely overrides the API data
  CC:
    testingNode:
      eidasService:
        proxyService:
          status: INACTIVE
  # example of a complete declaration (not merged with API data)
  CD:
    countryCode: CD
    testingNode:
      status: ACTIVE
      country:
        countryCode: CD
        countryName: CD country
      commonSigningCertificates:
        - base64:
            "MIIBgTCCASegAwIBAgIUQGLeNW4pjT0Rq4GWIsOXPhgqL80wCgYIKoZIzj0EAwIw\
            FjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwHhcNMjQwNjE4MTY0NjM0WhcNMzQwNjE2\
            MTY0NjM0WjAWMRQwEgYDVQQDDAtleGFtcGxlLm9yZzBZMBMGByqGSM49AgEGCCqG\
            SM49AwEHA0IABPD4Prk6CFMRi37spJ0oEvt6FKSs26IPO2/BJ7kNkD6OXeAf1drh\
            bfT6HNBN01E+Vwv31n+7FwARV9V2JbapX7mjUzBRMB0GA1UdDgQWBBT9YGdBu19O\
            sXMqzhcIcoSnSxsOUjAfBgNVHSMEGDAWgBT9YGdBu19OsXMqzhcIcoSnSxsOUjAP\
            BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCt8HPmYZywCWiVEVvB\
            msDMBZvtFvQAvCJVcIRa/9o3agIgQaJcfoc0KUTZ/QX/OZ/gfD5nUnH4QYI6WHC3\
            fkHAP/I="
          expirationDays: 1234
          mdsl: false
          service: true
          connector: true
          middlewareHosted: false
      # commonTlsCertificates TBA
      mdsl: null
      eidasConnectors:
        - status: ACTIVE
          metadataUrl: https://test.example.org/EidasNode/ConnectorMetadata
          signingCertificates: []
          # tlsCertificates TBA
          scope: public
      middlewareServiceHosted: []
      eidasService:
        middlewareServiceProvided: null
        proxyService:
          status: ACTIVE
          metadataUrl: https://test.example.org/EidasNode/ServiceMetadata
          signingCertificates: []
          # tlsCertificates TBA
metadata_service_lists:
  testingNode: # or productionNode
    # no country binding a priori, country code derived from territory attribute
    - metadataUrl: https://test.example.org/some-aggregate-mdservicelist.xml
      signingCertificates:
        # a mapping similar to country data can be provided
        - base64:
            "MIIBgTCCASegAwIBAgIUQGLeNW4pjT0Rq4GWIsOXPhgqL80wCgYIKoZIzj0EAwIw\
            FjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwHhcNMjQwNjE4MTY0NjM0WhcNMzQwNjE2\
            MTY0NjM0WjAWMRQwEgYDVQQDDAtleGFtcGxlLm9yZzBZMBMGByqGSM49AgEGCCqG\
            SM49AwEHA0IABPD4Prk6CFMRi37spJ0oEvt6FKSs26IPO2/BJ7kNkD6OXeAf1drh\
            bfT6HNBN01E+Vwv31n+7FwARV9V2JbapX7mjUzBRMB0GA1UdDgQWBBT9YGdBu19O\
            sXMqzhcIcoSnSxsOUjAfBgNVHSMEGDAWgBT9YGdBu19OsXMqzhcIcoSnSxsOUjAP\
            BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCt8HPmYZywCWiVEVvB\
            msDMBZvtFvQAvCJVcIRa/9o3agIgQaJcfoc0KUTZ/QX/OZ/gfD5nUnH4QYI6WHC3\
            fkHAP/I="
        # or just the certificate
        - "MIIBgTCCASegAwIBAgIUQGLeNW4pjT0Rq4GWIsOXPhgqL80wCgYIKoZIzj0EAwIw\
          FjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwHhcNMjQwNjE4MTY0NjM0WhcNMzQwNjE2\
          MTY0NjM0WjAWMRQwEgYDVQQDDAtleGFtcGxlLm9yZzBZMBMGByqGSM49AgEGCCqG\
          SM49AwEHA0IABPD4Prk6CFMRi37spJ0oEvt6FKSs26IPO2/BJ7kNkD6OXeAf1drh\
          bfT6HNBN01E+Vwv31n+7FwARV9V2JbapX7mjUzBRMB0GA1UdDgQWBBT9YGdBu19O\
          sXMqzhcIcoSnSxsOUjAfBgNVHSMEGDAWgBT9YGdBu19OsXMqzhcIcoSnSxsOUjAP\
          BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCt8HPmYZywCWiVEVvB\
          msDMBZvtFvQAvCJVcIRa/9o3agIgQaJcfoc0KUTZ/QX/OZ/gfD5nUnH4QYI6WHC3\
          fkHAP/I="
# configuration tasks
eidas_node_props:
  - template: config/eidas.xml.j2
    component: PS
    detailed_proxyservice: true
  - template: config/metadata/MetadataFetcher_Connector.properties.j2
    component: PS
    detailed_proxyservice: false
  # ...
eidas_node_mds_certs:
  - dir: config/metadata-certs
    component: null
    cc_links: false
single_proxyservice_endpoint_per_country: false # if no proxyservice is provided for a country, this global option must be disabled
```

You can use `--write-config-schema` to export a JSON schema for configuration file validation and auto-completion in your editor.

## Modules

## Python API

TBA

# License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
