# eidas_node_trust_config

Aggregate trust data (metadata endpoints and certificates) for configuring eIDAS node from the [eIDAS dashboard](https://eidas.ec.europa.eu/efda/browse/notification/eid-chapter-contacts), Metadata Service Lists (MDSL) and manual configuration.

## Installation

To install the package, run the following command:

```sh
pip install git+https://github.com/grnet/eidas_node_trust_config.git
```

Some required changes to dependency [pyXMLSecurity](https://github.com/IdentityPython/pyXMLSecurity/) need to be resolved upstream before this package can be published to PyPi. Until that happens the dependency points to a patched fork of this library; you may install from this repository.

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

You can use command line arguments or a (YAML) configuration file. Some options may only be provided in the latter.

A sample configuration file may be added is provided (TBA).

You can export a JSON schema to use for validation and auto-completion of your configuration file with `--write-config-schema` in your editor.

## Modules

## Python API

TBA

# License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.