from setuptools import setup, find_packages
from eidas_node_trust_config import name as package_name

__author__ = 'Zenon Mousmoulas'
__version__ = '0.4.0'

install_requires = [
    'pyyaml',
    'jsonschema',
    'jsonpointer',
    'jinja2',
    'requests',
    'pyXMLSecurity @ git+https://github.com/zmousm/pyXMLSecurity.git@87b1c2334c48bd44a22393077d874219b6675baa#egg=pyXMLSecurity',
    'lxml',
    'cryptography'
]

setup(
    name=package_name,
    version=__version__,
    description='eIDAS node trust configuration',
    author=__author__,
    url='https://github.com/grnet/eidas_node_trust_config',
    license='EUPL-1.2',
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: European Union Public Licence 1.2 (EUPL 1.2)',
        'Development Status :: 3 - Alpha',
    ],
    packages=find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    package_data={package_name: ['schemas/*.json', 'schemas/*.xsd']},
    entry_points={
        'console_scripts': [
            f"{package_name} = {package_name}.__main__:main",
        ],
    },
    python_requires='>=3.7',
)