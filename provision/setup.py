from setuptools import setup, find_packages

setup(
    name='acc_provision',
    version='1.9.3',
    description='Tool to provision ACI for ACI Containers Controller',
    author="Cisco Systems, Inc.",
    author_email="apicapi@noironetworks.com",
    url='http://github.com/noironetworks/aci-containers/',
    license="http://www.apache.org/licenses/LICENSE-2.0",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'acc-provision=acc_provision.acc_provision:main',
        ]
    },
    install_requires=[
          'requests',
          'pyyaml',
          'jinja2',
          'pyopenssl',
    ],
)
