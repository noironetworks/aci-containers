# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='aci-containers',
    version='1.0.0',
    description='Container orchestration plugins for ACI',
    long_description=readme,
    author='Rob Adams',
    author_email='readams@readams.net',
    url='https://github.com/noironetworks/opflex-cont',
    license=license,
    packages=find_packages(exclude=('tests', 'docs')),
    install_requires = ['requests', 'aci-integration-module'],
    entry_points = {
        'console_scripts': [
            'opflex-agent-cni=cni.opflex_agent_cni:cni_main',
            'aci-policy-controller=k8s.aci_policy_controller:policy_main'
        ]
    }
)
