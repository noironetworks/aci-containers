#
# Minimal Makefile to run aci-containers-provisioning tests
#

test:
	pep8 --ignore E501 aci-containers-provision.py apic.py
	flake8 --ignore E501 aci-containers-provision.py apic.py
	py.test aci-containers-provision.py apic.py
