#
# Minimal Makefile to run aci-containers-provisioning tests
#

dist: test
	python setup.py sdist

test:
	pep8 --ignore E501 acc_provision
	flake8 --ignore E501 acc_provision
	py.test acc_provision

clean:
	rm -rf dist acc_provision.egg-info

upload: clean
	python setup.py sdist upload
