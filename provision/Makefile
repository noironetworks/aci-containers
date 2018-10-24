#
# Minimal Makefile to run aci-containers-provisioning tests
#

dist: test
	python setup.py sdist

test:
	flake8 --ignore E501,E731,E741,W504 acc_provision
	python -m pytest acc_provision

clean:
	rm -rf dist acc_provision.egg-info acc_provision/__pycache__ testdata/tmp-*

upload: clean
	python setup.py sdist upload
