import collections
import filecmp
import functools
import os
import sys

import acc_provision


def in_testdir(f):
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        os.chdir("testdata")
        try:
            ret = f(*args, **kwds)
        except:
            raise
        finally:
            os.chdir("..")
        return ret
    return wrapper


@in_testdir
def test_base_case():
    run_provision(
        "base_case.inp.yaml",
        "base_case.kube.yaml",
        "base_case.apic.txt"
    )


@in_testdir
def test_with_comments():
    run_provision(
        "with_comments.inp.yaml",
        "with_comments.kube.yaml",
        "with_comments.apic.txt"
    )


@in_testdir
def test_with_overrides():
    run_provision(
        "with_overrides.inp.yaml",
        "with_overrides.kube.yaml",
        "with_overrides.apic.txt"
    )


@in_testdir
def test_sample():
    tmpout = os.tempnam(".", "tmp-stdout-")
    with open(tmpout, "w") as tmpoutfd:
        origout = sys.stdout
        sys.stdout = tmpoutfd
        try:
            args = get_args(sample=True)
            acc_provision.main(args, no_random=True)
        finally:
            sys.stdout = origout
    assert filecmp.cmp(tmpout, "../acc_provision/provision-config.yaml")
    run_provision(tmpout, "sample.kube.yaml", None)
    os.remove(tmpout)


@in_testdir
def test_devnull_errors():
    tmperr = os.tempnam(".", "tmp-stderr-")
    with open(tmperr, "w") as tmperrfd:
        origout = sys.stdout
        sys.stderr = tmperrfd
        try:
            args = get_args()
            acc_provision.main(args, no_random=True)
        finally:
            sys.stderr = origout
    assert filecmp.cmp(tmperr, "devnull.stderr.txt")
    os.remove(tmperr)


@in_testdir
def test_helpmsg():
    tmpout = os.tempnam(".", "tmp-stdout-")
    with open(tmpout, "w") as tmpoutfd:
        origout = sys.stdout
        sys.stdout = tmpoutfd
        try:
            sys.argv = ["acc_provision.py", "--help"]
            acc_provision.main(no_random=True)
        except SystemExit:
            pass
        finally:
            sys.stdout = origout
    assert filecmp.cmp(tmpout, "help.stdout.txt")
    os.remove(tmpout)


def get_args(**overrides):
    arg = {
        "config": None,
        "output": None,
        "apicfile": None,
        "apic": False,
        "delete": False,
        "username": "admin",
        "password": "",
        "sample": False,
        "debug": False,
    }
    argc = collections.namedtuple('argc', arg.keys())
    args = argc(**arg)
    args = args._replace(**overrides)
    return args


def run_provision(inpfile, expectedkube=None, expectedapic=None):
    # Exec main
    args = get_args(
        config=inpfile,
        output=os.tempnam(".", "tmp-kube-"))
    apicfile = os.tempnam(".", "tmp-apic-")
    acc_provision.main(args, apicfile, no_random=True)

    # Verify generated configs
    if expectedkube is not None:
        assert filecmp.cmp(args.output, expectedkube)
    if expectedapic is not None:
        assert filecmp.cmp(apicfile, expectedapic)

    # Cleanup
    os.remove(args.output)
    os.remove(apicfile)
