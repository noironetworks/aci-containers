import collections
import filecmp
import glob
import os

import acc_provision


def test_main():
    arg = {
        "config": None,
        "output": None,
        "apicfile": None,
        "apic": False,
        "delete": False,
        "username": "admin",
        "password": "",
        "sample": False,
        "debug": True,
    }
    argc = collections.namedtuple('argc', arg.keys())
    args = argc(**arg)

    os.chdir("testdata")
    for inp in glob.glob("*.inp.yaml"):
        # Exec main
        args = args._replace(config=inp)
        args = args._replace(output=os.tempnam(".", "tmp-kube-"))
        apicfile = os.tempnam(".", "tmp-apic-")
        acc_provision.main(args, apicfile)

        # Verify generated configs
        expectedkube = inp[:-8] + 'out.yaml'
        assert filecmp.cmp(args.output, expectedkube)
        expectedapic = inp[:-8] + 'apic.txt'
        assert filecmp.cmp(apicfile, expectedapic)

        # Cleanup
        os.remove(args.output)
        os.remove(apicfile)
