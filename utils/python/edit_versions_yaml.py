import yaml
import optparse
import os

VERSIONS_PATH = os.path.dirname(os.path.realpath(__file__)) + "/../../provision/acc_provision/versions.yaml"


def read_yaml_file(file):
    with open(file, 'r') as stream:
        try:
            orig_data = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return orig_data


def modify_yaml(opt0, opt1, opt2, opt3, data):
    data['versions'][float(opt0)]['openvswitch_version'] = opt3
    data['versions'][float(opt0)]['opflex_agent_version'] = opt2
    data['versions'][float(opt0)]['cnideploy_version'] = opt1
    data['versions'][float(opt0)]['aci_containers_controller_version'] = opt1
    data['versions'][float(opt0)]['aci_containers_host_version'] = opt1
    return data


def create_new_yaml(file, new_data):
    with open(file, 'w') as stream:
        yaml.dump(new_data, stream, default_flow_style=False, allow_unicode=True)


def main():

    parser = optparse.OptionParser()
    parser.add_option("--branch-id",
                      dest="release_branch",
                      help="one of them : 1.7, 1.8 or 1.9")
    parser.add_option("--acicontainers-tools",
                      dest="acicontainers_tools",
                      help="last successful build for AciContainers-tools job")
    parser.add_option("--opflex-container",
                      dest="opflex_container",
                      help="last successful build for OpFlex-container")
    parser.add_option("--ovs-container",
                      dest="ovs_container",
                      help="last successful build for OVS-container")

    (opts, _) = parser.parse_args()
    if (not opts.release_branch or not opts.acicontainers_tools or not opts.opflex_container or not opts.ovs_container):
        parser.error("Required parameter(s) missing")

    orig_data = read_yaml_file(VERSIONS_PATH)
    data = modify_yaml(opts.release_branch, opts.acicontainers_tools, opts.opflex_container, opts.ovs_container, orig_data)
    os.remove(VERSIONS_PATH)
    create_new_yaml(VERSIONS_PATH, data)


if __name__ == '__main__':
    main()
