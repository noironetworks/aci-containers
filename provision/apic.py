import json
import requests


requests.packages.urllib3.disable_warnings()


class Apic(object):
    def __init__(self, addr, username, password, ssl=True, verify=False):
        self.addr = addr
        self.ssl = ssl
        self.username = username
        self.password = password
        self.cookies = None
        self.verify = verify
        self.debug = False
        self.login()

    def url(self, path):
        if self.ssl:
            return 'https://%s%s' % (self.addr, path)
        return 'http://%s%s' % (self.addr, path)

    def get(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.get(self.url(path), **args)

    def post(self, path, data):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.post(self.url(path), **args)

    def delete(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        return requests.delete(self.url(path), **args)

    def login(self):
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' % \
            (self.username, self.password)
        path = '/api/aaaLogin.json'
        req = requests.post(self.url(path), data=data, verify=False)
        if req.status_code == 200:
            resp = json.loads(req.text)
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.cookies = {'APIC-Cookie': token}
        return req

    def provision(self, data):
        for path in data:
            try:
                if data[path] is not None:
                    resp = self.post(path, data[path])
                    if self.debug:
                        print path, resp.text
            except Exception as e:
                # print it, otherwise ignore it
                print "Error in provisioning %s: %s" % (path, str(e))

    def unprovision(self, data):
        for path in data:
            try:
                if path not in ["/api/node/mo/uni/tn-common.json"]:
                    resp = self.delete(path)
                    if self.debug:
                        print path, resp.text
            except Exception as e:
                # print it, otherwise ignore it
                print "Error in un-provisioning %s: %s" % (path, str(e))

if __name__ == '__main__':
    data = {
        "/api/node/mo/uni/tn-common.json": None,
        "/api/node/mo/uni/tn-mandeep.json": '''{
            "fvTenant": {
                "attributes": {
                    "name": "%s",
                    "rn": "tn-%s",
                    "dn": "uni/tn-%s"
                }
            }
        }''' % (("mandeep",) * 3),
    }
    apic = Apic('10.30.120.140', 'admin', 'noir0123')
    apic.debug = True
    apic.provision(data)
    apic.unprovision(data)
