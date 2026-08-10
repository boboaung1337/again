#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import socket
import sys

class PutHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        content_length = int(self.headers['Content-Length'])
        data = self.rfile.read(content_length)
        
        # Extract filename from path (remove leading slash)
        filename = urllib.parse.unquote(self.path[1:])
        if not filename:
            filename = "uploaded_file"
            
        with open(filename, 'wb') as f:
            f.write(data)
            
        self.send_response(200)
        self.end_headers()
        print(f"✓ Received: {filename} ({content_length} bytes)")
        
    def log_message(self, format, *args):
        # Clean console output
        print(f"  {self.address_string()} - {format % args}")


def find_free_port(start_port=8000, max_port=9000):
    """Find a free port in the given range"""
    for port in range(start_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free ports found in range {start_port}-{max_port}")


def format_url(ip, port, path=""):
    """Format URL, hiding port if it's 80"""
    if port == 80:
        return f"http://{ip}{path}"
    else:
        return f"http://{ip}:{port}{path}"


if __name__ == '__main__':
    # Get port from command line or find free one
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
        except ValueError:
            print(f"Error: Invalid port number '{sys.argv[1]}'")
            sys.exit(1)
    else:
        PORT = find_free_port()
    
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    
    print("=" * 60)
    print(" MCB0B0 UPLOAD SERVER - Server running on: (all interfaces)")
    print("=" * 60)

    # Show upload examples
    print("\n example usage:")
    print(f" ")
    if PORT == 80:
        print(f"   curl.exe -X PUT -T 'input_file' http://{IP}/output_filename")
        print(f" ")
        print(f'   powershell.exe -c "Invoke-WebRequest -Uri http://{IP}/output_filename -Method PUT -InFile \'C:\\ProgramData\\input_file\'"')
        print(f" ")

    else:
        print(f"   curl.exe -X PUT -T 'input_file' http://{IP}:{PORT}/output_filename")
        print(f" ")
        print(f'   powershell.exe -c "Invoke-WebRequest -Uri http://{IP}:{PORT}/output_filename -Method PUT -InFile \'C:\\ProgramData\\input_file\'"')
        print(f" ")

    print("-" * 60)
    
    server = HTTPServer(('0.0.0.0', PORT), PutHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
