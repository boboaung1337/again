from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def _log(self):
        print(f"\n--- {self.command} {self.path} ---")
        print("Headers:")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")

        length = int(self.headers.get("Content-Length", 0))
        if length:
            body = self.rfile.read(length)
            print(f"Body ({length} bytes):")
            print(body.decode("utf-8", errors="replace"))

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _log

if __name__ == "__main__":
    port = 80
    print(f"Listening on http://localhost:{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
