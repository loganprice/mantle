import os
import sys
import http.server
import socketserver

PORT = int(os.getenv("PORT", "8080"))

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        uid = os.getuid()
        msg = f"Hello from Mantle! Running as user {uid}\n"
        self.wfile.write(msg.encode())

if __name__ == "__main__":
    print(f"Starting server on port {PORT}...")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()
