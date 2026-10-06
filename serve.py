import http.server
import socket
from pathlib import Path

PORT = 8079
ROOT = Path(__file__).resolve().parent

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_POST(self):
        prefix = "/dump/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return
        name = Path(self.path[len(prefix):]).name
        if not name or not all(c.isalnum() or c in "._-" for c in name):
            self.send_error(400)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 8 << 20:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        (ROOT / "dumps").mkdir(exist_ok=True)
        with open(ROOT / "dumps" / name, "ab") as f:
            f.write(body)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "localhost"

if __name__ == "__main__":
    with http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler) as server:
        print(f"http://{local_ip()}:{PORT}/", flush=True)
        server.serve_forever()
