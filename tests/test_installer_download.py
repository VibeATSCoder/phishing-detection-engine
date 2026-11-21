"""Exercise authenticated installer downloads against a local HTTP fixture."""

import json
import os
import re
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest


INSTALLER = Path(__file__).resolve().parents[1] / "deploy" / "install.sh"


@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("curl"), reason="uses curl and /dev/fd")
def test_private_release_resumes_partial_download(tmp_path):
    payload = b"fixture release asset bytes"
    partial_size = 8
    filename = "release-asset.bin"
    token = "installer-fixture-token"
    requests = []

    class GitHubFixture(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization"), self.headers.get("Range")))
            if self.path.endswith("/releases/tags/v1"):
                data = json.dumps({"assets": [{"name": filename, "id": 17, "size": len(payload)}]}).encode()
                self.send_response(200)
            elif self.path.endswith("/releases/assets/17"):
                data = payload[partial_size:]
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {partial_size}-{len(payload) - 1}/{len(payload)}")
            else:
                self.send_error(404)
                return
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    source = INSTALLER.read_text()
    functions = []
    for name in ("human_size", "set_github_auth", "github_request", "resolve_asset", "fetch_asset"):
        functions.append(re.search(rf"(?ms)^{name}\(\).*?^}}", source).group())

    (tmp_path / filename).write_bytes(payload[:partial_size])
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    curl = mock_bin / "curl"
    # Keep curl's real header, range, timeout and progress handling. Redirect
    # only the network destination and refuse accidental outbound requests.
    curl.write_text(
        "#!/bin/bash\n"
        'url="${!#}"\n'
        '[[ "$*" != *"$GITHUB_TOKEN"* ]] || exit 60\n'
        '[[ "$url" == https://api.github.com/* ]] || exit 61\n'
        'if [[ "$url" == */assets/* ]]; then\n'
        '  [[ " $* " == *" --max-time 86400 "* && " $* " == *" --progress-bar "* ]] || exit 62\n'
        'fi\n'
        'exec "$FIXTURE_CURL" "${@:1:$#-1}" "$FIXTURE_API${url#https://api.github.com}"\n'
    )
    curl.chmod(0o755)
    with ThreadingHTTPServer(("127.0.0.1", 0), GitHubFixture) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            test_environment = os.environ | {
                "GITHUB_TOKEN": token,
                "GITHUB_USER": "",
                "ASSET_BASE_URL": "",
                "FIXTURE_API": f"http://127.0.0.1:{server.server_port}",
                "FIXTURE_CURL": shutil.which("curl"),
                "PATH": f"{mock_bin}:{os.environ['PATH']}",
                "NO_PROXY": "127.0.0.1",
            }
            run = subprocess.run(
                [
                    "bash", "-c",
                    "\n".join(functions) + """
                    OWNER=fixture
                    DOWNLOAD_TIMEOUT=86400
                    SOURCE_MODE=auto
                    RECHECK=0
                    HAVE_TTY=0
                    die() { echo "$*" >&2; exit 1; }
                    set_github_auth
                    fetch_asset private v1 release-asset.bin
                    """,
                ],
                env=test_environment, cwd=tmp_path, text=True, capture_output=True, timeout=10,
            )
        finally:
            server.shutdown()
            worker.join()

    assert run.returncode == 0, run.stdout + run.stderr
    assert (tmp_path / filename).read_bytes() == payload
    assert "resume release-asset.bin" in run.stdout
    assert token not in run.stdout + run.stderr
    assert requests == [
        ("/repos/fixture/private/releases/tags/v1", f"Bearer {token}", None),
        ("/repos/fixture/private/releases/assets/17", f"Bearer {token}", f"bytes={partial_size}-"),
    ]
