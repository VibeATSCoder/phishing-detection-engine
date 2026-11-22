"""Exercise authenticated installer downloads against a local HTTP fixture."""

import json
import os
import re
import select
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import time

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


@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("setsid"), reason="requires a controlling terminal")
@pytest.mark.parametrize("configure_only,embedding_failure", [(False, None), (True, None), (True, "404"), (True, "dimensions")])
def test_existing_install_can_configure_apis_with_or_without_downloads(tmp_path, configure_only, embedding_failure):
    import errno
    import pty
    import termios

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    index = tmp_path / "Embedding_Index"
    index.mkdir()
    for name in ("page_index.parquet", "block_embeddings.npy"):
        (index / name).touch()

    settings = deploy / ".env"
    embedding_settings = (
        "RAG_EMBED_MODE=api\nRAG_EMBED_API_BASE=https://api.avalai.ir/v1\nRAG_EMBED_MODEL=libertai/bge-m3\n"
        if embedding_failure else "RAG_EMBED_MODE=local\n"
    )
    settings.write_text(
        "OPENROUTER_BASE_URL=https://agent.example/v1\nOPENROUTER_MODEL=old-agent\n"
        "OPENROUTER_API_KEY=fixture-old-agent-key\nINTERNAL_REVIEW_API_KEY=fixture-internal-key\n"
        "PPD_API_KEY=fixture-browser-key\nRAG_BASE_URL=http://rag:8092\n"
        f"RAG_INDEX_HOST_PATH={index}\nREVIEW_LLM_TIMEOUT_S=15\nREVIEW_BUDGET_S=35\n" + embedding_settings
    )
    (deploy / "deploy.sh").write_text('printf "%s\\n" "$@" > deployment.args\n')
    source_deploy = INSTALLER.parent
    for name in ("compose.images.yaml", "compose.references.yaml", "COMPATIBILITY.json", "stack.env.example"):
        shutil.copyfile(source_deploy / name, deploy / name)

    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    commands = {
        "curl": """for arg do
    case "$arg" in
      https://api.avalai.ir/v1/embeddings)
        if [ "$FIXTURE_EMBEDDING_FAILURE" = 404 ]; then
          printf '{"error":{"message":"provider body stays private"}}\\n404'
        else
          printf '{"data":[{"embedding":[1]}]}\\n200'
        fi
        exit 0 ;;
      https://embeddings.example/v1/embeddings)
        python3 -c 'import json; print(json.dumps({"data":[{"embedding":[0.5]*1024}]})); print(200)'
        exit 0 ;;
    esac
done
touch unexpected-network-request; exit 22""",
        "docker": "exit 0",
        "df": "printf 'Available\\n128G\\n'",
    }
    for command, body in commands.items():
        tool = mock_bin / command
        tool.write_text(f"#!/bin/sh\n{body}\n")
        tool.chmod(0o755)

    args = ["--configure-providers"] if configure_only else ["--upgrade", "--ask-token", "--full", "--download-only"]
    prompts = [] if configure_only else [("GitHub token (input hidden): ", "fixture-github-token")]
    prompts.extend([
        ("Configure Decision model now? [Y/n]: ", ""),
        ("Decision model API base URL [https://api.avalai.ir/v1]: ", ""),
        ("Model ID [jev-latest]: ", ""),
        ("Decision API format (decisions or chat_completions) [decisions]: ", ""),
        ("Decision model API key (hidden): ", "fixture-decision-key"),
        ("Change the existing Review agent settings? [y/N]: ", "y"),
        ("Review agent API base URL [https://agent.example/v1]: ", "https://new-agent.example/v1"),
        ("Model ID [old-agent]: ", "agent-model"),
        ("Review agent API key (hidden): ", "fixture-agent-key"),
        ("Test the agent key with a small completion now? [y/N]: ", ""),
    ])
    if embedding_failure:
        prompts.extend([
            ("Embedding mode (local or api) [api]: ", ""),
            ("Change the existing RAG embeddings settings? [y/N]: ", ""),
            ("Retry with another API, use local BGE-M3, or stop? [api/local/stop]: ", "local"),
        ])
    else:
        prompts.extend([
            ("Embedding mode (local or api) [local]: ", "api"),
            ("Configure RAG embeddings now? [Y/n]: ", ""),
            ("RAG embeddings API base URL []: ", "https://embeddings.example/v1"),
            ("Model ID [BAAI/bge-m3]: ", "provider-bge-m3"),
            ("RAG embeddings API key (hidden): ", "fixture-rag-key"),
        ])

    terminal, slave = pty.openpty()
    try:
        process = subprocess.Popen(
            ["setsid", "--ctty", "bash", str(INSTALLER), *args],
            stdin=slave, stdout=slave, stderr=slave, cwd=tmp_path, env=os.environ | {
            "PATH": f"{mock_bin}:{os.environ['PATH']}", "NO_PROMPT": "0",
            "FIXTURE_EMBEDDING_FAILURE": embedding_failure or "",
            },
        )
    finally:
        os.close(slave)

    output = bytearray()
    try:
        deadline = time.monotonic() + 20
        cursor = 0
        for prompt, answer in prompts:
            needle = prompt.encode()
            while output.find(needle, cursor) == -1:
                readable, _, _ = select.select([terminal], [], [], max(0, deadline - time.monotonic()))
                assert readable, output.decode(errors="replace")
                output.extend(os.read(terminal, 4096))
            cursor = output.index(needle, cursor) + len(needle)
            if "API key" in prompt or "GitHub token" in prompt:
                while termios.tcgetattr(terminal)[3] & termios.ECHO:
                    assert time.monotonic() < deadline, output.decode(errors="replace")
                    time.sleep(0.01)
            os.write(terminal, answer.encode() + b"\n")
        while True:
            readable, _, _ = select.select([terminal], [], [], max(0, deadline - time.monotonic()))
            assert readable, output.decode(errors="replace")
            try:
                chunk = os.read(terminal, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            output.extend(chunk)
        assert process.wait(timeout=2) == 0, output.decode(errors="replace")
    finally:
        os.close(terminal)
        if process.poll() is None:
            process.kill()
            process.wait()

    saved = dict(line.split("=", 1) for line in settings.read_text().splitlines())
    assert saved["PPD_JEV_BASE_URL"] == "https://api.avalai.ir/v1"
    assert saved["PPD_JEV_API_FORMAT"] == "decisions"
    assert saved["PPD_JEV_MODEL"] == "jev-latest"
    assert saved["PPD_JEV_API_KEY"] == "fixture-decision-key"
    assert saved["OPENROUTER_BASE_URL"] == "https://new-agent.example/v1"
    assert saved["OPENROUTER_MODEL"] == "agent-model"
    assert saved["OPENROUTER_API_KEY"] == "fixture-agent-key"
    assert saved["REVIEW_LLM_TIMEOUT_S"] == "25"
    assert saved["REVIEW_BUDGET_S"] == "55"
    if embedding_failure:
        expected = b"Embedding probe failed (HTTP 404)" if embedding_failure == "404" else b"did not return a usable 1024-dimensional vector"
        assert expected in output
        assert b"provider body stays private" not in output
        assert saved["RAG_EMBED_MODE"] == "local"
    else:
        assert saved["RAG_EMBED_MODE"] == "api"
        assert saved["RAG_EMBED_API_BASE"] == "https://embeddings.example/v1"
        assert saved["RAG_EMBED_MODEL"] == "provider-bge-m3"
        assert saved["RAG_EMBED_API_KEY"] == "fixture-rag-key"
    assert saved["INTERNAL_REVIEW_API_KEY"] == "fixture-internal-key"
    assert saved["PPD_API_KEY"] == "fixture-browser-key"
    for secret in (b"fixture-decision-key", b"fixture-agent-key", b"fixture-rag-key", b"fixture-github-token"):
        assert secret not in output
    assert "GITHUB_TOKEN" not in saved
    assert not (tmp_path / "unexpected-network-request").exists()
    if configure_only:
        assert (tmp_path / "deployment.args").read_text().strip() == "--with-references"
