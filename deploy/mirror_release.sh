#!/usr/bin/env bash
# Copy the stack's release artefacts into a directory you can serve yourself.
#
#   ./deploy/mirror_release.sh /srv/persianphish
#   ./deploy/mirror_release.sh /srv/persianphish --with-references   # +2.9 GB
#
# Then serve that directory over plain HTTP and point installs at it:
#
#   cd /srv/persianphish && python3 -m http.server 8000
#   ASSET_BASE_URL=http://mirror.internal:8000 bash install.sh --full
#
# Why this is opt-in rather than the default
# ------------------------------------------
# Measured from a machine with ordinary connectivity, a GitHub release asset
# downloads at about 2.6 MB/s sustained, against 3.1 MB/s from Cloudflare's own
# speed test on the same link. GitHub is not the bottleneck there and a mirror
# buys nothing.
#
# It is worth doing when the deployment network throttles or blocks GitHub,
# which is common where this stack gets deployed, or when many hosts install the
# same artefacts and the egress is worth paying once.
#
# The files are copied byte for byte. Nothing is rebuilt, so a mirrored artefact
# is the same one the release workflow verified by loading and starting it.
set -euo pipefail

DEST="${1:?usage: mirror_release.sh <directory> [--with-references]}"
shift || true
WITH_REFERENCES=0
[ "${1:-}" = "--with-references" ] || [ "${1:-}" = "--full" ] && WITH_REFERENCES=1

OWNER="${GITHUB_OWNER:-VibeATSCoder}"
DETECTOR_VERSION="${DETECTOR_VERSION:-3.8.0}"
REVIEW_VERSION="${REVIEW_VERSION:-1.10.0}"
RAG_VERSION="${RAG_VERSION:-1.0.2}"
STACK_VERSION="${STACK_VERSION:-1.1.0}"

AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

mkdir -p "${DEST}"
cd "${DEST}"

grab() { # repo tag name
  local repo="$1" tag="$2" name="$3" id
  if [ -s "${name}" ]; then
    echo "  have  ${name}"
    return 0
  fi
  echo "  get   ${name}"
  if curl -fL -C - --retry 10 --retry-all-errors --progress-bar -o "${name}" \
       "https://github.com/${OWNER}/${repo}/releases/download/${tag}/${name}" 2>/dev/null; then
    return 0
  fi
  [ ${#AUTH[@]} -gt 0 ] || {
    echo "  ${OWNER}/${repo} is private and GITHUB_TOKEN is not set" >&2
    return 1
  }
  id="$(curl -fsSL "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${OWNER}/${repo}/releases/tags/${tag}" \
      | python3 -c "
import json,sys
want = sys.argv[1]
for asset in json.load(sys.stdin).get('assets', []):
    if asset['name'] == want:
        print(asset['id']); break
" "${name}")"
  [ -n "${id}" ] || { echo "  no asset ${name} in ${repo} ${tag}" >&2; return 1; }
  curl -fL -C - --retry 10 --retry-all-errors --progress-bar "${AUTH[@]}" \
    -H "Accept: application/octet-stream" -o "${name}" \
    "https://api.github.com/repos/${OWNER}/${repo}/releases/assets/${id}"
}

echo "mirroring into $(pwd)"
grab phishing-detection-engine "v${DETECTOR_VERSION}" \
  "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz"
grab phishing-detection-engine "v${DETECTOR_VERSION}" \
  "persianphish-stack-${STACK_VERSION}-deploy.tar.gz"
grab agentic-phishing-review "v${REVIEW_VERSION}" \
  "agentic-phishing-review-${REVIEW_VERSION}.tar.gz"

if [ "${WITH_REFERENCES}" -eq 1 ]; then
  for part in part00 part01 part02; do
    grab phishing-rag-service "v${RAG_VERSION}" \
      "phishing-rag-service-${RAG_VERSION}.tar.gz.${part}"
  done
  grab phishing-rag-service "v${RAG_VERSION}" \
    "phishing-rag-service-${RAG_VERSION}.tar.gz.parts.sha256"
  grab phishing-rag-service "v${RAG_VERSION}" load_release.sh
fi

echo
echo "mirrored $(find . -maxdepth 1 -type f | wc -l) files, $(du -sh . | cut -f1)"
echo
echo "serve it, then install from it:"
echo "  cd $(pwd) && python3 -m http.server 8000"
echo "  ASSET_BASE_URL=http://<this-host>:8000 bash install.sh$([ "${WITH_REFERENCES}" -eq 1 ] && echo ' --full')"
