#!/usr/bin/env bash
# One command to fetch, load and start the whole stack.
#
#   curl -fsSL https://raw.githubusercontent.com/VibeATSCoder/phishing-detection-engine/main/deploy/install.sh | bash
#
# or, having downloaded it:
#
#   bash install.sh                      detector + reviewer
#   bash install.sh --with-references    also the retrieval service (~3 GB more)
#   bash install.sh --download-only      fetch and load, do not start
#   bash install.sh --dir ~/somewhere    install somewhere other than ./persianphish
#
# Credentials. Public repositories need none. For private ones, either:
#
#   export GITHUB_TOKEN=ghp_...                       # token alone
#   export GITHUB_USER=you GITHUB_TOKEN=ghp_...       # username + token
#
# Downloads resume, so a dropped connection continues rather than restarting.
set -euo pipefail

OWNER="${GITHUB_OWNER:-VibeATSCoder}"
INSTALL_DIR="${PWD}/persianphish"
WITH_REFERENCES=0
DOWNLOAD_ONLY=0

# Versions the stack is released as. deploy/COMPATIBILITY.json records the same
# numbers and tests/test_release_contract.py asserts the two agree, so this
# cannot drift from the contract unnoticed.
DETECTOR_VERSION="${DETECTOR_VERSION:-3.2.1}"
REVIEW_VERSION="${REVIEW_VERSION:-1.4.1}"
RAG_VERSION="${RAG_VERSION:-1.0.2}"
STACK_VERSION="${STACK_VERSION:-1.1.0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) INSTALL_DIR="${2:?--dir needs a path}"; shift 2 ;;
    --with-references) WITH_REFERENCES=1; shift ;;
    --download-only) DOWNLOAD_ONLY=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

for required in docker curl python3 tar; do
  if ! command -v "${required}" >/dev/null 2>&1; then
    echo "Required command is missing: ${required}" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required (the 'docker compose' command)." >&2
  exit 1
fi

# Two auth shapes, because both are in common use. A username with a token is
# HTTP basic; a token alone is a bearer credential. Neither is needed while the
# repositories are public.
AUTH=()
if [ -n "${GITHUB_USER:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-u "${GITHUB_USER}:${GITHUB_TOKEN}")
  echo "authenticating as ${GITHUB_USER}"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  echo "authenticating with a token"
else
  echo "no credentials set; only public repositories will be reachable"
fi

mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"
echo "installing into $(pwd)"

# Fetch one release asset by name.
#
# A private asset cannot be taken from the browser download URL: that path needs
# a session cookie and answers 404 for a token. It has to be resolved to an
# asset id and pulled from the API with an octet-stream Accept header. The
# public URL is tried first because it needs no credentials at all.
fetch_asset() { # repo tag name
  local repo="$1" tag="$2" name="$3" id
  if [ -f "${name}.complete" ]; then
    echo "  have  ${name}"
    return 0
  fi
  echo "  get   ${name}"
  if curl -fL -C - --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
       -o "${name}" \
       "https://github.com/${OWNER}/${repo}/releases/download/${tag}/${name}" 2>/dev/null; then
    touch "${name}.complete"
    return 0
  fi
  if [ ${#AUTH[@]} -eq 0 ]; then
    echo "Cannot fetch ${name}: ${OWNER}/${repo} is not public and no credentials were given." >&2
    echo "Set GITHUB_TOKEN (optionally with GITHUB_USER) and run again." >&2
    return 1
  fi
  id="$(curl -fsSL "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${OWNER}/${repo}/releases/tags/${tag}" \
      | python3 -c "
import json,sys
want = sys.argv[1]
for asset in json.load(sys.stdin)['assets']:
    if asset['name'] == want:
        print(asset['id']); break
" "${name}")"
  if [ -z "${id}" ]; then
    echo "No asset named ${name} in ${OWNER}/${repo} ${tag}." >&2
    return 1
  fi
  curl -fL -C - --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
    "${AUTH[@]}" -H "Accept: application/octet-stream" -o "${name}" \
    "https://api.github.com/repos/${OWNER}/${repo}/releases/assets/${id}"
  touch "${name}.complete"
}

# Load an image unless it is already present, so re-running is cheap.
load_image() { # image_ref  artefact
  local image="$1" artefact="$2"
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "  have  ${image}"
    return 0
  fi
  echo "  load  ${image}"
  gunzip -c "${artefact}" | docker load >/dev/null
  docker image inspect "${image}" >/dev/null
}

echo
echo "downloading"
fetch_asset phishing-detection-engine "v${DETECTOR_VERSION}" \
  "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz"
fetch_asset phishing-detection-engine "v${DETECTOR_VERSION}" \
  "persianphish-stack-${STACK_VERSION}-deploy.tar.gz"
fetch_asset agentic-phishing-review "v${REVIEW_VERSION}" \
  "agentic-phishing-review-${REVIEW_VERSION}.tar.gz"

if [ "${WITH_REFERENCES}" -eq 1 ]; then
  # The reference image is ~2.9 GB compressed, above the 2 GB per-asset limit,
  # so it is published in parts and reassembled on load.
  for part in part00 part01 part02; do
    fetch_asset phishing-rag-service "v${RAG_VERSION}" \
      "phishing-rag-service-${RAG_VERSION}.tar.gz.${part}"
  done
  fetch_asset phishing-rag-service "v${RAG_VERSION}" \
    "phishing-rag-service-${RAG_VERSION}.tar.gz.parts.sha256"
  fetch_asset phishing-rag-service "v${RAG_VERSION}" load_release.sh
fi

echo
echo "unpacking the stack bundle"
tar -xzf "persianphish-stack-${STACK_VERSION}-deploy.tar.gz" --strip-components=1
# The bundle carries the deploy script as released. Take the current one from
# main as well, so a fix landed after the release still reaches the operator.
curl -fsSL -o deploy/deploy.sh \
  "https://raw.githubusercontent.com/${OWNER}/phishing-detection-engine/main/deploy/deploy.sh" \
  2>/dev/null || echo "  keeping the bundled deploy.sh"
chmod +x deploy/deploy.sh

echo
echo "loading images"
load_image "phishing-detection-engine:${DETECTOR_VERSION}-integrated" \
  "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz"
load_image "agentic-phishing-review:${REVIEW_VERSION}-integrated" \
  "agentic-phishing-review-${REVIEW_VERSION}.tar.gz"
if [ "${WITH_REFERENCES}" -eq 1 ]; then
  if docker image inspect "phishing-rag-service:${RAG_VERSION}" >/dev/null 2>&1; then
    echo "  have  phishing-rag-service:${RAG_VERSION}"
  else
    echo "  load  phishing-rag-service:${RAG_VERSION} (reassembling parts)"
    bash load_release.sh "phishing-rag-service-${RAG_VERSION}.tar.gz.part00"
  fi
fi

# One aggregated .env rather than one per service. Prefer the stack template
# from main, which documents every variable the three services read.
if [ ! -f deploy/.env ]; then
  curl -fsSL -o deploy/.env \
    "https://raw.githubusercontent.com/${OWNER}/phishing-detection-engine/main/deploy/stack.env.example" \
    2>/dev/null || cp .env.example deploy/.env
  echo
  echo "wrote deploy/.env from the template"
fi

missing=""
for key in OPENROUTER_API_KEY INTERNAL_REVIEW_API_KEY; do
  value="$(sed -n "s/^${key}=//p" deploy/.env | tail -n 1)"
  [ -z "${value//[[:space:]]/}" ] && missing="${missing} ${key}"
done
if [ "${WITH_REFERENCES}" -eq 1 ]; then
  value="$(sed -n 's/^RAG_INDEX_HOST_PATH=//p' deploy/.env | tail -n 1)"
  [ -z "${value//[[:space:]]/}" ] && missing="${missing} RAG_INDEX_HOST_PATH"
fi

if [ -n "${missing}" ] || [ "${DOWNLOAD_ONLY}" -eq 1 ]; then
  echo
  echo "Everything is downloaded and loaded into Docker."
  [ -n "${missing}" ] && {
    echo
    echo "Before starting, set these in $(pwd)/deploy/.env:"
    for key in ${missing}; do echo "  ${key}"; done
  }
  echo
  echo "Then run:"
  echo "  cd $(pwd) && bash deploy/deploy.sh$([ "${WITH_REFERENCES}" -eq 1 ] && echo ' --with-references')"
  exit 0
fi

echo
echo "starting"
if [ "${WITH_REFERENCES}" -eq 1 ]; then
  bash deploy/deploy.sh --with-references
else
  bash deploy/deploy.sh
fi
