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
#   bash install.sh --recheck            re-verify sizes of files already present
#
# Credentials. Public repositories need none. For private ones, either:
#
#   export GITHUB_TOKEN=ghp_...                       # token alone
#   export GITHUB_USER=you GITHUB_TOKEN=ghp_...       # username + token
#
# Safe to re-run at any point. An image already loaded is never downloaded
# again, a partial download resumes, and a corrupt one is detected and replaced
# rather than fed to docker load.
set -euo pipefail

OWNER="${GITHUB_OWNER:-VibeATSCoder}"
RAW="https://raw.githubusercontent.com/${OWNER}/phishing-detection-engine/main"
INSTALL_DIR="${PWD}/persianphish"
WITH_REFERENCES=0
DOWNLOAD_ONLY=0
RECHECK=0

# Versions this stack releases as. deploy/COMPATIBILITY.json records the same
# numbers and tests/test_release_contract.py asserts the two agree, so these
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
    --recheck) RECHECK=1; shift ;;
    -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo; echo "install failed: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# ------------------------------------------------------------- preflight ---
for required in docker curl python3 tar gzip; do
  command -v "${required}" >/dev/null 2>&1 || die "required command missing: ${required}"
done
docker compose version >/dev/null 2>&1 \
  || die "Docker Compose v2 is required (the 'docker compose' command)"
docker info >/dev/null 2>&1 \
  || die "cannot talk to the Docker daemon; is it running, and is your user in the docker group?"

# Two auth shapes, because both are in common use. A username with a token is
# HTTP basic; a token alone is a bearer credential. Neither is needed while a
# repository is public.
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

mkdir -p "${INSTALL_DIR}" || die "cannot create ${INSTALL_DIR}"
cd "${INSTALL_DIR}"
echo "installing into $(pwd)"

# Refuse to start a multi-gigabyte download that cannot possibly finish. The
# images need roughly twice their download size once Docker unpacks them.
need_gb=3
[ "${WITH_REFERENCES}" -eq 1 ] && need_gb=16
free_gb="$(df -BG --output=avail . | tail -1 | tr -dc '0-9')"
if [ -n "${free_gb}" ] && [ "${free_gb}" -lt "${need_gb}" ]; then
  die "only ${free_gb} GB free here; about ${need_gb} GB is needed$([ "${WITH_REFERENCES}" -eq 1 ] && echo ' with --with-references')"
fi

# ------------------------------------------------------------ downloading ---
# The size the release says an asset should be, so a partial or stale file is
# detected without needing a checksum. Empty when it cannot be determined.
remote_size() { # repo tag name
  local repo="$1" tag="$2" name="$3" size="" headers
  # The success of the request has to gate the parse. A private asset answers
  # 404 with a nine-byte "Not Found" body, and its headers still reach stdout
  # before curl exits non-zero, so reading them unconditionally yields an
  # expected size of 9 and fails the check on a perfectly good download.
  if headers="$(curl -fsIL --retry 3 --retry-all-errors \
                  "https://github.com/${OWNER}/${repo}/releases/download/${tag}/${name}" 2>/dev/null)"; then
    size="$(printf '%s' "${headers}" | tr -d '\r' \
            | awk 'BEGIN{IGNORECASE=1} /^content-length:/ {n=$2} END{print n}')"
  fi
  if [ -z "${size}" ] && [ ${#AUTH[@]} -gt 0 ]; then
    size="$(curl -fsSL "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
              "https://api.github.com/repos/${OWNER}/${repo}/releases/tags/${tag}" 2>/dev/null \
            | python3 -c "
import json,sys
want = sys.argv[1]
for asset in json.load(sys.stdin).get('assets', []):
    if asset['name'] == want:
        print(asset['size']); break
" "${name}" 2>/dev/null || true)"
  fi
  printf '%s' "${size}"
}

# Fetch one release asset by name, resuming a partial file.
#
# A private asset cannot be taken from the browser download URL: that path wants
# a session cookie and answers 404 for a token, which reads like the file is
# missing. It has to be resolved to an asset id and pulled from the API. The
# public URL is tried first because it needs no credentials at all.
fetch_asset() { # repo tag name
  local repo="$1" tag="$2" name="$3" expected local_size id
  expected="$(remote_size "${repo}" "${tag}" "${name}")"

  if [ -f "${name}" ]; then
    local_size="$(stat -c%s "${name}" 2>/dev/null || echo 0)"
    if [ -n "${expected}" ] && [ "${local_size}" = "${expected}" ]; then
      echo "  have  ${name}"
      return 0
    fi
    if [ -z "${expected}" ] && [ "${RECHECK}" -eq 0 ] && [ "${local_size}" -gt 0 ]; then
      echo "  have  ${name} (size unverified)"
      return 0
    fi
    echo "  resume ${name} (${local_size} of ${expected:-?} bytes)"
  else
    echo "  get   ${name}${expected:+ ($((expected / 1048576)) MB)}"
  fi

  if curl -fL -C - --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
       -o "${name}" \
       "https://github.com/${OWNER}/${repo}/releases/download/${tag}/${name}" 2>/dev/null; then
    :
  elif [ ${#AUTH[@]} -eq 0 ]; then
    die "cannot fetch ${name}: ${OWNER}/${repo} is not public and no credentials were given.
Set GITHUB_TOKEN (optionally with GITHUB_USER) and run again."
  else
    id="$(curl -fsSL "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
          "https://api.github.com/repos/${OWNER}/${repo}/releases/tags/${tag}" \
        | python3 -c "
import json,sys
want = sys.argv[1]
for asset in json.load(sys.stdin).get('assets', []):
    if asset['name'] == want:
        print(asset['id']); break
" "${name}")"
    [ -n "${id}" ] || die "no asset named ${name} in ${OWNER}/${repo} ${tag}"
    curl -fL -C - --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
      "${AUTH[@]}" -H "Accept: application/octet-stream" -o "${name}" \
      "https://api.github.com/repos/${OWNER}/${repo}/releases/assets/${id}" \
      || die "download of ${name} failed"
  fi

  if [ -n "${expected}" ]; then
    local_size="$(stat -c%s "${name}" 2>/dev/null || echo 0)"
    [ "${local_size}" = "${expected}" ] \
      || die "${name} is ${local_size} bytes but should be ${expected}. Re-run to resume."
  fi
}

# Download and load one image, but only if it is not already present. This is
# what makes re-running cheap: nothing re-downloads 699 MB to discover Docker
# already has it.
ensure_image() { # image  repo tag artefact
  local image="$1" repo="$2" tag="$3" artefact="$4"
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "  have  ${image}"
    return 0
  fi
  fetch_asset "${repo}" "${tag}" "${artefact}"
  # Catches a truncated or corrupted archive before docker sees it, and says so
  # in terms of the file rather than an opaque tar error.
  gzip -t "${artefact}" 2>/dev/null \
    || die "${artefact} is not a valid archive. Delete it and re-run to fetch it again."
  echo "  load  ${image}"
  gunzip -c "${artefact}" | docker load >/dev/null \
    || die "docker load of ${artefact} failed"
  docker image inspect "${image}" >/dev/null \
    || die "${artefact} loaded but did not provide ${image}"
}

step "images"
ensure_image "phishing-detection-engine:${DETECTOR_VERSION}-integrated" \
  phishing-detection-engine "v${DETECTOR_VERSION}" \
  "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz"
ensure_image "agentic-phishing-review:${REVIEW_VERSION}-integrated" \
  agentic-phishing-review "v${REVIEW_VERSION}" \
  "agentic-phishing-review-${REVIEW_VERSION}.tar.gz"

if [ "${WITH_REFERENCES}" -eq 1 ]; then
  if docker image inspect "phishing-rag-service:${RAG_VERSION}" >/dev/null 2>&1; then
    echo "  have  phishing-rag-service:${RAG_VERSION}"
  else
    # ~2.9 GB compressed, above the 2 GB per-asset limit, so it is published in
    # parts and reassembled by the loader that ships beside them.
    for part in part00 part01 part02; do
      fetch_asset phishing-rag-service "v${RAG_VERSION}" \
        "phishing-rag-service-${RAG_VERSION}.tar.gz.${part}"
    done
    fetch_asset phishing-rag-service "v${RAG_VERSION}" \
      "phishing-rag-service-${RAG_VERSION}.tar.gz.parts.sha256"
    fetch_asset phishing-rag-service "v${RAG_VERSION}" load_release.sh
    echo "  load  phishing-rag-service:${RAG_VERSION} (reassembling parts)"
    bash load_release.sh "phishing-rag-service-${RAG_VERSION}.tar.gz.part00" \
      || die "reassembling the reference image failed"
  fi
fi

step "compose files and scripts"
if [ ! -f deploy/compose.images.yaml ]; then
  fetch_asset phishing-detection-engine "v${DETECTOR_VERSION}" \
    "persianphish-stack-${STACK_VERSION}-deploy.tar.gz"
  tar -xzf "persianphish-stack-${STACK_VERSION}-deploy.tar.gz" --strip-components=1 \
    || die "could not unpack the stack bundle"
fi
mkdir -p deploy
# Always take these from main: a fix landed after the release still reaches the
# operator, and the bundle's copies are only a fallback for an offline install.
for f in deploy/deploy.sh deploy/compose.images.yaml deploy/compose.references.yaml; do
  if curl -fsSL --retry 3 --retry-all-errors -o "${f}.new" "${RAW}/${f}" 2>/dev/null; then
    mv "${f}.new" "${f}"
  else
    rm -f "${f}.new"
  fi
done
[ -f deploy/deploy.sh ] || die "deploy/deploy.sh is missing and could not be fetched"
[ -f deploy/compose.images.yaml ] || die "deploy/compose.images.yaml is missing"
chmod +x deploy/deploy.sh

step "configuration"
if [ ! -f deploy/.env ]; then
  curl -fsSL --retry 3 -o deploy/.env "${RAW}/deploy/stack.env.example" 2>/dev/null \
    || cp .env.example deploy/.env 2>/dev/null \
    || die "no configuration template available"
  echo "  wrote deploy/.env"
else
  echo "  keeping the existing deploy/.env"
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

run_cmd="cd $(pwd) && bash deploy/deploy.sh"
[ "${WITH_REFERENCES}" -eq 1 ] && run_cmd="${run_cmd} --with-references"

if [ -n "${missing}" ] || [ "${DOWNLOAD_ONLY}" -eq 1 ]; then
  echo
  echo "Everything is downloaded and loaded into Docker."
  if [ -n "${missing}" ]; then
    echo
    echo "Set these in $(pwd)/deploy/.env, then start:"
    for key in ${missing}; do echo "    ${key}"; done
  fi
  echo
  echo "  ${run_cmd}"
  exit 0
fi

step "starting"
eval "${run_cmd}"
