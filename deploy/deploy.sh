#!/usr/bin/env bash
# Deploy the integrated stack from saved images: detector + reviewer, and
# optionally the reference retrieval service.
#
# Nothing is built here. Download the image artefacts from the GitHub releases,
# put them in one directory, and run this from it.
#
#   deploy.sh                      images alongside this script (or --image-dir)
#   deploy.sh --image-dir ~/dl     images downloaded elsewhere
#   deploy.sh --with-references    also start the retrieval service
#   deploy.sh --full               same as --with-references
#   deploy.sh --verify             check artefact checksums before loading
#   deploy.sh --show-config        print the extension settings and exit
#
# Checksums are not verified by default. A mismatch used to abort the deploy,
# which turned a mangled .sha256 text file into a hard stop even when the image
# itself was fine. docker load rejects a damaged archive on its own, so a bad
# artefact still cannot be installed silently.
#
# Required in .env: OPENROUTER_API_KEY and INTERNAL_REVIEW_API_KEY.
set -euo pipefail

readonly DETECTOR_VERSION="3.8.2"
readonly REVIEW_VERSION="1.11.0"
# Overridable from .env, so --with-references matches the image you loaded.
RAG_VERSION="2.0.0"
readonly DETECTOR_IMAGE="phishing-detection-engine:${DETECTOR_VERSION}"
readonly REVIEW_IMAGE="agentic-phishing-review:${REVIEW_VERSION}"
RAG_IMAGE="phishing-rag-service:${RAG_VERSION}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Empty means "look in the usual places". Resolved to an absolute path below,
# before the script changes directory.
IMAGE_DIR=""
WITH_REFERENCES=0
VERIFY_CHECKSUMS=0
SHOW_CONFIG=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image-dir) IMAGE_DIR="${2:?--image-dir needs a path}"; shift 2 ;;
    --with-references|--full) WITH_REFERENCES=1; shift ;;
    --verify) VERIFY_CHECKSUMS=1; shift ;;
    --show-config) SHOW_CONFIG=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      # This script is refreshed from main by the installer, so a flag that
      # exists in the documentation but not in the copy on disk means the copy
      # is older than the instructions being followed. Saying only "unknown
      # option" left that as a puzzle.
      echo "unknown option: $1" >&2
      echo >&2
      echo "If you were told this option exists, this copy of deploy.sh is out" >&2
      echo "of date. Update it in place with:" >&2
      echo "  curl -fsSL -o \"${BASH_SOURCE[0]}\" \\" >&2
      echo "    https://raw.githubusercontent.com/VibeATSCoder/phishing-detection-engine/main/deploy/deploy.sh" >&2
      exit 2 ;;
  esac
done

# Resolve before the cd below, or a relative --image-dir (". " being the obvious
# one to type) silently becomes the script's own directory and nothing is found.
if [ -n "${IMAGE_DIR}" ]; then
  if [ ! -d "${IMAGE_DIR}" ]; then
    echo "--image-dir is not a directory: ${IMAGE_DIR}" >&2
    exit 1
  fi
  IMAGE_DIR="$(cd -- "${IMAGE_DIR}" && pwd)"
  SEARCH_DIRS=("${IMAGE_DIR}")
else
  # The artefacts normally sit beside the unpacked bundle, one level up from
  # this script, so look there as well as here.
  SEARCH_DIRS=("${SCRIPT_DIR}" "$(cd -- "${SCRIPT_DIR}/.." && pwd)" "${PWD}")
fi

# Answered before anything else is checked. Someone who just wants to know what
# to type into the extension should not need Docker running, the images present,
# or the stack started to find out.
# --- how to reach the stack ------------------------------------------------
# BIND_HOST selects which host interface the detector's port is published on:
# 127.0.0.1 by default (local only), 0.0.0.0 or a specific IP to reach it from
# another machine. These helpers turn that into the address an operator should
# actually open, and into a public/private judgement for the warning below. The
# reviewer and RAG are deliberately NOT governed by BIND_HOST (they keep their
# own loopback default), so their URLs are always shown on 127.0.0.1.

# Read one KEY=value from the .env in the current directory.
env_val() { sed -n "s/^$1=//p" .env | tail -n 1; }

# The address to put in a URL for whatever BIND_HOST selected. For 0.0.0.0 it
# resolves the host's primary outbound IP -- the address other machines use to
# reach it -- rather than printing a literal 0.0.0.0 nobody can open.
resolve_bind_host() {
  local bind ip
  bind="$(env_val BIND_HOST)"; bind="${bind:-127.0.0.1}"
  case "${bind}" in
    0.0.0.0)
      ip="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.][0-9.]*\).*/\1/p' | head -1)"
      [ -n "${ip}" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
      echo "${ip:-<this-host-ip>}" ;;
    localhost) echo "127.0.0.1" ;;
    *) echo "${bind}" ;;
  esac
}

# Succeeds when the detector is published somewhere other than loopback.
detector_is_exposed() {
  local bind; bind="$(env_val BIND_HOST)"; bind="${bind:-127.0.0.1}"
  [ "${bind}" != "127.0.0.1" ] && [ "${bind}" != "localhost" ]
}

# Print the service URLs, the API documentation pages, and -- when the detector
# is on a public interface with no key -- a warning. Assumes cwd holds .env.
print_access_block() {
  local host dport rport key
  host="$(resolve_bind_host)"
  dport="$(env_val PPD_HOST_PORT)"; dport="${dport:-8088}"
  rport="$(env_val REVIEW_HOST_PORT)"; rport="${rport:-8090}"
  key="$(env_val PPD_API_KEY)"
  echo "detector   http://${host}:${dport}/health"
  echo "API docs   http://${host}:${dport}/docs            Swagger UI -- try the API from a browser"
  echo "           http://${host}:${dport}/redoc           ReDoc -- readable reference"
  echo "           http://${host}:${dport}/openapi.json    OpenAPI schema (JSON)"
  echo "metrics    http://${host}:${dport}/metrics"
  echo "reviewer   http://127.0.0.1:${rport}/ready         internal; stays on loopback"
  if detector_is_exposed && [ -z "${key//[[:space:]]/}" ]; then
    echo
    echo "  !! WARNING: the detector is published on a network interface with no"
    echo "     PPD_API_KEY set. Anyone who can reach this host can drive it, and"
    echo "     every URL it inspects spends OpenRouter budget. Set PPD_API_KEY in"
    echo "     deploy/.env and re-run, or front it with an authenticating reverse"
    echo "     proxy. For production, prefer BIND_HOST=127.0.0.1 + a TLS proxy."
  fi
}

# Ready-to-run example requests with the configured port and key filled in.
# They use 127.0.0.1 on purpose: the operator runs them on the server right
# after install, and a host cannot reach its own public IP (NAT hairpin), so a
# public-IP sample would appear to "hang". A note says how to call it remotely.
print_sample_curls() {
  local dport key kh base
  dport="$(env_val PPD_HOST_PORT)"; dport="${dport:-8088}"
  key="$(env_val PPD_API_KEY)"
  base="http://127.0.0.1:${dport}"
  if [ -n "${key//[[:space:]]/}" ]; then kh=" -H 'X-API-Key: ${key}'"; else kh=""; fi
  echo "Sample requests (run here on the server; 127.0.0.1 always works locally):"
  echo
  echo "  # 1. Health -- no key needed"
  echo "  curl -s ${base}/health"
  echo
  echo "  # 2. A known-good site -- instant allowlist hit"
  echo "  curl -s -X POST ${base}/v1/detect \\"
  echo "    -H 'Content-Type: application/json'${kh} \\"
  echo "    -d '{\"url\":\"https://www.digikala.com/\"}'"
  echo
  echo "  # 3. Any other URL -- full crawl + model + agent review, can take ~30-60s"
  echo "  curl -s -X POST ${base}/v1/detect \\"
  echo "    -H 'Content-Type: application/json'${kh} \\"
  echo "    -d '{\"url\":\"https://example.com/login\"}'"
  echo
  echo "  # 4. Interactive API docs -- open in a browser"
  echo "  ${base}/docs"
  if detector_is_exposed; then
    local phost; phost="$(resolve_bind_host)"
    echo
    echo "  From another machine, replace http://127.0.0.1:${dport} with http://${phost}:${dport}"
    echo "  (a server cannot reach its own public IP -- always test locally with 127.0.0.1)."
  fi
}

if [ "${SHOW_CONFIG}" -eq 1 ]; then
  cd "${SCRIPT_DIR}"
  [ -f .env ] || { echo "no deploy/.env here; run the installer first" >&2; exit 1; }
  ppd_key="$(env_val PPD_API_KEY)"
  ppd_host="$(resolve_bind_host)"
  ppd_port="$(env_val PPD_HOST_PORT)"; ppd_port="${ppd_port:-8088}"
  print_access_block
  echo
  print_sample_curls
  echo
  echo "Browser extension — open its options page and set:"
  echo "  Backend URL   http://${ppd_host}:${ppd_port}"
  if [ -z "${ppd_key//[[:space:]]/}" ]; then
    echo "  API key       (leave empty — this detector requires none)"
  else
    echo "  API key       ${ppd_key}"
  fi
  exit 0
fi

# Only docker is required. sha256sum used to be, which meant a host without
# coreutils could not deploy at all even though nothing needed hashing.
if ! command -v docker >/dev/null 2>&1; then
  echo "Required command is missing: docker" >&2
  exit 1
fi
if [ "${VERIFY_CHECKSUMS}" -eq 1 ] && ! command -v sha256sum >/dev/null 2>&1; then
  echo "--verify needs sha256sum, which is not installed." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required (the 'docker compose' command)." >&2
  exit 1
fi

cd "${SCRIPT_DIR}"
if [ ! -f .env ]; then
  if [ -f ../.env ]; then
    cp ../.env .env
    echo "using the .env from the repository root"
  else
    echo "Missing .env. Run 'cp ../.env.example .env' and fill it in." >&2
    exit 1
  fi
fi
for required in OPENROUTER_API_KEY INTERNAL_REVIEW_API_KEY; do
  value="$(sed -n "s/^${required}=//p" .env | tail -n 1)"
  if [ -z "${value//[[:space:]]/}" ]; then
    echo "${required} must be set in .env before deployment." >&2
    exit 1
  fi
done
unset value

# The reviewer reads OpenRouter settings from .env via env_file, which the shell
# cannot shadow. An older compose file that still interpolates ${OPENROUTER_*}
# would, though, so warn if the shell exports one that disagrees with .env: it
# is the difference between the agent working and it silently 403-ing on every
# call while every container reports healthy.
for shadow in OPENROUTER_API_KEY OPENROUTER_BASE_URL OPENROUTER_MODEL; do
  shell_val="$(printenv "${shadow}" || true)"
  file_val="$(sed -n "s/^${shadow}=//p" .env | tail -n 1)"
  if [ -n "${shell_val}" ] && [ -n "${file_val}" ] && [ "${shell_val}" != "${file_val}" ]; then
    echo "warning: ${shadow} is exported in your shell and differs from .env;" >&2
    echo "         the container uses the .env value. Unset it if the agent misbehaves." >&2
  fi
done
unset shadow shell_val file_val

# Load any image artefact that is present and not already loaded. Verifying the
# checksum first matters more here than usual: a truncated multi-hundred-megabyte
# download loads as a corrupt image rather than failing outright.
load_artefact() { # image_ref  glob
  local image="$1" pattern="$2" artefact
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "already loaded: ${image}"
    return 0
  fi
  local matches=() dir
  for dir in "${SEARCH_DIRS[@]}"; do
    # find takes the pattern as a literal, so it needs no unquoted glob expansion.
    mapfile -t matches < <(find "${dir}" -maxdepth 1 -name "${pattern}" 2>/dev/null | sort)
    [ ${#matches[@]} -gt 0 ] && break
  done
  if [ ${#matches[@]} -eq 0 ]; then
    echo "Missing ${image} and no artefact matching ${pattern}." >&2
    echo "Looked in:" >&2
    printf '  %s\n' "${SEARCH_DIRS[@]}" >&2
    echo "Download it from the GitHub release for that component, or pass" >&2
    echo "--image-dir with the directory holding the .tar.gz files." >&2
    return 1
  fi
  artefact="${matches[0]}"
  # Opt-in only; see the note at the top of this file.
  if [ "${VERIFY_CHECKSUMS}" -eq 1 ] && [ -f "${artefact}.sha256" ]; then
    echo "verifying $(basename "${artefact}")"
    ( cd "$(dirname "${artefact}")" && sha256sum --check "$(basename "${artefact}").sha256" )
  fi
  echo "loading $(basename "${artefact}")"
  gunzip -c "${artefact}" | docker load
  docker image inspect "${image}" >/dev/null
}

load_artefact "${DETECTOR_IMAGE}" "phishing-detection-engine-*.tar.gz"
load_artefact "${REVIEW_IMAGE}" "agentic-phishing-review-*.tar.gz"

COMPOSE=(-f compose.images.yaml)
if [ "${WITH_REFERENCES}" -eq 1 ]; then
  env_rag_version="$(sed -n 's/^RAG_VERSION=//p' .env | tail -n 1)"
  if [ -n "${env_rag_version//[[:space:]]/}" ]; then
    RAG_VERSION="${env_rag_version}"
    RAG_IMAGE="phishing-rag-service:${RAG_VERSION}"
    echo "using RAG_VERSION=${RAG_VERSION} from .env"
  fi
  if ! docker image inspect "${RAG_IMAGE}" >/dev/null 2>&1; then
    echo "Missing ${RAG_IMAGE}. It ships as split parts; reassemble it first:" >&2
    echo "  bash load_release.sh phishing-rag-service-${RAG_VERSION}.tar.gz.part00" >&2
    exit 1
  fi
  if ! grep -q '^RAG_INDEX_HOST_PATH=..*' .env; then
    echo "RAG_INDEX_HOST_PATH must point at the Embedding_Index directory in .env." >&2
    exit 1
  fi
  # Starting the service is not the same as using it. The reviewer reads
  # RAG_BASE_URL and supplies no references when it is empty, so without this
  # --full brought up a healthy retrieval service that nothing ever called:
  # /ready reported reference_service_configured false while the container sat
  # there answering queries for no one. Caught in a clean-container install.
  if ! grep -q '^RAG_BASE_URL=..*' .env; then
    if grep -q '^RAG_BASE_URL=' .env; then
      sed -i.bak 's|^RAG_BASE_URL=.*|RAG_BASE_URL=http://rag:8092|' .env
      rm -f .env.bak
    else
      printf '\nRAG_BASE_URL=http://rag:8092\n' >> .env
    fi
    echo "pointed the reviewer at the retrieval service"
  fi
  COMPOSE+=(-f compose.references.yaml)
  echo "reference retrieval enabled"
fi

docker compose --env-file .env "${COMPOSE[@]}" up -d

wait_healthy() { # service
  local service="$1" id health
  id="$(docker compose --env-file .env "${COMPOSE[@]}" ps -q "${service}")"
  if [ -z "${id}" ]; then
    echo "The ${service} container was not created." >&2
    return 1
  fi
  # The reference service loads a multi-gigabyte index before it reports ready,
  # so this waits minutes rather than seconds.
  for _ in $(seq 1 150); do
    health="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${id}")"
    case "${health}" in
      healthy) echo "${service}: healthy"; return 0 ;;
      unhealthy)
        docker compose --env-file .env "${COMPOSE[@]}" logs --no-color --tail=200 "${service}"
        echo "${service} became unhealthy; review the logs above." >&2
        return 1 ;;
      none) echo "${service}: running (no healthcheck defined)"; return 0 ;;
    esac
    sleep 2
  done
  docker compose --env-file .env "${COMPOSE[@]}" logs --no-color --tail=200 "${service}"
  echo "Timed out waiting for ${service} to become healthy." >&2
  return 1
}

wait_healthy review
wait_healthy detector
[ "${WITH_REFERENCES}" -eq 1 ] && wait_healthy rag

detector_port="$(env_val PPD_HOST_PORT)"; detector_port="${detector_port:-8088}"
review_port="$(env_val REVIEW_HOST_PORT)"; review_port="${review_port:-8090}"
detector_host="$(resolve_bind_host)"

echo
docker compose --env-file .env "${COMPOSE[@]}" ps
echo
print_access_block
# What to type into the browser extension. Printing this is the difference
# between a running stack and a usable one: the key is generated or left empty
# during the install, and an operator who did not write it down at the time had
# no way to find out which, or what it was.
ppd_key="$(env_val PPD_API_KEY)"
echo
echo "Browser extension — open its options page and set:"
echo "  Backend URL   http://${detector_host}:${detector_port}"
if [ -z "${ppd_key//[[:space:]]/}" ]; then
  echo "  API key       (leave empty — this detector requires none)"
else
  echo "  API key       ${ppd_key}"
fi
echo
print_sample_curls
echo
echo "Show this again at any time:  bash deploy/deploy.sh --show-config"
echo
echo "PersianPhish stack is up: detector ${DETECTOR_VERSION}, reviewer ${REVIEW_VERSION}."
