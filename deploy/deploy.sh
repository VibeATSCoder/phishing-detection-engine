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
#
# Required in .env: OPENROUTER_API_KEY and INTERNAL_REVIEW_API_KEY.
set -euo pipefail

readonly DETECTOR_VERSION="3.2.1"
readonly REVIEW_VERSION="1.4.1"
readonly RAG_VERSION="1.0.2"
readonly DETECTOR_IMAGE="phishing-detection-engine:${DETECTOR_VERSION}-integrated"
readonly REVIEW_IMAGE="agentic-phishing-review:${REVIEW_VERSION}-integrated"
readonly RAG_IMAGE="phishing-rag-service:${RAG_VERSION}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

IMAGE_DIR="${SCRIPT_DIR}"
WITH_REFERENCES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image-dir) IMAGE_DIR="${2:?--image-dir needs a path}"; shift 2 ;;
    --with-references) WITH_REFERENCES=1; shift ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

for command in docker sha256sum; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Required command is missing: ${command}" >&2
    exit 1
  fi
done
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

# Load any image artefact that is present and not already loaded. Verifying the
# checksum first matters more here than usual: a truncated multi-hundred-megabyte
# download loads as a corrupt image rather than failing outright.
load_artefact() { # image_ref  glob
  local image="$1" pattern="$2" artefact
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "already loaded: ${image}"
    return 0
  fi
  local matches=()
  # find takes the pattern as a literal, so it needs no unquoted glob expansion.
  mapfile -t matches < <(find "${IMAGE_DIR}" -maxdepth 1 -name "${pattern}" | sort)
  if [ ${#matches[@]} -eq 0 ]; then
    echo "Missing ${image} and no artefact matching ${pattern} in ${IMAGE_DIR}." >&2
    echo "Download it from the GitHub release for that component." >&2
    return 1
  fi
  artefact="${matches[0]}"
  if [ -f "${artefact}.sha256" ]; then
    echo "verifying $(basename "${artefact}")"
    ( cd "$(dirname "${artefact}")" && sha256sum --check "$(basename "${artefact}").sha256" )
  else
    echo "warning: no checksum beside $(basename "${artefact}"); loading unverified" >&2
  fi
  echo "loading $(basename "${artefact}")"
  gunzip -c "${artefact}" | docker load
  docker image inspect "${image}" >/dev/null
}

load_artefact "${DETECTOR_IMAGE}" "phishing-detection-engine-*.tar.gz"
load_artefact "${REVIEW_IMAGE}" "agentic-phishing-review-*.tar.gz"

COMPOSE=(-f compose.images.yaml)
if [ "${WITH_REFERENCES}" -eq 1 ]; then
  if ! docker image inspect "${RAG_IMAGE}" >/dev/null 2>&1; then
    echo "Missing ${RAG_IMAGE}. It ships as split parts; reassemble it first:" >&2
    echo "  bash load_release.sh phishing-rag-service-${RAG_VERSION}.tar.gz.part00" >&2
    exit 1
  fi
  if ! grep -q '^RAG_INDEX_HOST_PATH=..*' .env; then
    echo "RAG_INDEX_HOST_PATH must point at the Embedding_Index directory in .env." >&2
    exit 1
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

detector_port="$(sed -n 's/^PPD_HOST_PORT=//p' .env | tail -n 1)"
review_port="$(sed -n 's/^REVIEW_HOST_PORT=//p' .env | tail -n 1)"
detector_port="${detector_port:-8088}"
review_port="${review_port:-8090}"

echo
docker compose --env-file .env "${COMPOSE[@]}" ps
echo
echo "detector  http://127.0.0.1:${detector_port}/health"
echo "reviewer  http://127.0.0.1:${review_port}/ready"
echo "metrics   http://127.0.0.1:${detector_port}/metrics and :${review_port}/metrics"
echo
echo "Smoke test:"
echo "  curl -s -X POST http://127.0.0.1:${detector_port}/v1/detect \\"
echo "    -H 'Content-Type: application/json' -d '{\"url\":\"https://www.digikala.com/\"}'"
echo
echo "PersianPhish stack is up: detector ${DETECTOR_VERSION}, reviewer ${REVIEW_VERSION}."
