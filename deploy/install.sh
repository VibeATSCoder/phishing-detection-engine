#!/usr/bin/env bash
# One command to fetch, load and start the whole stack.
#
#   curl -fsSL https://raw.githubusercontent.com/VibeATSCoder/phishing-detection-engine/main/deploy/install.sh | bash
#
# or, having downloaded it:
#
#   bash install.sh                      detector + reviewer
#   bash install.sh --full               everything, including reference retrieval
#   bash install.sh --with-references    same as --full
#   bash install.sh --download-only      fetch and load, do not start
#   bash install.sh --dir ~/somewhere    install somewhere other than ./persianphish
#   bash install.sh --recheck            re-verify sizes of files already present
#
# If you already downloaded the release files by hand, or you want to, run it
# interactively and pick how the images should be provided:
#
#   bash install.sh -i                   ask, then do it
#   bash install.sh --artefact-dir ~/dl  use files already downloaded to ~/dl
#   bash install.sh --manual             print each link and wait while you fetch it
#
# --artefact-dir may be given more than once, and is searched before anything is
# downloaded, so a file you already have is never fetched twice.
#
# Credentials are found automatically, in this order: an exported GITHUB_TOKEN
# or GH_TOKEN, then `gh auth token`, then git's credential helper, then an
# export in a shell profile. Public repositories need none at all. To override
# or to force basic auth:
#
#   export GITHUB_TOKEN=ghp_...                       # token alone
#   export GITHUB_USER=you GITHUB_TOKEN=ghp_...       # username + token
#   NO_TOKEN_DISCOVERY=1 bash install.sh              # look nowhere
#
# ASSET_BASE_URL serves the artefacts from somewhere other than GitHub, for a
# network that reaches a mirror faster. Any plain HTTP server will do, and a
# missing file falls back to GitHub:
#
#   ASSET_BASE_URL=https://files.example.ir/persianphish bash install.sh --full
#
# A Hugging Face dataset repository works as that mirror with no extra tooling:
# it is free, has no size or egress limit that this stack comes close to, serves
# from a CDN, and its download path is exactly the ${BASE}/${name} shape used
# above. Measured against the GitHub releases from the same machine, GitHub
# sustained 2.81 MB/s and Hugging Face 4.42 MB/s, and both support the ranged
# resume this script relies on. Upload the mirrored directory once:
#
#   pip install -U huggingface_hub && hf auth login
#   hf upload <user>/persianphish-artifacts <mirror-dir> . --repo-type=dataset
#
# then install from it, with no credentials needed by the operator at all:
#
#   ASSET_BASE_URL=https://huggingface.co/datasets/<user>/persianphish-artifacts/resolve/main \
#     bash install.sh --full
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
# How the image artefacts are obtained. auto downloads them; local takes them
# from a directory they were downloaded to earlier; manual prints each link and
# waits for the operator to fetch it. INTERACTIVE asks which, rather than
# assuming, because the right answer depends on what the network allows.
SOURCE_MODE="auto"
INTERACTIVE=0
ARTEFACT_DIRS=()

# Versions this stack releases as. deploy/COMPATIBILITY.json records the same
# numbers and tests/test_release_contract.py asserts the two agree, so these
# cannot drift from the contract unnoticed.
DETECTOR_VERSION="${DETECTOR_VERSION:-3.3.0}"
REVIEW_VERSION="${REVIEW_VERSION:-1.5.0}"
RAG_VERSION="${RAG_VERSION:-1.0.2}"
STACK_VERSION="${STACK_VERSION:-1.1.0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) INSTALL_DIR="${2:?--dir needs a path}"; shift 2 ;;
    --with-references|--full) WITH_REFERENCES=1; shift ;;
    --download-only) DOWNLOAD_ONLY=1; shift ;;
    --recheck) RECHECK=1; shift ;;
    -i|--interactive) INTERACTIVE=1; shift ;;
    --manual) SOURCE_MODE="manual"; shift ;;
    --artefact-dir)
      ARTEFACT_DIRS+=("${2:?--artefact-dir needs a path}")
      SOURCE_MODE="local"; shift 2 ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo; echo "install failed: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# ------------------------------------------------------ asking the operator ---
# Read from the terminal, never from stdin. The documented way to run this is
# `curl ... | bash`, which hands the script itself to bash on stdin: a plain
# `read` there consumes the rest of the script instead of waiting for an answer.
HAVE_TTY=0
[ -r /dev/tty ] && HAVE_TTY=1
# Returns 1 when the terminal is at end of input. The caller has to act on
# that: a prompt loop that treats EOF as an empty answer never terminates, it
# just reprints the question forever at whatever speed the CPU allows.
ask() { # prompt  default -> answer on stdout
  local prompt="$1" default="${2:-}" reply=""
  if [ "${HAVE_TTY}" -eq 0 ]; then
    printf '%s' "${default}"
    return 1
  fi
  printf '%s' "${prompt}" > /dev/tty
  if ! IFS= read -r reply < /dev/tty; then
    printf '%s' "${default}"
    return 1
  fi
  printf '%s' "${reply:-${default}}"
}

# Bytes as something a person can compare against what their browser reported.
human_size() {
  local n="${1:-}"
  [ -n "${n}" ] || return 0
  if   [ "${n}" -ge 1073741824 ]; then printf '%s.%s GB' "$((n / 1073741824))" "$(( (n % 1073741824) * 10 / 1073741824 ))"
  elif [ "${n}" -ge 1048576 ];    then printf '%s MB' "$((n / 1048576))"
  elif [ "${n}" -ge 1024 ];       then printf '%s KB' "$((n / 1024))"
  else printf '%s bytes' "${n}"; fi
}
say() { # write to the terminal when there is one, so prompts are not piped away
  if [ "${HAVE_TTY}" -eq 1 ]; then echo "$*" > /dev/tty; else echo "$*"; fi
}

# The link an operator would click. Public releases serve this directly; for a
# private repository it is the page to open while signed in, which is the whole
# reason manual mode exists — a browser has the session cookie that a token
# cannot substitute for on this path.
asset_url() { # repo tag name
  printf 'https://github.com/%s/%s/releases/download/%s/%s' "${OWNER}" "$1" "$2" "$3"
}

# Take a file the operator already has instead of downloading it. Searched
# before every download, in every mode, so pointing at a directory of
# half-finished downloads resumes them rather than starting over.
#
# Hard-linked when possible and copied otherwise: the source directory may be a
# separate filesystem, and multi-gigabyte artefacts should not be duplicated
# just to move them one directory over when they need not be.
adopt_local() { # name  expected_size -> 0 if the file is now in the install dir
  local name="$1" expected="${2:-}" dir src size
  for dir in ${ARTEFACT_DIRS[@]+"${ARTEFACT_DIRS[@]}"}; do
    src="${dir%/}/${name}"
    [ -f "${src}" ] || continue
    size="$(stat -c%s "${src}" 2>/dev/null || echo 0)"
    if [ -n "${expected}" ] && [ "${size}" != "${expected}" ]; then
      echo "  skip  ${src} is ${size} bytes, expected ${expected}" >&2
      continue
    fi
    [ "$(readlink -f "${src}")" = "$(readlink -f "./${name}")" ] && return 0
    ln "${src}" "./${name}" 2>/dev/null || cp "${src}" "./${name}" || continue
    echo "  use   ${name} from ${dir%/}"
    return 0
  done
  return 1
}

# Ask for one file to be fetched by hand, and do not continue until it is there.
# Re-checks after every answer rather than trusting the confirmation, because
# the failure this exists to catch — a browser that saved a 404 page, or saved
# to Downloads instead of here — looks exactly like success to the operator.
prompt_for_asset() { # repo tag name expected
  local repo="$1" tag="$2" name="$3" expected="${4:-}" url reply size
  url="$(asset_url "${repo}" "${tag}" "${name}")"
  while :; do
    say ""
    say "  needed: ${name}${expected:+  ($(human_size "${expected}"))}"
    say "  from:   ${url}"
    say "  into:   $(pwd)"
    if [ "${HAVE_TTY}" -eq 0 ]; then
      die "manual mode needs a terminal to ask on. Download install.sh and run it directly rather than piping it to bash."
    fi
    if ! reply="$(ask '  [Enter] once downloaded, (d) download it for me, (q) quit: ' '')"; then
      die "no answer available on the terminal, so ${name} cannot be asked for.
Either download it to $(pwd) and run again, or drop --manual to fetch it here."
    fi
    case "${reply}" in
      q|Q) die "stopped at ${name}. Re-run when you have it; nothing already downloaded is lost." ;;
      d|D) return 1 ;;  # caller falls through to the normal download path
    esac
    if [ ! -f "./${name}" ]; then
      # The overwhelmingly common case: saved to the browser's download folder.
      if adopt_local "${name}" "${expected}"; then return 0; fi
      for dir in "${HOME}/Downloads" "${HOME}/downloads" "${HOME}"; do
        if [ -f "${dir}/${name}" ]; then
          say "  found it in ${dir}, taking it from there"
          ln "${dir}/${name}" "./${name}" 2>/dev/null || cp "${dir}/${name}" "./${name}"
          break
        fi
      done
    fi
    if [ ! -f "./${name}" ]; then
      say "  ${name} is still not in $(pwd) — check the filename matches exactly"
      continue
    fi
    size="$(stat -c%s "./${name}" 2>/dev/null || echo 0)"
    if [ -n "${expected}" ] && [ "${size}" != "${expected}" ]; then
      say "  ${name} is ${size} bytes but should be ${expected}; the download is incomplete"
      continue
    fi
    echo "  have  ${name} (provided by hand)"
    return 0
  done
}

# ------------------------------------------------------------- preflight ---
for required in docker curl python3 tar gzip; do
  command -v "${required}" >/dev/null 2>&1 || die "required command missing: ${required}"
done
docker compose version >/dev/null 2>&1 \
  || die "Docker Compose v2 is required (the 'docker compose' command)"
docker info >/dev/null 2>&1 \
  || die "cannot talk to the Docker daemon; is it running, and is your user in the docker group?"

# ----------------------------------------------------- interactive choices ---
# Only when asked for, and only with a terminal to ask on: the one-line install
# has to stay non-interactive, and piping this script to bash leaves no tty.
if [ "${INTERACTIVE}" -eq 1 ]; then
  [ "${HAVE_TTY}" -eq 1 ] \
    || die "-i needs a terminal. Download install.sh and run it directly rather than piping it to bash."
  say ""
  say "How should the images be provided?"
  say "  1) Download them now from the GitHub releases   (default)"
  say "  2) Use files I have already downloaded          (I will give the directory)"
  say "  3) Show me each link and wait while I download  (for a browser-only network)"
  case "$(ask '  choice [1]: ' 1)" in
    2) SOURCE_MODE="local" ;;
    3) SOURCE_MODE="manual" ;;
    *) SOURCE_MODE="auto" ;;
  esac

  if [ "${SOURCE_MODE}" = "local" ] && [ ${#ARTEFACT_DIRS[@]} -eq 0 ]; then
    while :; do
      answer="$(ask "  directory holding the downloaded files [${PWD}]: " "${PWD}")" \
        || die "no answer available on the terminal; pass --artefact-dir instead"
      # ~ is not expanded by read, so a typed ~/dl would otherwise be a
      # directory literally named "~".
      answer="${answer/#\~/${HOME}}"
      if [ -d "${answer}" ]; then
        ARTEFACT_DIRS+=("${answer}")
        say "  using $(cd -- "${answer}" && pwd)"
        break
      fi
      say "  no such directory: ${answer}"
    done
  fi

  if [ "${WITH_REFERENCES}" -eq 0 ]; then
    say ""
    say "Include the reference retrieval service? It improves the reviewer's"
    say "judgement but adds 2.9 GB to download and needs 8 GB of memory to run."
    case "$(ask '  include it? [y/N]: ' n)" in
      y|Y|yes|YES) WITH_REFERENCES=1 ;;
    esac
  fi
  unset answer
fi

# Files already downloaded are worth finding whatever the mode: an interrupted
# run leaves them in the install directory, and the operator may simply have put
# them where they ran the script from.
ARTEFACT_DIRS+=("${INSTALL_DIR}" "${PWD}")

# Find a token wherever this machine already keeps one, rather than making the
# operator export it first. Every source below is somewhere a token legitimately
# lives on a machine that already talks to this GitHub account, and each is read
# only, so the common case is genuinely one line with nothing set up.
discover_token() {
  local token=""

  # 1. Already exported, under either of the two names in common use.
  token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  if [ -n "${token}" ]; then printf '%s|%s' "${token}" "environment"; return 0; fi

  # 2. The GitHub CLI, if it is installed and logged in. This is the usual case
  #    on a developer machine and needs nothing from the operator.
  if command -v gh >/dev/null 2>&1; then
    token="$(gh auth token 2>/dev/null || true)"
    if [ -n "${token}" ]; then printf '%s|%s' "${token}" "gh auth"; return 0; fi
  fi

  # 3. Git's credential helper, which is what a previous `git push` populated.
  #
  #    GIT_TERMINAL_PROMPT=0 is what keeps this from hanging, and it is not
  #    optional. Closing stdin does not stop git asking: with no helper able to
  #    answer, it opens the terminal directly and prompts for a GitHub username
  #    and password. That went unnoticed for as long as this script only ever
  #    ran non-interactively, where there is no terminal to prompt on. Running
  #    it with -i or --manual gave it one, and token discovery then sat on
  #    "Username for 'https://github.com':" and swallowed the operator's answers
  #    to the install's own questions. GIT_ASKPASS covers the helpers that pop a
  #    window instead of using the terminal.
  if command -v git >/dev/null 2>&1; then
    token="$(printf 'protocol=https\nhost=github.com\n\n' \
             | GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true GCM_INTERACTIVE=never \
               git credential fill 2>/dev/null \
             | sed -n 's/^password=//p' | head -n 1)"
    if [ -n "${token}" ]; then printf '%s|%s' "${token}" "git credential helper"; return 0; fi
  fi

  # 4. A shell profile that exports one. Read with sed rather than sourced: this
  #    script must never execute someone's profile as a side effect.
  #
  #    Values that are variable references are skipped. A profile very commonly
  #    contains both the real token and a line aliasing it, as in
  #    `export GH_TOKEN="$GITHUB_TOKEN"`, and taking the last match hands back
  #    the literal string "$GITHUB_TOKEN", which then fails as a 401 that looks
  #    like a bad token rather than a parsing mistake.
  local profile candidate
  for profile in "${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.profile" "${HOME}/.zshrc"; do
    [ -r "${profile}" ] || continue
    while IFS= read -r candidate; do
      # shellcheck disable=SC2016  # matching a literal $, not expanding one
      case "${candidate}" in
        ''|'$'*|*'${'*) continue ;;
      esac
      printf '%s|%s' "${candidate}" "$(basename "${profile}")"
      return 0
    done <<EOF
$(sed -n 's/^[[:space:]]*export[[:space:]]\{1,\}\(GITHUB_TOKEN\|GH_TOKEN\)=["'"'"']\{0,1\}\([^"'"'"'[:space:]]\{1,\}\).*/\2/p' "${profile}")
EOF
  done

  return 1
}

AUTH=()
TOKEN_SOURCE=""
if [ -z "${GITHUB_TOKEN:-}" ] && [ "${NO_TOKEN_DISCOVERY:-0}" != "1" ]; then
  if found="$(discover_token)"; then
    GITHUB_TOKEN="${found%%|*}"
    TOKEN_SOURCE="${found##*|}"
  fi
fi
if [ -n "${GITHUB_USER:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-u "${GITHUB_USER}:${GITHUB_TOKEN}")
  echo "authenticating as ${GITHUB_USER}${TOKEN_SOURCE:+ (token from ${TOKEN_SOURCE})}"
elif [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  echo "authenticating with a token${TOKEN_SOURCE:+ from ${TOKEN_SOURCE}}"
else
  echo "no credentials found; only public repositories will be reachable"
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
  if [ -n "${ASSET_BASE_URL:-}" ]; then
    if headers="$(curl -fsIL --retry 3 --retry-all-errors \
                    "${ASSET_BASE_URL%/}/${name}" 2>/dev/null)"; then
      printf '%s' "$(printf '%s' "${headers}" | tr -d '\r' \
              | awk 'BEGIN{IGNORECASE=1} /^content-length:/ {n=$2} END{print n}')"
      return 0
    fi
    return 0
  fi
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
    # A file the operator already fetched, wherever they put it. Checked before
    # any request so --artefact-dir never re-downloads what it was given, and so
    # manual mode only asks for what is genuinely absent.
    adopt_local "${name}" "${expected}" && return 0
    if [ "${SOURCE_MODE}" = "manual" ]; then
      # Returns non-zero only when the operator asked for it to be downloaded
      # after all, which falls through to the normal path below.
      prompt_for_asset "${repo}" "${tag}" "${name}" "${expected}" && return 0
    elif [ "${SOURCE_MODE}" = "local" ]; then
      # Not a failure. --artefact-dir says where the files already are, not that
      # nothing may ever be downloaded: refusing outright meant an operator who
      # had both images on disk was still stopped dead by the 15 KB bundle of
      # compose files, and told to go and fetch it by hand. Use what is there,
      # fetch what is not, and say which is happening. --manual is the mode for
      # an operator who wants to be asked before anything is downloaded.
      echo "  ${name} is not in the directories given; fetching it"
    fi
    echo "  get   ${name}${expected:+ ($(human_size "${expected}"))}"
  fi

  # A mirror, when the deployment network reaches one faster than it reaches
  # GitHub. Measured from a machine with ordinary connectivity, GitHub sustains
  # ~2.6 MB/s and Cloudflare's own speed test ~3.1 MB/s, so mirroring buys
  # nothing there and is not the default. It matters where GitHub is throttled
  # or blocked, which is exactly where this stack tends to be deployed.
  #
  # Plain HTTP GET by filename, so anything serves it: nginx, S3, a bucket
  # behind a CDN, or `python3 -m http.server` in the directory. Falls through to
  # GitHub when the mirror does not have the file, so a partial mirror is fine.
  if [ -n "${ASSET_BASE_URL:-}" ]; then
    if curl -fL -C - --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
         -o "${name}" "${ASSET_BASE_URL%/}/${name}" 2>/dev/null; then
      echo "    from ${ASSET_BASE_URL%/}"
      if [ -n "${expected}" ]; then
        local_size="$(stat -c%s "${name}" 2>/dev/null || echo 0)"
        [ "${local_size}" = "${expected}" ] \
          || die "${name} is ${local_size} bytes but the mirror said ${expected}"
      fi
      return 0
    fi
    echo "    not on the mirror; falling back to GitHub" >&2
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
ensure_image "phishing-detection-engine:${DETECTOR_VERSION}" \
  phishing-detection-engine "v${DETECTOR_VERSION}" \
  "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz"
ensure_image "agentic-phishing-review:${REVIEW_VERSION}" \
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

# The retrieval service mounts its index from the host rather than carrying it
# in the image, so --full needs a path that only this machine knows. Look in the
# places it actually lands before asking the operator for it.
discover_index() {
  local candidate
  for candidate in \
    "${RAG_INDEX_HOST_PATH:-}" \
    "${PWD}/Embedding_Index" \
    "${HOME}/Embedding_Index" \
    /var/services/idk/Phishing_RAG/Phishing_RAG_S3_Output/Output/Embedding_Index \
    /data/Embedding_Index \
    /opt/persianphish/Embedding_Index
  do
    [ -n "${candidate}" ] || continue
    # block_index.parquet is the file the retriever opens first, so its presence
    # is what makes a directory an index rather than a directory of that name.
    if [ -f "${candidate}/block_index.parquet" ]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

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
  if [ -z "${value//[[:space:]]/}" ]; then
    if index_dir="$(discover_index)"; then
      # sed with | as the delimiter, because the value is a path.
      sed -i.bak "s|^RAG_INDEX_HOST_PATH=.*|RAG_INDEX_HOST_PATH=${index_dir}|" deploy/.env
      rm -f deploy/.env.bak
      echo "  found the reference index at ${index_dir}"
    else
      missing="${missing} RAG_INDEX_HOST_PATH"
      echo "  no reference index found; set RAG_INDEX_HOST_PATH in deploy/.env" >&2
      echo "  it is the Embedding_Index directory containing block_index.parquet" >&2
    fi
  fi
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
