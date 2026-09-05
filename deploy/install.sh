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
#   bash install.sh --no-prompt          never ask; write the template and stop
#   bash install.sh --no-install         never install packages; just report
#
# On a host that is missing Docker, curl, python3, tar or gzip, it offers to
# install them rather than stopping at the first one. Docker comes from the
# official get.docker.com script, which is the one path that produces the engine
# and the Compose v2 plugin on every distribution; the smaller tools come from
# apt, dnf, yum, zypper, pacman or apk. A stopped daemon is started, and a user
# who cannot reach the socket is offered the docker group. Nothing is installed
# without asking, and nothing is installed at all without a terminal.
#
# With a terminal available it asks for what the services need and writes
# deploy/.env for you: the model endpoint and key (checked against the provider
# before it is accepted), a generated shared secret for the detector-to-reviewer
# call, an optional key on the detector itself, and an optional VirusTotal key
# for the intelligence monitor. Nothing has to be edited by hand. Without a
# terminal, or with --no-prompt, it writes the template and reports what is
# missing exactly as before, so CI is unaffected.
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

# Everything below is inside a block so that bash parses the whole script before
# it executes a line of it. Two reasons, both seen in practice:
#
#   * `curl ... | bash` feeds the script in as it arrives. A die() early in the
#     file exits while curl is still writing, and curl reports its own failure
#     over the top of ours: "curl: (23) Failure writing output to destination",
#     which reads like a download problem rather than the missing dependency it
#     actually was.
#   * A connection dropped mid-transfer would otherwise run whichever half of
#     the script had arrived.
{

OWNER="${GITHUB_OWNER:-VibeATSCoder}"
RAW="https://raw.githubusercontent.com/${OWNER}/phishing-detection-engine/main"
# Re-running from inside an existing install should update it, not nest a
# second one inside it. Someone who has installed once and comes back to pick up
# a fix naturally runs the command from the directory they are already in, and
# got /home/you/persianphish/persianphish for it — a second copy that then
# downloads everything again and leaves the first one stale.
if [ -f "${PWD}/deploy/compose.images.yaml" ] || [ -f "${PWD}/deploy/.env" ]; then
  INSTALL_DIR="${PWD}"
else
  INSTALL_DIR="${PWD}/persianphish"
fi
WITH_REFERENCES=0
FETCH_INDEX=0
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
DETECTOR_VERSION="${DETECTOR_VERSION:-3.8.0}"
REVIEW_VERSION="${REVIEW_VERSION:-1.10.0}"
RAG_VERSION="${RAG_VERSION:-1.0.2}"
STACK_VERSION="${STACK_VERSION:-1.1.0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) INSTALL_DIR="${2:?--dir needs a path}"; shift 2 ;;
    --with-references|--full) WITH_REFERENCES=1; shift ;;
    --download-only) DOWNLOAD_ONLY=1; shift ;;
    --recheck) RECHECK=1; shift ;;
    --no-prompt) NO_PROMPT=1; shift ;;
    --no-install) NO_INSTALL=1; shift ;;
    -i|--interactive) INTERACTIVE=1; shift ;;
    --manual) SOURCE_MODE="manual"; shift ;;
    --artefact-dir)
      ARTEFACT_DIRS+=("${2:?--artefact-dir needs a path}")
      SOURCE_MODE="local"; shift 2 ;;
    -h|--help) sed -n '2,75p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo; echo "install failed: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# ------------------------------------------------------ asking the operator ---
# Read from the terminal, never from stdin. The documented way to run this is
# `curl ... | bash`, which hands the script itself to bash on stdin: a plain
# `read` there consumes the rest of the script instead of waiting for an answer.
# Opening it is the only honest test. [ -r /dev/tty ] inspects the device node's
# permission bits, which are satisfied on a machine that has a console even when
# this process has no controlling terminal — a systemd unit, a container without
# -t, a setsid'd CI step. That reported a terminal, the installer began asking
# questions, and every prompt failed with "/dev/tty: No such device or address".
HAVE_TTY=0
if { exec 3<>/dev/tty; } 2>/dev/null; then
  HAVE_TTY=1
  exec 3>&-
fi
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

# Read a value that must not be echoed to the screen or land in scrollback.
ask_secret() { # prompt -> value on stdout
  local prompt="$1" reply=""
  if [ "${HAVE_TTY}" -eq 0 ]; then
    return 1
  fi
  printf '%s' "${prompt}" > /dev/tty
  if ! IFS= read -rs reply < /dev/tty; then
    printf '\n' > /dev/tty
    return 1
  fi
  printf '\n' > /dev/tty
  printf '%s' "${reply}"
}

# A shared secret between the detector and the reviewer. It is never typed by a
# person and never leaves the host, so generating it is strictly better than
# asking someone to invent one.
generate_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# Set a key in deploy/.env, replacing any existing definition.
#
# Done in python rather than sed because these are secrets: a key can contain
# any byte, including the sed delimiter and backreference characters, and a
# mangled value here fails at first request rather than at write time.
# Passed through the environment rather than argv on purpose: /proc/<pid>/cmdline
# is world readable, so a key on the command line is visible in ps to every user
# on the host for as long as the write takes. /proc/<pid>/environ is not.
set_env() { # key value
  PPD_SET_KEY="$1" PPD_SET_VALUE="$2" python3 - <<'PY'
import os, pathlib
key, value = os.environ["PPD_SET_KEY"], os.environ["PPD_SET_VALUE"]
path = pathlib.Path("deploy/.env")
lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
out, replaced = [], False
for line in lines:
    if line.lstrip().startswith(f"{key}="):
        if not replaced:
            out.append(f"{key}={value}")
            replaced = True
        continue
    out.append(line)
if not replaced:
    out.append(f"{key}={value}")
path.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
PY
}

env_value() { # key -> current value in deploy/.env
  sed -n "s/^$1=//p" deploy/.env 2>/dev/null | tail -n 1
}

# Confirm the key and endpoint actually work before the install claims success.
# A wrong key is otherwise discovered at the first detection, by which point the
# operator has no reason to connect the two.
check_openrouter() { # key base_url model -> 0 if a completion comes back
  local key="$1" base="$2" model="$3" body
  body="$(curl -s --max-time 30 "${base%/}/chat/completions" \
      -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" \
      -d "{\"model\":\"${model}\",\"messages\":[{\"role\":\"user\",\"content\":\"ok\"}],\"max_tokens\":1}" \
    2>/dev/null)" || return 1
  printf '%s' "${body}" | grep -q '"choices"'
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
# A missing dependency used to end the install with one line naming the command
# and nothing else, which on a fresh Debian or Ubuntu host is every time. Offer
# to install what is missing instead, and only refuse when that is not possible.

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  fi
fi

detect_pm() {
  local pm
  for pm in apt-get dnf yum zypper pacman apk; do
    if command -v "${pm}" >/dev/null 2>&1; then
      printf '%s' "${pm}"
      return 0
    fi
  done
  return 1
}

pm_install() { # package...
  local pm="$1"; shift
  case "${pm}" in
    apt-get)
      ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get update -qq \
        && ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf)    ${SUDO} dnf install -y -q "$@" ;;
    yum)    ${SUDO} yum install -y -q "$@" ;;
    zypper) ${SUDO} zypper --non-interactive install "$@" ;;
    pacman) ${SUDO} pacman -Sy --noconfirm "$@" ;;
    apk)    ${SUDO} apk add --no-cache "$@" ;;
    *) return 1 ;;
  esac
}

# The package that provides a command, per manager. Only the names that actually
# differ are listed; anything absent here is named the same everywhere.
pkg_for() { # pm command
  case "$2" in
    python3) case "$1" in apk) printf 'python3' ;; *) printf 'python3' ;; esac ;;
    *) printf '%s' "$2" ;;
  esac
}

may_install() { # what -> 0 if we are allowed to try
  if [ "${NO_INSTALL:-0}" = "1" ]; then
    return 1
  fi
  if [ "$(id -u)" -ne 0 ] && [ -z "${SUDO}" ]; then
    return 1
  fi
  if [ "${HAVE_TTY}" -eq 0 ]; then
    # Unattended: installing packages without being asked is not this script's
    # decision to make on someone else's machine.
    return 1
  fi
  case "$(ask "  install $1 now? [Y/n]: " y)" in
    n|N|no|NO) return 1 ;;
    *) return 0 ;;
  esac
}

PM="$(detect_pm || true)"

# --- the small tools ---------------------------------------------------------
missing_tools=""
for required in curl python3 tar gzip; do
  command -v "${required}" >/dev/null 2>&1 || missing_tools="${missing_tools} ${required}"
done
if [ -n "${missing_tools}" ]; then
  say ""
  say "Missing:${missing_tools}"
  if [ -z "${PM}" ]; then
    die "no supported package manager found; install${missing_tools} and run again"
  fi
  packages=""
  for tool in ${missing_tools}; do
    packages="${packages} $(pkg_for "${PM}" "${tool}")"
  done
  if may_install "them with ${PM}"; then
    # shellcheck disable=SC2086
    pm_install "${PM}" ${packages} || die "could not install${missing_tools}"
  else
    die "install${missing_tools} and run again"
  fi
  for required in ${missing_tools}; do
    command -v "${required}" >/dev/null 2>&1 \
      || die "${required} is still missing after the install"
  done
  say "  installed"
fi

# --- docker ------------------------------------------------------------------
install_docker() {
  # Docker's own script is the one path that produces the engine *and* the
  # Compose v2 plugin on every distribution this is likely to meet. Distribution
  # packages vary: Debian's docker.io ships no compose plugin at all on older
  # releases, and the plugin package is named differently everywhere.
  say ""
  say "  Docker will be installed with the official script from get.docker.com,"
  say "  which adds Docker's repository and the Compose v2 plugin."
  case "$(ask '  proceed? [Y/n]: ' y)" in
    n|N|no|NO) return 2 ;;   # declined, which is not the same as failed
  esac
  local script
  script="$(mktemp)" || return 1
  curl -fsSL --connect-timeout 15 --max-time 120 https://get.docker.com -o "${script}" || { rm -f "${script}"; return 1; }
  ${SUDO} sh "${script}"
  local status=$?
  rm -f "${script}"
  return ${status}
}

if ! command -v docker >/dev/null 2>&1; then
  say ""
  say "Docker is not installed."
  if [ "${NO_INSTALL:-0}" = "1" ] || { [ "$(id -u)" -ne 0 ] && [ -z "${SUDO}" ]; } \
     || [ "${HAVE_TTY}" -eq 0 ]; then
    die "install Docker Engine and Compose v2, then run again:
  https://docs.docker.com/engine/install/"
  fi
  # Captured rather than tested bare: under set -e a non-zero return from a
  # bare call exits the script instantly, so the case below never ran and the
  # operator saw the prompt and then nothing at all.
  docker_rc=0
  install_docker || docker_rc=$?
  case ${docker_rc} in
    0) : ;;
    2) die "Docker is required. Install it and run this again:
  https://docs.docker.com/engine/install/" ;;
    *) die "the Docker install did not finish. Install it by hand and run this
again:  https://docs.docker.com/engine/install/" ;;
  esac
  command -v docker >/dev/null 2>&1 || die "docker is still missing after the install"
  say "  Docker installed"
fi

# --- the daemon --------------------------------------------------------------
start_daemon() {
  if command -v systemctl >/dev/null 2>&1; then
    ${SUDO} systemctl enable --now docker >/dev/null 2>&1 && return 0
  fi
  if command -v service >/dev/null 2>&1; then
    ${SUDO} service docker start >/dev/null 2>&1 && return 0
  fi
  # WSL and some containers run neither: dockerd has to be started by hand.
  return 1
}

if ! docker info >/dev/null 2>&1; then
  # Two very different causes look identical from here: the daemon is down, or
  # it is up and this user may not talk to its socket.
  if [ -n "${SUDO}" ] && ${SUDO} docker info >/dev/null 2>&1; then
    say ""
    say "The Docker daemon is running but your user cannot reach its socket."
    if [ "${HAVE_TTY}" -eq 1 ] && [ "${NO_INSTALL:-0}" != "1" ]; then
      case "$(ask "  add $(id -un) to the docker group? [Y/n]: " y)" in
        n|N|no|NO) : ;;
        *) ${SUDO} usermod -aG docker "$(id -un)" 2>/dev/null \
             && say "  added — it takes effect at your next login" ;;
      esac
    fi
    # Group membership does not apply to a shell that is already running, so
    # this run goes through sudo. Overriding the name means every later call in
    # this script picks it up without threading a variable through all of them;
    # sudo resolves the binary from PATH, so this does not recurse.
    say "  using sudo for Docker in this run"
    docker() { sudo docker "$@"; }
    DOCKER_NEEDS_SUDO=1
  else
    say ""
    say "The Docker daemon is not responding; trying to start it."
    if start_daemon && docker info >/dev/null 2>&1; then
      say "  started"
    elif [ -n "${SUDO}" ] && ${SUDO} docker info >/dev/null 2>&1; then
      say "  started; using sudo for Docker in this run"
      docker() { sudo docker "$@"; }
      DOCKER_NEEDS_SUDO=1
    else
      die "cannot talk to the Docker daemon.
Start it and run again. On most systems:  sudo systemctl start docker
Under WSL without systemd:                sudo dockerd &"
    fi
  fi
fi
DOCKER_NEEDS_SUDO="${DOCKER_NEEDS_SUDO:-0}"

# --- compose v2 --------------------------------------------------------------
if ! docker compose version >/dev/null 2>&1; then
  say ""
  say "Docker is present but the Compose v2 plugin is not."
  installed=0
  if [ -n "${PM}" ] && may_install "the Compose plugin with ${PM}"; then
    case "${PM}" in
      apt-get) pm_install "${PM}" docker-compose-plugin 2>/dev/null \
                 || pm_install "${PM}" docker-compose-v2 2>/dev/null || true ;;
      dnf|yum|zypper) pm_install "${PM}" docker-compose-plugin 2>/dev/null || true ;;
      pacman)  pm_install "${PM}" docker-compose 2>/dev/null || true ;;
      apk)     pm_install "${PM}" docker-cli-compose 2>/dev/null || true ;;
    esac
    docker compose version >/dev/null 2>&1 && installed=1
  fi
  if [ "${installed}" -eq 0 ]; then
    die "Docker Compose v2 is required (the 'docker compose' command).
Install it with:  https://docs.docker.com/compose/install/linux/"
  fi
  say "  installed"
fi

# These three are consulted by the questions below, so they have to be
# defined before them: bash resolves a function at the point of the call,
# and they used to sit several hundred lines further down.
# ------------------------------------------------------------ downloading ---
# What of the retrieval service this machine already has.
#
# Prints one of: image | artefacts | none. The 2.9 GB download is the reason
# most people never enable references, so finding a copy already present is the
# difference between offering it and not.
find_local_rag() {
  if docker image inspect "phishing-rag-service:${RAG_VERSION}" >/dev/null 2>&1; then
    printf 'image'
    return 0
  fi
  local dir
  for dir in ${ARTEFACT_DIRS[@]+"${ARTEFACT_DIRS[@]}"} "${PWD}"; do
    [ -d "${dir}" ] || continue
    if [ -f "${dir%/}/phishing-rag-service-${RAG_VERSION}.tar.gz.part00" ] \
       || [ -f "${dir%/}/phishing-rag-service-${RAG_VERSION}.tar.gz" ]; then
      printf 'artefacts'
      return 0
    fi
  done
  printf 'none'
}

# Memory actually available to containers, in GB. The retrieval service memory
# maps a 3 GB index and answers in 5-7 seconds at 8 GB; at 4 GB it exceeds the
# reviewer's timeout and the references never arrive, which looks like the
# service being broken rather than starved.
host_memory_gb() {
  local kb
  kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  printf '%s' "$((kb / 1024 / 1024))"
}

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

# ----------------------------------------------------- interactive choices ---
# Asked by default whenever there is a terminal to ask on, which the one-line
# install does have: piping the script to bash replaces stdin and leaves
# /dev/tty alone. It used to require -i, so the ordinary `curl | bash` reader was
# never offered the choice and simply watched a 699 MB download start without
# being told it could point at files it already had.
#
# Skipped when the answer is already on the command line, and skipped entirely
# without a terminal or under --no-prompt, so automation is unchanged.
if [ "${INTERACTIVE}" -eq 1 ] && [ "${HAVE_TTY}" -eq 0 ]; then
  die "-i needs a terminal. Download install.sh and run it directly rather than piping it to bash."
fi
# The source menu is skipped when a flag already answered it.
if [ "${HAVE_TTY}" -eq 1 ] && [ "${NO_PROMPT:-0}" != "1" ] \
   && { [ "${INTERACTIVE}" -eq 1 ] || [ "${SOURCE_MODE}" = "auto" ]; }; then
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

fi

# Asked whenever there is a terminal, whatever the image source is. It used to
# live inside the source-menu block, so passing --artefact-dir — the flag for
# "I already have the images", which is exactly when someone is most likely to
# have the reference image too — skipped the question entirely.
if [ "${HAVE_TTY}" -eq 1 ] && [ "${NO_PROMPT:-0}" != "1" ]; then
# Asked on every interactive run, not only under -i. Gating it behind a flag
# meant the ordinary one-line install never mentioned references at all, so an
# operator with the image already sitting on disk was never offered it.
#
# The question is shaped by what this machine actually has, because the honest
# answer differs enormously: loading a copy already present takes a minute,
# and fetching one is 2.9 GB.
if [ "${WITH_REFERENCES}" -eq 0 ]; then
  rag_local="$(find_local_rag)"
  rag_index="$(discover_index || true)"
  mem_gb="$(host_memory_gb)"
  say ""
  say "The reference retrieval service compares a page against known-good"
  say "originals, which sharpens the reviewer's judgement on pages it has"
  say "seen something similar to."
  say ""
  say "It is no longer required to catch brand impersonation: the reviewer"
  say "carries a table of well-known Iranian brands and their real domains,"
  say "and convicts on that alone. Leaving this off costs you very little."
  case "${rag_local}" in
    image)     say "  the image is already loaded on this machine" ;;
    # Deliberately not "no download needed": this only sees that files of the
    # right name are present. Each is still checked against the size the release
    # reports before it is used, and one that does not match is refused and
    # fetched instead.
    artefacts) say "  image artefacts found here — checked against the release before use" ;;
    none)      say "  not present here: enabling it downloads 2.9 GB" ;;
  esac
  if [ -n "${rag_index}" ]; then
    say "  index found at ${rag_index}"
  else
    # Be explicit that this is a dead end rather than a missing setting. The
    # index is a 3 GB directory of parquet files built from the reference
    # corpus; no release publishes it, so an operator who does not already have
    # one cannot obtain it by answering a prompt. Asking for a path without
    # saying so sent people looking for a file that was never on their machine.
    say "  no index here — it is published and can be downloaded (about 1 GB)."
  fi
  if [ "${mem_gb}" -gt 0 ] && [ "${mem_gb}" -lt 8 ]; then
    say "  warning: this host has ${mem_gb} GB of RAM and the service wants 8 GB."
    say "  Below that its queries exceed the reviewer's timeout and no"
    say "  references arrive, which looks like a broken service."
  fi
  # Default yes only when it costs nothing: already here, and an index to use.
  if [ "${rag_local}" != "none" ] && [ -n "${rag_index}" ]; then
    default="y"; prompt='  enable it? [Y/n]: '
  elif [ -z "${rag_index}" ]; then
    default="n"; prompt='  enable it, downloading the index? [y/N]: '
  else
    default="n"; prompt='  enable it? [y/N]: '
  fi
  case "$(ask "${prompt}" "${default}")" in
    y|Y|yes|YES)
      WITH_REFERENCES=1
      if [ -z "${rag_index}" ]; then
        # Offer the download first. Pointing at a copy already on the machine
        # stays available below, because somebody who has one should not spend
        # a gigabyte fetching the same thing again.
        say ""
        say "  The index is published as five parts totalling about 1 GB."
        say "  It unpacks to roughly 1.8 GB under $(pwd)/Embedding_Index."
        # Recorded, not done here: the fetch needs fetch_asset, which is
        # defined further down with the rest of the download machinery. Bash
        # resolves a function at the point of call, so doing it here would fail
        # with "fetch_asset: command not found". discover_index looks in the
        # install directory, so once it lands the configuration step finds it
        # without being told.
        case "$(ask '  download it now? [Y/n]: ' y)" in
          n|N|no|NO) : ;;
          *) FETCH_INDEX=1; rag_index="pending" ;;
        esac
      fi
      if [ -z "${rag_index}" ]; then
        while :; do
          answer="$(ask '  path to an Embedding_Index you already have (empty to skip): ' '')" \
            || answer=""
          answer="${answer/#\~/${HOME}}"
          if [ -z "${answer//[[:space:]]/}" ]; then
            say "  no index given, so references stay off"
            WITH_REFERENCES=0
            break
          fi
          if [ -f "${answer%/}/block_index.parquet" ]; then
            RAG_INDEX_HOST_PATH="$(cd -- "${answer}" && pwd)"
            export RAG_INDEX_HOST_PATH
            say "  using ${RAG_INDEX_HOST_PATH}"
            break
          fi
          say "  that directory has no block_index.parquet in it"
        done
      fi ;;
  esac
  unset rag_local rag_index mem_gb default prompt answer
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



# Ask for a token when a private repository turns out to need one.
#
# Credentials are discovered automatically where a machine already has them, but
# a fresh host has none, and the install then died on the first private asset
# with an instruction to set an environment variable and start over. Asking
# costs one prompt and saves the whole run.
CREDENTIALS_PROMPTED=0
prompt_for_credentials() { # repo
  local repo="$1" token=""
  [ "${CREDENTIALS_PROMPTED}" -eq 0 ] || return 1
  CREDENTIALS_PROMPTED=1
  [ "${HAVE_TTY}" -eq 1 ] || return 1
  [ "${NO_PROMPT:-0}" != "1" ] || return 1
  say ""
  say "${OWNER}/${repo} is private, so this download needs a GitHub token."
  say "Create one at https://github.com/settings/tokens with 'repo' scope."
  say "Leave it empty to stop here instead."
  token="$(ask_secret '  GitHub token: ')" || token=""
  [ -n "${token//[[:space:]]/}" ] || return 1
  GITHUB_TOKEN="${token}"
  AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  say "  using it for the rest of this install"
  return 0
}

# Where an asset can actually be fetched from, and how big it should be.
#
# Printed as "<url>|<size>", size empty when it cannot be determined. Deciding
# the source *before* transferring is what lets the transfer show progress: the
# old shape tried the public URL first and threw its stderr away to hide the 404
# that a private repository answers with, which discarded curl's progress bar
# along with it. A 699 MB download then printed nothing at all for minutes and
# looked like a hang.
resolve_asset() { # repo tag name -> "url|size"
  local repo="$1" tag="$2" name="$3" headers size url id
  size_of() { printf '%s' "$1" | tr -d '\r' \
    | awk 'BEGIN{IGNORECASE=1} /^content-length:/ {n=$2} END{print n}'; }

  if [ -n "${ASSET_BASE_URL:-}" ]; then
    url="${ASSET_BASE_URL%/}/${name}"
    if headers="$(curl -fsIL --connect-timeout 10 --max-time 30 --retry 2 --retry-all-errors "${url}" 2>/dev/null)"; then
      printf '%s|%s' "${url}" "$(size_of "${headers}")"
      return 0
    fi
    echo "    not on the mirror; falling back to GitHub" >&2
  fi

  url="https://github.com/${OWNER}/${repo}/releases/download/${tag}/${name}"
  if headers="$(curl -fsIL --connect-timeout 10 --max-time 30 --retry 2 --retry-all-errors "${url}" 2>/dev/null)"; then
    printf '%s|%s' "${url}" "$(size_of "${headers}")"
    return 0
  fi

  # A private asset cannot be taken from the browser download URL: that path
  # wants a session cookie and answers 404 for a token, which reads like the
  # file is missing. It has to be resolved to an asset id and pulled from the
  # API instead.
  if [ ${#AUTH[@]} -gt 0 ]; then
    local meta
    meta="$(curl -fsSL --connect-timeout 10 --max-time 60 "${AUTH[@]}" -H "Accept: application/vnd.github+json" \
              "https://api.github.com/repos/${OWNER}/${repo}/releases/tags/${tag}" 2>/dev/null \
            | python3 -c "
import json,sys
want = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit
for asset in data.get('assets', []):
    if asset['name'] == want:
        print(f\"{asset['id']}|{asset['size']}\"); break
" "${name}" 2>/dev/null || true)"
    if [ -n "${meta}" ]; then
      id="${meta%%|*}"
      printf '%s|%s' "https://api.github.com/repos/${OWNER}/${repo}/releases/assets/${id}" "${meta##*|}"
      return 0
    fi
  fi
  return 1
}

# Fetch one release asset by name, resuming a partial file.
fetch_asset() { # repo tag name
  local repo="$1" tag="$2" name="$3" resolved url expected local_size
  local headers=()

  # Ask where it lives, but do not insist yet. An operator who already has the
  # file — the whole point of --artefact-dir and --manual — may be on a host
  # with no route to GitHub at all, and failing here would refuse to use a file
  # sitting right there.
  resolved="$(resolve_asset "${repo}" "${tag}" "${name}")" || resolved=""
  url="${resolved%%|*}"
  expected="${resolved##*|}"
  [ -n "${resolved}" ] || { url=""; expected=""; }

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
    echo "  resume ${name} — $(human_size "${local_size}") of $(human_size "${expected}") already here"
  else
    adopt_local "${name}" "${expected}" && return 0
    if [ "${SOURCE_MODE}" = "manual" ]; then
      prompt_for_asset "${repo}" "${tag}" "${name}" "${expected}" && return 0
    elif [ "${SOURCE_MODE}" = "local" ]; then
      echo "  ${name} is not in the directories given; fetching it"
    fi
  fi

  # Only now does a source actually have to exist.
  if [ -z "${url}" ]; then
    if [ ${#AUTH[@]} -eq 0 ]; then
      prompt_for_credentials "${repo}" || true
      resolved="$(resolve_asset "${repo}" "${tag}" "${name}")" || resolved=""
      url="${resolved%%|*}"
      expected="${resolved##*|}"
      [ -n "${resolved}" ] || { url=""; expected=""; }
    fi
    [ -n "${url}" ] || die "cannot fetch ${name} from ${OWNER}/${repo}.
The repository is private and no usable credentials were given. Either make it
public, or set GITHUB_TOKEN and run again. If you already have the file, pass
--artefact-dir with the directory holding it."
  fi
  case "${url}" in
    https://api.github.com/*) headers=("${AUTH[@]}" -H "Accept: application/octet-stream") ;;
  esac

  if [ ! -f "${name}" ]; then
    echo "  get   ${name}${expected:+ — $(human_size "${expected}")}"
    case "${url}" in
      https://api.github.com/*) echo "        from the GitHub release (authenticated)" ;;
      https://github.com/*)     echo "        from the GitHub release" ;;
      *)                        echo "        from ${url%/*}" ;;
    esac
  fi

  # stderr is deliberately not redirected: that is where curl draws the progress
  # bar, and the operator needs to see a multi-hundred-megabyte transfer moving.
  curl -fL -C - --connect-timeout 20 --retry 10 --retry-delay 5 --retry-all-errors --progress-bar \
    ${headers[@]+"${headers[@]}"} -o "${name}" "${url}" \
    || die "download of ${name} failed. Re-run to resume from where it stopped."

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
  # in terms of the file rather than an opaque tar error. Announced because on a
  # 699 MB artefact it is ten to twenty seconds of nothing.
  echo "  check ${artefact}"
  gzip -t "${artefact}" 2>/dev/null \
    || die "${artefact} is not a valid archive. Delete it and re-run to fetch it again."
  # docker load's own layer progress is left visible. Suppressing it made the
  # slowest step in the whole install — a minute or more of unpacking 1.85 GB of
  # layers — completely silent, which is what the download used to look like.
  echo "  load  ${image} — unpacking layers, this takes a minute"
  gunzip -c "${artefact}" | docker load \
    || die "docker load of ${artefact} failed"
  docker image inspect "${image}" >/dev/null \
    || die "${artefact} loaded but did not provide ${image}"
}

# In manual mode, show the whole list before asking for any of it. Being handed
# one link at a time is the wrong shape for the situation manual mode exists for:
# somebody moving files across from a browser can fetch them all at once, and
# needs to know how much there is before they start.
if [ "${SOURCE_MODE}" = "manual" ]; then
  say ""
  say "These are the files this install needs. Download them in your browser"
  say "into  $(pwd)  and they will be picked up as you go."
  say ""
  needed=0
  if ! docker image inspect "phishing-detection-engine:${DETECTOR_VERSION}" >/dev/null 2>&1 \
     && [ ! -f "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz" ]; then
    say "  $(asset_url phishing-detection-engine "v${DETECTOR_VERSION}" \
          "phishing-detection-engine-${DETECTOR_VERSION}.tar.gz")"
    needed=$((needed + 1))
  fi
  if ! docker image inspect "agentic-phishing-review:${REVIEW_VERSION}" >/dev/null 2>&1 \
     && [ ! -f "agentic-phishing-review-${REVIEW_VERSION}.tar.gz" ]; then
    say "  $(asset_url agentic-phishing-review "v${REVIEW_VERSION}" \
          "agentic-phishing-review-${REVIEW_VERSION}.tar.gz")"
    needed=$((needed + 1))
  fi
  if [ "${WITH_REFERENCES}" -eq 1 ] \
     && ! docker image inspect "phishing-rag-service:${RAG_VERSION}" >/dev/null 2>&1; then
    for part in part00 part01 part02 parts.sha256; do
      [ -f "phishing-rag-service-${RAG_VERSION}.tar.gz.${part}" ] && continue
      say "  $(asset_url phishing-rag-service "v${RAG_VERSION}" \
            "phishing-rag-service-${RAG_VERSION}.tar.gz.${part}")"
      needed=$((needed + 1))
    done
  fi
  if [ "${needed}" -eq 0 ]; then
    say "  nothing to download — everything is already here or already loaded."
  else
    say ""
    say "  ${needed} file(s). A private repository needs you to be signed in to"
    say "  GitHub in that browser. Press Enter when you have started them, or"
    say "  just continue — each one is asked for again in turn."
    ask '  [Enter] to continue: ' '' >/dev/null || true
  fi
fi

# Fetch and unpack the reference index.
#
# The index used to be undistributable: a 3 GB directory that existed only where
# it was built, so enabling references was impossible for anyone who had not
# built it themselves. Only three files in it are ever opened at runtime — the
# embedding matrix, its block metadata, and the page table — and those pack to
# about 1 GB, which is publishable. The 891 MB block_index.parquet and the
# 333 MB bm25 pickle are build inputs and are deliberately not shipped.
fetch_index() {
  local parts="part00 part01 part02 part03 part04" part
  local base="embedding-index-${RAG_VERSION}.tar.gz"
  say "  fetching the index"
  for part in ${parts}; do
    fetch_asset phishing-rag-service "v${RAG_VERSION}" "${base}.${part}" || return 1
  done
  fetch_asset phishing-rag-service "v${RAG_VERSION}" "${base}.parts.sha256" || return 1
  if command -v sha256sum >/dev/null 2>&1 && [ -f "${base}.parts.sha256" ]; then
    say "  verifying the parts"
    sha256sum -c "${base}.parts.sha256" >/dev/null 2>&1 || {
      say "  the parts did not verify; delete them and try again"
      return 1
    }
  fi
  say "  unpacking (about 1.8 GB)"
  mkdir -p Embedding_Index || return 1
  # Streamed: joining to a single file first would need a second gigabyte of
  # disk for no reason.
  cat ${base}.part?? | tar -C Embedding_Index -xzf - || return 1
  [ -f "Embedding_Index/_fast/block_emb.npy" ] || {
    say "  the archive unpacked but the embedding matrix is not there"
    return 1
  }
  rm -f ${base}.part?? "${base}.parts.sha256"
  say "  index ready at $(pwd)/Embedding_Index"
  return 0
}

step "images"
if [ "${FETCH_INDEX:-0}" -eq 1 ]; then
  if ! fetch_index; then
    say "  the index could not be fetched, so references stay off"
    WITH_REFERENCES=0
  fi
fi
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
  if curl -fsSL --connect-timeout 10 --max-time 30 --retry 2 --retry-all-errors \
       -o "${f}.new" "${RAW}/${f}" 2>/dev/null; then
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
  curl -fsSL --connect-timeout 10 --max-time 30 --retry 2 \
       -o deploy/.env "${RAW}/deploy/stack.env.example" 2>/dev/null \
    || cp .env.example deploy/.env 2>/dev/null \
    || die "no configuration template available"
  echo "  wrote deploy/.env"
else
  echo "  keeping the existing deploy/.env"
fi

# Collect what the services need, rather than leaving an operator to discover
# which of twenty keys in a template are the two that actually matter. Only when
# there is a terminal to ask on: the piped one-line install still reaches one,
# because a pipe replaces stdin and leaves /dev/tty alone, but CI does not and
# must fall through to the template exactly as before.
if [ "${HAVE_TTY}" -eq 1 ] && [ "${NO_PROMPT:-0}" != "1" ]; then
  say "Answer these and deploy/.env is written for you. Ctrl-C to stop and edit"
  say "it by hand instead; anything already set is offered as the default."

  # --- OpenRouter endpoint --------------------------------------------------
  current_base="$(env_value OPENROUTER_BASE_URL)"
  current_base="${current_base:-https://openrouter.ai/api/v1}"
  say ""
  say "The review agent's language model provider."
  say "  1) https://openrouter.ai/api/v1        OpenRouter (default)"
  say "  2) https://api.openai.com/v1           OpenAI-compatible endpoint"
  say "  3) something else — a gateway or proxy you run"
  case "$(ask '  choice [1]: ' 1)" in
    2) base_url="https://api.openai.com/v1" ;;
    3) base_url="$(ask '  base URL: ' "${current_base}")" ;;
    *) base_url="https://openrouter.ai/api/v1" ;;
  esac
  set_env OPENROUTER_BASE_URL "${base_url}"

  # --- model ---------------------------------------------------------------
  current_model="$(env_value OPENROUTER_MODEL)"
  current_model="${current_model:-google/gemma-4-31b-it}"
  model="$(ask "  model [${current_model}]: " "${current_model}")"
  set_env OPENROUTER_MODEL "${model}"

  # --- API key, verified before it is accepted ------------------------------
  existing_key="$(env_value OPENROUTER_API_KEY)"
  while :; do
    if [ -n "${existing_key//[[:space:]]/}" ]; then
      say ""
      say "  an API key is already set for ${base_url}"
      case "$(ask '  keep it? [Y/n]: ' y)" in
        n|N|no|NO) : ;;
        *) api_key="${existing_key}" ;;
      esac
    fi
    if [ -z "${api_key:-}" ]; then
      say ""
      api_key="$(ask_secret '  API key (not shown as you type): ')" || api_key=""
    fi
    if [ -z "${api_key//[[:space:]]/}" ]; then
      say "  a key is required for the review agent to work"
      case "$(ask '  try again? [Y/n]: ' y)" in
        n|N|no|NO) api_key=""; break ;;
      esac
      existing_key=""; continue
    fi
    say "  checking the key against ${base_url} ..."
    if check_openrouter "${api_key}" "${base_url}" "${model}"; then
      say "  the key works"
      break
    fi
    say "  that key did not return a completion — it may be wrong, out of"
    say "  credit, or the model name may not exist on this endpoint"
    case "$(ask '  use it anyway? [y/N]: ' n)" in
      y|Y|yes|YES) break ;;
    esac
    api_key=""; existing_key=""
  done
  [ -n "${api_key:-}" ] && set_env OPENROUTER_API_KEY "${api_key}"

  # --- internal shared secret ----------------------------------------------
  existing_review="$(env_value INTERNAL_REVIEW_API_KEY)"
  say ""
  say "The detector authenticates to the reviewer with a shared secret. Nobody"
  say "types this one, so generating it is the better answer."
  if [ -n "${existing_review//[[:space:]]/}" ]; then
    say "  one is already set"
    case "$(ask '  keep it? [Y/n]: ' y)" in
      n|N|no|NO) set_env INTERNAL_REVIEW_API_KEY "$(generate_key)"; say "  generated a new one" ;;
      *) : ;;
    esac
  else
    say "  1) generate one now (recommended)"
    say "  2) I will supply my own"
    case "$(ask '  choice [1]: ' 1)" in
      2) supplied="$(ask_secret '  internal review key: ')" || supplied=""
         if [ -n "${supplied//[[:space:]]/}" ]; then
           set_env INTERNAL_REVIEW_API_KEY "${supplied}"
         else
           set_env INTERNAL_REVIEW_API_KEY "$(generate_key)"; say "  empty, so generated one instead"
         fi ;;
      *) set_env INTERNAL_REVIEW_API_KEY "$(generate_key)"; say "  generated" ;;
    esac
  fi

  # --- optional detector key ------------------------------------------------
  say ""
  say "An API key on the detector itself is optional: it is published only on"
  say "127.0.0.1, so an empty value is a reasonable choice on a single host."
  say "Whatever you pick here is what the browser extension needs; leaving it"
  say "open means the extension's API key field stays empty."
  say "  1) leave it open (default)"
  say "  2) generate one"
  say "  3) I will supply my own"
  case "$(ask '  choice [1]: ' 1)" in
    2) ppd_key="$(generate_key)"; set_env PPD_API_KEY "${ppd_key}"
       # Shown, not hidden. Unlike the other secrets this one has to be typed
       # into the browser extension by hand, and generating it silently left the
       # operator with a running stack and no way to connect to it.
       say "  generated — put this in the extension's API key field:"
       say "    ${ppd_key}"
       say "  (printed again by: bash deploy/deploy.sh --show-config)" ;;
    3) supplied="$(ask_secret '  detector API key: ')" || supplied=""
       [ -n "${supplied//[[:space:]]/}" ] && set_env PPD_API_KEY "${supplied}" ;;
    *) set_env PPD_API_KEY "" ;;
  esac

  # --- VirusTotal -----------------------------------------------------------
  # Collected here because this is where an operator sets the stack up, but it
  # belongs to the intelligence monitor rather than to either service started
  # below. Saying so is better than implying the detector will start using it.
  say ""
  say "VirusTotal API key — optional. The intelligence monitor uses it to"
  say "corroborate candidate domains; neither service started here reads it."
  say "Press Enter to skip."
  vt_key="$(ask_secret '  VirusTotal API key: ')" || vt_key=""
  if [ -n "${vt_key//[[:space:]]/}" ]; then
    set_env VIRUSTOTAL_API_KEY "${vt_key}"
    set_env VT_BASE_URL "https://www.virustotal.com/api/v3"
    say "  saved for the monitor"
  fi

  unset api_key existing_key existing_review supplied vt_key ppd_key
  say ""
  say "  deploy/.env written"
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

# Quoted: an unquoted path breaks cd the moment a directory has a space in it,
# which "cd /home/a b/persianphish" reports as "too many arguments".
run_cmd="cd '$(pwd)' && bash deploy/deploy.sh"
[ "${WITH_REFERENCES}" -eq 1 ] && run_cmd="${run_cmd} --with-references"

# deploy.sh is a separate process, so the docker() override defined above does
# not reach it. If this user was just added to the docker group, sg starts a
# shell with that membership already active — which the current login shell will
# not have until the operator logs out and back in.
if [ "${DOCKER_NEEDS_SUDO}" -eq 1 ]; then
  # `id -nG` with no argument reports the groups *this process* was started
  # with, which cannot include one added a few seconds ago — so the sg branch
  # was never taken in exactly the situation it was written for. Naming the user
  # queries the group database instead, which is already up to date.
  if command -v sg >/dev/null 2>&1 \
     && id -nG "$(id -un)" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    say ""
    say "  Starting under the docker group you were just added to."
    run_cmd="sg docker -c \"${run_cmd}\""
  else
    say ""
    say "  Docker needs sudo for this user, so the start below runs under sudo."
    say "  Log out and back in once and it will not need to again."
    # `sudo ${run_cmd}` cannot work: run_cmd begins with cd, which is a shell
    # builtin and not a program sudo can execute — it failed with
    # "sudo: 'cd': command not found". A shell has to run the whole string.
    run_cmd="${SUDO} bash -c \"${run_cmd}\""
  fi
fi

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

}  # end of the parse-before-execute block
