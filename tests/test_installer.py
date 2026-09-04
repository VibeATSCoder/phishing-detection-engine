"""Properties of deploy/install.sh that cannot be checked by running it.

The installer is the first thing an operator touches and the hardest thing to
test, because exercising it end to end means downloading gigabytes. These cases
cover the parts that broke in ways nothing else would have caught.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "install.sh"
SOURCE = INSTALLER.read_text(encoding="utf-8")


def test_installer_is_valid_bash() -> None:
    subprocess.run(["bash", "-n", str(INSTALLER)], check=True)


def test_git_credential_lookup_can_never_prompt() -> None:
    """Token discovery must not ask the operator anything.

    `git credential fill` does not stop at a closed stdin: with no helper able
    to answer it opens the terminal itself and asks for a GitHub username and
    password. Non-interactively there is no terminal and it fails silently,
    which is why this survived unnoticed. Under -i or --manual there is one,
    and discovery then sat on "Username for 'https://github.com':" and ate the
    answers the operator was typing to the installer's own questions.
    """
    call = re.search(r"[^\n]*git credential fill", SOURCE)
    assert call, "the git credential lookup has gone; drop this test with it"
    # The environment is set on the preceding continuation line.
    window = SOURCE[max(0, call.start() - 300) : call.end()]
    assert "GIT_TERMINAL_PROMPT=0" in window, (
        "git credential fill must run with GIT_TERMINAL_PROMPT=0 or it will "
        "prompt on the terminal and consume the installer's own input"
    )


def test_ask_reports_end_of_input_rather_than_returning_a_default() -> None:
    """A prompt loop that reads EOF as an empty answer never terminates.

    Both of ask()'s failure paths — no terminal at all, and a terminal at end
    of input — have to be distinguishable from a real answer, or --manual spins
    reprinting its question as fast as the CPU allows.
    """
    body = re.search(r"^ask\(\) \{.*?^\}", SOURCE, re.S | re.M)
    assert body, "ask() has been renamed or removed"
    assert body.group(0).count("return 1") == 2, (
        "ask() must return non-zero both when there is no terminal and when "
        "reading from it hits EOF"
    )


@pytest.mark.parametrize(
    "flag",
    ["-i", "--interactive", "--manual", "--artefact-dir", "--full", "--download-only"],
)
def test_documented_flags_are_accepted(flag: str) -> None:
    """--help lists these; parsing them has to agree with the documentation."""
    assert flag in SOURCE, f"{flag} is documented but not handled"


def test_help_mentions_the_manual_download_options() -> None:
    help_text = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        capture_output=True, text=True, check=True,
    ).stdout
    for expected in ("--artefact-dir", "--manual", "-i"):
        assert expected in help_text, f"--help does not mention {expected}"


def test_artefact_dir_does_not_refuse_to_fetch_what_it_was_not_given() -> None:
    """--artefact-dir says where files are, not that nothing may be downloaded.

    Refusing outright meant an operator holding both image artefacts was still
    stopped dead by the 15 KB bundle of compose files and told to fetch it by
    hand. --manual is the mode for being asked before anything is downloaded.
    """
    assert "is not in the directories given; fetching it" in SOURCE, (
        "local mode must fall back to downloading a file it was not given"
    )
    assert "or drop --artefact-dir to download it here" not in SOURCE, (
        "the old refuse-and-die branch is back"
    )


def test_a_terminal_is_detected_by_opening_it_not_by_stat() -> None:
    """[ -r /dev/tty ] is true on a host with a console even when this process
    has no controlling terminal — a systemd unit, a container without -t, a
    setsid'd CI step. The installer then began asking questions and every prompt
    failed with "/dev/tty: No such device or address".
    """
    assert "exec 3<>/dev/tty" in SOURCE, (
        "the terminal check must open /dev/tty, not stat it"
    )
    assert "[ -r /dev/tty ] && HAVE_TTY=1" not in SOURCE, "the stat-only check is back"


def test_generated_secrets_are_not_passed_on_the_command_line() -> None:
    """/proc/<pid>/cmdline is world readable; /proc/<pid>/environ is not.

    A secret in argv is visible in ps to every user on the host for as long as
    the write takes.
    """
    assert "PPD_SET_KEY=" in SOURCE and "PPD_SET_VALUE=" in SOURCE, (
        "set_env must pass the key and value through the environment"
    )


def test_the_shared_secret_can_be_generated() -> None:
    """Nobody types this one, so asking a person to invent it is strictly worse."""
    assert "generate_key()" in SOURCE
    assert "openssl rand -hex 32" in SOURCE
    assert "/dev/urandom" in SOURCE, "there must be a fallback without openssl"


def test_the_model_key_is_checked_before_it_is_accepted() -> None:
    """A wrong key is otherwise found at the first detection, long after the
    operator has any reason to connect the two events."""
    assert "check_openrouter()" in SOURCE
    assert "chat/completions" in SOURCE


def test_prompting_can_be_turned_off_for_automation() -> None:
    assert "--no-prompt" in SOURCE
    assert 'NO_PROMPT:-0' in SOURCE


def test_secrets_are_read_without_echo() -> None:
    assert "ask_secret()" in SOURCE
    assert "read -rs reply" in SOURCE, "a key must not land in the terminal scrollback"


def test_the_virustotal_key_is_described_as_the_monitor_s() -> None:
    """Collected here for convenience, but neither service started here reads
    it. Saying so beats implying the detector will start using it."""
    assert "VIRUSTOTAL_API_KEY" in SOURCE
    assert "neither service started here reads it" in SOURCE


def test_the_script_is_parsed_before_any_of_it_runs() -> None:
    """`curl | bash` feeds the script in as it arrives.

    Without a wrapping block, a connection that drops mid-transfer leaves bash
    running whichever half arrived: measured on the previous version, the
    largest prefix that still parsed was 610 lines, and running it authenticated
    with the operator's token and created the install directory. It also made a
    genuine early failure unreadable — bash exiting while curl was still writing
    produced "curl: (23) Failure writing output to destination" on top of the
    real message, which reads like a download problem.
    """
    body = SOURCE.split("set -euo pipefail", 1)[1]
    assert body.lstrip().startswith("#") or body.lstrip().startswith("{"), body[:80]
    assert "\n{\n" in SOURCE, "the executable body must be inside a block"
    assert SOURCE.rstrip().endswith("}  # end of the parse-before-execute block")


def test_no_prefix_of_the_script_is_executable() -> None:
    """The property the block above exists to provide."""
    import subprocess

    lines = SOURCE.splitlines()
    for cut in range(200, len(lines), 50):
        prefix = "\n".join(lines[:cut])
        done = subprocess.run(
            ["bash", "-n"], input=prefix, text=True, capture_output=True
        )
        assert done.returncode != 0, f"the first {cut} lines parse and would run"


def test_missing_dependencies_are_offered_rather_than_refused() -> None:
    """A bare "required command missing: docker" is every fresh Debian host."""
    assert "detect_pm()" in SOURCE
    for manager in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk"):
        assert manager in SOURCE, f"{manager} is not handled"
    assert "get.docker.com" in SOURCE


def test_nothing_is_installed_without_asking_or_without_a_terminal() -> None:
    assert "--no-install" in SOURCE
    assert "NO_INSTALL:-0" in SOURCE
    assert "may_install()" in SOURCE


def test_declining_an_install_is_not_reported_as_a_failure() -> None:
    """Returning 2 for "declined" keeps it distinct from "the install broke"."""
    assert "return 2 ;;   # declined, which is not the same as failed" in SOURCE
    assert "install_docker || docker_rc=$?" in SOURCE, (
        "a bare call would be killed by set -e before the case could run"
    )


def test_a_user_outside_the_docker_group_is_handled() -> None:
    """Group membership does not reach a shell that is already running."""
    assert "usermod -aG docker" in SOURCE
    assert "docker() { sudo docker" in SOURCE, "later calls need to pick up sudo"
    assert "sg docker -c" in SOURCE, "deploy.sh runs in a separate shell"


def test_the_download_shows_progress() -> None:
    """curl draws its progress bar on stderr.

    The old shape tried the public URL first and sent stderr to /dev/null to
    hide the 404 that a private repository answers with — which threw the
    progress bar away with it. A 699 MB transfer then printed nothing for
    minutes and read as a hang.
    """
    transfer = [
        line for line in SOURCE.splitlines() if "--progress-bar" in line
    ]
    assert transfer, "the transfer no longer asks for a progress bar"
    body = SOURCE.split("# stderr is deliberately not redirected", 1)
    assert len(body) == 2, "the reason stderr is kept must stay documented"
    following = body[1].split("\n\n", 1)[0]
    assert "2>/dev/null" not in following, "progress is being discarded again"


def test_the_source_is_resolved_before_the_transfer_starts() -> None:
    """So the transfer itself can be noisy without leaking probe failures."""
    assert "resolve_asset()" in SOURCE
    assert SOURCE.index("resolve_asset()") < SOURCE.index("fetch_asset()")


def test_every_network_call_is_bounded() -> None:
    """An unreachable host must fail, not hang — which looks like the same bug."""
    offenders = []
    for number, line in enumerate(SOURCE.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("curl ") and "$(curl " not in stripped:
            continue
        if stripped.startswith("#"):
            continue
        if "connect-timeout" in stripped or "--max-time" in stripped:
            continue
        offenders.append(f"{number}: {stripped[:70]}")
    assert not offenders, "unbounded curl calls:\n" + "\n".join(offenders)


def test_a_private_repository_asks_for_a_token() -> None:
    """A fresh host has no credentials, and dying with "set GITHUB_TOKEN and
    start over" wastes everything already downloaded."""
    assert "prompt_for_credentials()" in SOURCE
    assert "github.com/settings/tokens" in SOURCE


def test_the_image_source_is_offered_without_being_asked_for() -> None:
    """`curl | bash` has a terminal — a pipe replaces stdin, not /dev/tty — so
    the ordinary reader should be offered local files rather than watching a
    699 MB download begin."""
    assert '[ "${SOURCE_MODE}" = "auto" ]' in SOURCE


def test_a_file_already_on_disk_is_used_without_a_network() -> None:
    """--artefact-dir exists for hosts that cannot reach GitHub at all."""
    fetch = SOURCE.split("fetch_asset() {", 1)[1].split("\n}", 1)[0]
    assert fetch.index("resolved=\"$(resolve_asset") < fetch.index("adopt_local")
    assert "|| resolved=\"\"" in fetch, (
        "a failed lookup must not abort before local files are considered"
    )


def test_the_load_step_is_not_silenced() -> None:
    """Unpacking 1.85 GB of layers is the slowest step in the install.

    With docker load's output sent to /dev/null it printed nothing at all for a
    minute or more, which is exactly what the silent download looked like before
    it was fixed — and the operator reported it the same way.
    """
    assert "docker load >/dev/null" not in SOURCE, "layer progress is hidden again"
    assert "unpacking layers" in SOURCE, "the wait should be announced"


def test_the_archive_check_is_announced() -> None:
    """gzip -t on a 699 MB artefact is ten to twenty seconds of nothing."""
    assert 'echo "  check ${artefact}"' in SOURCE


def test_manual_mode_lists_everything_before_asking_for_any_of_it() -> None:
    """Manual mode exists for someone moving files across from a browser. One
    link at a time is the wrong shape: they can fetch them together, and need to
    know how much there is before starting."""
    assert "These are the files this install needs" in SOURCE
    assert 'if [ "${SOURCE_MODE}" = "manual" ]; then' in SOURCE
    plan = SOURCE.index("These are the files this install needs")
    images = SOURCE.index('step "images"')
    assert plan < images, "the list has to come before the first request"


def test_the_sudo_handoff_runs_a_shell_not_a_builtin() -> None:
    """`sudo ${run_cmd}` cannot work.

    run_cmd starts with cd, which is a shell builtin with no executable behind
    it, so sudo has nothing to exec: reported live as
    "sudo: 'cd': command not found" after a complete, successful install.
    """
    assert 'run_cmd="${SUDO} ${run_cmd}"' not in SOURCE, "the broken form is back"
    assert 'run_cmd="${SUDO} bash -c \\"${run_cmd}\\""' in SOURCE


def test_group_membership_is_read_from_the_database_not_the_process() -> None:
    """`id -nG` with no argument reports the groups the *process* started with.

    A group added seconds earlier by usermod cannot appear there, so the sg
    branch was never taken in exactly the case it was written for, and every
    such install fell through to the sudo branch instead.
    """
    assert 'id -nG "$(id -un)"' in SOURCE
    assert "id -nG 2>/dev/null | tr" not in SOURCE, "the process-local check is back"


def test_the_install_path_is_quoted_in_the_start_command() -> None:
    """An unquoted path breaks cd as soon as a directory contains a space."""
    assert """run_cmd="cd '$(pwd)' && bash deploy/deploy.sh\"""" in SOURCE


def test_references_are_offered_on_an_ordinary_run() -> None:
    """The question used to require -i, so the one-line install never mentioned
    the retrieval service at all — including to someone who already had the
    image sitting on disk."""
    assert "The reference retrieval service compares" in SOURCE
    block = SOURCE.split("Asked whenever there is a terminal", 1)
    assert len(block) == 2, "the references question must have its own guard"
    guard = block[1].split("\n", 6)[4]
    assert "SOURCE_MODE" not in guard, (
        "--artefact-dir must not skip the references question: having the images "
        "locally is exactly when the reference image is likely to be local too"
    )


def test_a_local_reference_image_is_found_before_downloading() -> None:
    assert "find_local_rag()" in SOURCE
    assert "phishing-rag-service:${RAG_VERSION}" in SOURCE
    assert "tar.gz.part00" in SOURCE


def test_helpers_are_defined_before_the_questions_that_call_them() -> None:
    """bash resolves a function at the point of call, and these three used to sit
    several hundred lines below the prompt that used them."""
    question = SOURCE.index("The reference retrieval service compares")
    for name in ("find_local_rag()", "host_memory_gb()", "discover_index()"):
        assert SOURCE.index(f"\n{name} {{") < question, f"{name} is defined too late"


def test_the_memory_warning_is_honest_about_the_consequence() -> None:
    """Below 8 GB the queries exceed the reviewer's timeout and no references
    arrive, which presents as a broken service rather than a starved one."""
    assert "host_memory_gb" in SOURCE
    assert "exceed the reviewer's timeout" in SOURCE


def test_local_artefacts_are_not_promised_as_a_skipped_download() -> None:
    """find_local_rag only sees filenames; each file is still size-checked."""
    said = [
        line for line in SOURCE.splitlines()
        if line.strip().startswith(("say ", "echo ")) and "no download needed" in line
    ]
    assert not said, f"promised to the operator on: {said}"
    assert "checked against the release before use" in SOURCE
