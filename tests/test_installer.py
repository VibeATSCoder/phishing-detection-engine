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
