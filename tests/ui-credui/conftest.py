"""Recording support for the credential-dialog injection tests.

The interesting frames are the ones where a field stays empty while a log line
claims the keystrokes were queued, so the recording is the artifact worth
reading -- not a nice-to-have.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

RECORDING_FPS = 10
OUTPUT_DIR = Path("recording-artifacts")

_active = None


def pytest_sessionstart(session):
    global _active
    if os.environ.get("WINTEGRATE_RECORD") != "1" or os.name != "nt":
        return
    try:
        from wintegrate import ContinuousRecorder

        arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output = OUTPUT_DIR / f"credui-injection-{arch}.mp4"
        recorder = ContinuousRecorder(output, fps=RECORDING_FPS)
        if recorder.start():
            _active = (recorder, output)
            print(f"session recording -> {output}")
    except Exception as exc:
        print(f"recording failed to start ({type(exc).__name__}: {exc})")


def pytest_sessionfinish(session, exitstatus):
    global _active
    if _active is None:
        return
    recorder, output = _active
    try:
        recorder.stop()
        size = output.stat().st_size if output.exists() else 0
        print(f"recording saved: {output} ({size / 1024:.0f} KB)")
    except Exception as exc:
        print(f"recording failed to stop cleanly ({type(exc).__name__}: {exc})")
    finally:
        _active = None


def pytest_runtest_logstart(nodeid, location):
    if _active is None:
        return
    recorder, _output = _active
    filename, _lineno, _domain = location
    recorder.caption = nodeid.split("::")[-1]
    recorder.caption_subtitle = str(filename)


def pytest_runtest_logfinish(nodeid, location):
    if _active is None:
        return
    recorder, _output = _active
    recorder.caption = ""
    recorder.caption_subtitle = ""
