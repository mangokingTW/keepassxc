# Credential-dialog injection tests

A reproduction and a fix check for
[#12956](https://github.com/keepassxreboot/keepassxc/issues/12956): auto-type no
longer reaches the "Windows Security" credential prompt.

These drive a real desktop with
[wintegrate](https://github.com/mangokingTW/wintegrate) and need no
WinAppDriver, no attached display and no KeePassXC build.

## What each test is for

| test | asserts | why it exists |
| --- | --- | --- |
| `test_dialog_is_the_brokered_one` | the dialog is `Credential Dialog Xaml Host` owned by `CredentialUIBroker` | so a later failure cannot be a look-alike window |
| `test_injected_input_reaches_the_dialog` | **strict xfail** — the behaviour a user expects | xfails while the bug is present, hard-fails once it stops being present, so the baseline cannot rot |
| `test_uiaccess_helper_reaches_the_dialog` | the same `SendInput`, from a signed uiAccess process, does arrive | separates "UIPI blocks this" from "the dialog is broken" |

## Why the witness is the API's return value

UIA reports **zero** `Edit` children for this dialog, before anything is typed.
A field-contents check therefore cannot distinguish "the text did not arrive"
from "the text cannot be read" — the first version of these tests did exactly
that and was unreadable. So `credui_host.py` calls
`CredUIPromptForWindowsCredentials` itself and writes what it returned to a
file; an unsubmitted dialog leaves no file, which is a meaningful answer.

`Get-Credential` is not used: it answers "Access is denied" instead of showing
UI in a non-interactive host.

## Running them

```
pip install "wintegrate[video]>=0.5.10" pytest
pytest tests/ui-credui -v -s -rxX
```

The fix test skips unless a signed helper is installed, because an absent helper
must not read as a working fix:

```
CREDUI_UIACCESS_HELPER=C:\Program Files\keepassxc-uiaccess\typehelper.exe
```

`.github/workflows/wintegrate-credui-12956.yml` builds it, signs it with a
throwaway certificate, installs it under `Program Files` and runs the matrix.

## What these tests do *not* show

They do not attribute the change to KB5074109. That needs a machine without the
update; there isn't one here, so the tests state what today does rather than
what changed.
