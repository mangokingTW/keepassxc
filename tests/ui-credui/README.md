# Credential-prompt Auto-Type check (#12956)

Four files, each here for one reason. They are driven by
`.github/workflows/wintegrate-credui-evidence.yml`, which builds a patched and
an unpatched KeePassXC from the same steps and runs this check against both.

| file | why it exists |
|---|---|
| `verify_with_wintegrate.py` | the check itself: opens a database, selects an entry, raises a real credential prompt, performs Auto-Type at it, and reports whether the prompt was filled in. Driven through [wintegrate](https://github.com/mangokingTW/wintegrate), which owns window discovery, focus, UIA and the recording |
| `credui_host.py` | raises the credential prompt by calling `CredUIPromptForWindowsCredentialsW`, and writes what it received. There is no other way to get a genuine `Credential Dialog Xaml Host` window owned by `CredentialUIBroker.exe` |
| `run_at_medium_integrity.py` | starts the check at Medium integrity from an elevated session. A hosted runner is elevated, and at High integrity the prompt accepts injected input whether or not the patch is present -- an earlier reproduction passed for exactly that reason and read as "the bug is gone" |
| `helper_watch.py` | watches for the uiAccess helper process while the sequence runs. It lives for the length of one Auto-Type, so a process list sampled by hand misses it, and without this "the prompt was not filled in" cannot be told apart from "the helper never started" |

## Running it by hand

```
python tests/ui-credui/run_at_medium_integrity.py ^
    python tests/ui-credui/verify_with_wintegrate.py ^
    --exe   <path to KeePassXC.exe> ^
    --db    <path to a .kdbx> --password <its password> ^
    --entry Windows --username probeuser ^
    --host-script tests/ui-credui/credui_host.py ^
    --result %TEMP%\credui_result.txt ^
    --artifacts artifacts ^
    --dwell 2.5
```

Settings are arguments rather than environment variables because
`run_at_medium_integrity.py` builds the child's environment block from the user
token, so anything exported by the caller does not arrive. `--dwell` only paces
the recording; it changes nothing that is asserted.

## What it needs on the machine

- `pip install "wintegrate[video]>=0.5.11"`
- the uiAccess helper built, signed with a certificate the machine trusts, and
  installed under `%ProgramFiles%` -- see the workflow. Without it the patched
  build behaves like the unpatched one, which is the intended fallback
- a desktop that does not take the foreground away mid-sequence. The helper
  drops keystrokes whose target is not in front, so a window that resurfaces
  eats the rest of the sequence; the run records every such theft

## What it leaves behind

In the artifact directory: `session_recording.mp4`, `session_events.json`
(every measurement, including the integrity level of each process involved),
`window_census.json`, screenshots at the points that matter, `harness.log`, and
`keepassxc-stderr.log` -- KeePassXC's own warnings, which are what distinguish
"delegation was never attempted" from "it was attempted and failed".
