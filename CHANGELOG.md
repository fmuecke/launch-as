# Changelog

## [0.3.2] - 2026-07-30

- Changed: Clarified that the returned error code messages are only corresponding win32 codes
- Changed: Using standard Win32 codes to reduce collisions with pass-through child exit codes.
- Fixed: Resizing in `--terminal` sessions
- Fixed: UTF-8 output configuration now runs before internal pseudoconsole-host dispatch.

## [0.3.1] - 2026-07-29

- Changed: Nonzero child exit codes now include the corresponding Windows message.
- Changed: `--terminal` is the sole current-pane option.
- Changed: Saving a prompted credential is opt-in.
- Fixed: Closing the host terminal now ends the related `--terminal` session.
- Fixed: Error codes of launch-as are now propagated properly

## [0.3.0] - 2026-07-28

- Added: First standalone release for launching a program as another local standard user.
- Added: Credential Manager support for remembered, prompted, and unattended starts.
- Added: `--terminal` for Windows Terminal and VS Code panes.
- Changed: Direct invocation is supported alongside the explicit `run` subcommand.

[0.3.2]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.2
[0.3.1]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.1
[0.3.0]: https://github.com/fmuecke/launch-as/releases/tag/v0.3.0
