# Settings

Settings let you tune agent behavior, including authorization and cleanup, and CLI behavior, including how long `monopass clip` leaves a copied secret on the clipboard.

## Inspect and change settings

Use `monopass ls-settings` to print every setting. Each line contains the full setting name, a tab, and its stored string value, ordered by name:

```text
$ monopass ls-settings
agent.authTtlSeconds	900
agent.autoDeleteOldVersionsAfterSeconds	15552000
agent.autoDeleteTrashItemsAfterSeconds	15552000
agent.denialTtlSeconds	60
agent.gcSeconds	3600
agent.settingsAuthTtlSeconds	300
agent.trustedProgramPaths	[]
cli.clearClipboardAfterSeconds	30
```

Use `monopass read-setting <name>` when you need just one value, such as in a script:

```text
$ monopass read-setting agent.authTtlSeconds
900
```

Use `monopass write-setting <name> <value>` to update a value. It prints nothing when the update succeeds. Pass the full `agent.*` or `cli.*` name exactly; monopass does not add the prefix for you.

```sh
monopass write-setting agent.authTtlSeconds 1800
```

Unknown names and invalid values fail rather than being stored. All duration values are integer seconds. A value of `0` disables only the two automatic-deletion settings described below. If you have an older vault, monopass renames its legacy `user.*` settings to the corresponding `agent.*` names when it opens the database.

## Available settings

| Setting | Default | Allowed values | What it controls |
| --- | --- | --- | --- |
| `agent.authTtlSeconds` | `900` | Integer seconds, `1..=604800` | How long an item-scope process-lineage authorization remains valid. |
| `agent.settingsAuthTtlSeconds` | `300` | Integer seconds, `1..=604800` | How long a settings-scope process-lineage authorization remains valid. |
| `agent.denialTtlSeconds` | `60` | Integer seconds, `1..=604800` | How long an explicit GUI **Deny** blocks another unlock request from the same process lineage and scope. |
| `agent.gcSeconds` | `3600` | Integer seconds, `60..=2592000` | The best-effort cleanup cadence while the database is unlocked. |
| `agent.autoDeleteTrashItemsAfterSeconds` | `15552000` | Integer seconds, `0..=157680000` | How long an item stays in `Trash` before cleanup permanently removes it. Moving or renaming a trashed item restarts its retention period. |
| `agent.autoDeleteOldVersionsAfterSeconds` | `15552000` | Integer seconds, `0..=157680000` | How long non-latest item versions remain before cleanup permanently removes them. |
| `agent.trustedProgramPaths` | `[]` | A JSON array of string glob patterns | Which external executables may use direct master-password unlock. |
| `cli.clearClipboardAfterSeconds` | `30` | Integer seconds, `10..=300` | How long `monopass clip` keeps a copied secret before clearing it, if the clipboard still contains the same text. |

The authorization and denial timers count time while the computer is asleep. Changing an authorization or denial duration applies to existing cached entries as well as future ones. Cleanup and retention changes take effect when cleanup next runs.

## Trust a direct-unlock client

By default, only the running monopass executable can use direct master-password unlock. GUI-capable builds normally show the unlock prompt instead. If you run a headless client that must submit the password itself, add only that executable's canonical path to `agent.trustedProgramPaths`:

```sh
monopass write-setting agent.trustedProgramPaths \
  '["/home/you/project/.venv/bin/python"]'
```

The value is JSON, not a shell path list. Patterns are matched case-sensitively against canonical executable paths. `*` does not match `/`, while `**` can match across path components. Keep this list narrow: every matching executable may request and submit your master password. Removing a pattern prevents future direct unlocks but does not revoke an authorization that has already been issued.
