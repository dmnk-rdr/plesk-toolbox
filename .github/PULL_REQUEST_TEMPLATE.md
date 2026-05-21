## Summary

<!-- One paragraph: what does this change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New audit (`audits.d/{sec,health}/NN-<group>-<name>.sh`)
- [ ] New tool (`tools.d/<group>/<name>.sh`)
- [ ] New mod (`mods.d/<name>/`)
- [ ] Library / dispatcher change
- [ ] Docs / config example

## Checklist

- [ ] `bash -n` passes on every changed `*.sh`
- [ ] `shellcheck -s bash` passes on every changed file (project exclusions: `SC1090,SC1091,SC2154,SC2034,SC2155`)
- [ ] Tested on a real Plesk Obsidian server when the change is non-trivial
- [ ] No personal server names, hostnames, IPs, or domains in the diff
- [ ] New audit files use `emit <id> <severity> <status> <message> [fix]` and stay read-only
- [ ] New tool files writing to the system use the `safety.sh` helpers (`tool_begin` / `tool_confirm` / `tool_run` / `tool_end`) and honour `--dry-run` / `--yes`
- [ ] Config tunables added are documented in `plesk-toolbox.conf.example`
- [ ] README updated when the audit / tool / mod list changes

## Linked issues

<!-- "Closes #123", "Refs #456" — or "none". -->
