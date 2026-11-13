# Security policy

**How to report a security bug in fsgate, and what counts as one.**

fsgate has not had an independent security review. [The threat model](docs/threat-model.md) says what each boundary stops and what it does not.

## Report a vulnerability

Report it privately through [GitHub's vulnerability reporting](https://github.com/farming-labs/fsgate/security/advisories/new). Do not open a public issue or pull request.

Include:

- The fsgate version or commit, and the operating system and kernel (`uname -sr`).
- A minimal reproduction, ideally a test against the real filesystem.
- What an attacker gains: which file or authority they reach, and from what position.

Reports are handled as they arrive, and there is no guaranteed response time. A confirmed bug gets a regression test, a fix in a new release, and a published GitHub advisory, which credits you if you want that.

## What counts

A vulnerability is a way past something fsgate says it stops. For example:

- Reading, writing, creating, or listing outside the grants, through the gate or from a locked process.
- Keeping authority through the gate after `revoke` or `narrow`.
- A silent fallback to ambient filesystem access.
- A broker that acts on a request it should refuse, or delivers a descriptor outside the grant.
- A decision through a gate or a broker that emits no audit event.

These are not vulnerabilities on their own:

- Anything the threat model lists under "Does not stop" or "Outside this model". If it understates a gap, or you can go further than it says, report that.
- Code that bypasses the gate before `lock()`. The gate alone is not a sandbox.

## Supported versions

| Version | Security fixes |
|---|---|
| The latest minor release on crates.io (0.4.x) | Yes |
| Older releases | No. Upgrade to the latest release. |
| Builds with `experimental-intercept` | No. The feature is experimental, unreviewed, and in no release. |

Reports about `experimental-intercept` are still welcome through the same channel.
