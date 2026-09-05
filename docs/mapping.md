# Scope, mapping and what this tool cannot prove

## What a config-only tool can and cannot do

This audits a running-configuration file. That bounds it: it proves what the configuration
says, not what the device is doing.

**Provable from the configuration**

- A service is enabled or disabled
- A password type is used (`secret` versus `password`)
- A control is applied to every member of a set (all vty lines, all interfaces)
- An access class or ACL is bound where it should be

**Not provable from the configuration — deliberately out of scope**

| Control | Why it needs more than the config |
|---|---|
| IOS image integrity | Requires the image hash from the device and a trusted reference |
| Installed licences and feature set | Not in the running-config |
| Banner wording matches the prescribed DoD text | The config shows a delimiter and free text; comparing to the mandated wording is a manual review |
| Password strength | Only the hash is stored, which is the point |
| An ACL is actually effective | Needs the topology, not the config — an ACL bound to an interface no traffic traverses passes every check |
| Physical port security | Needs the patching reality |
| Accounts have been reviewed | A process control, not a technical one |

Marking these as passed because the tool cannot see them is the failure mode this project
is built to avoid. They are listed here instead, so a reviewer can see the boundary.

## On STIG identifiers

V-IDs change between STIG releases. A rule written against `V-215807` from one quarterly
release can point at a different requirement — or at nothing — two releases later.

So `checks/disa-stig-ndm.yaml` uses local IDs (`NDM-001`...) and references the **SRG
requirement ID** and the **CCI**, both of which are stable across releases. To produce a
checklist for an actual assessment, map the local IDs to the V-IDs of the specific STIG
release you are assessed against, using STIG Viewer.

This is the honest way round. Hard-coding V-IDs makes a nicer-looking report that is wrong
within a quarter.

## Control mapping

| Local ID | CIS | SRG | CCI | NIST 800-53 |
|---|---|---|---|---|
| CIS-1.1.1 | 1.1.1 | SRG-APP-000156-NDM-000250 | CCI-000765 | AC-2, IA-2 |
| CIS-1.2.2 | 1.2.2 | SRG-APP-000412-NDM-000331 | CCI-000803 | SC-8 |
| CIS-1.2.5 | 1.2.5 | SRG-APP-000190-NDM-000267 | CCI-001133 | AC-11 |
| CIS-1.4.1 | 1.4.1 | SRG-APP-000171-NDM-000258 | CCI-000196 | IA-5 |
| CIS-1.4.3 | 1.4.3 | SRG-APP-000171-NDM-000258 | CCI-000196 | IA-5(1) |
| CIS-2.2.1 | 2.2.1 | SRG-APP-000515-NDM-000325 | CCI-001851 | AU-4, AU-9 |
| CIS-2.2.4 | 2.2.4 | SRG-APP-000374-NDM-000299 | CCI-001890 | AU-8 |
| CIS-2.3.1 | 2.3.1 | SRG-APP-000412-NDM-000331 | CCI-000803 | IA-5 |
| CIS-3.3.2 | 3.3.2 | SRG-NET-000230-RTR-000002 | CCI-002205 | SC-8 |
| NDM-003 | — | SRG-APP-000411-NDM-000330 | CCI-000068 | SC-8(1) |
| NDM-006 | — | SRG-APP-000340-NDM-000288 | CCI-002235 | AC-6(10) |
| NDM-007 | — | SRG-APP-000095-NDM-000225 | CCI-000130 | AU-3 |
| NDM-008 | — | SRG-APP-000038-NDM-000213 | CCI-001368 | AC-4 |
| NDM-009 | — | SRG-APP-000373-NDM-000298 | CCI-001891 | AU-8(1) |

Verify every row against the current benchmark and STIG release before using this mapping in
an assessment. It is a starting point, not an authority.

## Adding a platform

The parser is indentation-based and is not IOS-specific. NX-OS and IOS-XR parse correctly
today; what does not carry over is the patterns, because the command syntax differs
(`feature ssh` on NX-OS, a nested `ssh server` block on IOS-XR). Adding a platform means a
new benchmark YAML, not new parser code — which was the point of separating the two.
