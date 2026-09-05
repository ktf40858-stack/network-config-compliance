# network-config-compliance

Audits Cisco IOS running-configurations against **CIS Benchmark** and **DISA STIG** controls,
and fails a CI pipeline when a non-compliant configuration is about to ship.

A network engineer checking a router by hand takes twenty minutes and misses the vty line
that still accepts telnet. This does it in under a second, on every device, every time the
configuration changes.

```console
$ python -m netcompliance --config samples/non-compliant-router.cfg \
      --benchmark checks/cis-cisco-ios-l1.yaml checks/disa-stig-ndm.yaml

LAB-RTR-BAD - CIS Cisco IOS Benchmark - Level 1 (subset) v1.0

[ FAIL ] CIS-1.2.2      Set transport input ssh on all vty lines
                        missing in: line vty 0 4, line vty 5 15
[ FAIL ] CIS-1.4.1      Use enable secret rather than enable password
                        line 18: enable password EXAMPLE-NOT-A-REAL-SECRET
[ FAIL ] CIS-2.3.1      Do not use default SNMP community strings
                        line 57: snmp-server community public RO; line 58: snmp-server community private RW
...
0 pass, 18 fail, 0 n/a, 0 error - score 0.0%
```

The same command against [`samples/hardened-router.cfg`](samples/hardened-router.cfg) —
the remediated version of the same device — returns 100% and exit code 0.

---

## Why this exists

Configuration drift is where hardening goes to die. A device is hardened at commissioning,
then eighteen months of change requests later it has a read-write SNMP community again and
nobody noticed, because nobody re-reads a 900-line configuration.

The tool is built for the environment I am targeting: federal integrator work in Virginia,
where CIS and STIG compliance is contractual rather than optional, and where "we hardened it"
has to be evidenced per device, per control, on demand.

## Design decisions worth defending

**Checks are data, not code.** Adding a control means adding an entry to a YAML file. The
people who own a benchmark are rarely the people who own the tool, and a control that needs
a Python change to add is a control that does not get added.

**The parser understands hierarchy.** IOS nesting is expressed only by leading whitespace,
so `ip address` inside an `interface` block and `ip address` inside a `vrf definition` are
the same string in a flat grep. [`parser.py`](netcompliance/parser.py) builds a tree, which
is what makes per-interface and per-vty-line checks possible at all.

**Not applicable is not a pass.** A router-only control evaluated against a switch returns
`N/A` and is excluded from the score. Counting inapplicable controls as passed is how a
compliance dashboard reaches 94% while the network is wide open.

**An unknown match type or a broken regex is an ERROR, not a pass.** A silent failure in a
compliance tool is worse than no tool, because it produces a clean report. The test suite
asserts that every shipped benchmark evaluates without a single ERROR.

**Exit codes are made for CI.** `0` clean, `1` findings at or above `--fail-on`, `2` tool
error. That is what lets it gate a merge request.

## Install and run

```bash
git clone https://github.com/ktf40858-stack/network-config-compliance
cd network-config-compliance
python -m pip install -r requirements.txt

# audit
python -m netcompliance --config <config.cfg> --benchmark checks/cis-cisco-ios-l1.yaml

# a whole directory of devices, as a Markdown report
python -m netcompliance --config configs/*.cfg \
    --benchmark checks/*.yaml --format markdown --output report.md

# JSON, for a dashboard or a ticketing integration
python -m netcompliance --config <config.cfg> \
    --benchmark checks/cis-cisco-ios-l1.yaml --format json
```

| Option | |
|---|---|
| `--config` | one or more running-config files |
| `--benchmark` | one or more benchmark YAML files |
| `--format` | `terminal` (default), `markdown`, `json` |
| `--output` | write to a file instead of stdout |
| `--fail-on` | `high`, `medium` (default), `low`, `never` |

## Controls covered

| Benchmark | Controls | File |
|---|---|---|
| CIS Cisco IOS Level 1 (subset) | 18 | [`checks/cis-cisco-ios-l1.yaml`](checks/cis-cisco-ios-l1.yaml) |
| DISA NDM STIG (subset) | 10 | [`checks/disa-stig-ndm.yaml`](checks/disa-stig-ndm.yaml) |

Both are honest subsets: only controls a running-configuration can actually prove. Controls
that need a device query — IOS image integrity, installed licences, the actual contents of a
banner against the prescribed DoD wording — are listed as out of scope in
[`docs/mapping.md`](docs/mapping.md) rather than being quietly marked as passing.

A generated report: [`docs/sample-report.md`](docs/sample-report.md).

## Writing a check

```yaml
- id: CIS-1.2.2
  title: Set transport input ssh on all vty lines
  severity: high
  rationale: >
    Telnet carries credentials and session content in clear text. Any vty line that still
    accepts telnet undoes SSH on all the others, because an attacker only needs one.
  remediation: |
    line vty 0 15
     transport input ssh
  references:
    - CIS Cisco IOS Benchmark 1.2.2
  match:
    type: block_present
    block_pattern: '^line vty'
    pattern: '^transport input ssh$'
```

| `match.type` | Passes when |
|---|---|
| `global_present` | a top-level line matches `pattern` |
| `global_absent` | no top-level line matches `pattern` |
| `anywhere_absent` | `pattern` appears nowhere, at any nesting level |
| `block_present` | every block matching `block_pattern` contains `pattern` |
| `block_absent` | no block matching `block_pattern` contains `pattern` |

## Tests

```console
$ python -m pytest -q
................                                                         [100%]
16 passed in 0.10s
```

The suite covers the parser's hierarchy handling, each match type, the N/A-excluded-from-score
rule, and an end-to-end assertion that the hardened sample scores strictly better than the
non-compliant one on both benchmarks.

## CI

[`.github/workflows/compliance.yml`](.github/workflows/compliance.yml) runs the tests and
audits every `.cfg` under `samples/` on each push. Point it at the directory where your
device configurations are backed up and it becomes a compliance gate on configuration changes.

## Roadmap

- NX-OS and IOS-XR parsers (the tree model already generalises, the patterns do not)
- Automatic remediation script generation from the failed checks
- ARF / OSCAL output, so results feed an eMASS or Xacta workflow directly
- Pull configurations over NETCONF instead of reading files from disk

## A note on the sample configurations

`samples/` contains two synthetic configurations. They are not devices. Every credential is
the literal string `EXAMPLE-NOT-A-REAL-SECRET` or a `<PLACEHOLDER>`, and every address comes
from RFC 5737 or RFC 1918. Real device configurations must never be committed to a
repository — `.gitignore` blocks `configs-live/` and `*.live.cfg` for exactly that reason.

## Author

Kodjo Apedoh — Network & Cloud Security · Arlington, VA
CCNA · Fortinet NSE · Palo Alto SASE & Cloud Security
[LinkedIn](https://www.linkedin.com/in/kodjo-apedoh-03030990/) · [Other labs](https://github.com/ktf40858-stack)

## License

MIT — see [LICENSE](LICENSE).
