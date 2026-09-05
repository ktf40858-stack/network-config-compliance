# Compliance report - LAB-RTR-BAD

**Benchmark:** CIS Cisco IOS Benchmark - Level 1 (subset) v1.0  
**Generated:** 2026-09-05 13:57 UTC  
**Score:** 0.0% of applicable checks

| Result | Count |
|---|---|
| Pass | 0 |
| **Fail** | **18** |
| Not applicable | 0 |
| Error | 0 |

## Findings, most severe first

### CIS-1.1.1 - Enable aaa new-model

**Severity:** high  
**Evidence:** `no matching global line`

Without aaa new-model the device falls back to the legacy line-password model, where authentication cannot be centralised, per-user accountability is lost, and command authorization is unavailable. Every other AAA control depends on this one.

**Remediation**

```
configure terminal
 aaa new-model
```

- CIS Cisco IOS Benchmark 1.1.1
- NIST 800-53 AC-2, IA-2

### CIS-1.1.2 - Enable aaa authentication login

**Severity:** high  
**Evidence:** `no matching global line`

Defines which method list authenticates login attempts. Absent it, lines fall back to the line password and there is no per-user identity in the audit trail.

**Remediation**

```
aaa authentication login default group tacacs+ local
```

- CIS Cisco IOS Benchmark 1.1.2

### CIS-1.2.2 - Set transport input ssh on all vty lines

**Severity:** high  
**Evidence:** `missing in: line vty 0 4, line vty 5 15`

Telnet carries credentials and session content in clear text. Any vty line that still accepts telnet undoes SSH on all the others, because an attacker only needs one.

**Remediation**

```
line vty 0 15
 transport input ssh
```

- CIS Cisco IOS Benchmark 1.2.2
- NIST 800-53 SC-8

### CIS-1.4.1 - Use enable secret rather than enable password

**Severity:** high  
**Evidence:** `line 18: enable password EXAMPLE-NOT-A-REAL-SECRET`

enable password is stored with the reversible type 7 encoding, which is decoded by any of a dozen public tools in under a second. enable secret stores a hash.

**Remediation**

```
no enable password
enable secret <value>
```

- CIS Cisco IOS Benchmark 1.4.1
- NIST 800-53 IA-5

### CIS-1.4.3 - Local users must use username secret, not username password

**Severity:** high  
**Evidence:** `line 20: username admin privilege 15 password EXAMPLE-NOT-A-REAL-SECRET; line 21: username operator password EXAMPLE-NOT-A-REAL-SECRET`

username with a plain password is stored as type 0 or reversible type 7. username secret stores a type 9 (scrypt) or type 8 (PBKDF2) hash.

**Remediation**

```
no username <name> password <value>
username <name> privilege 15 secret <value>
```

- CIS Cisco IOS Benchmark 1.4.3
- NIST 800-53 IA-5(1)

### CIS-2.1.4 - Disable the HTTP server

**Severity:** high  
**Evidence:** `line 26: ip http server`

The IOS HTTP server has a long CVE history, and when it is enabled it is frequently unauthenticated or backed by the enable password over clear text. If web management is genuinely needed, use ip http secure-server and restrict it with an access class.

**Remediation**

```
no ip http server
no ip http secure-server
```

- CIS Cisco IOS Benchmark 2.1.4
- CVE-2019-1861, CVE-2023-20198

### CIS-2.2.1 - Enable logging to a syslog host

**Severity:** high  
**Evidence:** `no matching global line`

Local buffered logging is lost on reload and is under the control of anyone who gains privileged access to the device. Without an off-box copy there is nothing to investigate after an incident.

**Remediation**

```
logging host <SYSLOG_SERVER>
logging trap informational
```

- CIS Cisco IOS Benchmark 2.2.1
- NIST 800-53 AU-4, AU-9

### CIS-2.3.1 - Do not use default SNMP community strings

**Severity:** high  
**Evidence:** `line 57: snmp-server community public RO; line 58: snmp-server community private RW`

public and private are the first two strings any scanner tries. A read-only community still exposes the full running-configuration on many platforms; a read-write community is equivalent to administrative access.

**Remediation**

```
no snmp-server community public
no snmp-server community private
snmp-server group <GROUP> v3 priv
```

- CIS Cisco IOS Benchmark 2.3.1
- NIST 800-53 IA-5

### CIS-2.3.2 - No SNMP read-write community

**Severity:** high  
**Evidence:** `line 58: snmp-server community private RW`

An SNMP RW community allows the configuration to be written, and on IOS it allows the configuration to be copied off the device over TFTP. It is administrative access protected by a string that travels in clear text under SNMPv2c.

**Remediation**

```
no snmp-server community <string> RW
```

- CIS Cisco IOS Benchmark 2.3.2

### CIS-3.3.2 - Authenticate OSPF adjacencies

**Severity:** high  
**Evidence:** `missing in: interface GigabitEthernet0/0, interface GigabitEthernet0/1, interface GigabitEthernet0/2`

An unauthenticated OSPF process accepts hellos from anything on the segment. Injecting a route with a better metric redirects traffic through an attacker-controlled host, which is a routing-layer man-in-the-middle that leaves the data plane looking healthy.

**Remediation**

```
interface <name>
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 <key>
```

- CIS Cisco IOS Benchmark 3.3.2
- NIST 800-53 SC-8

### CIS-1.2.3 - Disable the auxiliary port

**Severity:** medium  
**Evidence:** `missing in: line aux 0`

The aux port is almost never used and is regularly forgotten during hardening. If a modem is ever attached to it, it becomes an unauthenticated path into the device.

**Remediation**

```
line aux 0
 no exec
 transport input none
```

- CIS Cisco IOS Benchmark 1.2.3

### CIS-1.2.5 - Set an exec-timeout on all vty lines

**Severity:** medium  
**Evidence:** `missing in: line vty 0 4, line vty 5 15`

An idle administrative session left open on an unattended workstation is a fully privileged session available to whoever walks past it.

**Remediation**

```
line vty 0 15
 exec-timeout 10 0
```

- CIS Cisco IOS Benchmark 1.2.5
- NIST 800-53 AC-11

### CIS-1.4.2 - Enable service password-encryption

**Severity:** medium  
**Evidence:** `no matching global line`

Type 7 encoding is trivially reversible and does not count as protection. It is still worth enabling, because it stops a password being read over a shoulder or scraped out of a configuration pasted into a ticket. It is a mitigation, not a control.

**Remediation**

```
service password-encryption
```

- CIS Cisco IOS Benchmark 1.4.2

### CIS-2.2.4 - Set logging timestamps with the date and time

**Severity:** medium  
**Evidence:** `no matching global line`

A log line without a timestamp cannot be correlated with anything else. Uptime-based timestamps, the IOS default, are unusable across devices.

**Remediation**

```
service timestamps log datetime msec show-timezone
```

- CIS Cisco IOS Benchmark 2.2.4
- NIST 800-53 AU-8

### CIS-3.1.1 - Disable IP source routing

**Severity:** medium  
**Evidence:** `no matching global line`

Source routing lets the sender dictate the path a packet takes, which is used to reach networks that routing policy would otherwise keep unreachable and to bypass filtering.

**Remediation**

```
no ip source-route
```

- CIS Cisco IOS Benchmark 3.1.1

### CIS-3.2.1 - Disable proxy ARP on all interfaces

**Severity:** medium  
**Evidence:** `missing in: interface GigabitEthernet0/0, interface GigabitEthernet0/1, interface GigabitEthernet0/2`

Proxy ARP lets the router answer ARP for addresses it does not own, which blurs the segmentation boundary and enables ARP-based man-in-the-middle across it.

**Remediation**

```
interface <name>
 no ip proxy-arp
```

- CIS Cisco IOS Benchmark 3.2.1

### CIS-1.3.1 - Set a login banner

**Severity:** low  
**Evidence:** `no matching global line`

A banner asserting that the system is monitored and that unauthorised access is prohibited is what makes prosecution possible in several jurisdictions. It is a legal control implemented in configuration.

**Remediation**

```
banner login ^C
*** Authorised access only. Activity is monitored and recorded. ***
^C
```

- CIS Cisco IOS Benchmark 1.3.1

### CIS-2.1.1 - Disable the BOOTP server

**Severity:** low  
**Evidence:** `no matching global line`

Unused service reachable from the network. It has no place on a device that is not a BOOTP server, and it widens the attack surface for nothing.

**Remediation**

```
no ip bootp server
```

- CIS Cisco IOS Benchmark 2.1.1

## All checks

| ID | Check | Severity | Status |
|---|---|---|---|
| CIS-1.1.1 | Enable aaa new-model | high | FAIL |
| CIS-1.1.2 | Enable aaa authentication login | high | FAIL |
| CIS-1.2.2 | Set transport input ssh on all vty lines | high | FAIL |
| CIS-1.2.3 | Disable the auxiliary port | medium | FAIL |
| CIS-1.2.5 | Set an exec-timeout on all vty lines | medium | FAIL |
| CIS-1.3.1 | Set a login banner | low | FAIL |
| CIS-1.4.1 | Use enable secret rather than enable password | high | FAIL |
| CIS-1.4.2 | Enable service password-encryption | medium | FAIL |
| CIS-1.4.3 | Local users must use username secret, not username password | high | FAIL |
| CIS-2.1.1 | Disable the BOOTP server | low | FAIL |
| CIS-2.1.4 | Disable the HTTP server | high | FAIL |
| CIS-2.2.1 | Enable logging to a syslog host | high | FAIL |
| CIS-2.2.4 | Set logging timestamps with the date and time | medium | FAIL |
| CIS-2.3.1 | Do not use default SNMP community strings | high | FAIL |
| CIS-2.3.2 | No SNMP read-write community | high | FAIL |
| CIS-3.1.1 | Disable IP source routing | medium | FAIL |
| CIS-3.2.1 | Disable proxy ARP on all interfaces | medium | FAIL |
| CIS-3.3.2 | Authenticate OSPF adjacencies | high | FAIL |
