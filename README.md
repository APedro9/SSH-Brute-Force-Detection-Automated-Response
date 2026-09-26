# SSH Brute-Force Detection & Automated Response
### Home Lab Incident Report — Wazuh SIEM

---

## Summary

This project simulates an SSH brute-force attack against a lab target and demonstrates the full detection-to-response lifecycle using Wazuh. A default Wazuh install logs failed SSH authentication attempts individually but does not correlate repeated failures from the same source into a single actionable alert. To close this gap, a custom correlation rule was written to detect 5+ failed SSH logins from the same IP within 60 seconds, tagged to MITRE ATT&CK technique T1110 (Brute Force). An active-response action was then chained to that rule to automatically block the attacking IP at the host firewall. End-to-end testing confirmed detection in approximately **2 seconds** and a live firewall block within approximately **4 seconds** of the first failed login attempt.

## Environment

| Component | Role | Details |
|---|---|---|
| Kali Linux (VirtualBox) | Attacker | Hydra 9.6, used to generate brute-force SSH traffic |
| Ubuntu Desktop (VirtualBox) | Target | OpenSSH server, Wazuh agent 4.14.7 |
| Ubuntu (VirtualBox) | Wazuh Manager | Wazuh 4.14.7, manager + dashboard |

All three VMs were bridged onto the same local subnet (`192.168.1.0/24`) so they could reach each other directly. IP addresses were dynamic (DHCP) for this exercise; a production or repeatable lab setup would use static IPs or DHCP reservations to avoid address drift between sessions.

## Detection Gap Identified

Before writing any custom rule, a baseline was established by logging into the target normally and then deliberately failing authentication a few times. Wazuh's default ruleset logged each failure individually under **rule 5760** ("sshd: authentication failed," level 5) — matching the pattern `Failed password|Failed keyboard|authentication error`. This rule has no `frequency` or `timeframe` attribute and no `same_source_ip` grouping, so it fires once per failed attempt with no correlation.

An initial Hydra run against the target (5 attempts in ~5 seconds) confirmed this gap directly: the dashboard showed five separate level-5 alerts, with nothing flagging the pattern as a coordinated attack. A human analyst would have to notice the repetition themselves — which doesn't scale.

*(Note: the original project plan assumed the base failure rule would be 5716. Testing against this specific Wazuh version/ruleset showed the actual firing rule is 5760, so the custom rule below references 5760 instead.)*

## Rule Logic

Added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager:

```xml
<group name="local,syslog,sshd,">
  <rule id="100100" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH brute-force attempt detected: 5+ failed logins from same IP in 60 seconds</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

**Parameter breakdown:**
- `id="100100"` — custom rule IDs start at 100000+ to avoid colliding with Wazuh's built-in ruleset
- `level="10"` — high severity, deliberately set well above the routine level-5 noise from individual failures
- `frequency="5" timeframe="60"` — fires only after 5 matches of the base rule occur within a 60-second window
- `if_matched_sid=5760` — references the actual base "failed SSH login" rule confirmed during baseline testing
- `same_source_ip` — restricts correlation to failures from a single IP, so 5 unrelated failures from different sources won't false-positive as a brute-force
- `<mitre><id>T1110</id>` — maps the rule to MITRE ATT&CK's Brute Force technique (Credential Access tactic)

## Response Action

Added to `/var/ossec/etc/ossec.conf` on the manager:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>
```

When rule 100100 fires, the agent on the target executes `firewall-drop`, which adds `iptables` DROP rules for the offending source IP on both the `INPUT` and `FORWARD` chains. The block expires automatically after `600` seconds (10 minutes) — long enough to disrupt an automated attack in progress, short enough that a legitimate user who mistypes their password a few times isn't locked out indefinitely.

Wazuh's own **rule 651** ("Host Blocked by firewall-drop Active Response," level 3) confirms when the block itself is applied, providing a second, independent log entry that the response executed — separate from the detection alert.

## Metrics

**Test run (2026-09-26, 12:21:xx):**

| Event | Timestamp | Elapsed |
|---|---|---|
| First failed SSH login (rule 5760) | 12:21:27.7 | — |
| Hydra completes (5 attempts) | 12:21:28 | ~1s |
| Correlation rule fires (100100) | 12:21:29.7 | **~2s from first failure** |
| Host blocked (rule 651 / firewall-drop) | 12:21:31.4 | **~3.7s from first failure** |
| Attacker reconnect attempt | immediately after | `Connection timed out` |

- **Mean time to detect (MTTD): ~2 seconds** from first failed login to correlated brute-force alert
- **Mean time to respond: ~3.7 seconds** from first failed login to active firewall block
- **Detection threshold:** 5 failed attempts within 60 seconds
- Verified via `iptables -L -n -v` on the target: 11 packets (660 bytes) dropped from the attacker's IP following the block
- A second, independent test run reproduced the same result, confirming the rule is consistent and not a one-off

**Evidence captured:**
- Before: baseline SSH logins (successful + failed) showing default rule 5760 behavior
- Before: initial Hydra run showing 5 separate uncorrelated level-5 alerts
- After: `active-responses.log` showing the full JSON payload of rule 100100 firing and firewall-drop executing
- After: `iptables -L -n` before and after, showing DROP rules added for the attacker IP and later expiring after the 10-minute timeout
- After: Wazuh dashboard Events view showing the three-alert sequence (5760 → 100100 → 651) with millisecond-level timestamps
- After: Kali terminal showing a blocked reconnect attempt (`Connection timed out`) immediately following the attack

## What You'd Do in Production

- **Tune the threshold further** to reduce false positives from legitimate users who fumble their password — e.g., raising the frequency count or extending the timeframe slightly based on observed normal user behavior
- **Add notification integration** (Slack/email webhook via Wazuh's integrator) so the SOC/analyst is alerted in real time rather than relying on dashboard review
- **Extend the same pattern to other services** — RDP, web application login forms, VPN endpoints — using the same frequency/timeframe/same_source_ip approach against their respective base rules
- **Move to static IPs / DHCP reservations** for lab or production hosts feeding into the SIEM, to avoid the address-drift issue encountered mid-project, which can silently break agent-to-manager visibility or make historical alerts harder to correlate
- **Consider an allowlist** for trusted management IPs so the active-response never blocks legitimate admin access, even accidentally

---

*Lab environment sanitized for publication — internal IP ranges shown are private (RFC 1918) addresses local to an isolated home lab network.*
