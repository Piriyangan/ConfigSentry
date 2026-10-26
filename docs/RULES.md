# ConfigSentry rules

This file is generated with `python -m configsentry rules --markdown`. Do not edit by hand.

CIS references name the benchmark (and the section for Cisco IOS and ASA); check the exact recommendation number for your benchmark version. Huawei VRP and MikroTik have no CIS Benchmark, so those rules use NIST 800-53 references.

## Cisco IOS / IOS-XE (28 rules)

Input: `show running-config`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| IOS-001 | High | Passwords | Enable password is used instead of enable secret | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-002 | High | Passwords | Enable secret is not configured | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-003 | High | Passwords | Local user account uses 'password' instead of 'secret' | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-004 | Medium | Passwords | Reversible type 7 passwords or keys found | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-005 | Low | Passwords | MD5-based (type 5) secrets in use | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-006 | Low | Passwords | Password encryption service is not enabled | CIS Cisco IOS 1.4 Password Rules, NIST 800-53 IA-5 |
| IOS-007 | Medium | AAA | AAA new-model is not enabled | CIS Cisco IOS 1.1 AAA Rules, NIST 800-53 AC-2, AU-2 |
| IOS-008 | Medium | Management Access | SSH version 2 is not enforced | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 SC-8 |
| IOS-009 | Medium | Management Access | HTTP (clear-text) management server is enabled | CIS Cisco IOS 2.1 Global Service Rules, NIST 800-53 CM-7 |
| IOS-010 | High | Management Access | Telnet is allowed on VTY lines | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 SC-8 |
| IOS-011 | Medium | Management Access | VTY transport is not explicitly restricted | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 CM-6 |
| IOS-012 | Medium | Management Access | VTY lines have no access-class (any IP can try to log in) | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 AC-17 |
| IOS-013 | Medium | Management Access | VTY session timeout is disabled | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 AC-12 |
| IOS-014 | Low | Management Access | Console session timeout is disabled | CIS Cisco IOS 1.2 Access Rules, NIST 800-53 AC-12 |
| IOS-015 | Low | Management Access | Login brute-force protection is not configured | NIST 800-53 AC-7 |
| IOS-016 | Low | Management Access | No login or MOTD banner | CIS Cisco IOS 1.3 Banner Rules, NIST 800-53 AC-8 |
| IOS-017 | High | SNMP | Default SNMP community (public/private) in use | CIS Cisco IOS 1.5 SNMP Rules, NIST 800-53 IA-5 |
| IOS-018 | High | SNMP | SNMP read-write community configured | CIS Cisco IOS 1.5 SNMP Rules, NIST 800-53 AC-6 |
| IOS-019 | Medium | SNMP | SNMP community without an access list | CIS Cisco IOS 1.5 SNMP Rules, NIST 800-53 AC-3 |
| IOS-020 | Low | Logging | No remote syslog server configured | CIS Cisco IOS 2.2 Logging Rules, NIST 800-53 AU-6, AU-9 |
| IOS-021 | Low | Logging | Log messages have no timestamps | CIS Cisco IOS 2.2 Logging Rules, NIST 800-53 AU-8 |
| IOS-022 | Low | Logging | No NTP server configured | CIS Cisco IOS 2.3 NTP Rules, NIST 800-53 AU-8 |
| IOS-023 | Low | Services | CDP is enabled globally | CIS Cisco IOS 2.1 Global Service Rules, NIST 800-53 CM-7 |
| IOS-024 | Low | Services | IP source routing is not disabled | CIS Cisco IOS 3 Data Plane, NIST 800-53 SC-7 |
| IOS-025 | Low | Services | TCP keepalives for incoming sessions are not enabled | CIS Cisco IOS 2.1 Global Service Rules, NIST 800-53 SC-10 |
| IOS-026 | Medium | Layer 2 | Access ports without BPDU Guard | NIST 800-53 SC-5 |
| IOS-027 | Low | Layer 2 | DHCP snooping is not enabled | NIST 800-53 SC-7 |
| IOS-028 | Low | Routing | OSPF is running without authentication | CIS Cisco IOS 3 Data Plane (Routing Rules), NIST 800-53 SC-8 |

## Cisco NX-OS (Nexus) (17 rules)

Input: `show running-config`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| NXOS-001 | High | Management Access | Telnet server feature is enabled | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| NXOS-002 | Medium | Management Access | NX-API over clear-text HTTP is enabled | NIST 800-53 SC-8 |
| NXOS-003 | Medium | Passwords | Password strength check is disabled | NIST 800-53 IA-5 |
| NXOS-004 | Medium | Passwords | Reversible type 7 keys found | NIST 800-53 IA-5 |
| NXOS-005 | Medium | AAA | No central AAA login (TACACS+/RADIUS) | NIST 800-53 AC-2, NIST 800-53 AU-2 |
| NXOS-006 | Medium | Management Access | VTY lines have no access-class | NIST 800-53 AC-17 |
| NXOS-007 | Medium | Management Access | VTY session timeout is not set | NIST 800-53 AC-12 |
| NXOS-008 | Low | Management Access | Console session timeout is not set | NIST 800-53 AC-12 |
| NXOS-009 | Medium | Cryptography | SSH RSA key shorter than 2048 bits | NIST 800-53 SC-13 |
| NXOS-010 | Low | Management Access | No login banner | NIST 800-53 AC-8 |
| NXOS-011 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| NXOS-012 | High | SNMP | SNMP read-write community configured | NIST 800-53 AC-6 |
| NXOS-013 | Medium | SNMP | SNMP community without an ACL | NIST 800-53 AC-3 |
| NXOS-014 | Low | Logging | No remote syslog server configured | NIST 800-53 AU-6, NIST 800-53 AU-9 |
| NXOS-015 | Low | Logging | No NTP server configured | NIST 800-53 AU-8 |
| NXOS-016 | Medium | Layer 2 | Edge ports without BPDU Guard | NIST 800-53 SC-5 |
| NXOS-017 | Low | Routing | OSPF is running without authentication | NIST 800-53 SC-8 |

## Huawei VRP (S / CE switches, AR routers) (27 rules)

Input: `display current-configuration`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| VRP-001 | High | Management Access | Telnet server is enabled | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| VRP-002 | Medium | Management Access | SSH (STelnet) server is not enabled | NIST 800-53 SC-8 |
| VRP-003 | High | Management Access | Telnet allowed on VTY lines | NIST 800-53 SC-8 |
| VRP-004 | Medium | Management Access | VTY inbound protocol is not explicitly set | NIST 800-53 CM-6 |
| VRP-005 | High | AAA | VTY lines do not use AAA authentication | NIST 800-53 IA-2, NIST 800-53 AC-2 |
| VRP-006 | Medium | Management Access | VTY lines have no ACL (any IP can try to log in) | NIST 800-53 AC-17 |
| VRP-007 | Medium | Management Access | VTY session timeout is disabled | NIST 800-53 AC-12 |
| VRP-008 | High | Management Access | Console port has no authentication | NIST 800-53 IA-2 |
| VRP-009 | Low | Management Access | Console session timeout is disabled | NIST 800-53 AC-12 |
| VRP-010 | Medium | Management Access | HTTP (clear-text) web management is enabled | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| VRP-011 | Medium | Services | FTP server is enabled | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| VRP-012 | Low | Management Access | No login banner | NIST 800-53 AC-8 |
| VRP-013 | High | Passwords | Local user password stored in clear text | NIST 800-53 IA-5 |
| VRP-014 | Medium | Passwords | Local user password uses reversible 'cipher' | NIST 800-53 IA-5 |
| VRP-015 | Medium | AAA | Local user allowed to use Telnet, FTP or HTTP | NIST 800-53 SC-8, NIST 800-53 AC-6 |
| VRP-016 | Medium | Cryptography | Weak SSH ciphers allowed | NIST 800-53 SC-13 |
| VRP-017 | Low | Cryptography | Weak SSH HMAC algorithms allowed | NIST 800-53 SC-13 |
| VRP-018 | Medium | Cryptography | Weak SSH key exchange (DH group 1) allowed | NIST 800-53 SC-13 |
| VRP-019 | Medium | SNMP | SNMPv1 or SNMPv2c enabled | NIST 800-53 SC-8, NIST 800-53 IA-5 |
| VRP-020 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| VRP-021 | High | SNMP | SNMP write community configured | NIST 800-53 AC-6 |
| VRP-022 | Medium | SNMP | SNMP community without an ACL | NIST 800-53 AC-3 |
| VRP-023 | Low | Logging | No remote syslog server configured | NIST 800-53 AU-6, NIST 800-53 AU-9 |
| VRP-024 | Low | Logging | No NTP server configured | NIST 800-53 AU-8 |
| VRP-025 | Medium | Layer 2 | BPDU protection is not enabled | NIST 800-53 SC-5 |
| VRP-026 | Low | Layer 2 | DHCP snooping is not enabled | NIST 800-53 SC-7 |
| VRP-027 | Low | Routing | OSPF is running without authentication | NIST 800-53 SC-8 |

## Juniper Junos (EX / QFX / MX / SRX) (20 rules)

Input: `show configuration | display set`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| JUN-001 | High | Management Access | Telnet service is enabled | CIS Juniper OS Benchmark, NIST 800-53 SC-8 |
| JUN-002 | Medium | Services | FTP service is enabled | CIS Juniper OS Benchmark, NIST 800-53 CM-7 |
| JUN-003 | Medium | Management Access | Web management over clear-text HTTP is enabled | NIST 800-53 SC-8 |
| JUN-004 | High | Management Access | SSH root login is allowed | CIS Juniper OS Benchmark, NIST 800-53 AC-6 |
| JUN-005 | High | Cryptography | SSH protocol version 1 allowed | NIST 800-53 SC-8 |
| JUN-006 | Medium | Cryptography | Weak SSH ciphers allowed | NIST 800-53 SC-13 |
| JUN-007 | Medium | Passwords | MD5-based password hashes in use | CIS Juniper OS Benchmark, NIST 800-53 IA-5 |
| JUN-008 | Low | AAA | Login retry options (lockout) are not set | CIS Juniper OS Benchmark, NIST 800-53 AC-7 |
| JUN-009 | Low | Management Access | No idle timeout for login classes | NIST 800-53 AC-12 |
| JUN-010 | Low | Management Access | No login banner | NIST 800-53 AC-8 |
| JUN-011 | Low | Management Access | Console session not logged out on disconnect | CIS Juniper OS Benchmark, NIST 800-53 AC-12 |
| JUN-012 | Medium | Management Access | No firewall filter protecting the Routing Engine (lo0) | NIST 800-53 SC-7, NIST 800-53 AC-17 |
| JUN-013 | High | SNMP | Default SNMP community (public/private) in use | CIS Juniper OS Benchmark, NIST 800-53 IA-5 |
| JUN-014 | High | SNMP | SNMP read-write community configured | CIS Juniper OS Benchmark, NIST 800-53 AC-6 |
| JUN-015 | Medium | SNMP | SNMP community without client restrictions | CIS Juniper OS Benchmark, NIST 800-53 AC-3 |
| JUN-016 | Low | Logging | No remote syslog server configured | CIS Juniper OS Benchmark, NIST 800-53 AU-6 |
| JUN-017 | Low | Logging | No NTP server configured | NIST 800-53 AU-8 |
| JUN-018 | High | Firewall Policy | Security policy permits any source, destination and application | NIST 800-53 AC-4, NIST 800-53 SC-7 |
| JUN-019 | Low | Logging | Permit policy without session logging | NIST 800-53 AU-2, NIST 800-53 AU-12 |
| JUN-020 | Low | Routing | OSPF is running without authentication | NIST 800-53 SC-8 |

## MikroTik RouterOS (13 rules)

Input: `/export`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| MTK-001 | High | Management Access | Insecure IP services enabled (telnet / ftp / www / api) | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| MTK-002 | Medium | Management Access | IP services not restricted to management addresses | NIST 800-53 AC-17 |
| MTK-003 | High | Firewall Policy | No input-chain firewall drop rule | NIST 800-53 SC-7 |
| MTK-004 | Medium | Management Access | MAC Winbox / MAC Telnet available on all interfaces | NIST 800-53 CM-7, NIST 800-53 AC-17 |
| MTK-005 | Low | Services | Neighbor discovery enabled on all interfaces | NIST 800-53 CM-7 |
| MTK-006 | Low | Services | Bandwidth test server is enabled | NIST 800-53 CM-7 |
| MTK-007 | Medium | Services | DNS server accepts remote requests | NIST 800-53 SC-5, NIST 800-53 SC-7 |
| MTK-008 | Medium | Services | SOCKS or web proxy enabled | NIST 800-53 CM-7 |
| MTK-009 | Medium | Services | UPnP is enabled | NIST 800-53 CM-7 |
| MTK-010 | Low | Services | RoMON is enabled | NIST 800-53 CM-7 |
| MTK-011 | High | SNMP | SNMP enabled with the default community | NIST 800-53 IA-5 |
| MTK-012 | Low | Logging | No remote syslog configured | NIST 800-53 AU-6, NIST 800-53 AU-9 |
| MTK-013 | Low | Logging | No NTP client configured | NIST 800-53 AU-8 |

## Cisco ASA (19 rules)

Input: `show running-config`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| ASA-001 | High | Management Access | Telnet management access is allowed | CIS Cisco ASA 1 Management Plane, NIST 800-53 SC-8 |
| ASA-002 | High | Management Access | SSH or ASDM allowed from any address | CIS Cisco ASA 1 Management Plane, NIST 800-53 AC-17 |
| ASA-003 | Medium | Management Access | Management access allowed on the outside interface | NIST 800-53 SC-7, NIST 800-53 AC-17 |
| ASA-004 | Medium | Management Access | SSH version 2 is not enforced | CIS Cisco ASA 1 Management Plane, NIST 800-53 SC-8 |
| ASA-005 | Medium | Cryptography | Weak SSH key exchange (DH group 1) allowed | NIST 800-53 SC-13 |
| ASA-006 | Medium | Cryptography | Old TLS versions allowed for ASDM / SSL VPN | NIST 800-53 SC-8, NIST SP 800-52r2 |
| ASA-007 | Medium | Passwords | MD5-based password hashes ('encrypted') | CIS Cisco ASA 1 Management Plane, NIST 800-53 IA-5 |
| ASA-008 | Medium | Passwords | Minimum password length is below 12 | NIST 800-53 IA-5 |
| ASA-009 | Medium | AAA | SSH logins do not use AAA | CIS Cisco ASA 1 Management Plane, NIST 800-53 AC-2 |
| ASA-010 | Low | AAA | Local login lockout is not configured | NIST 800-53 AC-7 |
| ASA-011 | Low | Management Access | SSH session timeout longer than 15 minutes | NIST 800-53 AC-12 |
| ASA-012 | Low | Management Access | Console session timeout is disabled | NIST 800-53 AC-12 |
| ASA-013 | Low | Management Access | No login banner | NIST 800-53 AC-8 |
| ASA-014 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| ASA-015 | Medium | SNMP | SNMPv1 or SNMPv2c in use | NIST 800-53 SC-8 |
| ASA-016 | Medium | Logging | Logging is disabled | NIST 800-53 AU-2, NIST 800-53 AU-12 |
| ASA-017 | Low | Logging | No remote syslog server configured | NIST 800-53 AU-6, NIST 800-53 AU-9 |
| ASA-018 | Low | Logging | No NTP server configured | NIST 800-53 AU-8 |
| ASA-019 | High | Firewall Policy | Access list permits any IP to any destination | NIST 800-53 AC-4, NIST 800-53 SC-7 |

## FortiGate (FortiOS) (18 rules)

Input: `show`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| FGT-001 | High | Management Access | HTTP or Telnet admin access enabled on an interface | NIST 800-53 SC-8, NIST 800-53 CM-7 |
| FGT-002 | High | Management Access | Administrative access allowed on a WAN interface | NIST 800-53 AC-17, NIST 800-53 SC-7 |
| FGT-003 | High | Management Access | Administrator account without trusted hosts | NIST 800-53 AC-17, NIST 800-53 AC-3 |
| FGT-004 | Low | Management Access | Default 'admin' account still in use | NIST 800-53 AC-2, NIST 800-53 IA-2 |
| FGT-005 | Low | Management Access | Admin idle timeout is longer than 15 minutes | NIST 800-53 AC-12 |
| FGT-006 | Low | Management Access | Admin lockout threshold is too high | NIST 800-53 AC-7 |
| FGT-007 | Medium | Passwords | Password policy for administrators is disabled | NIST 800-53 IA-5 |
| FGT-008 | Medium | Management Access | Maintainer account is enabled | NIST 800-53 AC-2 |
| FGT-009 | Low | Management Access | No pre-login warning banner | NIST 800-53 AC-8 |
| FGT-010 | High | Cryptography | Strong crypto is disabled | NIST 800-53 SC-13 |
| FGT-011 | Medium | Cryptography | Old TLS versions allowed for admin HTTPS | NIST 800-53 SC-8, NIST SP 800-52r2 |
| FGT-012 | High | Cryptography | SSH version 1 enabled for administration | NIST 800-53 SC-8 |
| FGT-013 | High | Firewall Policy | Policy allows any source, any destination, any service | NIST 800-53 AC-4, NIST 800-53 SC-7 |
| FGT-014 | Medium | Firewall Policy | Policy allows all services (service ALL) | NIST 800-53 AC-4, NIST 800-53 CM-7 |
| FGT-015 | Medium | Logging | Accept policy with traffic logging disabled | NIST 800-53 AU-2, NIST 800-53 AU-12 |
| FGT-016 | High | SNMP | Default SNMP community name (public/private) | NIST 800-53 IA-5 |
| FGT-017 | Low | Logging | No remote log destination enabled | NIST 800-53 AU-6, NIST 800-53 AU-9 |
| FGT-018 | Low | System | USB auto-install of config or firmware is enabled | NIST 800-53 CM-5 |

## Palo Alto PAN-OS (18 rules)

Input: `XML export, or 'show config running' (set or default format)`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| PAN-001 | High | Management Access | Telnet enabled on the management interface | CIS Palo Alto Firewall Benchmark, NIST 800-53 SC-8 |
| PAN-002 | High | Management Access | HTTP enabled on the management interface | CIS Palo Alto Firewall Benchmark, NIST 800-53 SC-8 |
| PAN-003 | Medium | Management Access | Management interface not restricted by permitted IPs | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-17 |
| PAN-004 | High | Management Access | Interface management profile allows HTTP or Telnet | CIS Palo Alto Firewall Benchmark, NIST 800-53 SC-8 |
| PAN-005 | Low | Management Access | Admin idle timeout is longer than 15 minutes | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-12 |
| PAN-006 | Medium | AAA | Admin lockout is not configured | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-7 |
| PAN-007 | Medium | Passwords | Password complexity is not enabled | CIS Palo Alto Firewall Benchmark, NIST 800-53 IA-5 |
| PAN-008 | Low | AAA | Default 'admin' account still exists | NIST 800-53 AC-2 |
| PAN-009 | Low | Management Access | No login banner | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-8 |
| PAN-010 | Low | System | Update server identity is not verified | CIS Palo Alto Firewall Benchmark, NIST 800-53 SI-7 |
| PAN-011 | Medium | SNMP | SNMPv2c in use | CIS Palo Alto Firewall Benchmark, NIST 800-53 SC-8 |
| PAN-012 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| PAN-013 | Low | Logging | No syslog server profile configured | CIS Palo Alto Firewall Benchmark, NIST 800-53 AU-6 |
| PAN-014 | Low | Logging | No NTP server configured | NIST 800-53 AU-8 |
| PAN-015 | High | Firewall Policy | Rule allows any source, destination, application and service | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-4 |
| PAN-016 | Medium | Firewall Policy | Rule allows application any with service any | CIS Palo Alto Firewall Benchmark, NIST 800-53 AC-4 |
| PAN-017 | Medium | Logging | Allow rule without session-end logging | CIS Palo Alto Firewall Benchmark, NIST 800-53 AU-12 |
| PAN-018 | Low | Firewall Policy | Allow rule without security profiles | CIS Palo Alto Firewall Benchmark, NIST 800-53 SI-3 |

## Check Point Gaia (OS hardening) (17 rules)

Input: `show configuration (clish)`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| CKP-001 | High | Management Access | Telnet is enabled | CIS Check Point Firewall Benchmark, NIST 800-53 SC-8 |
| CKP-002 | High | Management Access | Management allowed from any host | CIS Check Point Firewall Benchmark, NIST 800-53 AC-17 |
| CKP-003 | Low | Management Access | CLI inactivity timeout longer than 15 minutes | CIS Check Point Firewall Benchmark, NIST 800-53 AC-12 |
| CKP-004 | Low | Management Access | Web portal session timeout longer than 15 minutes | CIS Check Point Firewall Benchmark, NIST 800-53 AC-12 |
| CKP-005 | Medium | Passwords | Minimum password length is below 12 | CIS Check Point Firewall Benchmark, NIST 800-53 IA-5 |
| CKP-006 | Low | Passwords | Password complexity is below 3 character types | CIS Check Point Firewall Benchmark, NIST 800-53 IA-5 |
| CKP-007 | Medium | AAA | Account lockout after failed logins is disabled | CIS Check Point Firewall Benchmark, NIST 800-53 AC-7 |
| CKP-008 | Low | Passwords | Password history checking is disabled | CIS Check Point Firewall Benchmark, NIST 800-53 IA-5 |
| CKP-009 | Low | Passwords | Passwords never expire | CIS Check Point Firewall Benchmark, NIST 800-53 IA-5 |
| CKP-010 | Low | Management Access | No login banner | CIS Check Point Firewall Benchmark, NIST 800-53 AC-8 |
| CKP-011 | Medium | SNMP | SNMPv1 / v2c allowed | CIS Check Point Firewall Benchmark, NIST 800-53 SC-8 |
| CKP-012 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| CKP-013 | High | SNMP | SNMP read-write community configured | NIST 800-53 AC-6 |
| CKP-014 | Low | Logging | No remote syslog server configured | CIS Check Point Firewall Benchmark, NIST 800-53 AU-6 |
| CKP-015 | Low | Logging | No NTP server configured | CIS Check Point Firewall Benchmark, NIST 800-53 AU-8 |
| CKP-016 | Low | AAA | Admin user uses the bash shell by default | CIS Check Point Firewall Benchmark, NIST 800-53 AC-6 |
| CKP-017 | Medium | Passwords | MD5-based password hashes in use | NIST 800-53 IA-5 |

## Sophos Firewall (SFOS) - beta (12 rules)

Input: `Entities.xml or the .tar from Backup & firmware > Import export`

| ID | Severity | Category | Check | References |
|---|---|---|---|---|
| SOP-001 | High | Management Access | Admin services enabled on the WAN zone | NIST 800-53 AC-17, NIST 800-53 SC-7 |
| SOP-002 | High | Firewall Policy | Rule accepts any source, destination and service | NIST 800-53 AC-4, NIST 800-53 SC-7 |
| SOP-003 | Medium | Firewall Policy | Rule accepts any service | NIST 800-53 AC-4, NIST 800-53 CM-7 |
| SOP-004 | Medium | Logging | Accept rule with traffic logging disabled | NIST 800-53 AU-2, NIST 800-53 AU-12 |
| SOP-005 | Low | Firewall Policy | Inbound WAN rule without IPS | NIST 800-53 SI-4 |
| SOP-006 | High | SNMP | Default SNMP community (public/private) in use | NIST 800-53 IA-5 |
| SOP-007 | Medium | SNMP | SNMPv1 / v2c enabled | NIST 800-53 SC-8 |
| SOP-008 | Medium | AAA | Admin login blocking (lockout) is disabled | NIST 800-53 AC-7 |
| SOP-009 | Low | Management Access | Admin session timeout is disabled or too long | NIST 800-53 AC-12 |
| SOP-010 | Medium | Passwords | Password complexity check is disabled | NIST 800-53 IA-5 |
| SOP-011 | Low | Management Access | Login disclaimer is disabled | NIST 800-53 AC-8 |
| SOP-012 | Low | Logging | No syslog server configured | NIST 800-53 AU-6, NIST 800-53 AU-9 |

