#!/usr/bin/env python3
"""Create sample reports for every report_type × severity combination (25 total)."""

import json, subprocess, tempfile, os, sys

BASE = "http://localhost:8000/api/v1"
COOKIE = "-b /tmp/cookies.txt"

TYPES = ["incident", "threat_advisory", "weekly_summary", "ioc_bulletin", "custom"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]

TLP_MAP = {
    "critical": "TLP:RED",
    "high": "TLP:AMBER",
    "medium": "TLP:GREEN",
    "low": "TLP:GREEN",
    "info": "TLP:CLEAR",
}

SAMPLES = {
    "incident": {
        "critical": {
            "title": "SolarWinds Supply Chain Compromise — Active Exploitation",
            "summary": "Nation-state actors compromised SolarWinds Orion build process, deploying SUNBURST backdoor to ~18,000 organizations. Active C2 channels detected in our infrastructure.",
            "tags": ["supply-chain", "sunburst", "apt29", "nation-state"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "On February 25, 2026, our SOC detected anomalous DNS queries from three internal SolarWinds Orion servers communicating with avsvmcloud[.]com — a known SUNBURST C2 domain. Investigation confirmed the presence of the SUNBURST backdoor (SHA256: ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6) in our Orion Platform v2020.2.1 HF5 installation. At least 47GB of data was exfiltrated over the past 72 hours."},
                {"key": "timeline", "title": "Timeline of Events", "body": "2026-02-23 03:14 UTC — Initial C2 beacon detected by DNS monitoring\n2026-02-23 06:30 UTC — SOC analyst escalated to Tier 3\n2026-02-23 08:00 UTC — IR team activated, network segment isolated\n2026-02-24 11:00 UTC — Forensic imaging of affected servers complete\n2026-02-25 09:00 UTC — Full scope identified: 3 Orion servers, 2 domain controllers accessed\n2026-02-25 14:00 UTC — Containment achieved, remediation in progress"},
                {"key": "impact", "title": "Impact Assessment", "body": "CRITICAL IMPACT: 3 SolarWinds Orion servers compromised. Lateral movement to 2 Active Directory domain controllers confirmed. Estimated 47GB data exfiltration including employee PII and financial records. 12 privileged accounts potentially compromised. Business operations in Finance and HR departments disrupted for 48+ hours."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Domains: avsvmcloud[.]com, freescanonline[.]com\nIPs: 13.59.205.66, 54.193.127.66\nSHA256: ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6\nSHA256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77\nNamedPipes: 583da945-62af-10e8-4902-a8f205c72b2e"},
                {"key": "response", "title": "Response Actions", "body": "1. Isolated all SolarWinds servers from network\n2. Reset all privileged account credentials\n3. Deployed emergency YARA rules across all endpoints\n4. Blocked all known C2 domains and IPs at perimeter firewall\n5. Engaged CrowdStrike IR retainer for forensic support\n6. Notified legal counsel and initiated breach notification timeline"},
                {"key": "recommendations", "title": "Recommendations", "body": "IMMEDIATE: Remove SolarWinds Orion from environment entirely. Deploy alternative monitoring (Zabbix/PRTG). Conduct enterprise-wide threat hunt using provided IOCs. LONG-TERM: Implement software supply chain verification. Deploy DNS sinkholing for known malicious domains. Enhance EDR coverage to 100% of servers."}
            ]
        },
        "high": {
            "title": "Ransomware Deployment Attempt — LockBit 3.0 Detected",
            "summary": "LockBit 3.0 ransomware deployment attempt detected and contained on 3 endpoints in the Finance department. Initial access via phishing email with macro-enabled document.",
            "tags": ["ransomware", "lockbit", "phishing", "finance"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "A LockBit 3.0 ransomware deployment was intercepted by EDR on three Finance department workstations. The attack originated from a phishing email disguised as an invoice from a known vendor. While the ransomware binary was downloaded, EDR prevented execution and encryption. No data loss occurred."},
                {"key": "timeline", "title": "Timeline of Events", "body": "2026-02-27 09:15 UTC — Phishing email received by finance-team@company.com\n2026-02-27 09:22 UTC — User opened attachment, macro executed\n2026-02-27 09:23 UTC — Cobalt Strike beacon deployed\n2026-02-27 09:25 UTC — EDR detected and blocked lateral movement\n2026-02-27 09:30 UTC — SOC alert generated, endpoints isolated\n2026-02-27 10:00 UTC — IR investigation initiated"},
                {"key": "impact", "title": "Impact Assessment", "body": "LIMITED IMPACT: 3 workstations compromised but contained. No lateral movement beyond initial foothold. No data encryption occurred. No data exfiltration detected. Finance operations resumed within 4 hours after endpoint reimaging."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Email: invoice-feb2026@malicious-vendor[.]com\nURL: hxxps://malicious-vendor[.]com/invoice.docm\nSHA256: a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01\nC2: 185.220.101[.]42:443\nMutex: Global\\LockBit3_Session"},
                {"key": "response", "title": "Response Actions", "body": "1. Isolated affected endpoints immediately\n2. Blocked sender domain at email gateway\n3. Reimaged all 3 affected workstations\n4. Conducted email trace — no other recipients clicked\n5. Updated email filtering rules for similar patterns"},
                {"key": "recommendations", "title": "Recommendations", "body": "Conduct targeted phishing awareness training for Finance department. Implement macro-blocking policy for external documents. Add vendor email domain verification to procurement process."}
            ]
        },
        "medium": {
            "title": "Unauthorized VPN Access from Anomalous Geographic Location",
            "summary": "Employee VPN account accessed from Russia while employee confirmed to be in US office. Credential compromise suspected via password reuse.",
            "tags": ["unauthorized-access", "vpn", "credential-theft"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Impossible travel alert triggered when employee J. Smith's VPN account connected from Moscow, Russia at 14:32 UTC while the employee was confirmed present in the New York office. Investigation revealed password reuse across a compromised third-party service."},
                {"key": "timeline", "title": "Timeline of Events", "body": "2026-02-26 14:32 UTC — VPN login from Moscow IP 91.108.56.0\n2026-02-26 14:33 UTC — Impossible travel alert triggered\n2026-02-26 14:45 UTC — Employee confirmed in NY office\n2026-02-26 15:00 UTC — Account disabled, session terminated\n2026-02-26 16:00 UTC — Password reset enforced, MFA re-enrolled"},
                {"key": "impact", "title": "Impact Assessment", "body": "MODERATE: VPN session active for approximately 28 minutes. Accessed shared drives for Marketing department. No sensitive data repositories touched. No privilege escalation attempted."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Source IP: 91.108.56.0 (Moscow, RU)\nVPN Account: jsmith@company.com\nSession Duration: 28 minutes\nAccessed Resources: \\\\fileserver\\marketing\\public"},
                {"key": "response", "title": "Response Actions", "body": "1. Terminated active VPN session\n2. Disabled and reset account credentials\n3. Re-enrolled MFA device\n4. Reviewed accessed files for sensitive content\n5. Added Moscow IP range to VPN geo-blocking"},
                {"key": "recommendations", "title": "Recommendations", "body": "Enforce password uniqueness policy. Deploy dark web credential monitoring. Implement conditional access policies with geographic restrictions."}
            ]
        },
        "low": {
            "title": "Failed Brute Force Attempt Against OWA Portal",
            "summary": "Automated brute force attack against Outlook Web App detected and blocked by WAF. No successful authentications. Source IP blacklisted.",
            "tags": ["brute-force", "owa", "blocked"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Web Application Firewall detected and blocked a credential stuffing attack against the Outlook Web App portal. Over 15,000 login attempts from a single IP address over 2 hours. All attempts failed. Rate limiting and IP blocking engaged automatically."},
                {"key": "timeline", "title": "Timeline of Events", "body": "2026-02-28 02:00 UTC — Attack began, WAF rate limiting triggered\n2026-02-28 02:05 UTC — Source IP auto-blocked after 500 failed attempts\n2026-02-28 04:00 UTC — Attack ceased\n2026-02-28 08:00 UTC — SOC reviewed during morning triage"},
                {"key": "impact", "title": "Impact Assessment", "body": "NO IMPACT: All attempts blocked by WAF. No successful authentications detected. No account lockouts triggered (lockout threshold not reached for any single account)."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Source IP: 45.33.32.156 (Tor exit node)\nTarget: mail.company.com/owa\nAttempts: 15,247 over 2 hours\nUnique usernames tried: 3,891"},
                {"key": "response", "title": "Response Actions", "body": "1. Verified WAF blocked all attempts\n2. Added IP to permanent blocklist\n3. Confirmed no successful logins\n4. No further action required"},
                {"key": "recommendations", "title": "Recommendations", "body": "Consider implementing CAPTCHA on OWA login after 3 failed attempts. Review Tor exit node blocking policy. Current WAF rules performed as expected."}
            ]
        },
        "info": {
            "title": "Scheduled Penetration Test Completed — Q1 2026",
            "summary": "Annual external penetration test completed by NCC Group. 2 medium and 5 low findings identified. Full remediation plan in progress.",
            "tags": ["pentest", "compliance", "scheduled"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "NCC Group completed the scheduled Q1 2026 external penetration test from February 20-25. The test covered all external-facing assets. No critical or high findings. 2 medium findings related to outdated TLS configurations and 5 low informational findings documented."},
                {"key": "timeline", "title": "Timeline of Events", "body": "2026-02-20 — Penetration test commenced (authorized window)\n2026-02-25 — Testing completed\n2026-02-27 — Draft report received\n2026-02-28 — Final report reviewed and accepted"},
                {"key": "impact", "title": "Impact Assessment", "body": "INFORMATIONAL: No exploitation achieved during testing. No data accessed. All findings are configuration-level improvements. Remediation timeline: 30 days for medium, 90 days for low."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "N/A — Authorized testing activity. Test source IPs whitelisted during engagement window."},
                {"key": "response", "title": "Response Actions", "body": "1. Findings triaged and assigned to remediation owners\n2. Medium findings: TLS 1.0/1.1 deprecation ticket created\n3. Low findings added to quarterly maintenance backlog"},
                {"key": "recommendations", "title": "Recommendations", "body": "Disable TLS 1.0 and 1.1 on all external-facing services. Update SSL certificate rotation schedule. Schedule next pentest for Q2 2026."}
            ]
        }
    },
    "threat_advisory": {
        "critical": {
            "title": "CVE-2026-21412 — Windows Zero-Day RCE Under Active Exploitation",
            "summary": "Microsoft confirmed a critical zero-day vulnerability in Windows kernel allowing remote code execution. Actively exploited by multiple APT groups. No patch available — mitigations required immediately.",
            "tags": ["zero-day", "windows", "rce", "cve-2026-21412", "actively-exploited"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "A critical zero-day vulnerability (CVE-2026-21412) in the Windows kernel's SMB handling allows unauthenticated remote code execution with SYSTEM privileges. Microsoft has confirmed active exploitation by at least 3 APT groups. CVSS score: 9.8. No patch is available — emergency mitigations must be applied immediately."},
                {"key": "threat_overview", "title": "Threat Overview", "body": "CVE-2026-21412 is a use-after-free vulnerability in the Windows SMB server driver (srv2.sys). An unauthenticated attacker can send specially crafted SMB packets to trigger the vulnerability and execute arbitrary code with SYSTEM privileges. The vulnerability affects Windows 10, Windows 11, and all Windows Server versions from 2016 onwards. Proof-of-concept exploit code is publicly available."},
                {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Initial Access: Exploit Public-Facing Application (T1190)\nExecution: Exploitation for Client Execution (T1203)\nPrivilege Escalation: Exploitation for Privilege Escalation (T1068)\nLateral Movement: Exploitation of Remote Services (T1210)\nMultiple APT groups observed chaining this with Mimikatz for credential harvesting."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Exploit payload SHA256: 8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b\nPost-exploitation beacon: 203.0.113.42:8443\nRegistry key created: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SMBHelper"},
                {"key": "affected_systems", "title": "Affected Systems", "body": "Windows 10 (all versions)\nWindows 11 (all versions)\nWindows Server 2016, 2019, 2022, 2025\nAny system with SMB port 445 exposed"},
                {"key": "mitigations", "title": "Mitigations", "body": "IMMEDIATE:\n1. Block SMB (port 445) at all network perimeters\n2. Disable SMBv1 on all systems\n3. Apply Microsoft workaround KB5034567 (disables vulnerable code path)\n4. Deploy YARA rule: rule CVE_2026_21412_Exploit { strings: $s1 = {48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0A} condition: $s1 }\n5. Monitor for anomalous SMB traffic patterns"}
            ]
        },
        "high": {
            "title": "APT28 Targeting European Energy Sector — New Campaign",
            "summary": "APT28 (Fancy Bear) launching targeted attacks against European energy infrastructure using novel malware 'BlackEnergy-NG'. Credential harvesting and SCADA access observed.",
            "tags": ["apt28", "fancy-bear", "energy-sector", "scada", "europe"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Russian GRU-linked APT28 has launched a new campaign targeting European energy companies. The campaign uses updated BlackEnergy malware ('BlackEnergy-NG') delivered through compromised vendor portals. At least 8 energy companies across Germany, France, and Poland have been targeted. SCADA system access has been confirmed in 2 organizations."},
                {"key": "threat_overview", "title": "Threat Overview", "body": "The campaign began in early February 2026 with watering-hole attacks on energy industry vendor portals. Compromised sites deliver BlackEnergy-NG through drive-by downloads exploiting a Chrome V8 vulnerability. The malware establishes persistence and begins reconnaissance of SCADA/ICS networks."},
                {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Initial Access: Drive-by Compromise (T1189)\nExecution: PowerShell (T1059.001)\nPersistence: Scheduled Task (T1053.005)\nDiscovery: Network Service Discovery (T1046)\nLateral Movement: Remote Services (T1021)\nCollection: Data from SCADA systems"},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "C2 Domains: update-energy[.]eu, vendor-portal-cdn[.]com\nC2 IPs: 185.165.190.20, 91.219.237.99\nSHA256 (loader): 4a5b6c7d8e9f0a1b2c3d4e5f6789abcdef0123456789\nMutex: Global\\BENG_Session_2026"},
                {"key": "affected_systems", "title": "Affected Systems", "body": "Energy sector organizations in EU\nSCADA/ICS networks running Siemens SIMATIC and ABB systems\nWindows workstations with Chrome browser"},
                {"key": "mitigations", "title": "Mitigations", "body": "1. Block listed C2 domains and IPs\n2. Isolate SCADA networks from corporate IT\n3. Review Chrome browser update status across fleet\n4. Implement application whitelisting on SCADA systems\n5. Monitor for anomalous PowerShell execution on OT-adjacent systems"}
            ]
        },
        "medium": {
            "title": "New Phishing Kit 'PhishMaster Pro' Targeting Financial Services",
            "summary": "A new phishing-as-a-service kit is being sold on dark web forums specifically targeting banking and financial institutions with sophisticated MFA bypass capabilities.",
            "tags": ["phishing", "mfa-bypass", "financial", "phishing-kit"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "A sophisticated phishing kit called 'PhishMaster Pro' has been identified on multiple dark web forums. The kit specifically targets financial institutions and includes real-time MFA token interception using reverse proxy techniques. Over 200 active deployments have been identified targeting major banks."},
                {"key": "threat_overview", "title": "Threat Overview", "body": "PhishMaster Pro uses Evilginx2-based reverse proxy to intercept session tokens and MFA codes in real-time. The kit includes pre-built templates for 50+ banking institutions, automated credential harvesting, and session hijacking capabilities. Sold for $500-2000/month on underground forums."},
                {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Initial Access: Phishing (T1566.002) via SMS and email\nCredential Access: Input Capture (T1056) through reverse proxy\nCollection: Man-in-the-Middle (T1557) for MFA interception\nExfiltration: Automated Exfiltration (T1020) to Telegram bots"},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Known phishing domains: secure-banking-login[.]com, mybank-verify[.]net\nPhishing kit fingerprint: X-PhishMaster header in response\nTelegram bot: @phishmaster_drops\nHosting: Bulletproof hosting in Moldova and Romania"},
                {"key": "affected_systems", "title": "Affected Systems", "body": "All major banking platforms\nMicrosoft 365 / Azure AD authentication\nOkta SSO portals\nAny service using TOTP or push-based MFA"},
                {"key": "mitigations", "title": "Mitigations", "body": "1. Implement FIDO2/WebAuthn hardware keys (resistant to reverse proxy phishing)\n2. Deploy anti-phishing browser extensions\n3. Monitor for unauthorized session tokens\n4. Train users on URL verification\n5. Implement token binding where supported"}
            ]
        },
        "low": {
            "title": "Updated Emotet Variant — Enhanced Evasion Techniques",
            "summary": "New Emotet variant observed with improved sandbox evasion and polymorphic packing. Current AV detection rates are adequate. Updated signatures recommended.",
            "tags": ["emotet", "malware", "evasion", "polymorphic"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "A new variant of the Emotet trojan has been identified with enhanced evasion capabilities including environment-aware execution delays, hardware fingerprint checks, and polymorphic binary packing. Current enterprise AV solutions detect this variant with 85-92% effectiveness. Updated signatures are being distributed."},
                {"key": "threat_overview", "title": "Threat Overview", "body": "The updated Emotet variant (dubbed 'Emotet v5.2' by researchers) primarily spreads through malicious email attachments disguised as shipping notifications. New features include checking for minimum RAM (4GB), mouse movement detection, and process hollowing into legitimate Windows binaries."},
                {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Initial Access: Spearphishing Attachment (T1566.001)\nExecution: User Execution (T1204.002)\nDefense Evasion: Virtualization/Sandbox Evasion (T1497), Process Injection (T1055)\nC2: Web Protocols (T1071.001)"},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Delivery emails from: shipping-notify@[various domains]\nAttachment pattern: Invoice_[6digits].xlsm\nC2 tier 1: 104.21.x.x range (Cloudflare-fronted)\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0)"},
                {"key": "affected_systems", "title": "Affected Systems", "body": "Windows endpoints (7, 10, 11)\nMicrosoft Office with macros enabled\nEndpoints without updated AV signatures"},
                {"key": "mitigations", "title": "Mitigations", "body": "1. Ensure AV signatures updated to latest definitions\n2. Block macro execution in documents from external sources\n3. Monitor for process hollowing indicators\n4. Standard email security filtering is effective for 95%+ of delivery attempts"}
            ]
        },
        "info": {
            "title": "CISA Adds 12 New Vulnerabilities to Known Exploited Catalog",
            "summary": "CISA has added 12 new vulnerabilities to the KEV catalog. Includes Cisco, Adobe, and Linux kernel CVEs. Federal agencies must patch within 21 days.",
            "tags": ["cisa", "kev", "patch-management", "compliance"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "CISA has added 12 new vulnerabilities to the Known Exploited Vulnerabilities (KEV) catalog as of February 28, 2026. These include CVEs affecting Cisco IOS XE, Adobe ColdFusion, Linux kernel, and VMware vCenter. Federal agencies have a 21-day remediation deadline. Private sector organizations are strongly encouraged to prioritize patching."},
                {"key": "threat_overview", "title": "Threat Overview", "body": "The newly added CVEs range from CVSS 7.2 to 9.1. Most concerning are CVE-2026-1234 (Cisco IOS XE auth bypass) and CVE-2026-5678 (VMware vCenter RCE). Both have been observed in targeted attacks against critical infrastructure. Exploitation complexity is low for all 12 CVEs."},
                {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Varies by CVE. Common patterns:\nExploit Public-Facing Application (T1190)\nPrivilege Escalation (T1068)\nSee individual CVE advisories for specific TTP details."},
                {"key": "indicators", "title": "Indicators of Compromise", "body": "Refer to individual CVE advisories:\nCVE-2026-1234, CVE-2026-1235, CVE-2026-2345\nCVE-2026-3456, CVE-2026-4567, CVE-2026-5678\nCVE-2026-6789, CVE-2026-7890, CVE-2026-8901\nCVE-2026-9012, CVE-2026-0123, CVE-2026-0234"},
                {"key": "affected_systems", "title": "Affected Systems", "body": "Cisco IOS XE 17.x\nAdobe ColdFusion 2021, 2023\nLinux kernel 5.15-6.5\nVMware vCenter 7.0, 8.0\nSee CISA BOD 22-01 for full details"},
                {"key": "mitigations", "title": "Mitigations", "body": "1. Cross-reference KEV catalog with asset inventory\n2. Prioritize patching for internet-facing systems\n3. Apply vendor patches per standard change management\n4. Federal agencies: comply with BOD 22-01 timeline (21 days)"}
            ]
        }
    },
    "weekly_summary": {
        "critical": {
            "title": "Weekly Threat Summary — Feb 22-28, 2026 (CRITICAL WEEK)",
            "summary": "Critical threat week: Windows zero-day under active exploitation, 3 ransomware campaigns targeting healthcare, 45% spike in phishing volume. Immediate action required.",
            "tags": ["weekly", "critical-week", "february-2026"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "This week saw an unprecedented threat level with a critical Windows zero-day (CVE-2026-21412) under active exploitation, three separate ransomware campaigns targeting healthcare organizations, and a 45% increase in phishing email volume. Our SOC processed 12,847 alerts with 23 true positive incidents requiring response."},
                {"key": "key_threats", "title": "Key Threats This Week", "body": "1. CVE-2026-21412 Windows SMB Zero-Day (CRITICAL) — Active exploitation by 3+ APT groups\n2. LockBit 3.0 healthcare campaign — 14 hospitals targeted globally\n3. APT28 energy sector campaign — BlackEnergy-NG deployed\n4. PhishMaster Pro phishing kit — 200+ active deployments\n5. New Emotet variant with enhanced evasion (moderate risk)"},
                {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "body": "New CVEs this week: 847\nCritical (CVSS 9.0+): 12\nWith known exploits: 8\nAdded to CISA KEV: 12\nPatched by vendors: 6 of 12 critical\nRemaining unpatched critical: CVE-2026-21412 (Windows), CVE-2026-21500 (Cisco)"},
                {"key": "statistics", "title": "Statistics & Trends", "body": "Total alerts processed: 12,847 (+23% WoW)\nTrue positives: 23 incidents\nMean time to detect: 4.2 minutes\nMean time to respond: 18.7 minutes\nPhishing emails blocked: 45,892 (+45% WoW)\nMalware samples collected: 1,247\nIOCs ingested: 8,934"},
                {"key": "recommendations", "title": "Recommendations", "body": "PRIORITY 1: Apply CVE-2026-21412 mitigations immediately\nPRIORITY 2: Verify healthcare sector organizations have updated ransomware defenses\nPRIORITY 3: Update all threat intelligence feeds with new APT28 IOCs\nPRIORITY 4: Conduct enterprise phishing simulation to test readiness"}
            ]
        },
        "high": {
            "title": "Weekly Threat Summary — Feb 15-21, 2026",
            "summary": "Elevated threat week with new APT campaign targeting defense contractors, critical Fortinet vulnerability, and increased cryptomining activity across cloud environments.",
            "tags": ["weekly", "february-2026"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "This week saw elevated threat activity with a new APT campaign targeting defense contractors, a critical Fortinet FortiOS vulnerability requiring immediate patching, and a 200% increase in cryptomining malware targeting AWS and Azure cloud environments. SOC processed 10,234 alerts with 15 true positive incidents."},
                {"key": "key_threats", "title": "Key Threats This Week", "body": "1. APT41 defense contractor campaign — new backdoor 'ShadowPad v4'\n2. CVE-2026-18753 Fortinet FortiOS RCE — PoC released\n3. Cloud cryptomining surge — compromised IAM keys\n4. Magecart Group 12 — targeting e-commerce checkouts\n5. Updated QakBot loader distribution via OneNote"},
                {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "body": "New CVEs: 712\nCritical: 8\nWith known exploits: 5\nMost urgent: CVE-2026-18753 (Fortinet FortiOS, CVSS 9.6)"},
                {"key": "statistics", "title": "Statistics & Trends", "body": "Total alerts: 10,234 (+12% WoW)\nTrue positives: 15\nMTTD: 5.1 min\nMTTR: 22.3 min\nPhishing blocked: 31,456\nMalware samples: 892\nIOCs ingested: 6,721"},
                {"key": "recommendations", "title": "Recommendations", "body": "1. Patch Fortinet FortiOS immediately (CVE-2026-18753)\n2. Review cloud IAM key rotation policies\n3. Enhance e-commerce transaction monitoring\n4. Block OneNote attachments from external email"}
            ]
        },
        "medium": {
            "title": "Weekly Threat Summary — Feb 8-14, 2026",
            "summary": "Moderate threat activity with standard phishing campaigns, new malware variants, and ongoing vulnerability disclosures. No critical emergencies.",
            "tags": ["weekly", "february-2026"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Standard operational tempo this week. No critical zero-days or active campaigns targeting our sector. Notable items include new Remcos RAT variant, Microsoft Patch Tuesday addressing 73 CVEs, and continued Akira ransomware activity in manufacturing sector."},
                {"key": "key_threats", "title": "Key Threats This Week", "body": "1. Microsoft Patch Tuesday — 73 CVEs, 6 critical\n2. New Remcos RAT variant with improved persistence\n3. Akira ransomware targeting manufacturing (not our sector)\n4. DDoS campaigns against European financial institutions\n5. Credential dumps: 2.3M records on BreachForums"},
                {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "body": "New CVEs: 623\nCritical: 6 (all patched by MS)\nPatch Tuesday: 73 total, 6 critical, 32 important\nNo zero-days this cycle"},
                {"key": "statistics", "title": "Statistics & Trends", "body": "Total alerts: 8,912 (baseline)\nTrue positives: 8\nMTTD: 3.8 min\nMTTR: 15.2 min\nPhishing blocked: 28,933\nIOCs ingested: 5,234"},
                {"key": "recommendations", "title": "Recommendations", "body": "1. Apply Patch Tuesday updates per standard schedule\n2. Update Remcos RAT detection signatures\n3. Check credential dumps for company email domains\n4. Standard operations — no emergency actions needed"}
            ]
        },
        "low": {
            "title": "Weekly Threat Summary — Feb 1-7, 2026",
            "summary": "Quiet week with below-average threat activity. Standard scanning and commodity malware. Good time for proactive threat hunting and tool maintenance.",
            "tags": ["weekly", "february-2026"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Below-average threat activity this week. No significant campaigns, zero-days, or incidents targeting our industry vertical. Standard commodity malware and automated scanning activity observed. Recommend using this lull for proactive threat hunting exercises and tool calibration."},
                {"key": "key_threats", "title": "Key Threats This Week", "body": "1. Continued Qakbot distribution (low volume)\n2. Generic WordPress exploitation attempts (automated)\n3. SSH brute force increase from East Asian IPs\n4. Commodity cryptominers targeting exposed Docker APIs\n5. No significant APT activity observed"},
                {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "body": "New CVEs: 489\nCritical: 3 (none in our stack)\nNo active exploitation detected\nRecommended: Use downtime to clear patch backlog"},
                {"key": "statistics", "title": "Statistics & Trends", "body": "Total alerts: 6,234 (-18% WoW)\nTrue positives: 3\nMTTD: 2.1 min\nMTTR: 8.5 min\nPhishing blocked: 19,234\nIOCs ingested: 3,892"},
                {"key": "recommendations", "title": "Recommendations", "body": "1. Conduct proactive threat hunting exercises\n2. Clear outstanding patch backlog\n3. Review and tune detection rules\n4. Update incident response playbooks for Q1 review"}
            ]
        },
        "info": {
            "title": "Weekly Threat Landscape Overview — January 2026 Recap",
            "summary": "Monthly retrospective: January 2026 threat landscape summarized. Key trends in ransomware evolution, AI-powered attacks, and regulatory changes.",
            "tags": ["monthly", "recap", "january-2026", "trends"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "January 2026 summary: 4 weekly summaries consolidated. Key trends: 15% increase in ransomware incidents YoY, emergence of AI-generated phishing content, and new EU NIS2 enforcement beginning. No critical incidents affecting our organization during the month."},
                {"key": "key_threats", "title": "Key Threats This Month", "body": "Top threat categories:\n1. Ransomware (38% of incidents)\n2. Phishing/Social Engineering (27%)\n3. Vulnerability exploitation (18%)\n4. Insider threats (9%)\n5. Supply chain (8%)"},
                {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "body": "Total new CVEs in January: 2,847\nCritical: 34\nAdded to CISA KEV: 18\nPatched in our environment: 100% of critical within SLA"},
                {"key": "statistics", "title": "Statistics & Trends", "body": "Monthly totals:\nAlerts processed: 38,234\nTrue positive incidents: 42\nAverage MTTD: 3.8 min\nAverage MTTR: 16.4 min\nPhishing blocked: 112,847\nTotal IOCs: 24,567"},
                {"key": "recommendations", "title": "Recommendations", "body": "Strategic recommendations for Q1:\n1. Budget for AI-powered email defense\n2. Prepare for NIS2 compliance requirements\n3. Review ransomware insurance coverage\n4. Conduct tabletop exercise for supply chain compromise scenario"}
            ]
        }
    },
    "ioc_bulletin": {
        "critical": {
            "title": "IOC Bulletin — Active C2 Infrastructure for CVE-2026-21412 Exploitation",
            "summary": "Emergency IOC bulletin containing confirmed C2 infrastructure being used in active CVE-2026-21412 exploitation campaigns. Block immediately.",
            "tags": ["ioc-bulletin", "cve-2026-21412", "c2", "emergency"],
            "sections": [
                {"key": "executive_summary", "title": "Summary", "body": "EMERGENCY: This bulletin contains IOCs associated with active exploitation of CVE-2026-21412 (Windows SMB zero-day). These C2 servers are confirmed active as of February 28, 2026. Block all indicators at network perimeter IMMEDIATELY."},
                {"key": "ioc_table", "title": "IOC Table", "body": "IP Addresses (C2 Servers):\n203.0.113.42 — Primary C2 (US-based VPS)\n198.51.100.17 — Secondary C2 (Netherlands)\n45.33.32.156 — Staging server (Germany)\n91.108.56.200 — Exfiltration endpoint (Russia)\n\nDomains:\nupdate-microsoft-security[.]com\nwindows-patch-kb[.]net\nsmbfix-download[.]org\n\nHashes (SHA-256):\n8a9b0c1d2e3f4a5b — Exploit payload\nce77d116a074dab7 — SUNBURST variant loader\nf6e5d4c3b2a10987 — Backdoor binary"},
                {"key": "context", "title": "Context & Attribution", "body": "These IOCs are associated with at least 3 distinct threat groups exploiting CVE-2026-21412. Attribution includes APT29 (Russia), Lazarus Group (North Korea), and an unattributed cybercrime group. Infrastructure overlap suggests shared exploit broker."},
                {"key": "detection", "title": "Detection Guidance", "body": "YARA Rule:\nrule CVE_2026_21412_C2 {\n  strings: $ua = \"Mozilla/5.0 (compatible; SMBFix/1.0)\"\n  $c2_1 = \"update-microsoft-security.com\"\n  condition: any of them\n}\n\nSuricata Rule:\nalert tcp any any -> any 445 (msg:\"CVE-2026-21412 Exploit Attempt\"; content:\"|FF|SMB\"; content:\"|00 00 00 90|\"; sid:2026001; rev:1;)"}
            ]
        },
        "high": {
            "title": "IOC Bulletin — LockBit 3.0 Healthcare Campaign Infrastructure",
            "summary": "IOCs from the ongoing LockBit 3.0 campaign targeting healthcare organizations. Includes C2 servers, malware hashes, and email indicators.",
            "tags": ["ioc-bulletin", "lockbit", "ransomware", "healthcare"],
            "sections": [
                {"key": "executive_summary", "title": "Summary", "body": "This bulletin provides IOCs from the active LockBit 3.0 ransomware campaign targeting healthcare organizations. Campaign active since February 15, 2026. At least 14 healthcare organizations globally have been targeted. Block and hunt for these indicators."},
                {"key": "ioc_table", "title": "IOC Table", "body": "C2 Servers:\n185.220.101.42:443 — Primary Cobalt Strike C2\n194.5.249.65:8443 — LockBit panel\n45.142.213.77:80 — Exfiltration staging\n\nEmail Indicators:\ninvoice-feb@medisupply[.]biz\nurgent-update@health-it-solutions[.]com\n\nHashes (SHA-256):\na1b2c3d4e5f67890 — Macro-enabled dropper\nb2c3d4e5f6789012 — Cobalt Strike beacon\nc3d4e5f678901234 — LockBit 3.0 encryptor"},
                {"key": "context", "title": "Context & Attribution", "body": "Attributed to LockBit ransomware affiliate 'LB-healthcare-02'. The affiliate specifically targets healthcare organizations, likely due to higher ransom payment rates in the sector. Initial access via phishing emails impersonating medical supply companies."},
                {"key": "detection", "title": "Detection Guidance", "body": "Sigma Rule:\ntitle: LockBit 3.0 Execution Indicators\nstatus: experimental\nlogsource: category: process_creation\ndetection:\n  selection: CommandLine|contains:\n    - 'vssadmin delete shadows'\n    - 'bcdedit /set {default} recoveryenabled No'\n  condition: selection\n\nNetwork: Monitor for connections to listed IPs on non-standard ports."}
            ]
        },
        "medium": {
            "title": "IOC Bulletin — Emotet v5.2 Distribution Network",
            "summary": "Updated IOCs for the new Emotet v5.2 variant including distribution infrastructure, payload hashes, and C2 communication patterns.",
            "tags": ["ioc-bulletin", "emotet", "botnet", "distribution"],
            "sections": [
                {"key": "executive_summary", "title": "Summary", "body": "This bulletin provides IOCs for the newly identified Emotet v5.2 variant. The botnet is currently in a rebuilding phase with moderate distribution volume. IOCs should be added to detection systems and blocklists as part of standard threat feed updates."},
                {"key": "ioc_table", "title": "IOC Table", "body": "Distribution URLs:\nhxxps://compromised-site1[.]com/wp-content/uploads/invoice.xlsm\nhxxps://compromised-site2[.]org/documents/shipping.xlsm\n\nPayload Hashes:\nd4e5f6a7b8c9d0e1 — Excel dropper\ne5f6a7b8c9d0e1f2 — Emotet DLL\nf6a7b8c9d0e1f2a3 — Secondary payload (TrickBot)\n\nC2 Tier 1 (Cloudflare-fronted):\n104.21.45.67\n104.21.89.12\n172.67.34.56"},
                {"key": "context", "title": "Context & Attribution", "body": "Emotet (TA542/Mummy Spider) continues to rebuild its botnet following the 2021 takedown. The v5.2 variant represents a significant evolution with improved evasion. Current infection volume is estimated at 50,000-100,000 systems globally."},
                {"key": "detection", "title": "Detection Guidance", "body": "YARA Rule:\nrule Emotet_V5_2 {\n  meta: description = \"Emotet v5.2 DLL\"\n  strings: $pdb = \"C:\\\\Users\\\\dev\\\\emotet\" $api = \"VirtualAllocEx\"\n  condition: all of them and filesize < 500KB\n}\n\nEmail filtering: Block .xlsm attachments from external senders."}
            ]
        },
        "low": {
            "title": "IOC Bulletin — Commodity Cryptominer Campaign Targeting Docker",
            "summary": "IOCs for automated cryptominer campaign exploiting exposed Docker daemon APIs. Low sophistication, easily blocked with proper configuration.",
            "tags": ["ioc-bulletin", "cryptominer", "docker", "cloud"],
            "sections": [
                {"key": "executive_summary", "title": "Summary", "body": "This bulletin documents IOCs from an automated cryptomining campaign targeting publicly exposed Docker daemon APIs (port 2375/2376). The campaign is low-sophistication and easily mitigated by ensuring Docker APIs are not exposed to the internet."},
                {"key": "ioc_table", "title": "IOC Table", "body": "Scanner IPs:\n45.95.169.10\n45.95.169.11\n45.95.169.12\n\nMining Pool:\nstratum+tcp://xmr-pool[.]minergate[.]com:45700\n\nContainer Image:\nalpine-xmrig:latest (Docker Hub, removed)\n\nWallet:\n49F7RVzJfNrNz8zCQj5...(XMR)"},
                {"key": "context", "title": "Context & Attribution", "body": "Automated, indiscriminate scanning campaign. No specific threat actor attribution. Targets of opportunity — any exposed Docker API will be compromised. Estimated revenue: <$1000/day across all infected hosts."},
                {"key": "detection", "title": "Detection Guidance", "body": "1. Check: docker port 2375 not exposed externally\n2. Monitor: CPU usage spikes on Docker hosts\n3. Hunt: containers running 'xmrig' or connecting to mining pools\n4. Network: Block outbound connections to known mining pools"}
            ]
        },
        "info": {
            "title": "IOC Bulletin — Quarterly Threat Feed Quality Assessment",
            "summary": "Informational bulletin documenting false positive rates and quality metrics for our threat intelligence feeds. No action required — for awareness.",
            "tags": ["ioc-bulletin", "feed-quality", "metrics", "quarterly"],
            "sections": [
                {"key": "executive_summary", "title": "Summary", "body": "Quarterly assessment of threat intelligence feed quality for Q4 2025 / Q1 2026. This informational bulletin documents false positive rates, coverage gaps, and recommendations for feed optimization. No immediate action required."},
                {"key": "ioc_table", "title": "IOC Table", "body": "Feed Performance Metrics:\n\nAbuseIPDB: 94.2% accuracy, 2.1% FP rate, 847K IOCs\nOTX: 89.7% accuracy, 4.3% FP rate, 1.2M IOCs\nURLhaus: 96.1% accuracy, 1.2% FP rate, 234K IOCs\nVirusTotal: 97.8% accuracy, 0.8% FP rate, 2.1M IOCs\nShodan: 91.3% accuracy, 3.2% FP rate, 567K IOCs\nNVD: 99.1% accuracy, 0.3% FP rate, 4.2K CVEs\nCISA KEV: 100% accuracy, 0% FP rate, 1,103 CVEs"},
                {"key": "context", "title": "Context & Attribution", "body": "N/A — This is an internal quality assessment, not a threat attribution bulletin. Feed quality scores are calculated based on correlation with confirmed incidents, industry sharing partners, and retrospective analysis."},
                {"key": "detection", "title": "Detection Guidance", "body": "Recommendations:\n1. Increase confidence weight for URLhaus and VirusTotal feeds\n2. Add secondary validation for OTX indicators above 4% FP rate\n3. Consider adding CIRCL MISP feed (evaluated at 93.5% accuracy)\n4. Maintain current NVD and KEV subscriptions (excellent quality)"}
            ]
        }
    },
    "custom": {
        "critical": {
            "title": "Board Briefing — Critical Cybersecurity Posture Update Q1 2026",
            "summary": "Executive board briefing on critical cybersecurity risks, active threats, and required budget allocation for emergency response capabilities.",
            "tags": ["board-briefing", "executive", "budget", "posture"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "BOARD ATTENTION REQUIRED: Our organization faces critical cybersecurity risks requiring immediate board-level decisions. Active zero-day threats (CVE-2026-21412) affect our infrastructure. Incident response costs have exceeded quarterly budget by 35%. Emergency funding request of $2.4M for enhanced defenses and a dedicated IR retainer is submitted for approval."},
                {"key": "body", "title": "Report Body", "body": "Current Threat Level: CRITICAL\n\nKey Risk Areas:\n1. Active zero-day affecting 847 Windows endpoints (no patch available)\n2. Ransomware targeting our industry vertical (3 peers compromised this month)\n3. Supply chain risk from 23 third-party vendors with outdated security postures\n\nFinancial Impact:\n- Estimated cost of breach (industry average): $4.45M\n- Current insurance coverage: $5M (adequate)\n- Q1 incident response costs: $890K vs $660K budget (35% over)\n\nProposed Investments:\n- Emergency IR retainer (CrowdStrike): $600K/year\n- EDR upgrade (full coverage): $450K\n- Zero trust network implementation: $1.2M\n- Security awareness training platform: $150K\nTotal: $2.4M"},
                {"key": "conclusion", "title": "Conclusion", "body": "The current threat landscape requires immediate board-level action. Without the proposed investments, we estimate a 40% probability of a material cyber incident within 6 months. The $2.4M investment represents less than 0.5% of annual revenue and provides substantial risk reduction. Board approval requested by March 15, 2026."}
            ]
        },
        "high": {
            "title": "Vendor Security Assessment — CloudVault Inc. (High Risk)",
            "summary": "Third-party security assessment of CloudVault Inc. reveals significant security gaps in their SaaS platform that stores our customer data. Risk acceptance or remediation required.",
            "tags": ["vendor-assessment", "third-party-risk", "saas", "cloudvault"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Security assessment of CloudVault Inc. (our primary cloud storage vendor) reveals HIGH risk. Key findings include: lack of encryption at rest for 30% of data stores, outdated SOC 2 Type II certification (expired 8 months ago), and no incident response plan shared with customers. CloudVault stores PII for approximately 150,000 of our customers."},
                {"key": "body", "title": "Report Body", "body": "Assessment Methodology: Vendor security questionnaire + external penetration test + SOC 2 review\n\nCritical Findings:\n1. Data encryption at rest: 70% coverage (target: 100%)\n2. SOC 2 Type II expired June 2025\n3. No shared incident notification SLA\n4. MFA not enforced for administrative access\n5. Backup recovery tested annually (industry best practice: quarterly)\n\nData at Risk:\n- 150,000 customer PII records\n- 45,000 financial transaction records\n- 12TB of document storage\n\nContractual Requirements:\n- 30-day remediation plan required per Section 8.3 of MSA\n- Right to audit clause exercisable (Section 9.1)\n- Escalation to CISO and Legal if no remediation within 60 days"},
                {"key": "conclusion", "title": "Conclusion", "body": "CloudVault must provide a remediation timeline within 30 days. If critical findings are not addressed within 90 days, recommend initiating vendor transition to alternative provider. Begin parallel evaluation of AWS S3 + client-side encryption as replacement architecture."}
            ]
        },
        "medium": {
            "title": "Security Architecture Review — Microservices Migration Phase 2",
            "summary": "Security review of the Phase 2 microservices migration. Identifies authentication, API security, and container orchestration concerns with recommended controls.",
            "tags": ["architecture-review", "microservices", "security-design"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "This report documents the security review of Phase 2 of the monolith-to-microservices migration. Overall assessment: MEDIUM risk. Key concerns include inter-service authentication design, API gateway configuration, and Kubernetes RBAC policies. 8 findings documented with recommended controls."},
                {"key": "body", "title": "Report Body", "body": "Architecture Review Findings:\n\n1. Inter-service Authentication (MEDIUM)\n   - Current: API keys in environment variables\n   - Recommended: mTLS with service mesh (Istio)\n\n2. API Gateway (LOW)\n   - Rate limiting configured but not per-tenant\n   - Recommended: Per-tenant rate limiting + circuit breakers\n\n3. Kubernetes RBAC (MEDIUM)\n   - 3 service accounts with cluster-admin role\n   - Recommended: Least-privilege RBAC per namespace\n\n4. Secret Management (LOW)\n   - Using Kubernetes secrets (base64, not encrypted)\n   - Recommended: HashiCorp Vault integration\n\n5. Container Images (LOW)\n   - Base images updated monthly\n   - Recommended: Weekly Trivy scans + automated rebuilds\n\n6-8. Additional findings in appendix."},
                {"key": "conclusion", "title": "Conclusion", "body": "Phase 2 migration can proceed with the documented controls implemented. Priority items: mTLS service mesh and RBAC tightening should be completed before production deployment. Remaining items can be addressed in the first sprint post-migration."}
            ]
        },
        "low": {
            "title": "Compliance Readiness — NIS2 Directive Gap Analysis",
            "summary": "Gap analysis comparing current security posture against EU NIS2 Directive requirements. 85% compliant with clear remediation path for remaining gaps.",
            "tags": ["compliance", "nis2", "eu-directive", "gap-analysis"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "Gap analysis against EU NIS2 Directive requirements shows 85% compliance. Major gaps: supply chain security documentation (Article 21.2d), incident reporting automation (Article 23), and board-level cybersecurity training (Article 20). Remediation estimated at 4-6 months and $180K."},
                {"key": "body", "title": "Report Body", "body": "NIS2 Compliance Assessment:\n\nFully Compliant (85%):\n- Risk management policies (Art. 21.2a) ✅\n- Incident handling procedures (Art. 21.2b) ✅\n- Business continuity (Art. 21.2c) ✅\n- Encryption and access control (Art. 21.2e-f) ✅\n- Vulnerability management (Art. 21.2h) ✅\n\nPartially Compliant (10%):\n- Supply chain security (Art. 21.2d) — Documentation needed\n- Cyber hygiene training (Art. 21.2g) — Board-level gaps\n\nNon-Compliant (5%):\n- Incident reporting within 24h (Art. 23) — Manual process, needs automation\n- Cross-border incident notification — No process defined\n\nRemediation Costs:\n- Supply chain documentation: $30K (consultant)\n- Incident reporting automation: $80K (tooling)\n- Board training program: $20K\n- Cross-border notification SOP: $50K (legal)"},
                {"key": "conclusion", "title": "Conclusion", "body": "We are well-positioned for NIS2 compliance with targeted investments. Recommend prioritizing incident reporting automation (highest regulatory risk) followed by supply chain documentation. Target full compliance by July 2026, ahead of the enforcement deadline."}
            ]
        },
        "info": {
            "title": "Security Team Training Plan — H1 2026",
            "summary": "Structured training plan for the security team covering certifications, hands-on labs, and conference attendance for the first half of 2026.",
            "tags": ["training", "certifications", "team-development"],
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "body": "This document outlines the H1 2026 training plan for the 12-person security team. Budget allocation: $48,000. Focus areas: cloud security certifications, incident response skills, and threat hunting capabilities. Goal: 80% of team achieves at least one new certification by June 2026."},
                {"key": "body", "title": "Report Body", "body": "Training Schedule:\n\nMarch 2026:\n- AWS Security Specialty (3 team members) — $900 each\n- SANS FOR508 Advanced IR (2 team members) — $8,000 each\n\nApril 2026:\n- CKS Kubernetes Security (2 members) — $400 each\n- Internal threat hunting workshop (all team) — $2,000\n\nMay 2026:\n- OSCP certification attempt (1 member) — $1,600\n- GIAC GCTI Threat Intelligence (2 members) — $2,500 each\n\nJune 2026:\n- BSides conference attendance (4 members) — $800 each\n- Annual tabletop exercise (all team) — $5,000\n\nBudget: $48,000 allocated, $46,200 planned spend"},
                {"key": "conclusion", "title": "Conclusion", "body": "Training plan approved by CISO. Team leads responsible for scheduling around operational requirements. Success metric: 80% certification achievement rate. Training budget utilization report due July 2026."}
            ]
        }
    }
}


def curl_post(path, data):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(data, f)
        tmp = f.name
    cmd = f"curl -s {COOKIE} -X POST {BASE}{path} -H 'Content-Type: application/json' -d @{tmp}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    os.unlink(tmp)
    try:
        return json.loads(result.stdout)
    except:
        return {"error": result.stdout}


created = 0
failed = 0

for rtype in TYPES:
    for severity in SEVERITIES:
        sample = SAMPLES[rtype][severity]
        payload = {
            "title": sample["title"],
            "summary": sample["summary"],
            "report_type": rtype,
            "severity": severity,
            "tlp": TLP_MAP[severity],
            "tags": sample["tags"],
            "content": {"sections": sample["sections"]},
        }
        result = curl_post("/reports", payload)
        rid = result.get("id")
        if rid:
            created += 1
            print(f"  [OK] {rtype}/{severity}: {sample['title'][:60]}... (id={rid[:8]})")
        else:
            failed += 1
            print(f"  [FAIL] {rtype}/{severity}: {str(result)[:120]}")

print(f"\n{'='*60}")
print(f"Created: {created}/25 | Failed: {failed}")
print(f"{'='*60}")
