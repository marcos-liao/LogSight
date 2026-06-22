// =============================================================================
// LogSight — Detection enrichment
// Per-detection context surfaced in the Detection Details panel: impact,
// mitigation, IoC hints, and framework mappings (NIST / OWASP / CVSS).
// MITRE comes from the alert itself; "why" comes from the rule/anomaly
// description; threshold-vs-observed comes from the alert's stats.
// Keyed by rule id (Layer 1) or anomaly type (Layer 2).
// =============================================================================

var DETECTION_ENRICHMENT = {

  // ---- Layer 1: rule-based ----
  'ssh-bruteforce': {
    ioc: ['Repeated "Failed password" from one source IP', 'High auth-failure rate in a short window', 'Sequential source ports from the same host'],
    impact: 'An attacker is systematically guessing credentials. Success grants an initial foothold and a valid account that blends into normal traffic.',
    mitigation: ['Deploy fail2ban / rate-limiting on SSH', 'Disable password auth — enforce key-based login', 'Restrict SSH to a bastion host or IP allowlist', 'Alert on > N failures per source per minute'],
    nist: ['PR.AC-7 Authentication commensurate with risk', 'DE.CM-1 Network monitoring', 'DE.AE-2 Event analysis'],
    owasp: ['A07:2021 Identification and Authentication Failures'],
    cvss: { score: 7.5, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N→C:H' }
  },
  'ssh-success-after-fail': {
    ioc: ['"Accepted password" immediately following a burst of failures from the same IP', 'Login outside business hours', 'First-seen source IP for the account'],
    impact: 'A brute-force attempt likely succeeded. The attacker now holds valid credentials and an interactive session.',
    mitigation: ['Force password reset for the affected account', 'Terminate active sessions from the source IP', 'Enable MFA', 'Hunt for post-login activity (sudo, downloads, new cron)'],
    nist: ['PR.AC-1 Identity & access management', 'RS.MI-2 Incidents are mitigated', 'DE.AE-2 Event analysis'],
    owasp: ['A07:2021 Identification and Authentication Failures'],
    cvss: { score: 8.1, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }
  },
  'webshell-access': {
    ioc: ['Requests with cmd=, eval(), system(), shell_exec()', 'POST to an uploads/ path then GET of a new script', 'Web-server user spawning shell commands'],
    impact: 'Remote code execution via a planted web shell — full control of the web application context and a pivot into the host.',
    mitigation: ['Remove the web shell and restore from known-good', 'Block write access to web-served directories', 'WAF rules for command-injection params', 'File-integrity monitoring on web roots'],
    nist: ['PR.DS-6 Integrity checking', 'DE.CM-4 Malicious code detection', 'RS.MI-1 Incidents are contained'],
    owasp: ['A03:2021 Injection', 'A05:2021 Security Misconfiguration'],
    cvss: { score: 9.8, severity: 'Critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
  },
  'sqli-attempt': {
    ioc: ['UNION SELECT, OR 1=1, comment sequences (-- , /* */) in query strings', 'sleep()/benchmark() time-based payloads', 'Errors referencing SQL syntax in app logs'],
    impact: 'Database compromise — data theft, authentication bypass, or destructive queries depending on privileges.',
    mitigation: ['Use parameterized queries / prepared statements', 'Least-privilege DB accounts', 'WAF signatures for SQLi', 'Input validation and output encoding'],
    nist: ['PR.IP-1 Secure configuration', 'DE.CM-1 Network monitoring'],
    owasp: ['A03:2021 Injection'],
    cvss: { score: 9.1, severity: 'Critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }
  },
  'xss-attempt': {
    ioc: ['<script>, onerror=, javascript: in request parameters', 'Reflected payloads in responses', 'document.cookie exfil attempts'],
    impact: 'Session hijacking, credential theft, or drive-by actions executed in a victim\'s browser.',
    mitigation: ['Context-aware output encoding', 'Content-Security-Policy headers', 'HttpOnly + SameSite cookies', 'Sanitize and validate input'],
    nist: ['PR.IP-1 Secure configuration', 'PR.DS-2 Data-in-transit protection'],
    owasp: ['A03:2021 Injection'],
    cvss: { score: 6.1, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' }
  },
  'path-traversal': {
    ioc: ['../ or encoded %2e%2e%2f sequences', 'Requests for /etc/passwd, /etc/shadow, /proc/self', 'Access outside the web root'],
    impact: 'Disclosure of sensitive files (configs, credentials, keys) and potential for further exploitation.',
    mitigation: ['Canonicalize and validate file paths', 'Run the app in a chroot / restricted FS', 'Deny access to system paths at the proxy', 'Least-privilege file permissions'],
    nist: ['PR.AC-4 Access permissions', 'PR.DS-5 Protections against data leaks'],
    owasp: ['A01:2021 Broken Access Control'],
    cvss: { score: 7.5, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }
  },
  'directory-bruteforce': {
    ioc: ['Burst of HTTP 404s from one source', 'Sequential/dictionary-style path requests', 'Scanner user-agents (gobuster, dirb, feroxbuster)'],
    impact: 'Reconnaissance to map hidden endpoints, backups, and admin panels — a precursor to targeted exploitation.',
    mitigation: ['Rate-limit by source IP', 'Return uniform responses for unknown paths', 'Remove sensitive files from web roots', 'Alert on 404-rate anomalies'],
    nist: ['DE.CM-1 Network monitoring', 'DE.AE-2 Event analysis'],
    owasp: ['A05:2021 Security Misconfiguration'],
    cvss: { score: 5.3, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }
  },
  'sensitive-file-access': {
    ioc: ['Reads of /etc/shadow, /etc/sudoers, .ssh/id_rsa, .bash_history', 'Access by an unexpected user or process', 'Follows a privilege-escalation event'],
    impact: 'Credential and secret harvesting — enables offline cracking, lateral movement, and persistence.',
    mitigation: ['auditd rules on sensitive files', 'Least-privilege + remove unnecessary sudo', 'Rotate any exposed secrets/keys', 'File-integrity monitoring'],
    nist: ['PR.AC-4 Access permissions', 'PR.DS-1 Data-at-rest protection', 'DE.CM-3 Personnel activity monitoring'],
    owasp: ['A01:2021 Broken Access Control'],
    cvss: { score: 7.8, severity: 'High', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' }
  },
  'reverse-shell': {
    ioc: ['nc -e, bash -i >& /dev/tcp/, mkfifo|nc patterns', 'Outbound connection to an unusual IP:port', 'Shell spawned by a service account'],
    impact: 'Interactive attacker control of the host with an outbound channel that often bypasses inbound firewall rules.',
    mitigation: ['Egress filtering / deny outbound to untrusted IPs', 'EDR detection of shell spawns', 'Network segmentation', 'Block known C2 infrastructure'],
    nist: ['DE.CM-7 Unauthorized activity monitoring', 'PR.PT-4 Communications protection', 'RS.MI-1 Incidents are contained'],
    owasp: ['A03:2021 Injection'],
    cvss: { score: 9.8, severity: 'Critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
  },
  'user-enumeration': {
    ioc: ['Repeated "Invalid user" / "no such user" from one source', 'Sweeps through common account names', 'Precedes a focused brute-force'],
    impact: 'The attacker is discovering valid accounts to target — early-stage reconnaissance for credential attacks.',
    mitigation: ['Uniform auth responses (don\'t reveal valid users)', 'Rate-limit by source IP', 'Alert on enumeration patterns', 'Disable unused accounts'],
    nist: ['DE.CM-1 Network monitoring', 'PR.AC-7 Authentication commensurate with risk'],
    owasp: ['A07:2021 Identification and Authentication Failures'],
    cvss: { score: 5.3, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }
  },
  'cron-modification': {
    ioc: ['crontab edits / new cron entries', 'Jobs invoking scripts in /tmp or world-writable paths', 'Changes outside a maintenance window'],
    impact: 'Persistence — the attacker re-establishes access on a schedule, surviving reboots and session loss.',
    mitigation: ['auditd on cron files and crontab', 'Baseline and alert on cron changes', 'Restrict who can edit cron', 'Review and remove unauthorized jobs'],
    nist: ['DE.CM-7 Unauthorized activity monitoring', 'PR.IP-3 Configuration change control'],
    owasp: ['A05:2021 Security Misconfiguration'],
    cvss: { score: 6.7, severity: 'Medium', vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }
  },
  'dns-tunneling': {
    ioc: ['Abnormally long subdomain labels', 'High query volume to one domain', 'TXT/NULL record queries; high entropy labels'],
    impact: 'Covert data exfiltration or C2 over DNS — often missed because DNS is widely allowed outbound.',
    mitigation: ['Restrict DNS to approved resolvers', 'Alert on label length & query-rate anomalies', 'Block known tunneling domains', 'DNS response policy zones (RPZ)'],
    nist: ['DE.CM-1 Network monitoring', 'PR.PT-4 Communications protection', 'DE.AE-3 Event data aggregation'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 7.4, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }
  },
  'port-scan': {
    ioc: ['Connections to many ports from one source', 'SYN bursts / connection resets', 'Firewall BLOCK entries clustering by source'],
    impact: 'Network reconnaissance mapping live hosts and exposed services — a precursor to targeted attacks.',
    mitigation: ['Rate-limit and alert on scan patterns', 'Minimize exposed services', 'Network segmentation', 'Drop (don\'t reject) to slow scanners'],
    nist: ['DE.CM-1 Network monitoring', 'DE.AE-2 Event analysis'],
    owasp: ['A05:2021 Security Misconfiguration'],
    cvss: { score: 5.3, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }
  },
  'privilege-escalation-su': {
    ioc: ['Repeated "FAILED su" / su authentication failures', 'Attempts to switch to root', 'Follows an initial-access event'],
    impact: 'The attacker is attempting to elevate to root/admin — a step toward full host compromise.',
    mitigation: ['Restrict su; prefer sudo with logging', 'Alert on failed su attempts', 'Strong root password / disable direct root', 'Least-privilege accounts'],
    nist: ['PR.AC-4 Access permissions', 'DE.CM-3 Personnel activity monitoring'],
    owasp: ['A01:2021 Broken Access Control'],
    cvss: { score: 7.8, severity: 'High', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' }
  },
  'large-outbound-transfer': {
    ioc: ['Unusually large bytes_sent/upload values', 'Transfers to external/unknown destinations', 'Off-hours bulk egress'],
    impact: 'Likely data exfiltration — sensitive data leaving the environment in bulk.',
    mitigation: ['DLP and egress monitoring', 'Alert on volume anomalies per host', 'Block/inspect large uploads to untrusted destinations', 'Segment sensitive data stores'],
    nist: ['PR.DS-5 Protections against data leaks', 'DE.CM-1 Network monitoring', 'PR.PT-4 Communications protection'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 7.5, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }
  },
  'log-tampering': {
    ioc: ['rm/truncate on /var/log', 'history -c / unset HISTFILE', 'rsyslog/journald stopped unexpectedly'],
    impact: 'Anti-forensics — the attacker is destroying evidence to hide activity and frustrate investigation.',
    mitigation: ['Ship logs off-host in real time (central SIEM)', 'Append-only / immutable log storage', 'Alert on logging-service stops', 'Monitor history/HISTFILE tampering'],
    nist: ['PR.PT-1 Audit/log records', 'DE.AE-3 Event data aggregation', 'PR.DS-6 Integrity checking'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 6.5, severity: 'Medium', vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H' }
  },
  'suspicious-sudo': {
    ioc: ['"NOT in sudoers" / sudo auth failures', 'Unexpected user attempting sudo', 'Repeated incorrect sudo passwords'],
    impact: 'Probing for privilege escalation — an account is testing elevated access it may not be authorized for.',
    mitigation: ['Review and tighten sudoers', 'Alert on sudo failures', 'Require MFA for privileged actions', 'Least-privilege accounts'],
    nist: ['PR.AC-4 Access permissions', 'DE.CM-3 Personnel activity monitoring'],
    owasp: ['A01:2021 Broken Access Control'],
    cvss: { score: 6.0, severity: 'Medium', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L' }
  },

  // ---- Layer 2: statistical / behavioral ----
  'event-chain': {
    ioc: ['Failed auth → successful login → privilege escalation from one source within minutes', 'Tight temporal clustering of distinct event types'],
    impact: 'A complete compromise sequence — initial access through to privilege escalation — strongly indicating an active intrusion.',
    mitigation: ['Treat as an active incident: isolate the host', 'Reset affected credentials and kill sessions', 'Full IR — hunt for persistence and lateral movement', 'Preserve logs for forensics'],
    nist: ['RS.AN-1 Investigate notifications', 'RS.MI-1 Incidents are contained', 'DE.AE-2 Event analysis'],
    owasp: ['A07:2021 Identification and Authentication Failures'],
    cvss: { score: 8.8, severity: 'High', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L' }
  },
  'frequency-spike': {
    ioc: ['Event rate exceeding 2× standard deviation above the baseline', 'Sudden burst concentrated in a short window'],
    impact: 'An abnormal surge in activity — often automated abuse (brute force, scanning, flooding) rather than normal user behavior.',
    mitigation: ['Identify the source(s) driving the spike', 'Rate-limit or block abusive sources', 'Correlate with rule-based alerts in the same window', 'Tune baselines to reduce noise'],
    nist: ['DE.AE-2 Event analysis', 'DE.CM-1 Network monitoring', 'DE.AE-5 Incident alert thresholds'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 5.3, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }
  },
  'off-hours': {
    ioc: ['Activity during historically low-traffic hours', 'Sessions outside the user\'s normal pattern'],
    impact: 'Off-hours activity can indicate an attacker operating when defenders are least likely to notice.',
    mitigation: ['Verify whether the activity is authorized', 'Alert on privileged actions outside business hours', 'Enforce time-based access controls where feasible'],
    nist: ['DE.CM-3 Personnel activity monitoring', 'DE.AE-2 Event analysis'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 4.3, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N' }
  },
  'volume-anomaly': {
    ioc: ['Log entries far larger than the norm', 'Oversized requests or responses'],
    impact: 'Unusual payload sizes can signal exfiltration, injection of large payloads, or buffer-related abuse.',
    mitigation: ['Inspect the oversized entries', 'Set size limits on requests/uploads', 'Correlate with egress monitoring'],
    nist: ['DE.AE-2 Event analysis', 'PR.DS-5 Protections against data leaks'],
    owasp: ['A09:2021 Security Logging and Monitoring Failures'],
    cvss: { score: 4.0, severity: 'Medium', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L' }
  }
};
