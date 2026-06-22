// =============================================================================
// LogSight - Security Framework Reference Data
// =============================================================================
// Global reference data for MITRE ATT&CK, NIST CSF, and OWASP Top 10.
// Used by intelligence reports, framework tagging, and the Learn mode.
// =============================================================================

var FRAMEWORKS = {

  // ===========================================================================
  // MITRE ATT&CK Techniques
  // ===========================================================================
  mitre: {
    // --- Reconnaissance ---
    'T1595': {
      name: 'Active Scanning',
      tactic: 'Reconnaissance',
      url: 'https://attack.mitre.org/techniques/T1595/'
    },
    'T1595.002': {
      name: 'Active Scanning: Vulnerability Scanning',
      tactic: 'Reconnaissance',
      url: 'https://attack.mitre.org/techniques/T1595/002/'
    },
    'T1592': {
      name: 'Gather Victim Host Information',
      tactic: 'Reconnaissance',
      url: 'https://attack.mitre.org/techniques/T1592/'
    },

    // --- Initial Access ---
    'T1190': {
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1190/'
    },
    'T1566': {
      name: 'Phishing',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1566/'
    },
    'T1566.001': {
      name: 'Phishing: Spearphishing Attachment',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1566/001/'
    },
    'T1566.002': {
      name: 'Phishing: Spearphishing Link',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1566/002/'
    },
    'T1078': {
      name: 'Valid Accounts',
      tactic: 'Persistence, Defense Evasion, Initial Access',
      url: 'https://attack.mitre.org/techniques/T1078/'
    },
    'T1133': {
      name: 'External Remote Services',
      tactic: 'Persistence, Initial Access',
      url: 'https://attack.mitre.org/techniques/T1133/'
    },
    'T1199': {
      name: 'Trusted Relationship',
      tactic: 'Initial Access',
      url: 'https://attack.mitre.org/techniques/T1199/'
    },

    // --- Execution ---
    'T1059': {
      name: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1059/'
    },
    'T1059.001': {
      name: 'Command and Scripting Interpreter: PowerShell',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1059/001/'
    },
    'T1059.003': {
      name: 'Command and Scripting Interpreter: Windows Command Shell',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1059/003/'
    },
    'T1059.004': {
      name: 'Command and Scripting Interpreter: Unix Shell',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1059/004/'
    },
    'T1204': {
      name: 'User Execution',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1204/'
    },
    'T1204.002': {
      name: 'User Execution: Malicious File',
      tactic: 'Execution',
      url: 'https://attack.mitre.org/techniques/T1204/002/'
    },

    // --- Persistence ---
    'T1053': {
      name: 'Scheduled Task/Job',
      tactic: 'Persistence, Execution',
      url: 'https://attack.mitre.org/techniques/T1053/'
    },
    'T1053.003': {
      name: 'Scheduled Task/Job: Cron',
      tactic: 'Persistence, Execution',
      url: 'https://attack.mitre.org/techniques/T1053/003/'
    },
    'T1053.005': {
      name: 'Scheduled Task/Job: Scheduled Task',
      tactic: 'Persistence, Execution',
      url: 'https://attack.mitre.org/techniques/T1053/005/'
    },
    'T1505.003': {
      name: 'Server Software Component: Web Shell',
      tactic: 'Persistence',
      url: 'https://attack.mitre.org/techniques/T1505/003/'
    },
    'T1098': {
      name: 'Account Manipulation',
      tactic: 'Persistence',
      url: 'https://attack.mitre.org/techniques/T1098/'
    },
    'T1136': {
      name: 'Create Account',
      tactic: 'Persistence',
      url: 'https://attack.mitre.org/techniques/T1136/'
    },
    'T1543.002': {
      name: 'Create or Modify System Process: Systemd Service',
      tactic: 'Persistence, Privilege Escalation',
      url: 'https://attack.mitre.org/techniques/T1543/002/'
    },

    // --- Privilege Escalation ---
    'T1548': {
      name: 'Abuse Elevation Control Mechanism',
      tactic: 'Privilege Escalation, Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1548/'
    },
    'T1548.003': {
      name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
      tactic: 'Privilege Escalation, Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1548/003/'
    },
    'T1068': {
      name: 'Exploitation for Privilege Escalation',
      tactic: 'Privilege Escalation',
      url: 'https://attack.mitre.org/techniques/T1068/'
    },

    // --- Defense Evasion ---
    'T1070': {
      name: 'Indicator Removal',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1070/'
    },
    'T1070.001': {
      name: 'Indicator Removal: Clear Windows Event Logs',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1070/001/'
    },
    'T1070.002': {
      name: 'Indicator Removal: Clear Linux or Mac System Logs',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1070/002/'
    },
    'T1027': {
      name: 'Obfuscated Files or Information',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1027/'
    },
    'T1562.001': {
      name: 'Impair Defenses: Disable or Modify Tools',
      tactic: 'Defense Evasion',
      url: 'https://attack.mitre.org/techniques/T1562/001/'
    },

    // --- Credential Access ---
    'T1110': {
      name: 'Brute Force',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/'
    },
    'T1110.001': {
      name: 'Brute Force: Password Guessing',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/001/'
    },
    'T1110.003': {
      name: 'Brute Force: Password Spraying',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1110/003/'
    },
    'T1003': {
      name: 'OS Credential Dumping',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1003/'
    },
    'T1003.008': {
      name: 'OS Credential Dumping: /etc/passwd and /etc/shadow',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1003/008/'
    },
    'T1552': {
      name: 'Unsecured Credentials',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1552/'
    },
    'T1552.001': {
      name: 'Unsecured Credentials: Credentials In Files',
      tactic: 'Credential Access',
      url: 'https://attack.mitre.org/techniques/T1552/001/'
    },

    // --- Discovery ---
    'T1083': {
      name: 'File and Directory Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1083/'
    },
    'T1082': {
      name: 'System Information Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1082/'
    },
    'T1049': {
      name: 'System Network Connections Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1049/'
    },
    'T1016': {
      name: 'System Network Configuration Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1016/'
    },
    'T1087': {
      name: 'Account Discovery',
      tactic: 'Discovery',
      url: 'https://attack.mitre.org/techniques/T1087/'
    },

    // --- Lateral Movement ---
    'T1021': {
      name: 'Remote Services',
      tactic: 'Lateral Movement',
      url: 'https://attack.mitre.org/techniques/T1021/'
    },
    'T1021.004': {
      name: 'Remote Services: SSH',
      tactic: 'Lateral Movement',
      url: 'https://attack.mitre.org/techniques/T1021/004/'
    },
    'T1021.001': {
      name: 'Remote Services: Remote Desktop Protocol',
      tactic: 'Lateral Movement',
      url: 'https://attack.mitre.org/techniques/T1021/001/'
    },

    // --- Collection ---
    'T1005': {
      name: 'Data from Local System',
      tactic: 'Collection',
      url: 'https://attack.mitre.org/techniques/T1005/'
    },
    'T1560': {
      name: 'Archive Collected Data',
      tactic: 'Collection',
      url: 'https://attack.mitre.org/techniques/T1560/'
    },

    // --- Command and Control ---
    'T1071': {
      name: 'Application Layer Protocol',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1071/'
    },
    'T1071.001': {
      name: 'Application Layer Protocol: Web Protocols',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1071/001/'
    },
    'T1071.004': {
      name: 'Application Layer Protocol: DNS',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1071/004/'
    },
    'T1105': {
      name: 'Ingress Tool Transfer',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1105/'
    },
    'T1573': {
      name: 'Encrypted Channel',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1573/'
    },
    'T1572': {
      name: 'Protocol Tunneling',
      tactic: 'Command and Control',
      url: 'https://attack.mitre.org/techniques/T1572/'
    },

    // --- Exfiltration ---
    'T1041': {
      name: 'Exfiltration Over C2 Channel',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1041/'
    },
    'T1048': {
      name: 'Exfiltration Over Alternative Protocol',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1048/'
    },
    'T1048.001': {
      name: 'Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1048/001/'
    },
    'T1567': {
      name: 'Exfiltration Over Web Service',
      tactic: 'Exfiltration',
      url: 'https://attack.mitre.org/techniques/T1567/'
    },

    // --- Impact ---
    'T1486': {
      name: 'Data Encrypted for Impact',
      tactic: 'Impact',
      url: 'https://attack.mitre.org/techniques/T1486/'
    },
    'T1489': {
      name: 'Service Stop',
      tactic: 'Impact',
      url: 'https://attack.mitre.org/techniques/T1489/'
    },
    'T1529': {
      name: 'System Shutdown/Reboot',
      tactic: 'Impact',
      url: 'https://attack.mitre.org/techniques/T1529/'
    }
  },

  // ===========================================================================
  // NIST Cybersecurity Framework (CSF) Functions & Categories
  // ===========================================================================
  nist: {
    // Identify
    'ID.AM-1': 'Physical devices and systems are inventoried',
    'ID.AM-2': 'Software platforms and applications are inventoried',
    'ID.AM-5': 'Resources are prioritized based on classification and business value',
    'ID.RA-1': 'Asset vulnerabilities are identified and documented',
    'ID.RA-5': 'Threats, vulnerabilities, likelihoods, and impacts are used to determine risk',

    // Protect
    'PR.AC-1': 'Identities and credentials are issued, managed, verified, revoked, and audited',
    'PR.AC-4': 'Access permissions and authorizations are managed with least privilege',
    'PR.AC-7': 'Users, devices, and other assets are authenticated commensurate with risk',
    'PR.DS-1': 'Data-at-rest is protected',
    'PR.DS-2': 'Data-in-transit is protected',
    'PR.DS-5': 'Protections against data leaks are implemented',
    'PR.IP-1': 'Baseline configuration of IT systems is established and maintained',
    'PR.IP-12': 'A vulnerability management plan is developed and implemented',
    'PR.PT-4': 'Communications and control networks are protected',

    // Detect
    'DE.AE-2': 'Detected events are analyzed to understand attack targets and methods',
    'DE.AE-3': 'Event data are collected and correlated from multiple sources',
    'DE.CM-1': 'The network is monitored to detect potential cybersecurity events',
    'DE.CM-4': 'Malicious code is detected',
    'DE.CM-7': 'Monitoring for unauthorized personnel, connections, devices, and software',
    'DE.CM-8': 'Vulnerability scans are performed',

    // Respond
    'RS.AN-1': 'Notifications from detection systems are investigated',
    'RS.AN-2': 'The impact of the incident is understood',
    'RS.MI-1': 'Incidents are contained',
    'RS.MI-2': 'Incidents are mitigated',
    'RS.RP-1': 'Response plan is executed during or after an incident',

    // Recover
    'RC.RP-1': 'Recovery plan is executed during or after a cybersecurity incident',
    'RC.IM-1': 'Recovery plans incorporate lessons learned'
  },

  // ===========================================================================
  // OWASP Top 10 (2021)
  // ===========================================================================
  owasp: {
    'A01:2021': {
      name: 'Broken Access Control',
      description: 'Failures in enforcing policy such that users can act outside their intended permissions. Includes unauthorized access to other users\' accounts, viewing sensitive data, and modifying access rights.',
      url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
    },
    'A02:2021': {
      name: 'Cryptographic Failures',
      description: 'Failures related to cryptography which often lead to sensitive data exposure. Includes use of weak algorithms, insufficient key management, and transmitting data in cleartext.',
      url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    },
    'A03:2021': {
      name: 'Injection',
      description: 'User-supplied data is not validated, filtered, or sanitized by the application. Includes SQL injection, NoSQL injection, OS command injection, and LDAP injection.',
      url: 'https://owasp.org/Top10/A03_2021-Injection/'
    },
    'A04:2021': {
      name: 'Insecure Design',
      description: 'A broad category representing design and architectural flaws. Focuses on risks related to missing or ineffective security controls and business logic flaws.',
      url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/'
    },
    'A05:2021': {
      name: 'Security Misconfiguration',
      description: 'Missing or misconfigured security hardening across the application stack. Includes unnecessary features enabled, default accounts unchanged, and overly permissive cloud permissions.',
      url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    },
    'A06:2021': {
      name: 'Vulnerable and Outdated Components',
      description: 'Using components with known vulnerabilities or that are unsupported. Includes libraries, frameworks, and other software modules running with known CVEs.',
      url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
    },
    'A07:2021': {
      name: 'Identification and Authentication Failures',
      description: 'Weaknesses in authentication mechanisms. Includes permitting brute-force attacks, weak passwords, improper session management, and missing multi-factor authentication.',
      url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
    },
    'A08:2021': {
      name: 'Software and Data Integrity Failures',
      description: 'Code and infrastructure that does not protect against integrity violations. Includes insecure CI/CD pipelines, auto-update without integrity verification, and insecure deserialization.',
      url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
    },
    'A09:2021': {
      name: 'Security Logging and Monitoring Failures',
      description: 'Insufficient logging, detection, monitoring, and active response. Without proper logging and monitoring, breaches cannot be detected or responded to in a timely manner.',
      url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
    },
    'A10:2021': {
      name: 'Server-Side Request Forgery (SSRF)',
      description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. Allows attackers to coerce the application to send requests to unexpected destinations.',
      url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'
    }
  }

};
