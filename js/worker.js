/* worker.js -- Web Worker for background log parsing & detection (LogSight)
 * Receives messages via postMessage, replies via postMessage.
 *
 * Messages IN:
 *   { type: 'parse',  id, data: { text: string, filename: string } }
 *   { type: 'detect', id, data: { lines: parsedLine[] } }
 *
 * Messages OUT:
 *   { type: 'progress',     id, percent: 0-100 }
 *   { type: 'parseResult',  id, result: { filename, lines, startDate, endDate, lineCount } }
 *   { type: 'detectResult', id, result: { alerts: [...] } }
 */

/* eslint-disable no-restricted-globals */
self.onmessage = function (e) {
  var msg = e.data;
  if (!msg || !msg.type) return;

  if (msg.type === 'parse')  return handleParse(msg.id, msg.data);
  if (msg.type === 'detect') return handleDetect(msg.id, msg.data);
};


/* ====================================================================
 *  PARSE
 * ==================================================================== */

function handleParse(id, data) {
  var text     = data.text || '';
  var filename = data.filename || '';

  var rawLines = text.split(/\r?\n/);
  var total    = rawLines.length;
  var parsed   = [];
  var startDate = null;
  var endDate   = null;

  var lastProgress = 0;

  for (var i = 0; i < total; i++) {
    var raw = rawLines[i];
    if (raw === '') continue;

    var line = parseLine(raw, i + 1, filename);
    parsed.push(line);

    if (line.timestamp) {
      if (!startDate || line.timestamp < startDate) startDate = line.timestamp;
      if (!endDate   || line.timestamp > endDate)   endDate   = line.timestamp;
    }

    // Progress every 10%
    var pct = Math.floor(((i + 1) / total) * 100);
    if (pct >= lastProgress + 10) {
      lastProgress = pct;
      self.postMessage({ type: 'progress', id: id, percent: pct });
    }
  }

  self.postMessage({
    type: 'parseResult',
    id: id,
    result: {
      filename:  filename,
      lines:     parsed,
      startDate: startDate,
      endDate:   endDate,
      lineCount: parsed.length
    }
  });
}


/* ------------------------------------------------------------------
 *  Line parser — self-contained (mirrors log-parser.js essentials)
 * ------------------------------------------------------------------ */

// Timestamp patterns (order matters — more specific first)
var TS_PATTERNS = [
  // ISO 8601  2026-06-21T14:30:00.123Z  or  2026-06-21 14:30:00,123
  {
    re: /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/,
    parse: function (m) { return new Date(m[1].replace(',', '.')); }
  },
  // Syslog BSD  Jun 21 03:14:01
  {
    re: /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,
    parse: function (m) {
      var now = new Date();
      var str = m[1] + ' ' + now.getFullYear();
      var d = new Date(str);
      // If parsed date is > 1 day in the future, assume previous year
      if (d.getTime() > now.getTime() + 86400000) {
        d.setFullYear(d.getFullYear() - 1);
      }
      return isNaN(d.getTime()) ? null : d;
    }
  },
  // Common Log Format  21/Jun/2026:14:30:00 +0000
  {
    re: /(\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})/,
    parse: function (m) {
      var s = m[1]
        .replace(/\//g, ' ')
        .replace(':', ' ');  // first colon between date and time
      return new Date(s);
    }
  },
  // Unix epoch seconds  1750000000  or  1750000000.123
  {
    re: /\b(1[4-9]\d{8}(?:\.\d+)?)\b/,
    parse: function (m) { return new Date(parseFloat(m[1]) * 1000); }
  },
  // Windows Event  06/21/2026 14:30:00
  {
    re: /(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})/,
    parse: function (m) { return new Date(m[1]); }
  }
];

// Severity patterns
var SEV_PATTERNS = [
  { re: /\b(EMERG|EMERGENCY)\b/i,  level: 'emergency' },
  { re: /\b(ALERT)\b/i,            level: 'alert' },
  { re: /\b(CRIT|CRITICAL)\b/i,    level: 'critical' },
  { re: /\b(FATAL)\b/i,            level: 'fatal' },
  { re: /\b(ERR|ERROR)\b/i,        level: 'error' },
  { re: /\b(WARN|WARNING)\b/i,     level: 'warning' },
  { re: /\b(NOTICE)\b/i,           level: 'notice' },
  { re: /\b(INFO)\b/i,             level: 'info' },
  { re: /\b(DEBUG|TRACE)\b/i,      level: 'debug' }
];

// Implicit severity keywords (when no explicit level tag)
var IMPLICIT_SEV = [
  { re: /\bfailed\b/i,               level: 'warning' },
  { re: /\bdenied\b/i,               level: 'warning' },
  { re: /\btimeout\b/i,              level: 'warning' },
  { re: /\brefused\b/i,              level: 'warning' },
  { re: /\bsegfault\b/i,             level: 'critical' },
  { re: /\bpanic\b/i,                level: 'critical' },
  { re: /\bout of memory\b/i,        level: 'critical' },
  { re: /\bkilled\b/i,               level: 'error' },
  { re: /\bcannot\b/i,               level: 'warning' }
];

function parseLine(raw, num, filename) {
  var timestamp = null;
  var severity  = 'info';

  // Extract timestamp
  for (var t = 0; t < TS_PATTERNS.length; t++) {
    var tm = raw.match(TS_PATTERNS[t].re);
    if (tm) {
      var d = TS_PATTERNS[t].parse(tm);
      if (d && !isNaN(d.getTime())) {
        timestamp = d;
        break;
      }
    }
  }

  // Extract severity — explicit first
  var foundExplicit = false;
  for (var s = 0; s < SEV_PATTERNS.length; s++) {
    if (SEV_PATTERNS[s].re.test(raw)) {
      severity = SEV_PATTERNS[s].level;
      foundExplicit = true;
      break;
    }
  }

  // Fall back to implicit severity
  if (!foundExplicit) {
    for (var k = 0; k < IMPLICIT_SEV.length; k++) {
      if (IMPLICIT_SEV[k].re.test(raw)) {
        severity = IMPLICIT_SEV[k].level;
        break;
      }
    }
  }

  return {
    num:       num,
    raw:       raw,
    timestamp: timestamp,
    severity:  severity,
    source:    filename
  };
}


/* ====================================================================
 *  DETECT — Layer 1 rule-based detection
 * ==================================================================== */

var DETECTION_RULES = [
  /* ---- Authentication ---- */
  {
    id: 'BRUTE_FORCE',
    name: 'Brute Force Attempt',
    description: 'Multiple failed authentication attempts from the same source in a short window.',
    severity: 'high',
    mitre: 'T1110',
    match: function (lines) {
      return windowCounter(lines, /failed\s+(password|login|auth)/i, 'ip', 10, 300);
    }
  },
  {
    id: 'SUCCESSFUL_AFTER_FAILURES',
    name: 'Successful Login After Failures',
    description: 'Successful login from an IP that previously had multiple failures — possible credential compromise.',
    severity: 'critical',
    mitre: 'T1078',
    match: function (lines) {
      var failIps = {};
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var ip = extractIP(line.raw);
        if (!ip) continue;
        if (/failed\s+(password|login|auth)/i.test(line.raw)) {
          failIps[ip] = (failIps[ip] || 0) + 1;
        }
        if (/accepted\s+(password|publickey|login)/i.test(line.raw) && failIps[ip] >= 3) {
          alerts.push({
            lineNum: line.num,
            evidence: 'Successful login from ' + ip + ' after ' + failIps[ip] + ' failures',
            source: line.source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Privilege Escalation ---- */
  {
    id: 'PRIV_ESCALATION',
    name: 'Privilege Escalation Indicator',
    description: 'Suspicious sudo or su usage, especially accessing sensitive files or running shells.',
    severity: 'high',
    mitre: 'T1548',
    match: function (lines) {
      var suspicious = /sudo:.*COMMAND=.*(\/bin\/sh|\/bin\/bash|\/etc\/shadow|\/etc\/passwd|chmod\s+[47]\d\d|chown\s+root|visudo|useradd|usermod)/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (suspicious.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Payload Delivery ---- */
  {
    id: 'REMOTE_DOWNLOAD',
    name: 'Remote Payload Download',
    description: 'wget, curl, or similar tool downloading from an external source.',
    severity: 'high',
    mitre: 'T1105',
    match: function (lines) {
      var dlPattern = /\b(wget|curl|fetch|python.*urllib|powershell.*downloadstring|invoke-webrequest|certutil.*urlcache)\b/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (dlPattern.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Persistence ---- */
  {
    id: 'CRON_PERSISTENCE',
    name: 'Cron Job Persistence',
    description: 'Cron job executing a script from /tmp or a non-standard location.',
    severity: 'medium',
    mitre: 'T1053.003',
    match: function (lines) {
      var cronTmp = /CRON.*CMD.*(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (cronTmp.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Web Attacks ---- */
  {
    id: 'SQL_INJECTION',
    name: 'SQL Injection Attempt',
    description: 'HTTP request containing SQL injection patterns.',
    severity: 'high',
    mitre: 'T1190',
    match: function (lines) {
      var sqli = /('|%27)(\s|%20)*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)(\s|%20)/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (sqli.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },
  {
    id: 'WEB_SHELL',
    name: 'Web Shell Indicator',
    description: 'HTTP request to a known web shell path or suspicious file upload.',
    severity: 'critical',
    mitre: 'T1505.003',
    match: function (lines) {
      var shell = /\/(c99|r57|b374k|wso|china\s*chopper|cmd|eval|shell|backdoor)\.(php|asp|aspx|jsp|cgi)\b/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (shell.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },
  {
    id: 'DIRECTORY_TRAVERSAL',
    name: 'Directory Traversal Attempt',
    description: 'Request containing path traversal sequences.',
    severity: 'medium',
    mitre: 'T1083',
    match: function (lines) {
      var traversal = /(\.\.[\/\\]){2,}|(%2e%2e[\/\\%]){2,}/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (traversal.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- DNS / Exfiltration ---- */
  {
    id: 'DNS_EXFIL',
    name: 'DNS Exfiltration Indicator',
    description: 'Unusually long DNS query labels that may encode exfiltrated data.',
    severity: 'high',
    mitre: 'T1048',
    match: function (lines) {
      // DNS labels longer than 50 chars or total query > 100 chars
      var longQuery = /query.*?([a-z0-9]{50,})\./i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (longQuery.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- System ---- */
  {
    id: 'SEGFAULT',
    name: 'Segmentation Fault',
    description: 'Process crash via segfault — may indicate exploitation or memory corruption.',
    severity: 'high',
    mitre: 'T1203',
    match: function (lines) {
      var segfault = /\bsegfault\b|segmentation\s+fault/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (segfault.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },
  {
    id: 'OOM_KILL',
    name: 'Out-of-Memory Kill',
    description: 'Kernel killed a process due to memory pressure.',
    severity: 'high',
    mitre: 'T1499',
    match: function (lines) {
      var oom = /out\s+of\s+memory|oom[_-]kill|killed\s+process/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (oom.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Lateral Movement ---- */
  {
    id: 'LATERAL_RDP',
    name: 'Lateral Movement via RDP',
    description: 'Windows Event 4624 Type 10 logon indicating RDP access.',
    severity: 'high',
    mitre: 'T1021.001',
    match: function (lines) {
      var rdp = /event\s*(id)?[:\s]*4624.*logon\s*type[:\s]*10/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (rdp.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  },

  /* ---- Crypto Mining ---- */
  {
    id: 'CRYPTO_MINING',
    name: 'Crypto Mining Indicator',
    description: 'Connection to known mining pools or mining-related process activity.',
    severity: 'medium',
    mitre: 'T1496',
    match: function (lines) {
      var mining = /\b(stratum\+tcp|xmrig|minerd|coinhive|cryptonight|nanopool|hashvault|mining[_-]?pool|monero.*pool)\b/i;
      var alerts = [];
      for (var i = 0; i < lines.length; i++) {
        if (mining.test(lines[i].raw)) {
          alerts.push({
            lineNum: lines[i].num,
            evidence: lines[i].raw.substring(0, 200),
            source: lines[i].source
          });
        }
      }
      return alerts;
    }
  }
];


/* ------------------------------------------------------------------
 *  Detection runner
 * ------------------------------------------------------------------ */
function handleDetect(id, data) {
  var lines  = data.lines || [];
  var alerts = [];
  var total  = DETECTION_RULES.length;
  var lastProgress = 0;

  for (var r = 0; r < total; r++) {
    var rule = DETECTION_RULES[r];
    var matches = [];

    try {
      matches = rule.match(lines);
    } catch (_) {
      // Rule failed — skip silently
    }

    if (matches && matches.length > 0) {
      alerts.push({
        ruleId:      rule.id,
        name:        rule.name,
        description: rule.description,
        severity:    rule.severity,
        mitre:       rule.mitre,
        matchCount:  matches.length,
        matches:     matches.slice(0, 50)  // cap detail to avoid huge payloads
      });
    }

    // Progress
    var pct = Math.floor(((r + 1) / total) * 100);
    if (pct >= lastProgress + 10) {
      lastProgress = pct;
      self.postMessage({ type: 'progress', id: id, percent: pct });
    }
  }

  self.postMessage({
    type: 'detectResult',
    id: id,
    result: { alerts: alerts }
  });
}


/* ------------------------------------------------------------------
 *  Helper: extract first IPv4 address from a string
 * ------------------------------------------------------------------ */
function extractIP(str) {
  var m = str.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  return m ? m[1] : null;
}


/* ------------------------------------------------------------------
 *  Helper: sliding-window counter for repeated pattern matches
 *  Used by brute-force detection.
 *
 *  Returns alerts when the same grouping key (e.g. source IP)
 *  triggers the pattern >= threshold times within windowSec seconds.
 * ------------------------------------------------------------------ */
function windowCounter(lines, pattern, groupBy, threshold, windowSec) {
  // Collect hits grouped by key
  var groups = {};  // key -> [{lineNum, timestamp}]
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!pattern.test(line.raw)) continue;

    var key;
    if (groupBy === 'ip') {
      key = extractIP(line.raw);
      if (!key) continue;
    } else {
      key = '_all';
    }

    if (!groups[key]) groups[key] = [];
    groups[key].push({ lineNum: line.num, ts: line.timestamp, source: line.source });
  }

  var alerts = [];
  var keys = Object.keys(groups);
  for (var k = 0; k < keys.length; k++) {
    var hits = groups[keys[k]];
    if (hits.length < threshold) continue;

    // Check if threshold hits fit within the window
    // Sort by timestamp
    hits.sort(function (a, b) {
      if (!a.ts || !b.ts) return 0;
      return a.ts - b.ts;
    });

    for (var j = 0; j <= hits.length - threshold; j++) {
      var first = hits[j];
      var last  = hits[j + threshold - 1];
      if (!first.ts || !last.ts) continue;

      var diffSec = (last.ts.getTime() - first.ts.getTime()) / 1000;
      if (diffSec <= windowSec) {
        alerts.push({
          lineNum:  first.lineNum,
          evidence: hits.length + ' matches from ' + keys[k] + ' within ' + Math.round(diffSec) + 's',
          source:   first.source
        });
        break; // one alert per group
      }
    }
  }

  return alerts;
}
