/**
 * Detection — Rule-based and statistical anomaly detection engine.
 * Part of the LogSight project.
 *
 * Layer 1: Pattern-matching rules with thresholds and MITRE ATT&CK tags.
 * Layer 2: Statistical baseline and anomaly detection.
 */
const Detection = (function () {
  'use strict';

  // Severity ordering for sorting alerts
  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  // ───────────────────────────────────────────────────────────────────────
  // Layer 1 — Rule-based detection
  // ───────────────────────────────────────────────────────────────────────

  var rules = [
    {
      id: 'ssh-bruteforce',
      name: 'SSH Brute Force',
      severity: 'high',
      pattern: /Failed password.*sshd/i,
      threshold: 10,
      groupBy: 'source_ip',
      mitre: ['T1110.001'],
      description: 'Multiple failed SSH password attempts detected, indicating a potential brute force attack against SSH authentication.'
    },
    {
      id: 'ssh-success-after-fail',
      name: 'Successful Login After Failed Burst',
      severity: 'critical',
      pattern: /Accepted\s+(password|publickey)\s+for/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1110.001', 'T1078'],
      description: 'A successful SSH login occurred following a burst of failed attempts, which may indicate a completed brute force compromise.'
    },
    {
      id: 'webshell-access',
      name: 'Web Shell Detection',
      severity: 'critical',
      pattern: /(?:cmd\s*=|eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|phpinfo\s*\()/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1505.003'],
      description: 'HTTP request contains parameters commonly associated with web shell command execution (cmd=, eval, system).'
    },
    {
      id: 'sqli-attempt',
      name: 'SQL Injection Attempt',
      severity: 'high',
      pattern: /(?:union\s+select|'\s*or\s+['"]?\d|'\s*or\s+1\s*=\s*1|;\s*drop\s+table|--\s*$|\/\*.*\*\/|benchmark\s*\(|sleep\s*\()/i,
      threshold: 3,
      groupBy: 'source_ip',
      mitre: ['T1190'],
      description: 'HTTP requests contain patterns consistent with SQL injection probing (UNION SELECT, OR 1=1, comment sequences).'
    },
    {
      id: 'xss-attempt',
      name: 'Cross-Site Scripting (XSS) Attempt',
      severity: 'medium',
      pattern: /(?:<script|onerror\s*=|onload\s*=|javascript\s*:|<img[^>]+onerror|<svg[^>]+onload|document\.cookie|alert\s*\()/i,
      threshold: 3,
      groupBy: 'source_ip',
      mitre: ['T1189'],
      description: 'HTTP requests contain XSS payload patterns such as <script> tags, event handlers, or javascript: URIs.'
    },
    {
      id: 'path-traversal',
      name: 'Path Traversal Attempt',
      severity: 'high',
      pattern: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|\/etc\/passwd|\/etc\/shadow|\/proc\/self)/i,
      threshold: 3,
      groupBy: 'source_ip',
      mitre: ['T1083'],
      description: 'Requests contain directory traversal sequences (../) or attempts to access sensitive system files.'
    },
    {
      id: 'directory-bruteforce',
      name: 'Directory Brute Force (404 Burst)',
      severity: 'medium',
      pattern: /"\s*(?:GET|POST|PUT|HEAD)\s+\S+\s+HTTP\/\S+"\s+404/i,
      threshold: 50,
      groupBy: 'source_ip',
      mitre: ['T1595.003'],
      description: 'A high volume of HTTP 404 responses from a single source indicates automated directory or file enumeration.'
    },
    {
      id: 'suspicious-sudo',
      name: 'Suspicious Sudo Usage',
      severity: 'high',
      pattern: /sudo:\s+\S+\s*:\s*(?:command not allowed|NOT in sudoers|3 incorrect password attempts|authentication failure)/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1548.003'],
      description: 'Sudo authentication failures or unauthorized sudo attempts detected, potentially indicating privilege escalation probing.'
    },
    {
      id: 'cron-modification',
      name: 'Cron Job Modification',
      severity: 'medium',
      pattern: /(?:crontab\[\d+\]:\s*\(.*\)\s*(?:REPLACE|LIST|BEGIN EDIT|END EDIT)|\/etc\/cron|CROND\[\d+\]:\s*\(.*\)\s*CMD)/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1053.003'],
      description: 'Cron table modifications detected, which could indicate persistence establishment through scheduled tasks.'
    },
    {
      id: 'large-outbound-transfer',
      name: 'Large Outbound Data Transfer',
      severity: 'medium',
      pattern: /(?:bytes_sent|out_bytes|upload|transferred)\s*[=:]\s*\d{7,}/i,
      matchLine: isLargeOutboundTransfer,
      threshold: 3,
      groupBy: null,
      mitre: ['T1048'],
      description: 'Unusually large outbound data transfers detected, possibly indicating data exfiltration.'
    },
    {
      id: 'dns-tunneling',
      name: 'DNS Tunneling Indicator',
      severity: 'high',
      pattern: /query(?:\[\w+\])?:\s+([a-zA-Z0-9\-]{40,})\./i,
      threshold: 5,
      groupBy: null,
      mitre: ['T1071.004'],
      description: 'DNS queries with abnormally long subdomain labels detected, a common indicator of DNS tunneling for data exfiltration or C2.'
    },
    {
      id: 'port-scan',
      name: 'Port Scan Indicator',
      severity: 'medium',
      pattern: /(?:SYN\s+(?:scan|flood)|connection\s+refused|reset\s+by\s+peer|port\s+\d+\s+unreachable|UFW\s+BLOCK)/i,
      threshold: 20,
      groupBy: 'source_ip',
      mitre: ['T1046'],
      description: 'Multiple connection attempts to different ports from the same source, consistent with network port scanning.'
    },
    {
      id: 'privilege-escalation-su',
      name: 'Privilege Escalation via su',
      severity: 'high',
      pattern: /(?:su\[\d+\]:\s*(?:FAILED|BAD)\s+SU|su:\s*(?:authentication failure|FAILED su for))/i,
      threshold: 3,
      groupBy: null,
      mitre: ['T1548.003'],
      description: 'Failed su (switch user) attempts detected, potentially indicating privilege escalation attempts.'
    },
    {
      id: 'sensitive-file-access',
      name: 'Unauthorized Sensitive File Access',
      severity: 'high',
      pattern: /(?:\/etc\/shadow|\/etc\/gshadow|\/etc\/sudoers|\.ssh\/authorized_keys|\.ssh\/id_rsa|\.bash_history)/,
      threshold: 1,
      groupBy: null,
      mitre: ['T1003.008', 'T1552.004'],
      description: 'Access to sensitive system files (shadow, sudoers, SSH keys) detected, which may indicate credential harvesting.'
    },
    {
      id: 'reverse-shell',
      name: 'Reverse Shell Indicator',
      severity: 'critical',
      pattern: /(?:nc\s+-[^l]*e\s|ncat\s.*-e\s|bash\s+-i\s+>|\/dev\/tcp\/|mkfifo\s+.*nc\s|python.*socket.*connect|perl.*socket.*INET)/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1059', 'T1071.001'],
      description: 'Command patterns consistent with reverse shell establishment detected (nc -e, bash -i redirect, /dev/tcp).'
    },
    {
      id: 'user-enumeration',
      name: 'User Enumeration',
      severity: 'medium',
      pattern: /(?:invalid user|no such user|user unknown|illegal user)\s+\S+/i,
      threshold: 10,
      groupBy: 'source_ip',
      mitre: ['T1087'],
      description: 'Multiple attempts to authenticate as non-existent users, indicating username enumeration activity.'
    },
    {
      id: 'log-tampering',
      name: 'Log Tampering Indicator',
      severity: 'critical',
      pattern: /(?:rsyslog.*stop|rm\s+.*\/var\/log|truncate\s+.*\.log|>\s*\/var\/log|history\s+-c|unset\s+HISTFILE)/i,
      threshold: 1,
      groupBy: null,
      mitre: ['T1070.002'],
      description: 'Commands associated with log deletion or history clearing detected, suggesting anti-forensics activity.'
    },
    {
      id: 'suspicious-user-agent',
      name: 'Suspicious User Agent',
      severity: 'low',
      pattern: /(?:User-Agent|"(?:GET|POST|PUT|HEAD).*HTTP).*(?:sqlmap|nikto|nmap|dirbuster|gobuster|masscan|wpscan|burp|ZAP|havij)/i,
      threshold: 1,
      groupBy: 'source_ip',
      mitre: ['T1595'],
      description: 'HTTP requests with user agent strings matching known offensive security tools (sqlmap, nikto, nmap, etc.).'
    }
  ];

  /**
   * Extract an IPv4 address from a log line.
   * @param {string} text - Log line text.
   * @returns {string|null} First IPv4 address found, or null.
   */
  function extractIP(text) {
    var m = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.exec(text);
    return m ? m[1] : null;
  }

  function splitCsvLine(text) {
    var fields = [];
    var cur = '';
    var quoted = false;

    for (var i = 0; i < text.length; i++) {
      var ch = text.charAt(i);
      if (ch === '"') {
        if (quoted && text.charAt(i + 1) === '"') {
          cur += '"';
          i++;
        } else {
          quoted = !quoted;
        }
      } else if (ch === ',' && !quoted) {
        fields.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    fields.push(cur);
    return fields;
  }

  function parsePanOsTrafficBytes(text) {
    var marker = /(?:^|\s)(\d+,\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2},[^,]*,TRAFFIC,)/.exec(text);
    if (!marker) return null;

    var payload = text.slice(marker.index + (marker[0].charAt(0) === ' ' ? 1 : 0));
    var fields = splitCsvLine(payload);
    if (fields.length < 32 || fields[3] !== 'TRAFFIC') return null;

    return {
      bytes: parseInt(fields[30], 10) || 0,
      bytesSent: parseInt(fields[31], 10) || 0,
      bytesReceived: parseInt(fields[32], 10) || 0
    };
  }

  function isLargeOutboundTransfer(text) {
    if (!text) return false;

    if (/(?:bytes_sent|out_bytes|upload|transferred)\s*[=:]\s*\d{7,}/i.test(text)) {
      return true;
    }

    // CEF commonly uses "out" for outbound bytes; some products map it as bytesOut/sentBytes.
    if (/\b(?:out|bytesOut|sentBytes|bytesSent)=\d{7,}\b/i.test(text)) {
      return true;
    }

    var panTraffic = parsePanOsTrafficBytes(text);
    return !!(panTraffic && panTraffic.bytesSent >= 10000000);
  }

  /**
   * Run all Layer 1 rules against parsed log lines.
   * @param {Array} parsedLines - Array of parsed line objects from LogParser.parseFile().
   * @returns {Array} Array of alert objects.
   */
  function runRules(parsedLines) {
    if (!parsedLines || !parsedLines.length) return [];

    var alerts = [];

    for (var r = 0; r < rules.length; r++) {
      var rule = rules[r];
      var allMatches = [];

      // Scan every line for this rule's pattern
      for (var i = 0; i < parsedLines.length; i++) {
        var line = parsedLines[i];
        var matched = rule.matchLine ? rule.matchLine(line.raw) : rule.pattern.test(line.raw);
        if (matched) {
          allMatches.push({ lineNum: line.num, text: line.raw });
        }
      }

      if (allMatches.length === 0) continue;

      if (rule.groupBy === 'source_ip') {
        // Group matches by extracted IP address
        var groups = {};
        for (var j = 0; j < allMatches.length; j++) {
          var ip = extractIP(allMatches[j].text) || '__no_ip__';
          if (!groups[ip]) groups[ip] = [];
          groups[ip].push(allMatches[j]);
        }

        var ips = Object.keys(groups);
        for (var k = 0; k < ips.length; k++) {
          var groupMatches = groups[ips[k]];
          if (groupMatches.length >= rule.threshold) {
            alerts.push({
              ruleId: rule.id,
              name: rule.name + (ips[k] !== '__no_ip__' ? ' (' + ips[k] + ')' : ''),
              severity: rule.severity,
              matches: groupMatches,
              count: groupMatches.length,
              mitre: rule.mitre.slice(),
              tag: 'RULE',
              description: rule.description,
              stats: { kind: 'count', label: 'matches', threshold: rule.threshold, observed: groupMatches.length }
            });
          }
        }
      } else {
        // No grouping -- apply threshold to total count
        if (allMatches.length >= rule.threshold) {
          alerts.push({
            ruleId: rule.id,
            name: rule.name,
            severity: rule.severity,
            matches: allMatches,
            count: allMatches.length,
            mitre: rule.mitre.slice(),
            tag: 'RULE',
            description: rule.description,
            stats: { kind: 'count', label: 'matches', threshold: rule.threshold, observed: allMatches.length }
          });
        }
      }
    }

    return alerts;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Layer 2 — Statistical analysis
  // ───────────────────────────────────────────────────────────────────────

  /**
   * Build a statistical baseline from parsed log lines.
   * @param {Array} parsedLines - Array of parsed line objects.
   * @returns {Object} Baseline object with per-minute stats, hourly heatmap, and per-IP frequency.
   */
  function buildBaseline(parsedLines) {
    if (!parsedLines || !parsedLines.length) {
      return { minuteBuckets: {}, eventsPerMinute: { mean: 0, stddev: 0 }, hourlyHeatmap: new Array(24).fill(0), ipFrequency: {} };
    }

    // Bucket events by minute
    var minuteBuckets = {};
    var hourlyHeatmap = new Array(24).fill(0);
    var ipFrequency = {};
    var totalWithTimestamp = 0;

    for (var i = 0; i < parsedLines.length; i++) {
      var line = parsedLines[i];
      var ts = line.timestamp;

      if (ts) {
        // Minute bucket key: YYYY-MM-DD HH:MM
        var minuteKey = ts.getFullYear() + '-' +
          String(ts.getMonth() + 1).padStart(2, '0') + '-' +
          String(ts.getDate()).padStart(2, '0') + ' ' +
          String(ts.getHours()).padStart(2, '0') + ':' +
          String(ts.getMinutes()).padStart(2, '0');
        minuteBuckets[minuteKey] = (minuteBuckets[minuteKey] || 0) + 1;

        // Hour heatmap
        hourlyHeatmap[ts.getHours()]++;
        totalWithTimestamp++;
      }

      // IP frequency
      var ip = extractIP(line.raw);
      if (ip) {
        ipFrequency[ip] = (ipFrequency[ip] || 0) + 1;
      }
    }

    // Calculate events per minute mean and stddev
    var minuteKeys = Object.keys(minuteBuckets);
    var counts = minuteKeys.map(function (k) { return minuteBuckets[k]; });
    var mean = 0;
    var stddev = 0;

    if (counts.length > 0) {
      var sum = 0;
      for (var c = 0; c < counts.length; c++) sum += counts[c];
      mean = sum / counts.length;

      var varianceSum = 0;
      for (var v = 0; v < counts.length; v++) {
        varianceSum += (counts[v] - mean) * (counts[v] - mean);
      }
      stddev = Math.sqrt(varianceSum / counts.length);
    }

    return {
      minuteBuckets: minuteBuckets,
      eventsPerMinute: { mean: mean, stddev: stddev },
      hourlyHeatmap: hourlyHeatmap,
      ipFrequency: ipFrequency,
      totalWithTimestamp: totalWithTimestamp
    };
  }

  /**
   * Detect statistical anomalies by comparing parsed lines against a baseline.
   * @param {Array} parsedLines - Array of parsed line objects.
   * @param {Object} baseline - Baseline object from buildBaseline().
   * @returns {Array} Array of anomaly alert objects.
   */
  function detectAnomalies(parsedLines, baseline) {
    if (!parsedLines || !parsedLines.length || !baseline) return [];

    var alerts = [];

    // ---- Frequency spikes: minutes with count > mean + 2*stddev ----
    var spikeThreshold = baseline.eventsPerMinute.mean + 2 * baseline.eventsPerMinute.stddev;
    if (spikeThreshold > 0 && baseline.eventsPerMinute.stddev > 0) {
      var spikeMinutes = [];
      var spikeEvidence = [];
      var minuteKeys = Object.keys(baseline.minuteBuckets);

      for (var m = 0; m < minuteKeys.length; m++) {
        var count = baseline.minuteBuckets[minuteKeys[m]];
        if (count > spikeThreshold) {
          spikeMinutes.push(minuteKeys[m]);
        }
      }

      if (spikeMinutes.length > 0) {
        // Collect sample evidence lines from spike periods + find the peak
        var peak = 0;
        for (var pm = 0; pm < spikeMinutes.length; pm++) {
          var c = baseline.minuteBuckets[spikeMinutes[pm]];
          if (c > peak) peak = c;
        }
        for (var s = 0; s < parsedLines.length && spikeEvidence.length < 10; s++) {
          var ln = parsedLines[s];
          if (!ln.timestamp) continue;
          var lnKey = ln.timestamp.getFullYear() + '-' +
            String(ln.timestamp.getMonth() + 1).padStart(2, '0') + '-' +
            String(ln.timestamp.getDate()).padStart(2, '0') + ' ' +
            String(ln.timestamp.getHours()).padStart(2, '0') + ':' +
            String(ln.timestamp.getMinutes()).padStart(2, '0');
          if (spikeMinutes.indexOf(lnKey) !== -1) {
            spikeEvidence.push({ lineNum: ln.num, text: ln.raw });
          }
        }

        alerts.push({
          type: 'frequency-spike',
          name: 'Event Frequency Spike',
          severity: 'high',
          evidence: spikeEvidence,
          description: spikeMinutes.length + ' minute(s) exceeded 2x standard deviation above mean (' +
            baseline.eventsPerMinute.mean.toFixed(1) + ' events/min, threshold: ' + spikeThreshold.toFixed(1) + ').',
          mitre: ['T1499'],
          tag: 'STAT',
          stats: { kind: 'rate', label: 'events/min', expected: +baseline.eventsPerMinute.mean.toFixed(1), threshold: +spikeThreshold.toFixed(1), observed: peak }
        });
      }
    }

    // ---- Off-hours activity: events in hours with < 5% of total activity ----
    if (baseline.totalWithTimestamp > 0) {
      var totalEvents = baseline.totalWithTimestamp;
      var offHours = [];

      for (var h = 0; h < 24; h++) {
        var pct = baseline.hourlyHeatmap[h] / totalEvents;
        if (pct > 0 && pct < 0.05) {
          offHours.push(h);
        }
      }

      if (offHours.length > 0) {
        var offHourEvidence = [];
        for (var o = 0; o < parsedLines.length && offHourEvidence.length < 10; o++) {
          var oLine = parsedLines[o];
          if (oLine.timestamp && offHours.indexOf(oLine.timestamp.getHours()) !== -1) {
            offHourEvidence.push({ lineNum: oLine.num, text: oLine.raw });
          }
        }

        if (offHourEvidence.length > 0) {
          alerts.push({
            type: 'off-hours',
            name: 'Off-Hours Activity',
            severity: 'medium',
            evidence: offHourEvidence,
            description: 'Activity detected during low-traffic hours (' +
              offHours.map(function (h) { return String(h).padStart(2, '0') + ':00'; }).join(', ') +
              '), which account for less than 5% of total events each.',
            mitre: ['T1078.004'],
            tag: 'STAT'
          });
        }
      }
    }

    // ---- Volume anomalies: unusually large log entries ----
    var lengths = parsedLines.map(function (l) { return l.raw.length; });
    var lenSum = 0;
    for (var li = 0; li < lengths.length; li++) lenSum += lengths[li];
    var lenMean = lenSum / lengths.length;
    var lenVarSum = 0;
    for (var lv = 0; lv < lengths.length; lv++) {
      lenVarSum += (lengths[lv] - lenMean) * (lengths[lv] - lenMean);
    }
    var lenStddev = Math.sqrt(lenVarSum / lengths.length);
    var lenThreshold = lenMean + 3 * lenStddev;

    if (lenStddev > 0) {
      var volumeEvidence = [];
      for (var vi = 0; vi < parsedLines.length && volumeEvidence.length < 5; vi++) {
        if (parsedLines[vi].raw.length > lenThreshold) {
          volumeEvidence.push({ lineNum: parsedLines[vi].num, text: parsedLines[vi].raw.substring(0, 200) + '...' });
        }
      }

      if (volumeEvidence.length > 0) {
        alerts.push({
          type: 'volume-anomaly',
          name: 'Unusually Large Log Entry',
          severity: 'low',
          evidence: volumeEvidence,
          description: volumeEvidence.length + ' log entry(ies) exceed 3x standard deviation in length (' +
            'mean: ' + lenMean.toFixed(0) + ' chars, threshold: ' + lenThreshold.toFixed(0) + ' chars).',
          mitre: ['T1071'],
          tag: 'STAT'
        });
      }
    }

    // ---- Event chains: failed auth -> success -> sudo within time window ----
    var chainAlerts = detectEventChains(parsedLines);
    for (var ci = 0; ci < chainAlerts.length; ci++) {
      alerts.push(chainAlerts[ci]);
    }

    return alerts;
  }

  /**
   * Detect suspicious event chains: failed auth -> success -> sudo within a time window.
   * @param {Array} parsedLines - Array of parsed line objects.
   * @returns {Array} Array of chain-based anomaly alerts.
   */
  function detectEventChains(parsedLines) {
    var alerts = [];
    var CHAIN_WINDOW_MS = 10 * 60 * 1000; // 10-minute window

    var failedPattern = /Failed password|authentication failure|FAILED SU|invalid user/i;
    var successPattern = /Accepted\s+(?:password|publickey)|session opened|Successful login/i;
    var sudoPattern = /sudo:.*COMMAND=|su\[\d+\]:\s*Successful/i;

    // Group events by source IP for chain analysis
    var ipEvents = {};

    for (var i = 0; i < parsedLines.length; i++) {
      var line = parsedLines[i];
      if (!line.timestamp) continue;

      var ip = extractIP(line.raw);
      if (!ip) continue;

      if (!ipEvents[ip]) ipEvents[ip] = [];

      var eventType = null;
      if (failedPattern.test(line.raw)) eventType = 'fail';
      else if (successPattern.test(line.raw)) eventType = 'success';
      else if (sudoPattern.test(line.raw)) eventType = 'sudo';

      if (eventType) {
        ipEvents[ip].push({
          type: eventType,
          timestamp: line.timestamp,
          lineNum: line.num,
          text: line.raw
        });
      }
    }

    var ips = Object.keys(ipEvents);
    for (var k = 0; k < ips.length; k++) {
      var events = ipEvents[ips[k]];
      if (events.length < 2) continue;

      // Sort events by timestamp
      events.sort(function (a, b) { return a.timestamp - b.timestamp; });

      // Look for fail -> success -> sudo chains. Report only ONE chain alert
      // per IP — consolidate all failed attempts into a single finding rather
      // than emitting one alert per failed-auth event.
      var chainReported = false;
      for (var e = 0; e < events.length && !chainReported; e++) {
        if (events[e].type !== 'fail') continue;

        var failTime = events[e].timestamp.getTime();
        var failCount = 0;
        // Count all fails for this IP up to the success (for evidence context)
        for (var fc = 0; fc < events.length; fc++) {
          if (events[fc].type === 'fail') failCount++;
        }
        var chainEvidence = [{ lineNum: events[e].lineNum, text: events[e].text }];
        var foundSuccess = false;

        for (var n = e + 1; n < events.length; n++) {
          var elapsed = events[n].timestamp.getTime() - failTime;
          if (elapsed > CHAIN_WINDOW_MS) break;

          if (events[n].type === 'success' && !foundSuccess) {
            foundSuccess = true;
            chainEvidence.push({ lineNum: events[n].lineNum, text: events[n].text });
          } else if (events[n].type === 'sudo' && foundSuccess) {
            chainEvidence.push({ lineNum: events[n].lineNum, text: events[n].text });

            alerts.push({
              type: 'event-chain',
              name: 'Suspicious Auth Chain (' + ips[k] + ')',
              severity: 'critical',
              evidence: chainEvidence,
              description: failCount + ' failed authentication attempts followed by a successful login and ' +
                'privilege escalation within ' + (CHAIN_WINDOW_MS / 60000) + ' minutes from IP ' + ips[k] + '.',
              mitre: ['T1078', 'T1548.003'],
              tag: 'STAT'
            });
            chainReported = true; // One chain alert per IP
            break;
          }
        }
      }
    }

    return alerts;
  }

  /**
   * Run both Layer 1 and Layer 2 detection, return combined and sorted alerts.
   * @param {Array} parsedLines - Array of parsed line objects.
   * @returns {Array} All alerts sorted by severity (critical > high > medium > low).
   */
  function runAll(parsedLines) {
    var ruleAlerts = runRules(parsedLines);
    var baseline = buildBaseline(parsedLines);
    var anomalyAlerts = detectAnomalies(parsedLines, baseline);

    var combined = ruleAlerts.concat(anomalyAlerts);

    // Sort by severity: critical first, then high, medium, low
    combined.sort(function (a, b) {
      var aOrder = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 99;
      var bOrder = SEVERITY_ORDER[b.severity] !== undefined ? SEVERITY_ORDER[b.severity] : 99;
      return aOrder - bOrder;
    });

    return combined;
  }

  // Public API
  return {
    rules: rules,
    runRules: runRules,
    buildBaseline: buildBaseline,
    detectAnomalies: detectAnomalies,
    runAll: runAll
  };
})();
