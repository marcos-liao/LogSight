/**
 * LogParser — Log file parsing, timestamp extraction, and format detection.
 * Part of the LogSight project.
 */
const LogParser = (function () {
  'use strict';

  // Month abbreviation lookup for date parsing
  const MONTH_MAP = {
    Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
    Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11
  };

  // Format detection patterns
  const FORMAT_PATTERNS = {
    // Palo Alto PAN-OS syslog/CSV: "... 1,2026/06/14 16:00:01,serial,TRAFFIC,..."
    'pan-os': /(?:^|\s)\d+,\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2},[^,]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|CORRELATION),/,
    // Common Event Format, usually with a syslog prefix but sometimes exported bare.
    cef: /(?:^|\s)CEF:\d+\|/,
    // Syslog: "Jun 21 03:14:01 hostname ..."
    syslog: /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+/,
    // Apache access log: 127.0.0.1 - - [21/Jun/2026:03:14:01 +0000] "GET ..."
    'apache-access': /^\S+\s+\S+\s+\S+\s+\[\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]/,
    // Apache error log: [Sat Jun 21 03:14:01.123456 2026] [module:level] ...
    'apache-error': /^\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(\.\d+)?\s+\d{4}\]/,
    // BIND DNS query log: "14-Jun-2025 10:00:01.123 client ..."
    bind: /^\d{1,2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{1,6}/,
    // Oracle Net listener log: "14-Jun-2026 16:00:02.000 * ... * establish * SERVICE * 0"
    'oracle-listener': /^\d{1,2}-[A-Z][a-z]{2}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{1,6}\s+\*/,
    // JSON log: starts with { and contains a recognizable timestamp field
    json: /^\s*\{.*"(timestamp|time|@timestamp|ts|datetime|date)":/
  };

  // Timestamp extraction patterns
  const TIMESTAMP_REGEX = {
    syslog: /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/,
    'pan-os': /(?:^|\s)\d+,(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2}),[^,]*,(?:TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|CORRELATION),/,
    cefSyslog: /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+CEF:\d+\|/,
    cefRt: /\brt=(\d{10,13}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\b/,
    'apache-access': /\[(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})\]/,
    'apache-error': /\[[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(\d{4})\]/,
    bind: /^(\d{1,2})-([A-Z][a-z]{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?/,
    'oracle-listener': /^(\d{1,2})-([A-Z][a-z]{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?/,
    json: /"(?:timestamp|time|@timestamp|ts|datetime|date)"\s*:\s*"([^"]+)"/
  };

  // Severity keywords mapped to severity levels
  const SEVERITY_KEYWORDS = [
    { pattern: /\bemerg(?:ency)?\b/i, level: 'emergency' },
    { pattern: /\balert\b/i, level: 'alert' },
    { pattern: /\bcrit(?:ical)?\b/i, level: 'critical' },
    { pattern: /\berr(?:or)?\b/i, level: 'error' },
    { pattern: /\bfail(?:ed|ure)?\b/i, level: 'error' },
    { pattern: /\bdenied\b/i, level: 'error' },
    { pattern: /\bwarn(?:ing)?\b/i, level: 'warning' },
    { pattern: /\bAccepted\b/, level: 'info' },
    { pattern: /\bnotice\b/i, level: 'notice' },
    { pattern: /\binfo\b/i, level: 'info' },
    { pattern: /\bdebug\b/i, level: 'debug' }
  ];

  /**
   * Detect the format of a single log line.
   * @param {string} line - A single line from a log file.
   * @returns {string} One of: 'syslog', 'apache-access', 'apache-error', 'json', 'unknown'.
   */
  function detectFormat(line) {
    if (!line || typeof line !== 'string') return 'unknown';
    var trimmed = line.trim();
    if (!trimmed) return 'unknown';

    // Check each format pattern in order of specificity
    if (FORMAT_PATTERNS['apache-error'].test(trimmed)) return 'apache-error';
    if (FORMAT_PATTERNS['apache-access'].test(trimmed)) return 'apache-access';
    if (FORMAT_PATTERNS['pan-os'].test(trimmed)) return 'pan-os';
    if (FORMAT_PATTERNS.cef.test(trimmed)) return 'cef';
    if (FORMAT_PATTERNS['oracle-listener'].test(trimmed)) return 'oracle-listener';
    if (FORMAT_PATTERNS.bind.test(trimmed)) return 'bind';
    if (FORMAT_PATTERNS.syslog.test(trimmed)) return 'syslog';
    if (FORMAT_PATTERNS.json.test(trimmed)) return 'json';

    // Fallback: try to detect ISO 8601 timestamps inline
    if (/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(trimmed)) return 'json';

    return 'unknown';
  }

  /**
   * Extract a Date object from a log line given its format.
   * @param {string} line - A single log line.
   * @param {string} format - The detected format type.
   * @returns {Date|null} Parsed date or null if extraction fails.
   */
  function extractTimestamp(line, format) {
    if (!line || !format) return null;

    var m;

    switch (format) {
      case 'syslog':
        m = TIMESTAMP_REGEX.syslog.exec(line);
        if (!m) return null;
        var year = new Date().getFullYear();
        var month = MONTH_MAP[m[1]];
        if (month === undefined) return null;
        return new Date(year, month, parseInt(m[2], 10),
          parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10));

      case 'pan-os':
        m = TIMESTAMP_REGEX['pan-os'].exec(line);
        if (!m) return null;
        return new Date(parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10),
          parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10));

      case 'cef':
        m = TIMESTAMP_REGEX.cefSyslog.exec(line);
        if (m) {
          var cefYear = new Date().getFullYear();
          var cefMonth = MONTH_MAP[m[1]];
          if (cefMonth !== undefined) {
            return new Date(cefYear, cefMonth, parseInt(m[2], 10),
              parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10));
          }
        }
        m = TIMESTAMP_REGEX.cefRt.exec(line);
        if (!m) return null;
        if (/^\d{10,13}$/.test(m[1])) {
          var epoch = parseInt(m[1], 10);
          if (m[1].length === 10) epoch *= 1000;
          var epochDate = new Date(epoch);
          return isNaN(epochDate.getTime()) ? null : epochDate;
        }
        var cefRtParts = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(m[1]);
        if (!cefRtParts) return null;
        var cefRtMonth = MONTH_MAP[cefRtParts[1]];
        if (cefRtMonth === undefined) return null;
        return new Date(parseInt(cefRtParts[3], 10), cefRtMonth, parseInt(cefRtParts[2], 10),
          parseInt(cefRtParts[4], 10), parseInt(cefRtParts[5], 10), parseInt(cefRtParts[6], 10));

      case 'apache-access':
        m = TIMESTAMP_REGEX['apache-access'].exec(line);
        if (!m) return null;
        var accMonth = MONTH_MAP[m[2]];
        if (accMonth === undefined) return null;
        // Build ISO string to let Date handle timezone offset
        var isoStr = m[3] + '-' + String(accMonth + 1).padStart(2, '0') + '-' + m[1] +
          'T' + m[4] + ':' + m[5] + ':' + m[6];
        var offset = m[7];
        var offSign = offset.charAt(0) === '+' ? 1 : -1;
        var offHours = parseInt(offset.substring(1, 3), 10);
        var offMins = parseInt(offset.substring(3, 5), 10);
        var dt = new Date(isoStr + 'Z');
        dt.setMinutes(dt.getMinutes() - offSign * (offHours * 60 + offMins));
        return isNaN(dt.getTime()) ? null : dt;

      case 'bind':
        m = TIMESTAMP_REGEX.bind.exec(line);
        if (!m) return null;
        var bindMonth = MONTH_MAP[m[2]];
        if (bindMonth === undefined) return null;
        var bindDate = new Date(parseInt(m[3], 10), bindMonth, parseInt(m[1], 10),
          parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10));
        if (m[7]) bindDate.setMilliseconds(parseInt(m[7].substring(0, 3).padEnd(3, '0'), 10));
        return isNaN(bindDate.getTime()) ? null : bindDate;

      case 'oracle-listener':
        m = TIMESTAMP_REGEX['oracle-listener'].exec(line);
        if (!m) return null;
        var oraListenerMonth = MONTH_MAP[m[2]];
        if (oraListenerMonth === undefined) return null;
        var oraListenerDate = new Date(parseInt(m[3], 10), oraListenerMonth, parseInt(m[1], 10),
          parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10));
        if (m[7]) oraListenerDate.setMilliseconds(parseInt(m[7].substring(0, 3).padEnd(3, '0'), 10));
        return isNaN(oraListenerDate.getTime()) ? null : oraListenerDate;

      case 'apache-error':
        m = TIMESTAMP_REGEX['apache-error'].exec(line);
        if (!m) return null;
        var errMonth = MONTH_MAP[m[1]];
        if (errMonth === undefined) return null;
        var errYear = parseInt(m[7], 10);
        var errDate = new Date(errYear, errMonth, parseInt(m[2], 10),
          parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10));
        if (m[6]) {
          // Add microsecond fraction as milliseconds
          var frac = m[6].substring(0, 3);
          errDate.setMilliseconds(parseInt(frac.padEnd(3, '0'), 10));
        }
        return isNaN(errDate.getTime()) ? null : errDate;

      case 'json':
        m = TIMESTAMP_REGEX.json.exec(line);
        if (m && m[1]) {
          var parsed = new Date(m[1]);
          return isNaN(parsed.getTime()) ? null : parsed;
        }
        // Fallback: try to find ISO 8601 anywhere in the line
        var isoMatch = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/.exec(line);
        if (isoMatch) {
          var isoParsed = new Date(isoMatch[1]);
          return isNaN(isoParsed.getTime()) ? null : isoParsed;
        }
        return null;

      default:
        // Try ISO 8601 as a last resort for unknown formats
        var fallback = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/.exec(line);
        if (fallback) {
          var fbDate = new Date(fallback[1]);
          return isNaN(fbDate.getTime()) ? null : fbDate;
        }
        return null;
    }
  }

  /**
   * Detect severity from a log line by scanning for keywords.
   * @param {string} line - A single log line.
   * @returns {string|null} Severity level or null.
   */
  function detectSeverity(line) {
    if (!line) return null;
    for (var i = 0; i < SEVERITY_KEYWORDS.length; i++) {
      if (SEVERITY_KEYWORDS[i].pattern.test(line)) {
        return SEVERITY_KEYWORDS[i].level;
      }
    }
    return null;
  }

  /**
   * Parse a single log line into a structured object.
   * @param {string} line - A single log line.
   * @returns {{ timestamp: Date|null, raw: string, format: string, severity: string|null }}
   */
  function parseLine(line) {
    var fmt = detectFormat(line);
    return {
      timestamp: extractTimestamp(line, fmt),
      raw: line,
      format: fmt,
      severity: detectSeverity(line)
    };
  }

  /**
   * Parse an entire log file text into structured data.
   * @param {string} text - The full text content of a log file.
   * @param {string} filename - The filename for reference.
   * @returns {{ filename: string, lines: Array, startDate: Date|null, endDate: Date|null, lineCount: number }}
   */
  function parseFile(text, filename) {
    if (!text || typeof text !== 'string') {
      return { filename: filename || '', lines: [], startDate: null, endDate: null, lineCount: 0 };
    }

    var rawLines = text.split(/\r?\n/);
    var parsedLines = [];
    var startDate = null;
    var endDate = null;

    for (var i = 0; i < rawLines.length; i++) {
      var line = rawLines[i];
      // Skip completely empty trailing line
      if (i === rawLines.length - 1 && line === '') continue;

      var parsed = parseLine(line);
      parsedLines.push({
        num: i + 1,
        raw: parsed.raw,
        timestamp: parsed.timestamp,
        format: parsed.format,
        severity: parsed.severity
      });

      if (parsed.timestamp) {
        if (!startDate || parsed.timestamp < startDate) {
          startDate = parsed.timestamp;
        }
        if (!endDate || parsed.timestamp > endDate) {
          endDate = parsed.timestamp;
        }
      }
    }

    return {
      filename: filename || '',
      lines: parsedLines,
      startDate: startDate,
      endDate: endDate,
      lineCount: parsedLines.length
    };
  }

  /**
   * Check if an ArrayBuffer contains text (not binary) data.
   * Examines the first 512 bytes for non-text characters.
   * @param {ArrayBuffer} arrayBuffer - The file content as ArrayBuffer.
   * @returns {boolean} True if the content appears to be text.
   */
  function isTextFile(arrayBuffer) {
    if (!arrayBuffer || !(arrayBuffer instanceof ArrayBuffer)) return false;
    var bytes = new Uint8Array(arrayBuffer, 0, Math.min(512, arrayBuffer.byteLength));
    if (bytes.length === 0) return true; // Empty file is technically text

    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      // Allow common text bytes: printable ASCII, tab, newline, carriage return
      if (b === 0) return false; // Null byte is a strong binary indicator
      if (b < 8) return false;   // Control chars 0x00-0x07
      if (b === 14 || b === 15) return false; // SO, SI
      if (b >= 16 && b <= 31 && b !== 27) return false; // Control chars except ESC
      // Bytes 128-255 are allowed (UTF-8 continuation bytes, Latin-1, etc.)
    }
    return true;
  }

  // Public API
  return {
    detectFormat: detectFormat,
    extractTimestamp: extractTimestamp,
    parseLine: parseLine,
    parseFile: parseFile,
    isTextFile: isTextFile
  };
})();
