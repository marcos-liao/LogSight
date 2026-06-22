/**
 * Pseudonymizer — Consistent replacement of identifiable data with dummy values.
 * Part of the LogSight project.
 *
 * Replaces IPs, hostnames, usernames, emails, and sensitive paths with
 * deterministic pseudonyms using NATO phonetic alphabet naming. Mappings
 * are consistent within a session: the same real value always produces
 * the same dummy value.
 */
const Pseudonymizer = (function () {
  'use strict';

  // NATO phonetic alphabet for naming pseudonyms
  var NATO = [
    'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot',
    'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima',
    'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo',
    'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
    'yankee', 'zulu'
  ];

  // Internal state: maps keyed by real value -> dummy value
  var ipv4Map = new Map();
  var ipv6Map = new Map();
  var hostnameMap = new Map();
  var usernameMap = new Map();
  var emailMap = new Map();
  var pathMap = new Map();

  // Counters for generating sequential dummy values
  var ipv4Counter = 1;
  var ipv6Counter = 1;
  var hostnameCounter = 0;
  var usernameCounter = 0;
  var emailCounter = 1;
  var pathCounter = 1;

  // RFC 5737 documentation ranges for IPv4 pseudonyms
  var IPV4_RANGES = ['198.51.100.', '203.0.113.'];

  /**
   * Get the NATO phonetic name for a given index (wraps and appends number if > 26).
   * @param {number} index - Zero-based index.
   * @returns {string} NATO name, e.g. 'alpha', 'bravo', ... 'alpha_2'
   */
  function natoName(index) {
    if (index < NATO.length) return NATO[index];
    var cycle = Math.floor(index / NATO.length) + 1;
    var pos = index % NATO.length;
    return NATO[pos] + '_' + cycle;
  }

  /**
   * Get or create a pseudonym for an IPv4 address.
   * Uses RFC 5737 documentation ranges (198.51.100.x, 203.0.113.x).
   * @param {string} realIP - The real IPv4 address.
   * @returns {string} The pseudonymized IPv4 address.
   */
  function pseudoIPv4(realIP) {
    if (ipv4Map.has(realIP)) return ipv4Map.get(realIP);

    // Skip loopback, link-local, and documentation ranges themselves
    if (realIP === '127.0.0.1' || realIP.startsWith('198.51.100.') || realIP.startsWith('203.0.113.')) {
      return realIP;
    }

    var rangeIdx = ipv4Counter <= 254 ? 0 : 1;
    var hostPart = ((ipv4Counter - 1) % 254) + 1;
    var dummy = IPV4_RANGES[rangeIdx] + hostPart;
    ipv4Map.set(realIP, dummy);
    ipv4Counter++;
    return dummy;
  }

  /**
   * Get or create a pseudonym for an IPv6 address.
   * Uses the 2001:db8::/32 documentation range.
   * @param {string} realIP - The real IPv6 address.
   * @returns {string} The pseudonymized IPv6 address.
   */
  function pseudoIPv6(realIP) {
    if (ipv6Map.has(realIP)) return ipv6Map.get(realIP);

    var dummy = '2001:db8::' + ipv6Counter;
    ipv6Map.set(realIP, dummy);
    ipv6Counter++;
    return dummy;
  }

  // Common log vocabulary that the hostname/username heuristics can grab by
  // mistake. These are never identifiers, so they must not be pseudonymized.
  var STOPWORDS = {};
  ['opened','closed','open','close','session','sessions','user','users','invalid','failure',
   'failed','password','authentication','accepted','disconnected','connection','connect',
   'unknown','none','null','localhost','uid','euid','gid','tty','ruser','rhost','logname',
   'for','from','by','on','to','the','and','port','service','daemon','cron','root','system',
   'pam_unix','sshd','sudo','su','login','logout','reload','start','stop','restart','enabled',
   'disabled','active','inactive','request','response','error','warning','notice','info','debug'
  ].forEach(function (w) { STOPWORDS[w] = true; });

  function isStopword(s) {
    return STOPWORDS[String(s).toLowerCase().replace(/[;:,.]+$/, '')] === true;
  }

  /**
   * Get or create a pseudonym for a hostname.
   * @param {string} realHost - The real hostname.
   * @returns {string} e.g. 'host_alpha', 'host_bravo'
   */
  function pseudoHostname(realHost) {
    if (isStopword(realHost)) return realHost;           // common word, not a host
    if (hostnameMap.has(realHost)) return hostnameMap.get(realHost);

    var dummy = 'host_' + natoName(hostnameCounter);
    hostnameMap.set(realHost, dummy);
    hostnameCounter++;
    return dummy;
  }

  /**
   * Get or create a pseudonym for a username.
   * @param {string} realUser - The real username.
   * @returns {string} e.g. 'user_alpha', 'user_bravo'
   */
  function pseudoUsername(realUser) {
    if (isStopword(realUser)) return realUser;           // common word, not a user
    if (usernameMap.has(realUser)) return usernameMap.get(realUser);

    // Skip 'root' and common system users
    if (realUser === 'root' || realUser === 'nobody' || realUser === 'www-data') {
      return realUser;
    }

    var dummy = 'user_' + natoName(usernameCounter);
    usernameMap.set(realUser, dummy);
    usernameCounter++;
    return dummy;
  }

  /**
   * Get or create a pseudonym for an email address.
   * @param {string} realEmail - The real email address.
   * @returns {string} e.g. 'person1@example.com'
   */
  function pseudoEmail(realEmail) {
    if (emailMap.has(realEmail)) return emailMap.get(realEmail);

    var dummy = 'person' + emailCounter + '@example.com';
    emailMap.set(realEmail, dummy);
    emailCounter++;
    return dummy;
  }

  /**
   * Get or create a pseudonym for a sensitive file path.
   * @param {string} realPath - The real file path.
   * @returns {string} e.g. '/var/app/path_01'
   */
  function pseudoPath(realPath) {
    if (pathMap.has(realPath)) return pathMap.get(realPath);

    var dummy = '/var/app/path_' + String(pathCounter).padStart(2, '0');
    pathMap.set(realPath, dummy);
    pathCounter++;
    return dummy;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Detection and replacement patterns
  // ───────────────────────────────────────────────────────────────────────

  // IPv4: four octets 0-255, not inside a longer number sequence
  var IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

  // IPv6: comprehensive pattern, alternatives ordered most-specific first so a
  // complete address is captured as a single match (avoids leaking numeric
  // segments of an address split across alternatives).
  // Alternatives ordered most-complete first: full 8-group form, then the
  // compressed "::" forms with the most trailing groups, and finally the bare
  // trailing/leading "::" forms. JS alternation is order-based (not longest-
  // match), so complete addresses must be tried before partial ones to avoid
  // leaving numeric tail segments unreplaced.
  var IPV6_RE = new RegExp(
    '(' +
      '(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' +                         // 1:2:3:4:5:6:7:8
      '|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}' +
      '|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}' +
      '|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}' +
      '|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}' +
      '|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}' +
      '|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}' +                     // 1:2:3:4:5:6::8
      '|(?:[0-9a-fA-F]{1,4}:){1,7}:' +                                     // 1::  ...  1:2:3:4:5:6:7::
      '|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)' +                               // ::8  /  ::
    ')', 'g'
  );

  // Email addresses
  var EMAIL_RE = /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g;

  // Hostnames: after sshd[ or common log hostname positions
  var HOSTNAME_AFTER_SSHD_RE = /(?:sshd\[?\d*\]?\s*:\s*.*?(?:from|on)\s+)(\S+)/gi;
  var HOSTNAME_SYSLOG_RE = /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)/gm;

  // Usernames: after 'for ', 'user=', 'by '
  var USERNAME_FOR_RE = /\bfor\s+(invalid\s+user\s+)?([a-zA-Z0-9_.\-]+)/gi;
  var USERNAME_USER_EQ_RE = /\buser=([a-zA-Z0-9_.\-]+)/gi;
  var USERNAME_BY_RE = /\bby\s+([a-zA-Z0-9_.\-]+)/gi;

  // Sensitive file paths: /home/*, /root, and other sensitive locations
  var SENSITIVE_PATH_RE = /(?:\/home\/[a-zA-Z0-9_.\-]+(?:\/[^\s'",:;)}\]]*)?|\/root(?:\/[^\s'",:;)}\]]*)?)/g;

  /**
   * Validate that a string looks like a real IPv4 address (each octet 0-255).
   * @param {string} ip - Candidate IPv4 string.
   * @returns {boolean}
   */
  function isValidIPv4(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      var n = parseInt(parts[i], 10);
      if (isNaN(n) || n < 0 || n > 255) return false;
    }
    return true;
  }

  /**
   * Validate that a string is plausibly a real IPv6 address — not a timestamp.
   * A real IPv6 must contain "::" (compression), a hex letter (a-f), or the
   * full 8-group form (7 colons). This rejects clock values like "08:00:01"
   * whose hex-digit groups would otherwise match the loose IPv6 pattern.
   * @param {string} s - Candidate IPv6 string.
   * @returns {boolean}
   */
  function isValidIPv6(s) {
    if (s.indexOf('::') !== -1) return true;        // compressed form
    if (/[a-fA-F]/.test(s)) return true;            // contains a hex letter
    var colons = (s.match(/:/g) || []).length;
    return colons >= 7;                              // full uncompressed form
  }

  /**
   * Process text, replacing all identifiable data with consistent pseudonyms.
   * @param {string} text - Input text (single line or multi-line).
   * @returns {string} Text with identifiable data replaced.
   */
  function process(text) {
    if (!text || typeof text !== 'string') return text;

    var result = text;

    // Order matters: replace emails before IPs (emails contain dots that could match IP parts),
    // and replace hostnames/usernames after IPs (so IP-based hostnames are handled first).

    // 1. Replace email addresses
    result = result.replace(EMAIL_RE, function (match, email) {
      return pseudoEmail(email);
    });

    // 2. Replace IPv6 addresses (before IPv4, since some mixed notations exist)
    result = result.replace(IPV6_RE, function (match, ip) {
      if (!isValidIPv6(ip)) return match; // skip timestamps & other false positives
      return pseudoIPv6(ip);
    });

    // 3. Replace IPv4 addresses
    result = result.replace(IPV4_RE, function (match, ip) {
      if (!isValidIPv4(ip)) return match;
      return pseudoIPv4(ip);
    });

    // 4. Replace sensitive file paths (/home/user/..., /root/...)
    result = result.replace(SENSITIVE_PATH_RE, function (match) {
      return pseudoPath(match);
    });

    // 5. Replace syslog hostnames (the hostname field after the timestamp).
    // Collect from every line (gm), then globally replace each so all
    // occurrences across a multi-line block stay consistent.
    var syslogHosts = [];
    var sh;
    HOSTNAME_SYSLOG_RE.lastIndex = 0;
    while ((sh = HOSTNAME_SYSLOG_RE.exec(text)) !== null) {
      var hcand = sh[1];
      if (hcand === 'localhost' || /^host_/.test(hcand) || isStopword(hcand)) continue;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hcand)) continue;
      if (syslogHosts.indexOf(hcand) === -1) syslogHosts.push(hcand);
    }
    for (var si = 0; si < syslogHosts.length; si++) {
      result = result.split(syslogHosts[si]).join(pseudoHostname(syslogHosts[si]));
    }

    // 6. Replace hostnames after sshd/service references
    var hostnameMatches = [];
    var hm;
    HOSTNAME_AFTER_SSHD_RE.lastIndex = 0;
    while ((hm = HOSTNAME_AFTER_SSHD_RE.exec(text)) !== null) {
      var candidate = hm[1];
      // Skip if it looks like an IP (already replaced) or a pseudonym
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(candidate)) continue;
      if (/^198\.51\.100\.|^203\.0\.113\./.test(candidate)) continue;
      if (/^host_/.test(candidate)) continue;
      hostnameMatches.push(candidate);
    }
    for (var hi = 0; hi < hostnameMatches.length; hi++) {
      var realHost = hostnameMatches[hi];
      var dummyHost = pseudoHostname(realHost);
      result = result.split(realHost).join(dummyHost);
    }

    // 7. Replace usernames after 'for ', 'user=', 'by '
    var usernameReplacements = [];

    var uf;
    USERNAME_FOR_RE.lastIndex = 0;
    while ((uf = USERNAME_FOR_RE.exec(text)) !== null) {
      var uname = uf[2];
      if (uname && uname.length > 1 && !/^\d+$/.test(uname)) {
        usernameReplacements.push(uname);
      }
    }

    var ue;
    USERNAME_USER_EQ_RE.lastIndex = 0;
    while ((ue = USERNAME_USER_EQ_RE.exec(text)) !== null) {
      if (ue[1] && ue[1].length > 1 && !/^\d+$/.test(ue[1])) {
        usernameReplacements.push(ue[1]);
      }
    }

    var ub;
    USERNAME_BY_RE.lastIndex = 0;
    while ((ub = USERNAME_BY_RE.exec(text)) !== null) {
      if (ub[1] && ub[1].length > 1 && !/^\d+$/.test(ub[1])) {
        usernameReplacements.push(ub[1]);
      }
    }

    // Deduplicate and apply username replacements (longest first to avoid partial matches)
    var uniqueUsernames = [];
    var seenUsernames = {};
    for (var su = 0; su < usernameReplacements.length; su++) {
      if (!seenUsernames[usernameReplacements[su]]) {
        seenUsernames[usernameReplacements[su]] = true;
        uniqueUsernames.push(usernameReplacements[su]);
      }
    }
    uniqueUsernames.sort(function (a, b) { return b.length - a.length; });

    for (var ru = 0; ru < uniqueUsernames.length; ru++) {
      var realUser = uniqueUsernames[ru];
      var dummyUser = pseudoUsername(realUser);
      if (realUser === dummyUser) continue; // System user, no replacement needed

      // Only replace usernames in contextual positions to avoid false positives.
      // Replace after 'for ', 'for invalid user ', 'user=', 'by '
      result = result.replace(new RegExp('(for\\s+(?:invalid\\s+user\\s+)?)' + escapeRegex(realUser) + '\\b', 'g'),
        '$1' + dummyUser);
      result = result.replace(new RegExp('(user=)' + escapeRegex(realUser) + '\\b', 'g'),
        '$1' + dummyUser);
      result = result.replace(new RegExp('(by\\s+)' + escapeRegex(realUser) + '\\b', 'g'),
        '$1' + dummyUser);
    }

    return result;
  }

  /**
   * Escape a string for use in a RegExp.
   * @param {string} str
   * @returns {string}
   */
  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Clear all internal mappings and reset counters.
   */
  function reset() {
    ipv4Map.clear();
    ipv6Map.clear();
    hostnameMap.clear();
    usernameMap.clear();
    emailMap.clear();
    pathMap.clear();
    ipv4Counter = 1;
    ipv6Counter = 1;
    hostnameCounter = 0;
    usernameCounter = 0;
    emailCounter = 1;
    pathCounter = 1;
  }

  /**
   * Return the current mapping table as an array of { real, dummy, type } objects.
   * @returns {Array<{real: string, dummy: string, type: string}>}
   */
  function getMapping() {
    var result = [];

    ipv4Map.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'ipv4' });
    });
    ipv6Map.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'ipv6' });
    });
    hostnameMap.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'hostname' });
    });
    usernameMap.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'username' });
    });
    emailMap.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'email' });
    });
    pathMap.forEach(function (dummy, real) {
      result.push({ real: real, dummy: dummy, type: 'path' });
    });

    return result;
  }

  /**
   * Reverse-map dummy values back to real values in a text string.
   * @param {string} text - Text containing pseudonymized values.
   * @returns {string} Text with real values restored.
   */
  function reverse(text) {
    if (!text || typeof text !== 'string') return text;

    var result = text;

    // Build reverse map: dummy -> real, process longest dummy values first
    // to avoid partial replacements
    var reversals = [];

    ipv4Map.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });
    ipv6Map.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });
    hostnameMap.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });
    usernameMap.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });
    emailMap.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });
    pathMap.forEach(function (dummy, real) { reversals.push({ dummy: dummy, real: real }); });

    // Sort by dummy value length descending to avoid partial replacement issues
    reversals.sort(function (a, b) { return b.dummy.length - a.dummy.length; });

    for (var i = 0; i < reversals.length; i++) {
      result = result.split(reversals[i].dummy).join(reversals[i].real);
    }

    return result;
  }

  // Public API
  return {
    reset: reset,
    process: process,
    getMapping: getMapping,
    reverse: reverse
  };
})();
