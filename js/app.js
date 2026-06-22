// =============================================================================
// LogSight — App orchestration
// Wires the UI to the core modules: SCENARIOS, LogParser, Detection,
// Timeline, LogViewer, Pseudonymizer.
// =============================================================================

document.addEventListener('DOMContentLoaded', function () {

  var LIMIT_MB = 500;

  // State
  var learnTimelineActive = false;
  var analyzeTimelineActive = false;
  var analyzeData = { lines: [], files: [], alerts: [] };
  var activeFileTab = 'all';

  // ───────────────────────────────────────────────────────────────────────
  // Helpers
  // ───────────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str == null ? '' : String(str)));
    return div.innerHTML;
  }

  function fmtDate(d) {
    if (!d) return '—';
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    var p = function (n) { return n < 10 ? '0' + n : '' + n; };
    return months[d.getMonth()] + ' ' + d.getDate() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function fmtDateShort(d) {
    if (!d) return '—';
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return d.getDate() + ' ' + months[d.getMonth()] + ' ' + d.getFullYear();
  }

  function daysBetween(a, b) {
    if (!a || !b) return 0;
    return Math.max(1, Math.round((b - a) / 86400000));
  }

  function daysLabel(n) {
    return n + (n === 1 ? ' day' : ' days');
  }

  // ---- Log drill-down context (breadcrumb) ----
  function currentMode() {
    var a = document.querySelector('.tab-content.active');
    return (a && a.id === 'tab-analyze') ? 'analyze' : 'learn';
  }

  function showLogContext(mode, text) {
    document.getElementById(mode + '-context-label').textContent = text;
    document.getElementById(mode + '-log-context').style.display = 'flex';
  }

  function clearDrill(mode) {
    LogViewer.filterByTimeRange(null, null);
    if (Timeline.chart) { Timeline.resetZoom(); Timeline.clearHighlight(); }
    document.getElementById(mode + '-log-context').style.display = 'none';
    if (mode === 'learn') updateLearnFilteredCount(); else updateAnalyzeFilteredCount();
  }

  // ───────────────────────────────────────────────────────────────────────
  // Tab navigation
  // ───────────────────────────────────────────────────────────────────────
  document.querySelectorAll('.nav-link').forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      switchTab(link.dataset.tab);
    });
  });

  function switchTab(tab) {
    document.querySelectorAll('.nav-link').forEach(function (l) {
      l.classList.toggle('active', l.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-content').forEach(function (t) { t.classList.remove('active'); });
    var el = document.getElementById('tab-' + tab);
    if (el) el.classList.add('active');
  }

  // ───────────────────────────────────────────────────────────────────────
  // Intel report tabs
  // ───────────────────────────────────────────────────────────────────────
  document.querySelectorAll('.intel-tab').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.intel-tab').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      document.querySelectorAll('.intel-panel').forEach(function (p) { p.classList.remove('active'); });
      document.getElementById('itab-' + btn.dataset.itab).classList.add('active');
    });
  });

  // ───────────────────────────────────────────────────────────────────────
  // Collapsible toggles
  // ───────────────────────────────────────────────────────────────────────
  var syslogRefToggle = document.getElementById('syslog-ref-toggle');
  var syslogRefContent = document.getElementById('syslog-ref-content');
  if (syslogRefToggle) {
    syslogRefToggle.addEventListener('click', function () {
      var isOpen = syslogRefContent.style.display !== 'none';
      syslogRefContent.style.display = isOpen ? 'none' : 'block';
      syslogRefToggle.classList.toggle('open', !isOpen);
    });
  }

  ['combine', 'combos'].forEach(function (id) {
    var toggle = document.getElementById('toggle-' + id);
    var body = document.getElementById('body-' + id);
    if (toggle && body) {
      toggle.addEventListener('click', function () {
        var isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : 'block';
        toggle.classList.toggle('open', !isOpen);
      });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // LEARN MODE
  // ═══════════════════════════════════════════════════════════════════════
  var scenarioSelect = document.getElementById('scenario-select');
  var btnLoadScenario = document.getElementById('btn-load-scenario');
  var diffStars = document.getElementById('diff-stars');
  var currentScenario = null;

  // Populate dropdown from SCENARIOS — mark unbuilt options disabled
  (function populateScenarios() {
    if (typeof SCENARIOS === 'undefined') return;
    var built = Object.keys(SCENARIOS);
    // Disable options that have no scenario data yet
    Array.prototype.forEach.call(scenarioSelect.options, function (opt) {
      if (opt.value && built.indexOf(opt.value) === -1) {
        opt.disabled = true;
        opt.text = opt.text + ' (coming soon)';
      }
    });
  })();

  scenarioSelect.addEventListener('change', function () {
    var sc = SCENARIOS[scenarioSelect.value];
    if (sc) {
      var stars = '';
      for (var i = 0; i < 5; i++) stars += i < sc.difficulty ? '★' : '☆';
      diffStars.textContent = stars;
    }
  });

  btnLoadScenario.addEventListener('click', function () {
    var id = scenarioSelect.value;
    var sc = SCENARIOS[id];
    if (!sc) return;
    currentScenario = sc;

    document.getElementById('scenario-title').textContent = sc.title;
    document.getElementById('scenario-logsource').textContent = sc.logSource;
    document.getElementById('scenario-mitre-tag').textContent = sc.mitreTags;
    document.getElementById('scenario-desc').textContent = sc.description;
    document.getElementById('scenario-intro').style.display = 'block';

    document.getElementById('learn-timeline-box').style.display = 'block';
    document.getElementById('learn-log-box').style.display = 'block';
    document.getElementById('learn-questions-box').style.display = 'block';
    document.getElementById('learn-intel-box').style.display = 'block';

    // Re-lock intel
    var intelBox = document.getElementById('learn-intel-box');
    intelBox.classList.add('intel-locked');
    document.getElementById('intel-lock-overlay').style.display = 'flex';
    document.getElementById('intel-content').style.display = 'none';

    // Parse the embedded logs
    var parsed = LogParser.parseFile(sc.logs.join('\n'), sc.logSource);

    // Render log viewer
    LogViewer.init('learn-log-viewer', parsed.lines);
    document.getElementById('learn-log-count').textContent = parsed.lineCount.toLocaleString() + ' lines';
    document.getElementById('learn-log-filtered').textContent = '';

    // Render timeline
    if (learnTimelineActive) Timeline.destroy();
    Timeline.create('learn-timeline-chart', parsed.lines, function (start, end) {
      LogViewer.filterByTimeRange(start, end);
      document.getElementById('learn-range-start').textContent = fmtDate(start);
      document.getElementById('learn-range-end').textContent = fmtDate(end);
      showLogContext('learn', 'Zoomed: ' + fmtDate(start) + ' – ' + fmtDate(end));
      updateLearnFilteredCount();
    });
    learnTimelineActive = true;
    if (parsed.startDate) document.getElementById('learn-range-start').textContent = fmtDate(parsed.startDate);
    if (parsed.endDate) document.getElementById('learn-range-end').textContent = fmtDate(parsed.endDate);

    // Render questions
    renderQuestions(sc.questions);

    // Pre-render intel (hidden until unlock)
    renderIntel(sc.intel);

    document.getElementById('scenario-intro').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  function updateLearnFilteredCount() {
    var stats = LogViewer.getStats();
    var el = document.getElementById('learn-log-filtered');
    if (stats.filtered < stats.total) {
      el.textContent = '(' + stats.filtered.toLocaleString() + ' shown)';
    } else {
      el.textContent = '';
    }
  }

  var quizAttempts = 0;

  function renderQuestions(questions) {
    quizAttempts = 0;
    var container = document.getElementById('learn-questions');
    container.innerHTML = '';
    questions.forEach(function (item, i) {
      var wrap = document.createElement('div');
      wrap.className = 'question-wrap';
      wrap.innerHTML =
        '<div class="question-item">' +
          '<span class="question-num">' + (i + 1) + '</span>' +
          '<span class="question-text">' + escapeHtml(item.q) + '</span>' +
          '<input type="text" class="question-input" data-answer="' + escapeHtml(item.a) + '" placeholder="Your answer...">' +
          '<span class="question-result"></span>' +
        '</div>' +
        '<div class="question-feedback" id="qfb-' + i + '" style="display:none;"></div>';
      container.appendChild(wrap);
    });
    // Remove any leftover Show-Answer button from a previous scenario
    var old = document.getElementById('btn-show-answers');
    if (old) old.remove();
  }

  function isAnswerCorrect(input) {
    var expected = (input.dataset.answer || '').toLowerCase().trim();
    var given = input.value.toLowerCase().trim();
    return given.length >= 2 && (expected === given || expected.indexOf(given) !== -1);
  }

  document.getElementById('btn-submit-answers').addEventListener('click', function () {
    if (!currentScenario) return;
    quizAttempts++;
    var inputs = document.querySelectorAll('#learn-questions .question-input');
    var correctCount = 0;

    inputs.forEach(function (input, i) {
      var result = input.parentElement.querySelector('.question-result');
      var fb = document.getElementById('qfb-' + i);
      var q = currentScenario.questions[i];
      if (isAnswerCorrect(input)) {
        result.textContent = '✓';
        result.style.color = 'var(--green)';
        input.style.borderColor = 'var(--green)';
        fb.style.display = 'none';
        correctCount++;
      } else {
        result.textContent = '✗';
        result.style.color = 'var(--red)';
        input.style.borderColor = 'var(--red)';
        // Attempts 1 & 2 → progressive hints. Attempt 3+ stops hinting (answer revealed via button).
        if (quizAttempts < 3 && q && q.hint) {
          fb.className = 'question-feedback fb-hint';
          fb.innerHTML = '<span class="fb-label">Hint ' + quizAttempts + '</span> ' + escapeHtml(q.hint);
          fb.style.display = 'block';
        }
      }
    });

    // After 3 attempts, offer a "Show Answer" button (with log evidence)
    if (quizAttempts >= 3 && !document.getElementById('btn-show-answers') && correctCount < inputs.length) {
      var btn = document.createElement('button');
      btn.id = 'btn-show-answers';
      btn.className = 'btn-secondary';
      btn.style.marginTop = '12px';
      btn.style.marginLeft = '8px';
      btn.textContent = 'Show Answers';
      btn.addEventListener('click', revealAnswers);
      document.getElementById('btn-submit-answers').insertAdjacentElement('afterend', btn);
    }

    // Unlock intel at >= 60% correct
    if (correctCount >= Math.ceil(inputs.length * 0.6)) {
      document.getElementById('learn-intel-box').classList.remove('intel-locked');
      document.getElementById('intel-lock-overlay').style.display = 'none';
      document.getElementById('intel-content').style.display = 'block';
      document.getElementById('intel-content').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  function revealAnswers() {
    if (!currentScenario) return;
    var inputs = document.querySelectorAll('#learn-questions .question-input');
    inputs.forEach(function (input, i) {
      var q = currentScenario.questions[i];
      var fb = document.getElementById('qfb-' + i);
      if (!q) return;
      var evidence = q.evidence ? '<div class="fb-evidence">' + escapeHtml(q.evidence) + '</div>' : '';
      fb.className = 'question-feedback fb-answer';
      fb.innerHTML = '<span class="fb-label">Answer</span> ' + escapeHtml(q.a) + evidence;
      fb.style.display = 'block';
    });
  }

  function renderIntel(intel) {
    document.getElementById('intel-ioc-list').innerHTML =
      intel.ioc.map(function (t) { return '<li>' + escapeHtml(t) + '</li>'; }).join('');
    document.getElementById('intel-risk-list').innerHTML =
      intel.risk.map(function (t) { return '<li>' + escapeHtml(t) + '</li>'; }).join('');
    document.getElementById('intel-mitigation-list').innerHTML =
      intel.mitigation.map(function (t) { return '<li>' + escapeHtml(t) + '</li>'; }).join('');

    var chain = document.getElementById('intel-attack-chain');
    chain.innerHTML = intel.attackSteps.map(function (s, i) {
      // Optional MITRE chips per step (cross-link to the Frameworks tab)
      var chips = '';
      if (s.mitre && s.mitre.length) {
        chips = s.mitre.map(function (id) {
          return '<span class="chain-mitre" data-mitre="' + escapeHtml(id) + '">' + escapeHtml(id) + '</span>';
        }).join('');
      }
      var html = '<div class="chain-step">' +
        '<span class="chain-num">' + (i + 1) + '</span>' +
        '<span class="chain-phase">' + escapeHtml(s.phase) + '</span>' +
        '<span class="chain-detail">' + escapeHtml(s.detail) + chips + '</span></div>';
      if (i < intel.attackSteps.length - 1) html += '<div class="chain-connector"></div>';
      return html;
    }).join('');

    var fw = intel.frameworks;
    document.getElementById('fw-mitre').innerHTML = fw.mitre.map(function (m) {
      return '<span class="fw-tag fw-tag-mitre" data-fw-id="' + escapeHtml(m.id) + '" title="' + escapeHtml(m.tactic) + '">' + escapeHtml(m.id) + ' ' + escapeHtml(m.name) + '</span>';
    }).join('');

    // Cross-link: clicking a MITRE chip in Attack Steps jumps to Frameworks
    // and flashes the matching technique tag.
    chain.querySelectorAll('.chain-mitre').forEach(function (chip) {
      chip.addEventListener('click', function () {
        var id = chip.dataset.mitre;
        document.querySelector('.intel-tab[data-itab="frameworks"]').click();
        var target = document.querySelector('.fw-tag[data-fw-id="' + id + '"]');
        if (target) {
          document.querySelectorAll('.fw-tag.fw-flash').forEach(function (t) { t.classList.remove('fw-flash'); });
          target.classList.add('fw-flash');
          target.scrollIntoView({ behavior: 'smooth', block: 'center' });
          setTimeout(function () { target.classList.remove('fw-flash'); }, 2000);
        }
      });
    });
    document.getElementById('fw-nist').innerHTML = fw.nist.map(function (n) {
      return '<span class="fw-tag fw-tag-nist">' + escapeHtml(n) + '</span>';
    }).join('');
    document.getElementById('fw-owasp').innerHTML = fw.owasp.map(function (o) {
      return '<span class="fw-tag fw-tag-owasp">' + escapeHtml(o) + '</span>';
    }).join('');

    var cvssClass = 'cvss-' + (fw.cvss.severity || 'medium').toLowerCase();
    document.getElementById('fw-cvss').innerHTML =
      '<span class="fw-tag fw-tag-cvss ' + cvssClass + '">CVSS ' + fw.cvss.score + ' — ' + (fw.cvss.severity || '').toUpperCase() + '</span>' +
      '<br><span style="font-size:11px;color:var(--text-tertiary);font-family:var(--font-mono);margin-top:4px;display:inline-block;">' + escapeHtml(fw.cvss.vector) + '</span>';
  }

  // Learn filter
  var learnFilter = document.getElementById('learn-log-filter');
  learnFilter.addEventListener('input', function () {
    LogViewer.filter(this.value);
    updateLearnFilteredCount();
  });
  document.getElementById('btn-learn-filter-clear').addEventListener('click', function () {
    learnFilter.value = '';
    LogViewer.clearFilter();
    updateLearnFilteredCount();
  });

  // Wrap toggle — shared LogViewer singleton, keep both buttons in sync
  var wrapOn = false;
  function toggleWrap() {
    wrapOn = !wrapOn;
    LogViewer.setWrap(wrapOn);
    ['btn-learn-wrap', 'btn-analyze-wrap'].forEach(function (id) {
      var b = document.getElementById(id);
      if (b) b.classList.toggle('active', wrapOn);
    });
  }
  document.getElementById('btn-learn-wrap').addEventListener('click', toggleWrap);
  document.getElementById('btn-analyze-wrap').addEventListener('click', toggleWrap);

  // Clicking a log line drops a marker on the timeline at that event's time.
  LogViewer.setLineClickHandler(function (line) {
    if (line.timestamp && Timeline.chart) {
      Timeline.highlightTime(line.timestamp);
      showLogContext(currentMode(), 'Marked line ' + line.num + ' (' + fmtDate(line.timestamp) + ') on timeline');
    }
  });

  // Clicking a timeline bar filters the log viewer to that time bucket.
  Timeline.setBarClickHandler(function (start, end) {
    LogViewer.filterByTimeRange(start, end);
    Timeline.highlightTime(start);
    var mode = currentMode();
    var stats = LogViewer.getStats();
    showLogContext(mode, fmtDate(start) + ' – ' + fmtDate(end) + ' · ' + stats.filtered.toLocaleString() + ' events');
    if (mode === 'learn') updateLearnFilteredCount(); else updateAnalyzeFilteredCount();
  });

  // Back / "Show all" — clear any drill-down and return to the full view.
  document.getElementById('learn-context-back').addEventListener('click', function () { clearDrill('learn'); });
  document.getElementById('analyze-context-back').addEventListener('click', function () { clearDrill('analyze'); });
  document.getElementById('btn-learn-zoom-reset').addEventListener('click', function () {
    if (learnTimelineActive) {
      Timeline.resetZoom();
      LogViewer.filterByTimeRange(null, null);
      updateLearnFilteredCount();
      var r = Timeline.getRange();
      if (r) {
        document.getElementById('learn-range-start').textContent = fmtDate(r.start);
        document.getElementById('learn-range-end').textContent = fmtDate(r.end);
      }
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // ANALYZE MODE — file loading
  // ═══════════════════════════════════════════════════════════════════════
  var dropzone = document.getElementById('dropzone');
  var fileInputFolder = document.getElementById('file-input-folder');
  var fileInputFiles = document.getElementById('file-input-files');

  document.getElementById('btn-pick-folder').addEventListener('click', function () {
    if (window.showDirectoryPicker) pickFolderModern();
    else fileInputFolder.click();
  });
  document.getElementById('btn-pick-files').addEventListener('click', function () {
    fileInputFiles.click();
  });

  function pickFolderModern() {
    window.showDirectoryPicker().then(function (dirHandle) {
      var promises = [];
      (function collect(handle) {
        return handle;
      })(dirHandle);
      var files = [];
      var iterate = dirHandle.values();
      function next() {
        return iterate.next().then(function (res) {
          if (res.done) return;
          var entry = res.value;
          if (entry.kind === 'file' && isLogFile(entry.name)) {
            return entry.getFile().then(function (f) { files.push(f); return next(); });
          }
          return next();
        });
      }
      next().then(function () { showFileSelection(files); });
    }).catch(function () { /* cancelled */ });
  }

  fileInputFolder.addEventListener('change', function (e) {
    showFileSelection(Array.prototype.slice.call(e.target.files).filter(function (f) { return isLogFile(f.name); }));
  });
  fileInputFiles.addEventListener('change', function (e) {
    showFileSelection(Array.prototype.slice.call(e.target.files).filter(function (f) { return isLogFile(f.name); }));
  });

  dropzone.addEventListener('dragover', function (e) { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('dragover'); });
  dropzone.addEventListener('drop', function (e) {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    var files = Array.prototype.slice.call(e.dataTransfer.files).filter(function (f) { return isLogFile(f.name); });
    if (files.length) showFileSelection(files);
  });

  function isLogFile(name) {
    if (/\.log$/i.test(name)) return true;
    if (name.indexOf('.') === -1) return true; // extensionless — validated on read
    return false;
  }

  // ---- Pre-load file selection ----
  function showFileSelection(files) {
    if (!files.length) return;
    window._selectedFiles = files;
    var container = document.getElementById('file-list');
    container.innerHTML = '';
    files.forEach(function (file, i) {
      var sizeMB = (file.size / (1024 * 1024)).toFixed(2);
      var div = document.createElement('div');
      div.className = 'file-item';
      div.innerHTML =
        '<input type="checkbox" checked data-index="' + i + '">' +
        '<span class="file-name">' + escapeHtml(file.name) + '</span>' +
        '<div class="file-item-bar"><div class="file-bar-track"><div class="file-bar-fill"></div></div></div>' +
        '<span class="file-pct">0%</span>' +
        '<span class="file-size">' + sizeMB + ' MB</span>';
      container.appendChild(div);
    });
    document.getElementById('file-selection').style.display = 'block';
    container.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
      cb.addEventListener('change', updateSelectionStats);
    });
    updateSelectionStats();
    document.getElementById('file-selection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function updateSelectionStats() {
    var checks = document.querySelectorAll('#file-list input[type="checkbox"]');
    var totalSize = 0, count = 0, maxFile = null, maxSize = 0;
    checks.forEach(function (cb) {
      if (cb.checked && window._selectedFiles) {
        var f = window._selectedFiles[parseInt(cb.dataset.index, 10)];
        totalSize += f.size; count++;
        if (f.size > maxSize) { maxSize = f.size; maxFile = f; }
      }
    });
    var mb = totalSize / (1024 * 1024);
    document.getElementById('selected-count').textContent = count + ' file' + (count !== 1 ? 's' : '');
    document.getElementById('selected-size').textContent = mb.toFixed(1) + ' MB';

    var pct = Math.min((mb / LIMIT_MB) * 100, 100);
    var bar = document.getElementById('preload-bar');
    bar.style.width = pct + '%';
    bar.className = 'preload-bar-fill' + (pct > 90 ? ' danger' : pct > 70 ? ' warn' : '');

    // Per-file proportional bars
    checks.forEach(function (cb) {
      var item = cb.closest('.file-item');
      var fill = item.querySelector('.file-bar-fill');
      var pctSpan = item.querySelector('.file-pct');
      if (cb.checked && totalSize > 0) {
        var fp = Math.round((window._selectedFiles[parseInt(cb.dataset.index, 10)].size / totalSize) * 100);
        fill.style.width = fp + '%';
        pctSpan.textContent = fp + '%';
      } else {
        fill.style.width = '0%';
        pctSpan.textContent = '—';
      }
    });

    // Dominant file warning
    var warning = document.getElementById('preload-warning');
    if (maxFile && count > 1) {
      var dom = Math.round((maxSize / totalSize) * 100);
      if (dom >= 40) {
        warning.textContent = '⚠ ' + maxFile.name + ' is ' + dom + '% of total — consider trimming to the relevant date range for better multi-source coverage.';
        warning.style.display = 'block';
      } else { warning.style.display = 'none'; }
    } else { warning.style.display = 'none'; }

    // Over-limit warning
    if (mb > LIMIT_MB) {
      warning.textContent = '⚠ Total ' + mb.toFixed(0) + ' MB exceeds the ' + LIMIT_MB + ' MB limit. Deselect some files or raise the limit in Settings.';
      warning.style.display = 'block';
    }
  }

  document.getElementById('btn-select-all').addEventListener('click', function () {
    document.querySelectorAll('#file-list input[type="checkbox"]').forEach(function (cb) { cb.checked = true; });
    updateSelectionStats();
  });
  document.getElementById('btn-select-none').addEventListener('click', function () {
    document.querySelectorAll('#file-list input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
    updateSelectionStats();
  });

  // ---- Load selected → read + parse ----
  document.getElementById('btn-load-selected').addEventListener('click', function () {
    var checks = document.querySelectorAll('#file-list input[type="checkbox"]');
    var selected = [];
    checks.forEach(function (cb) {
      if (cb.checked) selected.push(window._selectedFiles[parseInt(cb.dataset.index, 10)]);
    });
    if (!selected.length) return;

    document.getElementById('file-selection').style.display = 'none';
    document.getElementById('load-progress').style.display = 'block';
    loadFiles(selected);
  });

  function loadFiles(files) {
    var results = [];
    var idx = 0;

    function readNext() {
      if (idx >= files.length) { finishLoad(results); return; }
      var file = files[idx];
      document.getElementById('progress-file').textContent = 'Reading ' + file.name + '...';

      var reader = new FileReader();
      reader.onprogress = function (e) {
        if (e.lengthComputable) {
          var filePct = (e.loaded / e.total) * 100;
          var overall = ((idx + filePct / 100) / files.length) * 100;
          setProgress(overall);
        }
      };
      reader.onload = function (e) {
        var text = e.target.result;
        // Yield to the UI, then parse
        setTimeout(function () {
          document.getElementById('progress-file').textContent = 'Parsing ' + file.name + '...';
          var parsed = LogParser.parseFile(text, file.name);
          // Tag each line with its source file
          for (var i = 0; i < parsed.lines.length; i++) parsed.lines[i].source = file.name;
          results.push(parsed);
          idx++;
          setProgress(((idx) / files.length) * 100);
          readNext();
        }, 20);
      };
      reader.onerror = function () { idx++; readNext(); };
      reader.readAsText(file);
    }
    readNext();
  }

  function setProgress(pct) {
    document.getElementById('progress-bar').style.width = pct + '%';
    document.getElementById('progress-pct').textContent = Math.round(pct) + '%';
  }

  function finishLoad(results) {
    // Merge all lines, sort by timestamp
    var allLines = [];
    var startDate = null, endDate = null;
    results.forEach(function (r) {
      allLines = allLines.concat(r.lines);
      if (r.startDate && (!startDate || r.startDate < startDate)) startDate = r.startDate;
      if (r.endDate && (!endDate || r.endDate > endDate)) endDate = r.endDate;
    });
    allLines.sort(function (a, b) {
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return a.timestamp - b.timestamp;
    });

    analyzeData = { lines: allLines, files: results, alerts: [], startDate: startDate, endDate: endDate };

    document.getElementById('load-progress').style.display = 'none';
    renderPostLoadSummary(results, startDate, endDate);
  }

  function renderPostLoadSummary(results, startDate, endDate) {
    var tbody = document.getElementById('postload-files');
    var totalLines = 0;
    tbody.innerHTML = results.map(function (r) {
      totalLines += r.lineCount;
      var range = (r.startDate ? fmtDateShort(r.startDate) : '?') + ' — ' + (r.endDate ? fmtDateShort(r.endDate) : '?');
      var sizeMB = '—';
      return '<tr>' +
        '<td>' + escapeHtml(r.filename) + '</td>' +
        '<td>' + r.lineCount.toLocaleString() + '</td>' +
        '<td>' + range + '</td>' +
        '<td>' + (r._sizeMB || '') + '</td></tr>';
    }).join('');

    var coverage = startDate && endDate
      ? fmtDateShort(startDate) + ' — ' + fmtDateShort(endDate) + ' (' + daysLabel(daysBetween(startDate, endDate)) + ')'
      : 'No timestamps detected';
    document.getElementById('postload-coverage').textContent = coverage;
    document.getElementById('postload-total-lines').textContent = totalLines.toLocaleString();
    document.getElementById('postload-total-range').textContent = startDate && endDate ? daysLabel(daysBetween(startDate, endDate)) : '—';
    document.getElementById('postload-total-size').textContent = '';

    // Coverage-gap warnings
    var warnings = [];
    results.forEach(function (r) {
      if (r.endDate && endDate && (endDate - r.endDate) > 86400000) {
        warnings.push(r.filename + ' ends ' + fmtDateShort(r.endDate) + ' — no data near the end of the overall range');
      }
      if (r.startDate && startDate && (r.startDate - startDate) > 86400000) {
        warnings.push({ info: true, t: r.filename + ' starts ' + fmtDateShort(r.startDate) + ' — later than other sources' });
      }
      if (r.lineCount > 0 && !r.startDate) {
        warnings.push(r.filename + ' has no parseable timestamps — timeline correlation unavailable for this file');
      }
    });
    var wc = document.getElementById('postload-warnings');
    wc.innerHTML = warnings.map(function (w) {
      if (typeof w === 'object' && w.info) return '<div class="postload-warn-item info">' + escapeHtml(w.t) + '</div>';
      return '<div class="postload-warn-item">' + escapeHtml(w) + '</div>';
    }).join('');

    document.getElementById('postload-summary').style.display = 'block';
    document.getElementById('postload-summary').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  document.getElementById('btn-reload-files').addEventListener('click', function () {
    document.getElementById('postload-summary').style.display = 'none';
    document.getElementById('analyze-loader').style.display = 'block';
    document.getElementById('file-selection').style.display = 'none';
  });

  // ---- Load different files → return from workspace to the loader ----
  document.getElementById('btn-load-different').addEventListener('click', function () {
    document.getElementById('analyze-workspace').style.display = 'none';
    document.getElementById('file-selection').style.display = 'none';
    document.getElementById('postload-summary').style.display = 'none';
    document.getElementById('analyze-loader').style.display = 'block';
    document.getElementById('analyze-loader').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  // ---- Start Analysis → run detection, render workspace ----
  document.getElementById('btn-start-analysis').addEventListener('click', function () {
    document.getElementById('postload-summary').style.display = 'none';
    document.getElementById('analyze-loader').style.display = 'none';
    document.getElementById('analyze-workspace').style.display = 'block';

    // Populate the compact loaded-files bar
    var fileCount = analyzeData.files.length;
    var lineTotal = analyzeData.lines.length;
    var rangeTxt = (analyzeData.startDate && analyzeData.endDate)
      ? fmtDateShort(analyzeData.startDate) + ' – ' + fmtDateShort(analyzeData.endDate)
      : 'no timestamps';
    document.getElementById('loaded-summary').textContent =
      fileCount + ' file' + (fileCount !== 1 ? 's' : '') + ' · ' +
      lineTotal.toLocaleString() + ' lines · ' + rangeTxt;

    // Run detection — Layer 1 (rules) + Layer 2 (statistical)
    var alerts = Detection.runAll(analyzeData.lines);
    analyzeData.alerts = alerts;
    renderAlerts(alerts);

    // Build file tabs
    renderFileTabs(analyzeData.files);

    // Render log viewer (merged)
    LogViewer.init('analyze-log-viewer', analyzeData.lines);
    document.getElementById('analyze-log-count').textContent = analyzeData.lines.length.toLocaleString() + ' lines';
    document.getElementById('analyze-log-filtered').textContent = '';

    // Render timeline
    if (analyzeTimelineActive) Timeline.destroy();
    Timeline.create('analyze-timeline-chart', analyzeData.lines, function (start, end) {
      LogViewer.filterByTimeRange(start, end);
      document.getElementById('analyze-range-start').textContent = fmtDate(start);
      document.getElementById('analyze-range-end').textContent = fmtDate(end);
      showLogContext('analyze', 'Zoomed: ' + fmtDate(start) + ' – ' + fmtDate(end));
      updateAnalyzeFilteredCount();
    });
    analyzeTimelineActive = true;
    if (analyzeData.startDate) document.getElementById('analyze-range-start').textContent = fmtDate(analyzeData.startDate);
    if (analyzeData.endDate) document.getElementById('analyze-range-end').textContent = fmtDate(analyzeData.endDate);

    document.getElementById('analyze-workspace').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  var SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };
  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  function lineByNum(num) {
    for (var i = 0; i < analyzeData.lines.length; i++) {
      if (analyzeData.lines[i].num === num) return analyzeData.lines[i];
    }
    return null;
  }

  // Jump the log viewer + timeline to an alert's matches and highlight them.
  function focusAlert(alert) {
    var matches = alert.matches || alert.evidence || [];
    if (!matches.length) return;
    var nums = matches.map(function (m) { return m.lineNum; });
    LogViewer.scrollToLine(matches[0].lineNum);
    LogViewer.clearHighlights();
    LogViewer.highlightLines(nums, 'hl-alert');
    var ln = lineByNum(matches[0].lineNum);
    if (ln && ln.timestamp && analyzeTimelineActive) Timeline.highlightTime(ln.timestamp);
  }

  // Build the threshold-vs-observed snapshot from an alert's stats.
  function buildSnapshot(alert) {
    var s = alert.stats;
    if (!s) return '';
    var rows = [];
    if (s.kind === 'count') {
      var max = Math.max(s.threshold, s.observed) || 1;
      rows = [
        { label: 'Triggers at ≥ ' + s.threshold + ' ' + s.label, w: Math.round(s.threshold / max * 100), cls: 'snap-threshold' },
        { label: 'Observed: ' + s.observed + ' ' + s.label, w: Math.round(s.observed / max * 100), cls: 'snap-observed' }
      ];
    } else if (s.kind === 'rate') {
      var max2 = Math.max(s.expected, s.threshold, s.observed) || 1;
      rows = [
        { label: 'Baseline (normal): ' + s.expected + ' ' + s.label, w: Math.round(s.expected / max2 * 100), cls: 'snap-baseline' },
        { label: 'Alert threshold: ' + s.threshold + ' ' + s.label, w: Math.round(s.threshold / max2 * 100), cls: 'snap-threshold' },
        { label: 'Observed peak: ' + s.observed + ' ' + s.label, w: Math.round(s.observed / max2 * 100), cls: 'snap-observed' }
      ];
    } else {
      return '';
    }
    return '<div class="snapshot"><div class="snapshot-title">Trigger snapshot</div>' +
      rows.map(function (r) {
        return '<div class="snap-row"><span class="snap-label">' + escapeHtml(r.label) + '</span>' +
          '<div class="snap-bar-track"><div class="snap-bar ' + r.cls + '" style="width:' + r.w + '%"></div></div></div>';
      }).join('') + '</div>';
  }

  // Extract concrete indicators (IPs, line range) from an alert's matches.
  function extractIoc(alert) {
    var matches = alert.matches || alert.evidence || [];
    var ips = {}, out = [];
    var ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    matches.forEach(function (m) {
      var mm; ipRe.lastIndex = 0;
      while ((mm = ipRe.exec(m.text || '')) !== null) { ips[mm[1]] = (ips[mm[1]] || 0) + 1; }
    });
    Object.keys(ips).slice(0, 3).forEach(function (ip) {
      out.push('Source observed in this detection: ' + ip + ' (' + ips[ip] + ' events)');
    });
    if (matches.length) {
      var nums = matches.map(function (m) { return m.lineNum; });
      out.push('Evidence at lines ' + Math.min.apply(null, nums) + '–' + Math.max.apply(null, nums) + ' (' + matches.length + ' total)');
    }
    return out;
  }

  // Build the full detection-details panel for one alert.
  function buildDetail(alert, gi, mi) {
    var key = alert.ruleId || alert.type;
    var enr = (typeof DETECTION_ENRICHMENT !== 'undefined' && DETECTION_ENRICHMENT[key]) || {};
    var why = alert.description || 'This event matched the detection signature.';

    var listHtml = function (arr) {
      return (arr && arr.length)
        ? '<ul class="detail-list">' + arr.map(function (x) { return '<li>' + escapeHtml(x) + '</li>'; }).join('') + '</ul>'
        : '<span class="detail-empty">—</span>';
    };

    var iocHtml = listHtml((enr.ioc || []).concat(extractIoc(alert)));
    var mitiHtml = listHtml(enr.mitigation);
    var impactHtml = enr.impact ? escapeHtml(enr.impact) : '<span class="detail-empty">—</span>';

    var fw = '';
    (alert.mitre || []).forEach(function (id) { fw += '<span class="fw-tag fw-tag-mitre">' + escapeHtml(id) + '</span>'; });
    (enr.nist || []).forEach(function (n) { fw += '<span class="fw-tag fw-tag-nist">' + escapeHtml(n) + '</span>'; });
    (enr.owasp || []).forEach(function (o) { fw += '<span class="fw-tag fw-tag-owasp">' + escapeHtml(o) + '</span>'; });
    if (enr.cvss) {
      var cc = 'cvss-' + (enr.cvss.severity || 'medium').toLowerCase();
      fw += '<span class="fw-tag fw-tag-cvss ' + cc + '" title="' + escapeHtml(enr.cvss.vector || '') + '">CVSS ' + enr.cvss.score + ' ' + (enr.cvss.severity || '').toUpperCase() + '</span>';
    }
    if (!fw) fw = '<span class="detail-empty">—</span>';

    var jumpAttrs = 'data-g="' + gi + '"' + (mi != null ? ' data-m="' + mi + '"' : '');

    return '<div class="detail-inner">' +
      '<div class="detail-why"><span class="detail-why-label">Why it triggered</span>' + escapeHtml(why) + '</div>' +
      buildSnapshot(alert) +
      '<div class="detail-grid">' +
        '<div class="detail-block"><h5>Indicators of Compromise</h5>' + iocHtml + '</div>' +
        '<div class="detail-block"><h5>Impact</h5><p class="detail-impact">' + impactHtml + '</p></div>' +
        '<div class="detail-block"><h5>Mitigation</h5>' + mitiHtml + '</div>' +
        '<div class="detail-block"><h5>Frameworks</h5><div class="detail-fw">' + fw + '</div></div>' +
      '</div>' +
      '<button class="btn-secondary detail-jump" ' + jumpAttrs + '>Jump to logs →</button>' +
      '</div>';
  }

  function renderAlerts(alerts) {
    var list = document.getElementById('alert-list');
    if (!alerts.length) {
      list.innerHTML = '<div class="alert-item alert-low"><span class="alert-severity">OK</span><span class="alert-title">No threats detected by rule or statistical layers</span></div>';
      return;
    }

    // Group alerts by rule id / anomaly type so repeated detections collapse
    // into one expandable row. The timeline is independent of this grouping —
    // it is built from all log lines, so grouping never affects it.
    var groups = [];
    var byKey = {};
    alerts.forEach(function (a) {
      var key = a.ruleId || a.type || a.name;
      if (!byKey[key]) { byKey[key] = { key: key, members: [], tag: a.tag }; groups.push(byKey[key]); }
      byKey[key].members.push(a);
    });

    var html = groups.map(function (g, gi) {
      var sev = g.members[0].severity;
      var totalHits = 0;
      g.members.forEach(function (m) {
        if (SEV_RANK[m.severity] < SEV_RANK[sev]) sev = m.severity;
        totalHits += (m.matches || m.evidence || []).length;
      });
      var baseName = g.members[0].name.replace(/\s*\([^)]*\)\s*$/, '');
      var tagClass = g.tag === 'RULE' ? 'dtag-rule' : g.tag === 'STAT' ? 'dtag-behavior' : 'dtag-ml';
      var tagLabel = g.tag; // RULE / STAT / AI
      var multi = g.members.length > 1;

      var srcInfo = multi
        ? (g.members.length + ' sources · ' + totalHits + ' hits')
        : (function () { var mm = g.members[0].matches || g.members[0].evidence || []; return mm.length ? ('line ' + mm[0].lineNum + ' · ' + mm.length + ' hits') : ''; })();

      var header = '<div class="alert-item alert-' + sev + ' alert-clickable" data-group="' + gi + '">' +
        '<span class="alert-severity">' + (SEV_LABEL[sev] || sev) + '</span>' +
        '<span class="alert-chevron">&#9654;</span>' +
        '<span class="alert-title">' + escapeHtml(baseName) + '</span>' +
        '<span class="alert-source">' + srcInfo + '</span>' +
        '<span class="alert-tag dtag ' + tagClass + '">' + tagLabel + '</span></div>';

      var body;
      if (multi) {
        // Header expands occurrence rows; each occurrence expands its own detail.
        body = '<div class="alert-occurrences" id="occ-' + gi + '" style="display:none;">' +
          g.members.map(function (m, mi) {
            var mm2 = m.matches || m.evidence || [];
            var fl = mm2.length ? mm2[0].lineNum : '';
            var sub = m.name.replace(baseName, '').replace(/^\s*\(|\)\s*$/g, '').trim() || m.name;
            return '<div class="alert-occ" data-g="' + gi + '" data-m="' + mi + '">' +
                '<span class="alert-chevron">&#9654;</span>' +
                '<span class="occ-label">' + escapeHtml(sub) + '</span>' +
                '<span class="occ-meta">line ' + fl + ' · ' + mm2.length + ' hits</span></div>' +
              '<div class="alert-detail" id="detail-' + gi + '-' + mi + '" style="display:none;">' + buildDetail(m, gi, mi) + '</div>';
          }).join('') + '</div>';
      } else {
        // Header expands the single detail panel directly.
        body = '<div class="alert-detail" id="detail-' + gi + '" style="display:none;">' + buildDetail(g.members[0], gi, null) + '</div>';
      }
      return header + body;
    }).join('');
    list.innerHTML = html;

    function toggle(el, panel) {
      var open = panel.style.display !== 'none';
      panel.style.display = open ? 'none' : 'block';
      el.classList.toggle('open', !open);
    }

    // Header click: multi → toggle occurrences; single → toggle detail panel
    list.querySelectorAll('.alert-item').forEach(function (el) {
      el.addEventListener('click', function () {
        var gi = el.dataset.group;
        var g = groups[parseInt(gi, 10)];
        if (!g) return;
        toggle(el, document.getElementById(g.members.length > 1 ? 'occ-' + gi : 'detail-' + gi));
      });
    });

    // Occurrence click: toggle that member's detail panel
    list.querySelectorAll('.alert-occ').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.stopPropagation();
        toggle(el, document.getElementById('detail-' + el.dataset.g + '-' + el.dataset.m));
      });
    });

    // "Jump to logs" inside a detail panel
    list.querySelectorAll('.detail-jump').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var g = groups[parseInt(btn.dataset.g, 10)];
        if (!g) return;
        var alert = btn.dataset.m != null ? g.members[parseInt(btn.dataset.m, 10)] : g.members[0];
        focusAlert(alert);
      });
    });
  }

  function renderFileTabs(files) {
    var tabs = document.getElementById('log-file-tabs');
    var html = '<button class="file-tab active" data-file="all">All (merged)</button>';
    files.forEach(function (r) {
      html += '<button class="file-tab" data-file="' + escapeHtml(r.filename) + '">' + escapeHtml(r.filename) + '</button>';
    });
    tabs.innerHTML = html;
    tabs.querySelectorAll('.file-tab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        tabs.querySelectorAll('.file-tab').forEach(function (t) { t.classList.remove('active'); });
        tab.classList.add('active');
        activeFileTab = tab.dataset.file;
        var lines = activeFileTab === 'all'
          ? analyzeData.lines
          : analyzeData.lines.filter(function (l) { return l.source === activeFileTab; });
        LogViewer.setLines(lines);
        document.getElementById('analyze-log-count').textContent = lines.length.toLocaleString() + ' lines';
        updateAnalyzeFilteredCount();
      });
    });
  }

  function updateAnalyzeFilteredCount() {
    var stats = LogViewer.getStats();
    var el = document.getElementById('analyze-log-filtered');
    el.textContent = stats.filtered < stats.total ? '(' + stats.filtered.toLocaleString() + ' shown)' : '';
  }

  var analyzeFilter = document.getElementById('analyze-log-filter');
  analyzeFilter.addEventListener('input', function () {
    LogViewer.filter(this.value);
    updateAnalyzeFilteredCount();
  });
  document.getElementById('btn-analyze-filter-clear').addEventListener('click', function () {
    analyzeFilter.value = '';
    LogViewer.clearFilter();
    updateAnalyzeFilteredCount();
  });
  document.getElementById('btn-analyze-zoom-reset').addEventListener('click', function () {
    if (analyzeTimelineActive) {
      Timeline.resetZoom();
      LogViewer.filterByTimeRange(null, null);
      updateAnalyzeFilteredCount();
      var r = Timeline.getRange();
      if (r) {
        document.getElementById('analyze-range-start').textContent = fmtDate(r.start);
        document.getElementById('analyze-range-end').textContent = fmtDate(r.end);
      }
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // SETTINGS
  // ═══════════════════════════════════════════════════════════════════════
  var aiProvider = document.getElementById('ai-provider');
  aiProvider.addEventListener('change', function () {
    var isNone = aiProvider.value === 'none';
    document.getElementById('ai-key-group').style.display = isNone ? 'none' : 'block';
    document.getElementById('ai-model-group').style.display = isNone ? 'none' : 'block';
    document.getElementById('ai-actions').style.display = isNone ? 'none' : 'flex';
    document.getElementById('privacy-notice').style.display = isNone ? 'none' : 'flex';
    document.getElementById('ai-localonly-toggle').style.display = isNone ? 'none' : 'block';

    // Layer 3 badge tracks the connection state. The four feature cards stay
    // "Coming Soon" regardless — their actions aren't wired to the model yet.
    var layerBadge = document.getElementById('layer4-badge');
    if (isNone) {
      layerBadge.textContent = 'OFF';
      layerBadge.className = 'layer-badge layer-off';
    } else {
      layerBadge.textContent = 'ON';
      layerBadge.className = 'layer-badge layer-on';
    }

    if (aiProvider.value === 'openai') {
      document.getElementById('ai-key').placeholder = 'sk-...';
      document.getElementById('ai-model').innerHTML =
        '<option value="gpt-4o">gpt-4o</option><option value="gpt-4o-mini">gpt-4o-mini</option>';
    } else if (aiProvider.value === 'claude') {
      document.getElementById('ai-key').placeholder = 'sk-ant-...';
      document.getElementById('ai-model').innerHTML =
        '<option value="claude-sonnet-4-6">claude-sonnet-4-6</option><option value="claude-haiku-4-5">claude-haiku-4-5</option>';
    }
  });

  // ---- AI config: persistence + connection test ----
  var aiStatus = document.getElementById('ai-status');
  function setAiStatus(text, cls) {
    if (!aiStatus) return;
    aiStatus.textContent = text;
    aiStatus.className = 'ai-status' + (cls ? ' ' + cls : '');
  }

  // Restore saved AI config on load (this is what makes the session "stick"
  // across reloads / tab switches). Stored in localStorage — a standalone
  // local tool, so the key lives only in this browser and is sent only to the
  // chosen provider.
  (function restoreAiConfig() {
    var saved;
    try { saved = JSON.parse(localStorage.getItem('logsight_ai') || 'null'); } catch (e) { saved = null; }
    if (!saved || !saved.provider || saved.provider === 'none') return;
    aiProvider.value = saved.provider;
    aiProvider.dispatchEvent(new Event('change')); // rebuilds model list + ON state
    if (saved.model) document.getElementById('ai-model').value = saved.model;
    if (saved.key) document.getElementById('ai-key').value = saved.key;
    document.getElementById('ai-localonly').checked = !!saved.localOnly;
    setAiStatus('Restored saved config', 'ok');
  })();

  var btnSaveAi = document.getElementById('btn-save-ai');
  if (btnSaveAi) {
    btnSaveAi.addEventListener('click', function () {
      try {
        localStorage.setItem('logsight_ai', JSON.stringify({
          provider: aiProvider.value,
          model: document.getElementById('ai-model').value,
          key: document.getElementById('ai-key').value,
          localOnly: document.getElementById('ai-localonly').checked
        }));
        setAiStatus('Saved ✓ (persists in this browser)', 'ok');
      } catch (e) {
        setAiStatus('Save failed: ' + e.message, 'err');
      }
    });
  }

  var btnTestAi = document.getElementById('btn-test-ai');
  if (btnTestAi) {
    btnTestAi.addEventListener('click', function () {
      var provider = aiProvider.value;
      var key = document.getElementById('ai-key').value.trim();
      var model = document.getElementById('ai-model').value;
      if (!key) { setAiStatus('Enter an API key first', 'err'); return; }
      setAiStatus('Testing…', 'pending');

      var url, headers, body;
      if (provider === 'claude') {
        url = 'https://api.anthropic.com/v1/messages';
        headers = {
          'content-type': 'application/json',
          'x-api-key': key,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        };
        body = JSON.stringify({ model: model, max_tokens: 8, messages: [{ role: 'user', content: 'ping' }] });
      } else { // openai
        url = 'https://api.openai.com/v1/chat/completions';
        headers = { 'content-type': 'application/json', 'authorization': 'Bearer ' + key };
        body = JSON.stringify({ model: model, max_tokens: 8, messages: [{ role: 'user', content: 'ping' }] });
      }

      fetch(url, { method: 'POST', headers: headers, body: body })
        .then(function (res) {
          if (res.ok) {
            setAiStatus('✓ Connected to ' + provider + ' (' + model + ')', 'ok');
          } else {
            return res.json().then(function (j) {
              var msg = (j && j.error && j.error.message) ? j.error.message : ('HTTP ' + res.status);
              setAiStatus('✗ ' + res.status + ': ' + msg, 'err');
            }).catch(function () { setAiStatus('✗ HTTP ' + res.status, 'err'); });
          }
        })
        .catch(function (e) {
          // A TypeError here usually means the browser blocked the request (CORS)
          setAiStatus('✗ Request blocked or network error (' + e.message + ')', 'err');
        });
    });
  }

  // Pseudonymizer mapping table viewer
  var btnViewMapping = document.getElementById('btn-view-mapping');
  if (btnViewMapping) {
    btnViewMapping.addEventListener('click', function () {
      // Build a sample mapping from currently loaded logs (or scenario)
      Pseudonymizer.reset();
      var sample = analyzeData.lines.length
        ? analyzeData.lines.slice(0, 500).map(function (l) { return l.raw; }).join('\n')
        : (currentScenario ? currentScenario.logs.join('\n') : '');
      Pseudonymizer.process(sample);
      var mapping = Pseudonymizer.getMapping();
      showMappingModal(mapping);
    });
  }

  function showMappingModal(mapping) {
    var existing = document.getElementById('mapping-modal');
    if (existing) existing.remove();

    var modal = document.createElement('div');
    modal.id = 'mapping-modal';
    modal.className = 'modal-overlay';
    var rows = mapping.length
      ? mapping.map(function (m) {
          return '<tr><td>' + escapeHtml(m.type) + '</td><td>' + escapeHtml(m.real) + '</td><td>→</td><td class="map-dummy">' + escapeHtml(m.dummy) + '</td></tr>';
        }).join('')
      : '<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);">Load logs first to generate a mapping preview</td></tr>';
    modal.innerHTML =
      '<div class="modal-box">' +
        '<div class="modal-header"><h3>Pseudonymization Mapping</h3><button class="modal-close" id="modal-close">✕</button></div>' +
        '<p class="modal-desc">Real values (left) are replaced with consistent dummy values (right) before any data is sent to the AI provider. This table stays in your browser.</p>' +
        '<div class="modal-body"><table class="mapping-table"><thead><tr><th>Type</th><th>Real</th><th></th><th>Dummy</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
      '</div>';
    document.body.appendChild(modal);
    document.getElementById('modal-close').addEventListener('click', function () { modal.remove(); });
    modal.addEventListener('click', function (e) { if (e.target === modal) modal.remove(); });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // AI FEATURES (Layer 3) — wired to the live LLM via the AI module
  // ═══════════════════════════════════════════════════════════════════════
  function aiReady() { return typeof AI !== 'undefined' && AI.isReady(); }

  // Show/hide AI affordances based on whether a provider is connected.
  function updateAiUi() {
    var ready = aiReady();
    var panel = document.getElementById('ai-analyst');
    if (panel) panel.style.display = ready ? 'block' : 'none';
    var hintBtn = document.getElementById('btn-ai-hint');
    if (hintBtn) hintBtn.style.display = ready ? 'inline-block' : 'none';
    document.querySelectorAll('.feature-card').forEach(function (f) {
      f.classList.toggle('active', ready);
      f.classList.toggle('locked', !ready);
      var ic = f.querySelector('.feature-lock, .feature-check');
      if (ic) {
        if (ready) { ic.className = 'feature-check'; ic.innerHTML = '✓'; }
        else { ic.className = 'feature-lock'; ic.innerHTML = '&#128274;'; }
      }
    });
  }

  // Light Markdown → HTML for AI output (the container is white-space: pre-wrap).
  function mdLite(text) {
    var html = escapeHtml(text);
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/^#{1,6}\s*(.+)$/gm, '<span class="ai-h">$1</span>');
    return html;
  }

  function setAiResult(el, text, cls) {
    if (!el) return;
    el.className = 'ai-result' + (cls ? ' ' + cls : '');
    el.innerHTML = (cls === 'pending') ? escapeHtml(text) : mdLite(text);
    el.style.display = 'block';
  }

  // Build the pseudonymizable text context the model reasons over.
  function buildFindingsContext() {
    var d = analyzeData;
    var L = [];
    L.push('Dataset: ' + d.files.length + ' file(s), ' + d.lines.length + ' log lines.');
    if (d.startDate && d.endDate) L.push('Time range: ' + fmtDate(d.startDate) + ' – ' + fmtDate(d.endDate) + '.');
    L.push('Detections: ' + d.alerts.length);
    d.alerts.forEach(function (a) {
      var m = a.matches || a.evidence || [];
      L.push('- [' + (a.severity || '').toUpperCase() + '] ' + a.name + ' (' + a.tag + ', ' + m.length + ' hits)' + (a.description ? (' — ' + a.description) : ''));
      if (typeof AI !== 'undefined' && !AI.isLocalOnly()) {
        m.slice(0, 3).forEach(function (x) {
          var ln = lineByNum(x.lineNum);
          if (ln) L.push('    L' + x.lineNum + ': ' + (ln.raw || '').slice(0, 200));
        });
      }
    });
    return L.join('\n');
  }

  // No-AI fallback report so the Report button works offline too.
  function buildTemplateReport() {
    var d = analyzeData;
    if (!d.lines.length) return 'No logs loaded. Open Analyze mode, load log files, run the analysis, then generate a report.';
    var L = [];
    L.push('# Incident Report');
    L.push('');
    L.push('_Generated by LogSight · ' + new Date().toLocaleString() + '_');
    L.push('');
    L.push('## Dataset');
    L.push('- Files: ' + d.files.map(function (f) { return f.filename; }).join(', '));
    L.push('- Lines: ' + d.lines.length.toLocaleString());
    if (d.startDate && d.endDate) L.push('- Range: ' + fmtDate(d.startDate) + ' – ' + fmtDate(d.endDate));
    L.push('');
    L.push('## Detections (' + d.alerts.length + ')');
    d.alerts.forEach(function (a) {
      var m = a.matches || a.evidence || [];
      L.push('- [' + (a.severity || '').toUpperCase() + '] ' + a.name + ' — ' + m.length + ' hits (' + a.tag + ')' + (a.mitre && a.mitre.length ? (' · MITRE ' + a.mitre.join(', ')) : ''));
    });
    L.push('');
    L.push('_Connect an AI provider in Settings for a full narrative report (summary, timeline, IoC, recommended actions)._');
    return L.join('\n');
  }

  // ---- Summarize findings ----
  var btnAiSummarize = document.getElementById('btn-ai-summarize');
  if (btnAiSummarize) btnAiSummarize.addEventListener('click', function () {
    var el = document.getElementById('ai-result');
    if (!analyzeData.lines.length) { setAiResult(el, 'Run an analysis first.', 'err'); return; }
    setAiResult(el, 'Summarizing…', 'pending');
    AI.ask('You are a senior SOC analyst. Summarize these log findings concisely: what happened, the overall severity, and the top 3 priorities to act on. Plain language, no preamble.',
      buildFindingsContext(), { maxTokens: 700 })
      .then(function (t) { setAiResult(el, t); })
      .catch(function (e) { setAiResult(el, 'Error: ' + e.message, 'err'); });
  });

  // ---- Natural language query ----
  function doAiAsk() {
    var input = document.getElementById('ai-query-input');
    var q = input.value.trim();
    var el = document.getElementById('ai-result');
    if (!q) return;
    if (!analyzeData.lines.length) { setAiResult(el, 'Run an analysis first.', 'err'); return; }
    setAiResult(el, 'Thinking…', 'pending');
    AI.ask('You are a SOC analyst assistant. Answer the question using ONLY the provided findings. If the answer is not present in them, say so. Be concise.',
      'FINDINGS:\n' + buildFindingsContext() + '\n\nQUESTION: ' + q, { maxTokens: 700 })
      .then(function (t) { setAiResult(el, t); })
      .catch(function (e) { setAiResult(el, 'Error: ' + e.message, 'err'); });
  }
  var btnAiAsk = document.getElementById('btn-ai-ask');
  if (btnAiAsk) btnAiAsk.addEventListener('click', doAiAsk);
  var aiQueryInput = document.getElementById('ai-query-input');
  if (aiQueryInput) aiQueryInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') doAiAsk(); });

  // ---- Incident report (analyst button + footer Report button) ----
  function generateReport() {
    if (aiReady() && analyzeData.lines.length) {
      showTextModal('Incident Report', 'Generating report…', true);
      AI.ask('You are an incident responder. Write a concise incident report in Markdown with these sections: Summary, Timeline, Affected Systems, Indicators of Compromise, Recommended Actions. Base it strictly on the findings provided; do not invent data.',
        buildFindingsContext(), { maxTokens: 1500 })
        .then(function (t) { showTextModal('Incident Report', t); })
        .catch(function (e) { showTextModal('Incident Report', 'Error generating report: ' + e.message); });
    } else {
      showTextModal('Incident Report', buildTemplateReport());
    }
  }
  var btnAiReport = document.getElementById('btn-ai-report');
  if (btnAiReport) btnAiReport.addEventListener('click', generateReport);
  var btnExportReport = document.getElementById('btn-export-report');
  if (btnExportReport) btnExportReport.addEventListener('click', generateReport);

  // ---- Adaptive hint (Learn mode) ----
  var btnAiHint = document.getElementById('btn-ai-hint');
  if (btnAiHint) btnAiHint.addEventListener('click', function () {
    var el = document.getElementById('learn-ai-result');
    if (!currentScenario) { setAiResult(el, 'Load a scenario first.', 'err'); return; }
    setAiResult(el, 'Thinking of a hint…', 'pending');
    var ctx = 'Scenario: ' + currentScenario.title + '\n' + currentScenario.description +
      '\n\nLog sample:\n' + currentScenario.logs.slice(0, 40).join('\n');
    AI.ask('You are a patient cybersecurity instructor. Give ONE short, specific hint to help the student investigate this scenario. Do NOT reveal the final answers — nudge them toward the right log lines or technique.',
      ctx, { maxTokens: 250 })
      .then(function (t) { setAiResult(el, t); })
      .catch(function (e) { setAiResult(el, 'Error: ' + e.message, 'err'); });
  });

  // ---- Text/report modal with copy + download ----
  function showTextModal(title, text, pending) {
    var ex = document.getElementById('text-modal'); if (ex) ex.remove();
    var modal = document.createElement('div');
    modal.id = 'text-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML =
      '<div class="modal-box">' +
        '<div class="modal-header"><h3>' + escapeHtml(title) + '</h3><button class="modal-close" id="tm-close">✕</button></div>' +
        '<div class="modal-body"><div class="ai-result' + (pending ? ' pending' : '') + '" style="border:none;background:transparent;margin:0;padding:0;">' +
          (pending ? escapeHtml(text) : mdLite(text)) + '</div></div>' +
        '<div class="modal-actions"><button class="btn-secondary" id="tm-copy">Copy</button><button class="btn-secondary" id="tm-download">Download .md</button></div>' +
      '</div>';
    document.body.appendChild(modal);
    document.getElementById('tm-close').addEventListener('click', function () { modal.remove(); });
    modal.addEventListener('click', function (e) { if (e.target === modal) modal.remove(); });
    document.getElementById('tm-copy').addEventListener('click', function () {
      if (navigator.clipboard) navigator.clipboard.writeText(text);
      this.textContent = 'Copied';
      var b = this; setTimeout(function () { b.textContent = 'Copy'; }, 1200);
    });
    document.getElementById('tm-download').addEventListener('click', function () {
      var blob = new Blob([text], { type: 'text/markdown' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = title.replace(/\s+/g, '_') + '.md'; a.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
  }

  // Keep AI UI in sync with provider/save changes and on load.
  aiProvider.addEventListener('change', updateAiUi);
  if (btnSaveAi) btnSaveAi.addEventListener('click', function () { setTimeout(updateAiUi, 0); });
  updateAiUi();

  // ---- Max upload limit slider + perf impact ----
  var maxUploadSlider = document.getElementById('max-upload');
  var maxUploadValue = document.getElementById('max-upload-value');

  function updatePerfImpact(mb) {
    var cpuPct = Math.round(15 + (mb - 100) * (60 / 900));
    var memMB = Math.round(mb * 1.8 + 80);
    var memPct = Math.round((memMB / 4096) * 100);
    var level = mb <= 500 ? 'ok' : mb <= 700 ? 'warn' : 'danger';
    var speedLabel = mb <= 500 ? 'Smooth' : mb <= 700 ? 'Noticeable' : mb <= 850 ? 'Degraded' : 'Heavy';
    var speedPct = mb <= 200 ? 20 : mb <= 500 ? 35 : mb <= 700 ? 55 : mb <= 850 ? 75 : 90;

    var parseTime = mb <= 100 ? '< 1s' : mb <= 200 ? '~1-2s' : mb <= 400 ? '~3-5s' : mb <= 600 ? '~5-10s' : mb <= 800 ? '~10-20s' : '~20-30s';
    var filterTime = mb <= 100 ? 'instant' : mb <= 200 ? '< 0.5s' : mb <= 400 ? '~0.5s' : mb <= 600 ? '~1-2s' : mb <= 800 ? '~2-5s' : '~5-10s';
    var chartTime = mb <= 500 ? 'instant' : mb <= 700 ? '~0.5s' : mb <= 850 ? '~1-2s' : '~2-3s';
    var mlTime = mb <= 100 ? '~2-3s' : mb <= 200 ? '~3-5s' : mb <= 400 ? '~5-8s' : mb <= 600 ? '~8-15s' : mb <= 800 ? '~15-25s' : '~25-40s';

    var estClass = function (val) {
      if (/instant|< 1s|< 0\.5s|~1-2s|~2-3s|~3-5s/.test(val)) return 'est-ok';
      if (/~0\.5s|~5-8s|~5-10s|~8-15s/.test(val)) return 'est-warn';
      return 'est-danger';
    };

    var cpuLevel = cpuPct <= 35 ? 'level-ok' : cpuPct <= 55 ? 'level-warn' : 'level-danger';
    var memLevel = memPct <= 25 ? 'level-ok' : memPct <= 40 ? 'level-warn' : 'level-danger';
    var speedClass = level === 'ok' ? 'level-ok' : level === 'warn' ? 'level-warn' : 'level-danger';

    document.getElementById('perf-cpu-bar').style.width = cpuPct + '%';
    document.getElementById('perf-cpu-bar').className = 'perf-bar-fill perf-cpu ' + cpuLevel;
    document.getElementById('perf-cpu-value').textContent = cpuPct + '%';
    document.getElementById('perf-mem-bar').style.width = memPct + '%';
    document.getElementById('perf-mem-bar').className = 'perf-bar-fill perf-mem ' + memLevel;
    document.getElementById('perf-mem-value').textContent = memMB >= 1024 ? (memMB / 1024).toFixed(1) + ' GB' : '~' + memMB + ' MB';
    document.getElementById('perf-speed-bar').style.width = speedPct + '%';
    document.getElementById('perf-speed-bar').className = 'perf-bar-fill perf-speed ' + speedClass;
    document.getElementById('perf-speed-value').textContent = speedLabel;

    var setEst = function (id, val) {
      var el = document.getElementById(id);
      el.textContent = val;
      el.className = 'perf-est-value ' + estClass(val);
    };
    setEst('perf-parse', parseTime);
    setEst('perf-filter', filterTime);
    setEst('perf-chart', chartTime);
    setEst('perf-ml', mlTime);
  }

  if (maxUploadSlider) {
    maxUploadSlider.addEventListener('input', function () {
      var val = parseInt(this.value, 10);
      maxUploadValue.textContent = val >= 1000 ? '1 GB' : val + ' MB';
      LIMIT_MB = val;
      updatePerfImpact(val);
    });
    updatePerfImpact(500);
  }

  // ---- Keyboard shortcuts ----
  document.addEventListener('keydown', function (e) {
    if (e.ctrlKey && (e.key === 'f' || e.key === 'F')) {
      var active = document.querySelector('.tab-content.active');
      if (active) {
        var filter = active.querySelector('.log-filter-bar input');
        if (filter) { e.preventDefault(); filter.focus(); }
      }
    } else if (e.key === 'Escape') {
      var modal = document.getElementById('mapping-modal');
      if (modal) modal.remove();
    } else if (!e.ctrlKey && !e.metaKey && !e.altKey && /^[1-4]$/.test(e.key) &&
               document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT' && document.activeElement.tagName !== 'TEXTAREA') {
      var tabs = ['learn', 'analyze', 'guide', 'settings'];
      switchTab(tabs[parseInt(e.key, 10) - 1]);
    }
  });

});
