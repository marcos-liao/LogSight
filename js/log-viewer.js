/* log-viewer.js -- Virtual-scrolling log viewer for LogSight
 * No external dependencies.
 */
var LogViewer = {

  _container: null,
  _viewport:  null,
  _spacerTop: null,
  _spacerBot: null,
  _content:   null,

  _allLines:        [],   // full dataset
  _filteredLines:   [],   // after regex / time-range filter
  _highlightedNums: {},   // lineNum -> className
  _filterQuery:     null, // current RegExp or null
  _timeStart:       null, // Date or null
  _timeEnd:         null, // Date or null

  LINE_HEIGHT: 20,
  BUFFER:      50,
  _lastFirst:  -1,
  _lastLast:   -1,
  _multiSource: false,
  _scrollHandler: null,
  _wrap:        false,

  /* ------------------------------------------------------------------ */
  /*  init()                                                             */
  /* ------------------------------------------------------------------ */
  init: function (containerId, lines) {
    var container = document.getElementById(containerId);
    if (!container) return;

    this._container = container;
    this._allLines  = lines || [];
    this._filteredLines = this._allLines;
    this._filterQuery   = null;
    this._timeStart     = null;
    this._timeEnd       = null;
    this._highlightedNums = {};

    // Detect multi-source
    var sources = {};
    for (var i = 0; i < this._allLines.length; i++) {
      if (this._allLines[i].source) sources[this._allLines[i].source] = true;
    }
    this._multiSource = Object.keys(sources).length > 1;

    // Build DOM scaffold
    container.innerHTML = '';
    container.style.position = 'relative';
    container.style.overflow = 'auto';
    container.classList.toggle('wrap', this._wrap); // preserve wrap mode across inits

    this._spacerTop = document.createElement('div');
    this._spacerTop.style.height = '0px';
    container.appendChild(this._spacerTop);

    this._content = document.createElement('div');
    container.appendChild(this._content);

    this._spacerBot = document.createElement('div');
    this._spacerBot.style.height = '0px';
    container.appendChild(this._spacerBot);

    // Scroll + click listeners — bind once per container to avoid duplicates
    this._lastFirst = -1;
    this._lastLast  = -1;

    var self = this;
    if (!container._lvBound) {
      container._lvBound = true;
      container.addEventListener('scroll', function () { self._render(); }, { passive: true });
      container.addEventListener('click', function (e) { self._handleClick(e); });
    }

    this._applyWidth();
    this._render();
  },

  /* ------------------------------------------------------------------ */
  /*  Click on a log line → fire onLineClick(line) callback              */
  /* ------------------------------------------------------------------ */
  _onLineClick: null,

  setLineClickHandler: function (fn) {
    this._onLineClick = fn;
  },

  _handleClick: function (e) {
    if (!this._onLineClick) return;
    var el = e.target;
    while (el && el !== this._container && !(el.classList && el.classList.contains('log-line'))) {
      el = el.parentNode;
    }
    if (!el || !el.classList || !el.classList.contains('log-line')) return;
    var numEl = el.querySelector('.log-line-num');
    if (!numEl) return;
    var num = parseInt(numEl.textContent, 10);
    for (var i = 0; i < this._filteredLines.length; i++) {
      if (this._filteredLines[i].num === num) { this._onLineClick(this._filteredLines[i]); return; }
    }
  },

  /* ------------------------------------------------------------------ */
  /*  Compute a stable content width so horizontal scroll doesn't jump   */
  /*  as virtual-scroll recycles rows of differing length.               */
  /* ------------------------------------------------------------------ */
  CHAR_W: 7.25,   // approx px per char for 12px Courier New
  GUTTER: 80,     // line-number + source-tag + padding allowance

  _applyWidth: function () {
    if (!this._content) return;
    if (this._wrap) {
      this._content.style.minWidth = '';
      this._spacerTop.style.minWidth = '';
      this._spacerBot.style.minWidth = '';
      return;
    }
    var maxLen = 0;
    var lines = this._filteredLines;
    for (var i = 0; i < lines.length; i++) {
      var len = (lines[i].raw || '').length;
      if (len > maxLen) maxLen = len;
    }
    var widthPx = Math.ceil(this.GUTTER + maxLen * this.CHAR_W);
    // Never narrower than the viewport
    var minPx = Math.max(widthPx, this._container ? this._container.clientWidth : 0);
    this._content.style.minWidth = minPx + 'px';
    this._spacerTop.style.minWidth = minPx + 'px';
    this._spacerBot.style.minWidth = minPx + 'px';
  },

  /* ------------------------------------------------------------------ */
  /*  setWrap() — toggle line wrapping. Wrap mode renders all rows       */
  /*  (variable height) since virtual scroll assumes a fixed height.     */
  /* ------------------------------------------------------------------ */
  setWrap: function (on) {
    this._wrap = !!on;
    if (this._container) this._container.classList.toggle('wrap', this._wrap);
    this._lastFirst = -1;
    this._lastLast = -1;
    this._applyWidth();
    this._render();
  },

  /* ------------------------------------------------------------------ */
  /*  Core virtual-scroll render                                         */
  /* ------------------------------------------------------------------ */
  _render: function () {
    if (!this._container) return;

    var lines      = this._filteredLines;
    var totalCount = lines.length;

    // Wrap mode: lines have variable height, so virtual scrolling (which
    // assumes a fixed LINE_HEIGHT) can't be used. Render every filtered line.
    if (this._wrap) {
      if (this._lastFirst === 0 && this._lastLast === totalCount - 1) return;
      this._lastFirst = 0;
      this._lastLast = totalCount - 1;
      this._spacerTop.style.height = '0px';
      this._spacerBot.style.height = '0px';
      var whtml = '';
      for (var w = 0; w < totalCount; w++) whtml += this._renderLine(lines[w]);
      this._content.innerHTML = whtml;
      return;
    }

    var scrollTop     = this._container.scrollTop;
    var viewportH     = this._container.clientHeight;

    var firstVisible  = Math.floor(scrollTop / this.LINE_HEIGHT);
    var lastVisible   = Math.ceil((scrollTop + viewportH) / this.LINE_HEIGHT);

    var renderFirst = Math.max(0, firstVisible - this.BUFFER);
    var renderLast  = Math.min(totalCount - 1, lastVisible + this.BUFFER);

    // Skip DOM work if the window hasn't moved
    if (renderFirst === this._lastFirst && renderLast === this._lastLast) return;
    this._lastFirst = renderFirst;
    this._lastLast  = renderLast;

    // Spacers
    this._spacerTop.style.height = (renderFirst * this.LINE_HEIGHT) + 'px';
    this._spacerBot.style.height = (Math.max(0, totalCount - 1 - renderLast) * this.LINE_HEIGHT) + 'px';

    // Build HTML
    var html = '';
    for (var i = renderFirst; i <= renderLast; i++) {
      html += this._renderLine(lines[i]);
    }
    this._content.innerHTML = html;
  },

  /* ------------------------------------------------------------------ */
  /*  Render a single line to HTML string                                */
  /* ------------------------------------------------------------------ */
  _renderLine: function (line) {
    var classes = 'log-line';

    // Severity class
    var sev = (line.severity || '').toLowerCase();
    if (sev === 'warn' || sev === 'warning')                             classes += ' severity-warn';
    else if (sev === 'error')                                            classes += ' severity-error';
    else if (sev === 'critical' || sev === 'fatal' || sev === 'alert' || sev === 'emergency') classes += ' severity-critical';

    // Highlight class
    if (this._highlightedNums[line.num]) {
      classes += ' ' + this._highlightedNums[line.num];
    }

    var contentText = this._escapeHtml(line.raw || '');

    // If a regex filter is active, wrap matches
    if (this._filterQuery) {
      try {
        // Clone regex to reset lastIndex
        var re = new RegExp(this._filterQuery.source, this._filterQuery.flags);
        contentText = contentText.replace(re, '<span class="hl-match">$&</span>');
      } catch (_) { /* ignore */ }
    }

    var sourceTag = '';
    if (this._multiSource && line.source) {
      sourceTag = '<span class="log-line-source">' + this._escapeHtml(line.source) + '</span>';
    }

    // Fixed height only in virtual-scroll (non-wrap) mode. In wrap mode the row
    // must grow to fit wrapped text, so we let it auto-size.
    var style = this._wrap
      ? 'line-height:' + this.LINE_HEIGHT + 'px'
      : 'height:' + this.LINE_HEIGHT + 'px;line-height:' + this.LINE_HEIGHT + 'px';

    return '<div class="' + classes + '" style="' + style + '">' +
      '<span class="log-line-num">' + line.num + '</span>' +
      sourceTag +
      '<span class="log-line-content">' + contentText + '</span>' +
      '</div>';
  },

  /* ------------------------------------------------------------------ */
  /*  setLines()                                                         */
  /* ------------------------------------------------------------------ */
  setLines: function (lines) {
    this._allLines = lines || [];
    this._refilter();

    // Re-detect multi-source
    var sources = {};
    for (var i = 0; i < this._allLines.length; i++) {
      if (this._allLines[i].source) sources[this._allLines[i].source] = true;
    }
    this._multiSource = Object.keys(sources).length > 1;
  },

  /* ------------------------------------------------------------------ */
  /*  scrollToLine(lineNum)                                              */
  /* ------------------------------------------------------------------ */
  scrollToLine: function (lineNum) {
    if (!this._container) return;

    // Find index of line in filtered set
    var idx = -1;
    for (var i = 0; i < this._filteredLines.length; i++) {
      if (this._filteredLines[i].num === lineNum) { idx = i; break; }
    }
    if (idx < 0) return;

    this._container.scrollTop = idx * this.LINE_HEIGHT;
    this._render();
  },

  /* ------------------------------------------------------------------ */
  /*  filter(query) -> matched count                                     */
  /* ------------------------------------------------------------------ */
  filter: function (query) {
    if (!query) {
      this._filterQuery = null;
    } else {
      try {
        this._filterQuery = new RegExp(query, 'gi');
      } catch (_) {
        // Treat as literal string
        this._filterQuery = new RegExp(this._escapeRegex(query), 'gi');
      }
    }
    return this._refilter();
  },

  /* ------------------------------------------------------------------ */
  /*  clearFilter()                                                      */
  /* ------------------------------------------------------------------ */
  clearFilter: function () {
    this._filterQuery = null;
    this._timeStart   = null;
    this._timeEnd     = null;
    this._refilter();
  },

  /* ------------------------------------------------------------------ */
  /*  filterByTimeRange(start, end)                                      */
  /* ------------------------------------------------------------------ */
  filterByTimeRange: function (start, end) {
    this._timeStart = start ? new Date(start) : null;
    this._timeEnd   = end   ? new Date(end)   : null;
    this._refilter();
  },

  /* ------------------------------------------------------------------ */
  /*  Internal: apply all active filters                                 */
  /* ------------------------------------------------------------------ */
  _refilter: function () {
    var result = this._allLines;
    var matchCount = 0;

    // Time range filter
    if (this._timeStart || this._timeEnd) {
      var ts = this._timeStart ? this._timeStart.getTime() : -Infinity;
      var te = this._timeEnd   ? this._timeEnd.getTime()   : Infinity;
      result = result.filter(function (line) {
        if (!line.timestamp) return false;
        var t = line.timestamp.getTime();
        return t >= ts && t <= te;
      });
    }

    // Regex filter
    if (this._filterQuery) {
      var re = this._filterQuery;
      result = result.filter(function (line) {
        re.lastIndex = 0;
        return re.test(line.raw || '');
      });
      matchCount = result.length;
    } else {
      matchCount = result.length;
    }

    this._filteredLines = result;

    // Reset scroll to top and re-render
    if (this._container) {
      this._container.scrollTop = 0;
    }
    this._lastFirst = -1;
    this._lastLast  = -1;
    this._applyWidth();
    this._render();

    return matchCount;
  },

  /* ------------------------------------------------------------------ */
  /*  getStats() -> {total, filtered, visible}                           */
  /* ------------------------------------------------------------------ */
  getStats: function () {
    var visible = 0;
    if (this._container) {
      var viewportH = this._container.clientHeight;
      visible = Math.ceil(viewportH / this.LINE_HEIGHT);
      visible = Math.min(visible, this._filteredLines.length);
    }
    return {
      total:    this._allLines.length,
      filtered: this._filteredLines.length,
      visible:  visible
    };
  },

  /* ------------------------------------------------------------------ */
  /*  highlightLines(lineNums, className)                                */
  /* ------------------------------------------------------------------ */
  highlightLines: function (lineNums, className) {
    var cls = className || 'hl-detection';
    for (var i = 0; i < lineNums.length; i++) {
      this._highlightedNums[lineNums[i]] = cls;
    }
    // Force re-render
    this._lastFirst = -1;
    this._lastLast  = -1;
    this._render();
  },

  /* ------------------------------------------------------------------ */
  /*  clearHighlights()                                                  */
  /* ------------------------------------------------------------------ */
  clearHighlights: function () {
    this._highlightedNums = {};
    this._lastFirst = -1;
    this._lastLast  = -1;
    this._render();
  },

  /* ------------------------------------------------------------------ */
  /*  destroy()                                                          */
  /* ------------------------------------------------------------------ */
  destroy: function () {
    if (this._container && this._scrollHandler) {
      this._container.removeEventListener('scroll', this._scrollHandler);
    }
    if (this._container) {
      this._container.innerHTML = '';
    }
    this._container     = null;
    this._viewport      = null;
    this._spacerTop     = null;
    this._spacerBot     = null;
    this._content       = null;
    this._allLines      = [];
    this._filteredLines = [];
    this._highlightedNums = {};
    this._filterQuery   = null;
    this._timeStart     = null;
    this._timeEnd       = null;
    this._scrollHandler = null;
    this._lastFirst     = -1;
    this._lastLast      = -1;
  },

  /* ------------------------------------------------------------------ */
  /*  Helpers                                                            */
  /* ------------------------------------------------------------------ */
  _escapeHtml: function (str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },

  _escapeRegex: function (str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
};
