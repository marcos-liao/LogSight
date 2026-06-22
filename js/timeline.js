/* timeline.js -- Chart.js timeline wrapper for LogSight
 * Globals expected: Chart, ChartZoom (chartjs-plugin-zoom UMD)
 */
var Timeline = {

  chart: null,
  _onZoom: null,
  _canvasId: null,
  _highlightAnnotation: null,

  /* ------------------------------------------------------------------ */
  /*  Bucket-size heuristic                                              */
  /* ------------------------------------------------------------------ */
  _pickInterval: function (startMs, endMs) {
    var rangeMs = endMs - startMs;
    var MINUTE  = 60 * 1000;
    var HOUR    = 60 * MINUTE;
    var DAY     = 24 * HOUR;

    if (rangeMs < HOUR)       return { ms: MINUTE,         label: '1 min' };
    if (rangeMs < DAY)        return { ms: 5 * MINUTE,     label: '5 min' };
    if (rangeMs < 7 * DAY)    return { ms: HOUR,           label: '1 hr'  };
    return                           { ms: 6 * HOUR,       label: '6 hr'  };
  },

  /* ------------------------------------------------------------------ */
  /*  Build stacked datasets from parsed lines                           */
  /* ------------------------------------------------------------------ */
  _buildDatasets: function (parsedLines) {
    if (!parsedLines || parsedLines.length === 0) {
      return { labels: [], datasets: [], startMs: 0, endMs: 0 };
    }

    // Only lines with a valid timestamp can be placed on a time axis.
    var timed = parsedLines.filter(function (l) { return l.timestamp instanceof Date && !isNaN(l.timestamp.getTime()); });
    if (timed.length === 0) {
      return { labels: [], datasets: [], startMs: 0, endMs: 0 };
    }

    // Sort by timestamp
    var sorted = timed.slice().sort(function (a, b) {
      return a.timestamp - b.timestamp;
    });

    var startMs = sorted[0].timestamp.getTime();
    var endMs   = sorted[sorted.length - 1].timestamp.getTime();

    // Guard: if every timestamp is identical, widen the window by 1 minute
    if (endMs === startMs) { endMs = startMs + 60000; }

    var interval = this._pickInterval(startMs, endMs);
    var bucketMs = interval.ms;

    // Initialise buckets
    var buckets = {}; // key = bucket start ms
    for (var t = startMs - (startMs % bucketMs); t <= endMs; t += bucketMs) {
      buckets[t] = { info: 0, warn: 0, error: 0 };
    }

    // Fill
    for (var i = 0; i < sorted.length; i++) {
      var ts  = sorted[i].timestamp.getTime();
      var key = ts - (ts % bucketMs);
      if (!buckets[key]) buckets[key] = { info: 0, warn: 0, error: 0 };

      var sev = (sorted[i].severity || '').toLowerCase();
      if (sev === 'error' || sev === 'critical' || sev === 'fatal' || sev === 'alert' || sev === 'emergency') {
        buckets[key].error++;
      } else if (sev === 'warn' || sev === 'warning') {
        buckets[key].warn++;
      } else {
        buckets[key].info++;
      }
    }

    // Convert to arrays
    var keys = Object.keys(buckets).map(Number).sort(function (a, b) { return a - b; });
    var labels     = [];
    var infoData   = [];
    var warnData   = [];
    var errorData  = [];

    for (var k = 0; k < keys.length; k++) {
      labels.push(new Date(keys[k]));
      infoData.push(buckets[keys[k]].info);
      warnData.push(buckets[keys[k]].warn);
      errorData.push(buckets[keys[k]].error);
    }

    var datasets = [
      {
        label: 'Info / Normal',
        data: infoData,
        backgroundColor: 'rgba(56, 142, 255, 0.75)',
        borderColor: 'rgba(56, 142, 255, 1)',
        borderWidth: 1
      },
      {
        label: 'Warning',
        data: warnData,
        backgroundColor: 'rgba(230, 170, 40, 0.80)',
        borderColor: 'rgba(230, 170, 40, 1)',
        borderWidth: 1
      },
      {
        label: 'Error / Critical',
        data: errorData,
        backgroundColor: 'rgba(220, 60, 60, 0.80)',
        borderColor: 'rgba(220, 60, 60, 1)',
        borderWidth: 1
      }
    ];

    return { labels: labels, datasets: datasets, startMs: startMs, endMs: endMs, bucketMs: bucketMs };
  },

  /* ------------------------------------------------------------------ */
  /*  X-axis tick formatter                                              */
  /* ------------------------------------------------------------------ */
  _formatTick: function (value, sameDay) {
    var d = value instanceof Date ? value : new Date(value);
    var hh = String(d.getHours()).padStart(2, '0');
    var mm = String(d.getMinutes()).padStart(2, '0');
    if (sameDay) return hh + ':' + mm;

    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return months[d.getMonth()] + ' ' + d.getDate() + ' ' + hh + ':' + mm;
  },

  /* ------------------------------------------------------------------ */
  /*  create()                                                           */
  /* ------------------------------------------------------------------ */
  create: function (canvasId, parsedLines, onZoom) {
    var self = this;
    this._highlightTs = null; // clear any marker from a previous chart
    this._canvasId = canvasId;
    this._onZoom   = onZoom || null;

    if (this.chart) this.destroy();

    var built = this._buildDatasets(parsedLines);
    var labels   = built.labels;
    var datasets = built.datasets;
    var startMs  = built.startMs;
    var endMs    = built.endMs;
    this._bucketMs = built.bucketMs || 60000;

    // Determine if entire range falls on a single calendar day
    var sameDay = false;
    if (labels.length > 0) {
      var first = labels[0];
      var last  = labels[labels.length - 1];
      sameDay = (first.getFullYear() === last.getFullYear() &&
                 first.getMonth()    === last.getMonth()    &&
                 first.getDate()     === last.getDate());
    }

    var canvas = document.getElementById(canvasId);
    var ctx    = canvas.getContext('2d');

    this.chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        onClick: function (evt) {
          if (!self._onBarClick || !self.chart) return;
          var pts = self.chart.getElementsAtEventForMode(evt, 'index', { intersect: false }, false);
          if (!pts.length) return;
          var idx = pts[0].index;
          var label = self.chart.data.labels[idx];
          if (label == null) return;
          var startMs = label instanceof Date ? label.getTime() : new Date(label).getTime();
          self._onBarClick(new Date(startMs), new Date(startMs + self._bucketMs));
        },
        interaction: {
          mode: 'index',
          intersect: false
        },
        scales: {
          x: {
            type: 'time',
            stacked: true,
            time: {
              tooltipFormat: 'MMM d, HH:mm:ss',
              displayFormats: {
                minute: sameDay ? 'HH:mm' : 'MMM d HH:mm',
                hour:   sameDay ? 'HH:mm' : 'MMM d HH:mm',
                day:    'MMM d'
              }
            },
            min: startMs ? new Date(startMs) : undefined,
            max: endMs   ? new Date(endMs)   : undefined,
            ticks: {
              maxRotation: 0,
              autoSkip: true,
              maxTicksLimit: 12,
              color: '#999'
            },
            grid: {
              color: 'rgba(255,255,255,0.06)'
            }
          },
          y: {
            stacked: true,
            beginAtZero: true,
            title: {
              display: true,
              text: 'Events',
              color: '#999'
            },
            ticks: {
              precision: 0,
              color: '#999'
            },
            grid: {
              color: 'rgba(255,255,255,0.06)'
            }
          }
        },
        plugins: {
          legend: {
            position: 'top',
            labels: {
              boxWidth: 12,
              padding: 10,
              color: '#ccc'
            }
          },
          tooltip: {
            callbacks: {
              title: function (items) {
                if (!items.length) return '';
                var d = new Date(items[0].parsed.x);
                return self._formatTick(d, sameDay);
              }
            }
          },
          zoom: {
            // Pan is gated behind Shift so a plain drag is ALWAYS zoom-select.
            // Without the modifier, drag-to-pan and drag-to-zoom both fire on
            // the same gesture and the chart behaves inconsistently.
            pan: {
              enabled: true,
              mode: 'x',
              modifierKey: 'shift',
              onPanComplete: function (ctx) { self._emitZoom(ctx.chart); }
            },
            zoom: {
              wheel: {
                enabled: true
              },
              pinch: {
                enabled: true
              },
              drag: {
                enabled: true,
                backgroundColor: 'rgba(56, 142, 255, 0.15)',
                borderColor: 'rgba(56, 142, 255, 0.6)',
                borderWidth: 1
              },
              mode: 'x',
              onZoomComplete: function (ctx) { self._emitZoom(ctx.chart); }
            }
          }
        }
      },
      // Inline plugin registered at creation so it actually runs. It draws a
      // dashed marker at self._highlightTs whenever that value is set.
      plugins: [{
        id: 'highlightLine',
        afterDraw: function (chart) {
          if (self._highlightTs == null) return;
          var xScale = chart.scales.x, yScale = chart.scales.y;
          if (!xScale || !yScale) return;
          var x = xScale.getPixelForValue(self._highlightTs);
          if (x < xScale.left || x > xScale.right) return;
          var ctx = chart.ctx;
          ctx.save();
          ctx.beginPath();
          ctx.moveTo(x, yScale.top);
          ctx.lineTo(x, yScale.bottom);
          ctx.lineWidth = 2;
          ctx.strokeStyle = 'rgba(234, 75, 74, 0.9)';
          ctx.setLineDash([4, 3]);
          ctx.stroke();
          // little triangle marker at top
          ctx.beginPath();
          ctx.setLineDash([]);
          ctx.moveTo(x - 4, yScale.top);
          ctx.lineTo(x + 4, yScale.top);
          ctx.lineTo(x, yScale.top + 6);
          ctx.closePath();
          ctx.fillStyle = 'rgba(234, 75, 74, 0.95)';
          ctx.fill();
          ctx.restore();
        }
      }]
    });
  },

  /* ------------------------------------------------------------------ */
  /*  Internal: fire onZoom callback                                     */
  /* ------------------------------------------------------------------ */
  _emitZoom: function (chart) {
    if (!this._onZoom) return;
    var xScale = chart.scales.x;
    if (!xScale) return;
    this._onZoom(new Date(xScale.min), new Date(xScale.max));
  },

  /* ------------------------------------------------------------------ */
  /*  resetZoom()                                                        */
  /* ------------------------------------------------------------------ */
  resetZoom: function () {
    if (this.chart) {
      this.chart.resetZoom();
    }
  },

  /* ------------------------------------------------------------------ */
  /*  getRange() -> {start: Date, end: Date}                             */
  /* ------------------------------------------------------------------ */
  getRange: function () {
    if (!this.chart) return null;
    var xScale = this.chart.scales.x;
    if (!xScale) return null;
    return {
      start: new Date(xScale.min),
      end:   new Date(xScale.max)
    };
  },

  /* ------------------------------------------------------------------ */
  /*  highlightTime(date)                                                */
  /* ------------------------------------------------------------------ */
  _highlightTs: null,
  _onBarClick: null,
  _bucketMs: 60000,

  setBarClickHandler: function (fn) {
    this._onBarClick = fn;
  },

  highlightTime: function (date) {
    if (!this.chart) return;
    this._highlightTs = date instanceof Date ? date.getTime() : date;
    this.chart.draw();
  },

  clearHighlight: function () {
    this._highlightTs = null;
    if (this.chart) this.chart.draw();
  },

  /* ------------------------------------------------------------------ */
  /*  update(parsedLines)                                                */
  /* ------------------------------------------------------------------ */
  update: function (parsedLines) {
    if (!this.chart) return;

    var built = this._buildDatasets(parsedLines);
    this.chart.data.labels   = built.labels;
    this.chart.data.datasets = built.datasets;

    // Reset axis bounds
    this.chart.options.scales.x.min = built.startMs ? new Date(built.startMs) : undefined;
    this.chart.options.scales.x.max = built.endMs   ? new Date(built.endMs)   : undefined;

    this.chart.update();
  },

  /* ------------------------------------------------------------------ */
  /*  destroy()                                                          */
  /* ------------------------------------------------------------------ */
  destroy: function () {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
    this._onZoom = null;
    this._canvasId = null;
  }
};
