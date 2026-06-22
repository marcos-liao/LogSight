// =============================================================================
// LogSight — Layer 3: AI assistant
// Calls the configured LLM provider (Claude / OpenAI) from the browser.
// All context is pseudonymized via Pseudonymizer before sending, and the
// model's response is reverse-mapped back to real values for display.
// The API key lives only in localStorage and is sent only to the provider.
// =============================================================================

var AI = (function () {
  'use strict';

  function getConfig() {
    try { return JSON.parse(localStorage.getItem('logsight_ai') || 'null'); } catch (e) { return null; }
  }

  function isReady() {
    var c = getConfig();
    return !!(c && c.provider && c.provider !== 'none' && c.key);
  }

  function isLocalOnly() {
    var c = getConfig();
    return !!(c && c.localOnly);
  }

  // Send a system prompt + user content to the provider. Returns Promise<string>.
  // opts: { maxTokens, raw } — raw skips pseudonymization (use only for content
  // that has none, never for log data).
  function ask(systemPrompt, userText, opts) {
    opts = opts || {};
    var c = getConfig();
    if (!isReady()) return Promise.reject(new Error('AI is not configured. Choose a provider and enter an API key in Settings.'));

    // Pseudonymize context (and prompt, in case it embeds identifiers).
    // We do NOT reset the map here so dummy values stay consistent across calls.
    var sysOut = opts.raw ? systemPrompt : Pseudonymizer.process(systemPrompt || '');
    var userOut = opts.raw ? userText : Pseudonymizer.process(userText || '');

    var url, headers, body;
    if (c.provider === 'claude') {
      url = 'https://api.anthropic.com/v1/messages';
      headers = {
        'content-type': 'application/json',
        'x-api-key': c.key,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      };
      body = JSON.stringify({
        model: c.model,
        max_tokens: opts.maxTokens || 1024,
        system: sysOut,
        messages: [{ role: 'user', content: userOut }]
      });
    } else { // openai
      url = 'https://api.openai.com/v1/chat/completions';
      headers = { 'content-type': 'application/json', 'authorization': 'Bearer ' + c.key };
      body = JSON.stringify({
        model: c.model,
        max_tokens: opts.maxTokens || 1024,
        messages: [
          { role: 'system', content: sysOut },
          { role: 'user', content: userOut }
        ]
      });
    }

    return fetch(url, { method: 'POST', headers: headers, body: body })
      .then(function (res) {
        if (!res.ok) {
          return res.json().then(function (j) {
            throw new Error((j && j.error && j.error.message) ? j.error.message : ('HTTP ' + res.status));
          }).catch(function (e) {
            if (e instanceof Error && e.message) throw e;
            throw new Error('HTTP ' + res.status);
          });
        }
        return res.json();
      })
      .then(function (j) {
        var text = c.provider === 'claude'
          ? (j.content && j.content[0] && j.content[0].text)
          : (j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content);
        text = text || '';
        // Reverse-map dummy → real so the user reads real values.
        return opts.raw ? text : Pseudonymizer.reverse(text);
      });
  }

  return { ask: ask, isReady: isReady, isLocalOnly: isLocalOnly, getConfig: getConfig };
})();
