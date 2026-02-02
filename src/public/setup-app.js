// Gerald Setup - Enhanced UX with skeleton loaders and collapsible sections
// Preserves all original functionality

(function () {
  var statusEl = document.getElementById('status');
  var authGroupEl = document.getElementById('authGroup');
  var authChoiceEl = document.getElementById('authChoice');
  var logEl = document.getElementById('log');

  // Initialize collapsible sections
  function initCollapsibles() {
    var headers = document.querySelectorAll('.card-header-collapsible');
    headers.forEach(function(header) {
      header.addEventListener('click', function() {
        var targetId = this.getAttribute('data-target');
        var content = document.getElementById(targetId);
        
        if (content) {
          var isCollapsed = content.classList.contains('collapsed');
          
          if (isCollapsed) {
            content.classList.remove('collapsed');
            this.classList.add('active');
          } else {
            content.classList.add('collapsed');
            this.classList.remove('active');
          }
        }
      });
    });
  }

  // Show skeleton loaders
  function showSkeletons() {
    statusEl.innerHTML = '<div class="skeleton skeleton-text"></div>';
    authGroupEl.innerHTML = '<option value="">Loading...</option>';
    authChoiceEl.innerHTML = '<option value="">Loading...</option>';
  }

  // Hide skeleton loaders
  function hideSkeletons() {
    // Status will be updated by setStatus
    // Auth dropdowns will be populated by renderAuth
  }

  function setStatus(s) {
    statusEl.textContent = s;
  }

  function renderAuth(groups) {
    authGroupEl.innerHTML = '';
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      var opt = document.createElement('option');
      opt.value = g.value;
      opt.textContent = g.label + (g.hint ? ' - ' + g.hint : '');
      authGroupEl.appendChild(opt);
    }

    authGroupEl.onchange = function () {
      var sel = null;
      for (var j = 0; j < groups.length; j++) {
        if (groups[j].value === authGroupEl.value) sel = groups[j];
      }
      authChoiceEl.innerHTML = '';
      var opts = (sel && sel.options) ? sel.options : [];
      for (var k = 0; k < opts.length; k++) {
        var o = opts[k];
        var opt2 = document.createElement('option');
        opt2.value = o.value;
        opt2.textContent = o.label + (o.hint ? ' - ' + o.hint : '');
        authChoiceEl.appendChild(opt2);
      }
    };

    authGroupEl.onchange();
  }

  function httpJson(url, opts) {
    opts = opts || {};
    opts.credentials = 'same-origin';
    return fetch(url, opts).then(function (res) {
      if (!res.ok) {
        return res.text().then(function (t) {
          throw new Error('HTTP ' + res.status + ': ' + (t || res.statusText));
        });
      }
      return res.json();
    });
  }

  function refreshStatus() {
    showSkeletons();
    setStatus('Loading...');
    
    return httpJson('/setup/api/status').then(function (j) {
      hideSkeletons();
      
      var ver = j.openclawVersion ? (' | ' + j.openclawVersion) : '';
      setStatus((j.configured ? 'Configured - open /openclaw' : 'Not configured - run setup below') + ver);
      renderAuth(j.authGroups || []);

      // Pre-select default auth group if specified by server
      if (j.defaultAuthGroup) {
        authGroupEl.value = j.defaultAuthGroup;
        authGroupEl.onchange();
        if (j.defaultAuthChoice) {
          authChoiceEl.value = j.defaultAuthChoice;
        }
      }

      // Show that API key is pre-configured from env var
      if (j.hasDefaultApiKey) {
        var secretEl = document.getElementById('authSecret');
        if (secretEl && !secretEl.value) {
          secretEl.placeholder = 'Pre-configured from environment (leave blank to use default)';
        }
      }

      // Show that SendGrid key is pre-configured from env var
      if (j.hasSendgridEnv) {
        var sgEl = document.getElementById('sendgridApiKey');
        if (sgEl && !sgEl.value) {
          sgEl.placeholder = 'Pre-configured from environment (leave blank to use default)';
        }
      }

      // Pre-fill client domain: server default → auto-detect from current hostname
      var clientDomainEl = document.getElementById('clientDomain');
      if (clientDomainEl && !clientDomainEl.value) {
        if (j.defaultClientDomain) {
          clientDomainEl.value = j.defaultClientDomain;
        } else {
          // Auto-detect from current hostname (strip gerald./dev. prefix, skip railway domains)
          var host = window.location.hostname.toLowerCase();
          if (host && host.indexOf('.up.railway.app') === -1 && host !== 'localhost') {
            var domain = host.replace(/^(gerald|dev)\./, '');
            clientDomainEl.value = domain;
          }
        }
      }

      // If channels are unsupported, surface it for debugging.
      if (j.channelsAddHelp && j.channelsAddHelp.indexOf('telegram') === -1) {
        logEl.textContent += '\nNote: this openclaw build does not list telegram in `channels add --help`. Telegram auto-add will be skipped.\n';
      }

    }).catch(function (e) {
      hideSkeletons();
      setStatus('Error: ' + String(e));
    });
  }

  document.getElementById('run').onclick = function () {
    var payload = {
      flow: document.getElementById('flow').value,
      authChoice: authChoiceEl.value,
      authSecret: document.getElementById('authSecret').value,
      telegramToken: document.getElementById('telegramToken').value,
      discordToken: document.getElementById('discordToken').value,
      slackBotToken: document.getElementById('slackBotToken').value,
      slackAppToken: document.getElementById('slackAppToken').value,
      clientDomain: document.getElementById('clientDomain').value,
      clientName: document.getElementById('clientName').value,
      guardrailLevel: document.getElementById('guardrailLevel').value,
      githubRepo: document.getElementById('githubRepo').value,
      githubToken: document.getElementById('githubToken').value,
      prodBranch: document.getElementById('prodBranch').value || 'main',
      devBranch: document.getElementById('devBranch').value || 'development',
      sendgridApiKey: document.getElementById('sendgridApiKey').value,
      sendgridSenderEmail: document.getElementById('sendgridSenderEmail').value,
      contactFromName: document.getElementById('contactFromName').value,
      allowedEmails: document.getElementById('allowedEmails').value,
      sendgridKey: document.getElementById('sendgridApiKey').value || document.getElementById('sendgridKey').value,
      twilioSid: document.getElementById('twilioSid').value,
      twilioToken: document.getElementById('twilioToken').value,
      twilioPhone: document.getElementById('twilioPhone').value,
      turnstileSiteKey: document.getElementById('turnstileSiteKey').value,
      turnstileSecretKey: document.getElementById('turnstileSecretKey').value
    };

    logEl.textContent = 'Running...\n';
    
    // Auto-scroll log output
    logEl.scrollTop = logEl.scrollHeight;

    fetch('/setup/api/run', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.text();
    }).then(function (text) {
      var j;
      try { j = JSON.parse(text); } catch (_e) { j = { ok: false, output: text }; }
      logEl.textContent += (j.output || JSON.stringify(j, null, 2));
      logEl.scrollTop = logEl.scrollHeight;
      return refreshStatus();
    }).catch(function (e) {
      logEl.textContent += '\nError: ' + String(e) + '\n';
      logEl.scrollTop = logEl.scrollHeight;
    });
  };

  // Pairing approve helper
  var pairingBtn = document.getElementById('pairingApprove');
  if (pairingBtn) {
    pairingBtn.onclick = function () {
      var channel = prompt('Enter channel (telegram or discord):');
      if (!channel) return;
      channel = channel.trim().toLowerCase();
      if (channel !== 'telegram' && channel !== 'discord') {
        alert('Channel must be "telegram" or "discord"');
        return;
      }
      var code = prompt('Enter pairing code (e.g. 3EY4PUYS):');
      if (!code) return;
      logEl.textContent += '\nApproving pairing for ' + channel + '...\n';
      fetch('/setup/api/pairing/approve', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ channel: channel, code: code.trim() })
      }).then(function (r) { return r.text(); })
        .then(function (t) { 
          logEl.textContent += t + '\n';
          logEl.scrollTop = logEl.scrollHeight;
        })
        .catch(function (e) { 
          logEl.textContent += 'Error: ' + String(e) + '\n';
          logEl.scrollTop = logEl.scrollHeight;
        });
    };
  }

  document.getElementById('reset').onclick = function () {
    if (!confirm('Reset setup? This deletes the config file so onboarding can run again.')) return;
    logEl.textContent = 'Resetting...\n';
    fetch('/setup/api/reset', { method: 'POST', credentials: 'same-origin' })
      .then(function (res) { return res.text(); })
      .then(function (t) { 
        logEl.textContent += t + '\n';
        logEl.scrollTop = logEl.scrollHeight;
        return refreshStatus();
      })
      .catch(function (e) { 
        logEl.textContent += 'Error: ' + String(e) + '\n';
        logEl.scrollTop = logEl.scrollHeight;
      });
  };

  // GitHub token save handler with enhanced UX
  var githubTokenSaveBtn = document.getElementById('githubTokenSave');
  var githubRepoSelect = document.getElementById('githubRepo');
  var githubTokenStatus = document.getElementById('githubTokenStatus');

  if (githubTokenSaveBtn) {
    githubTokenSaveBtn.onclick = function () {
      var token = document.getElementById('githubToken').value.trim();
      if (!token) {
        alert('Enter a GitHub token first');
        return;
      }

      githubTokenSaveBtn.disabled = true;
      githubTokenSaveBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="animation: spin 1s linear infinite;"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="2" stroke-dasharray="10 5"/></svg> Validating...';
      githubRepoSelect.innerHTML = '<option value="">Loading repos...</option>';
      githubRepoSelect.disabled = true;
      
      if (githubTokenStatus) {
        githubTokenStatus.innerHTML = '<div class="skeleton skeleton-text" style="width: 100%; height: 16px; margin-top: 4px;"></div>';
        githubTokenStatus.style.color = '#8892b0';
      }

      // First try /installation/repositories (fine-grained PATs with selected repos)
      // Falls back to /user/repos if that fails
      var allRepos = [];

      function fetchInstallationRepos() {
        return fetch('https://api.github.com/installation/repositories?per_page=100', {
          headers: { 'Authorization': 'Bearer ' + token }
        }).then(function(res) {
          if (!res.ok) return null; // Not an installation token, fall back
          return res.json().then(function(data) {
            return data.repositories || null;
          });
        }).catch(function() { return null; });
      }

      function fetchPage(page) {
        return fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member&page=' + page, {
          headers: { 'Authorization': 'Bearer ' + token }
        })
        .then(function(res) {
          if (!res.ok) throw new Error('Invalid token or API error (HTTP ' + res.status + ')');
          return res.json().then(function(repos) {
            return { repos: repos, hasMore: repos.length === 100 };
          });
        });
      }

      function fetchAllPages(page) {
        return fetchPage(page).then(function(result) {
          allRepos = allRepos.concat(result.repos);
          if (result.hasMore) {
            return fetchAllPages(page + 1);
          }
          return allRepos;
        });
      }

      // Try installation repos first (fine-grained PATs with selected repos), fall back to user repos
      fetchInstallationRepos()
        .then(function(installRepos) {
          if (installRepos && installRepos.length > 0) return installRepos;
          return fetchAllPages(1);
        })
        .then(function(repos) {
          githubTokenSaveBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M13 4L6 11L3 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg> Saved';
          githubTokenSaveBtn.style.background = '#22c55e';
          githubTokenSaveBtn.style.borderColor = '#22c55e';
          githubTokenSaveBtn.style.color = '#0a0a0f';
          
          if (githubTokenStatus) {
            githubTokenStatus.innerHTML = '✓ Token validated — ' + repos.length + ' repos found';
            githubTokenStatus.style.color = '#22c55e';
          }

          githubRepoSelect.innerHTML = '<option value="">Select a repository...</option>';

          repos.forEach(function(repo) {
            var opt = document.createElement('option');
            opt.value = repo.full_name;
            opt.textContent = repo.full_name + (repo.private ? ' 🔒' : '');
            githubRepoSelect.appendChild(opt);
          });

          githubRepoSelect.disabled = false;

          // Reset button after 3s
          setTimeout(function() {
            githubTokenSaveBtn.innerHTML = 'Save Token';
            githubTokenSaveBtn.style.background = '';
            githubTokenSaveBtn.style.borderColor = '';
            githubTokenSaveBtn.style.color = '';
            githubTokenSaveBtn.disabled = false;
          }, 3000);
        })
        .catch(function(err) {
          githubTokenSaveBtn.innerHTML = 'Save Token';
          githubTokenSaveBtn.style.background = '';
          githubTokenSaveBtn.style.borderColor = '';
          githubTokenSaveBtn.style.color = '';
          githubTokenSaveBtn.disabled = false;
          githubRepoSelect.innerHTML = '<option value="">Save token first...</option>';
          
          if (githubTokenStatus) {
            githubTokenStatus.innerHTML = '✗ ' + err.message;
            githubTokenStatus.style.color = '#ef4444';
          }
        });
    };
  }

  // Add CSS for spin animation
  var style = document.createElement('style');
  style.textContent = '@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
  document.head.appendChild(style);

  // Initialize everything
  initCollapsibles();
  refreshStatus();
})();
