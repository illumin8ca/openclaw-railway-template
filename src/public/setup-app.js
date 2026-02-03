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

      // Auto-fill SendGrid key from env var
      if (j.hasSendgridEnv) {
        var sgEl = document.getElementById('sendgridApiKey');
        if (sgEl && !sgEl.value) {
          sgEl.placeholder = 'Pre-configured from environment (leave blank to use default)';
        }
      }

      // Auto-fill allowed emails from env var
      if (j.defaultAllowedEmails) {
        var emailsEl = document.getElementById('allowedEmails');
        if (emailsEl && !emailsEl.value) {
          emailsEl.value = j.defaultAllowedEmails;
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

      // Auto-fill SendGrid sender email based on client domain
      var senderEmailEl = document.getElementById('sendgridSenderEmail');
      if (senderEmailEl && !senderEmailEl.value && clientDomainEl && clientDomainEl.value) {
        senderEmailEl.value = 'noreply@' + clientDomainEl.value;
      }
      // Update sender email when domain changes
      if (clientDomainEl && senderEmailEl) {
        clientDomainEl.addEventListener('input', function() {
          if (!senderEmailEl.dataset.userEdited) {
            senderEmailEl.value = clientDomainEl.value ? 'noreply@' + clientDomainEl.value : '';
          }
        });
        senderEmailEl.addEventListener('input', function() {
          senderEmailEl.dataset.userEdited = 'true';
        });
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
      githubRepo: document.getElementById('github-repo-select').value,
      githubToken: '', // OAuth token is stored separately in github-oauth.json
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

      // Show completion banner if setup succeeded
      if (j.ok) {
        var banner = document.createElement('div');
        banner.style.cssText = 'margin-top: 24px; padding: 24px; border-radius: 12px; background: rgba(0,255,135,0.06); border: 1px solid rgba(0,255,135,0.2); text-align: center;';
        
        var title = document.createElement('div');
        title.style.cssText = 'font-size: 20px; font-weight: 700; color: #00ff87; margin-bottom: 8px;';
        title.textContent = '✅ Setup Complete!';
        banner.appendChild(title);

        var subtitle = document.createElement('div');
        subtitle.style.cssText = 'font-size: 14px; color: #94a3b8; margin-bottom: 16px;';
        subtitle.textContent = 'Your Gerald deployment is ready to go.';
        banner.appendChild(subtitle);

        if (j.clientDomain) {
          var link = document.createElement('a');
          link.href = 'https://gerald.' + j.clientDomain;
          link.target = '_blank';
          link.style.cssText = 'display: inline-block; padding: 12px 32px; background: #00ff87; color: #0a0a0f; font-weight: 600; font-size: 15px; border-radius: 999px; text-decoration: none; transition: opacity 0.15s;';
          link.textContent = 'Open Gerald Dashboard →';
          link.onmouseover = function() { link.style.opacity = '0.85'; };
          link.onmouseout = function() { link.style.opacity = '1'; };
          banner.appendChild(link);

          var links = document.createElement('div');
          links.style.cssText = 'margin-top: 16px; font-size: 13px; color: #64748b;';
          links.innerHTML = '<a href="https://' + j.clientDomain + '" target="_blank" style="color: #00b4d8; text-decoration: none;">Production</a>' +
            ' · <a href="https://dev.' + j.clientDomain + '" target="_blank" style="color: #00b4d8; text-decoration: none;">Dev</a>' +
            ' · <a href="https://gerald.' + j.clientDomain + '" target="_blank" style="color: #00b4d8; text-decoration: none;">Dashboard</a>';
          banner.appendChild(links);
        }

        logEl.parentNode.insertBefore(banner, logEl.nextSibling);
      }

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

  // ── GitHub OAuth Device Flow ──────────────────────────────────────────
  window.deviceCode = null;
  window.pollInterval = null;

  window.startGitHubAuth = async function() {
    document.getElementById('github-not-connected').style.display = 'none';
    document.getElementById('github-auth-progress').style.display = 'block';
    
    try {
      const res = await fetch('/setup/api/github/start-auth', { method: 'POST' });
      const data = await res.json();
      
      window.deviceCode = data.device_code;
      document.getElementById('github-user-code').textContent = data.user_code;
      
      // Start polling
      window.pollInterval = setInterval(window.pollGitHubAuth, (data.interval || 5) * 1000);
    } catch (err) {
      alert('Failed to start GitHub auth: ' + err.message);
      window.resetGitHubUI();
    }
  };

  window.pollGitHubAuth = async function() {
    try {
      const res = await fetch('/setup/api/github/poll-auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_code: window.deviceCode })
      });
      const data = await res.json();
      
      if (data.status === 'success') {
        clearInterval(window.pollInterval);
        window.showConnectedState(data.username);
        window.loadRepos();
      } else if (data.error && data.error !== 'authorization_pending') {
        clearInterval(window.pollInterval);
        alert('Authorization failed: ' + data.error);
        window.resetGitHubUI();
      }
    } catch (err) {
      clearInterval(window.pollInterval);
      alert('Polling error: ' + err.message);
      window.resetGitHubUI();
    }
  };

  window.loadRepos = async function() {
    try {
      const res = await fetch('/setup/api/github/repos');
      const data = await res.json();
      
      if (!data.repos) {
        alert('Failed to load repos: ' + (data.error || 'Unknown error'));
        return;
      }
      
      const select = document.getElementById('github-repo-select');
      select.innerHTML = '<option value="">Select a repository...</option>';
      
      data.repos.forEach(function(repo) {
        var opt = document.createElement('option');
        opt.value = repo.full_name;
        opt.textContent = repo.full_name + (repo.private ? ' 🔒' : '');
        select.appendChild(opt);
      });
      
      // Pre-select gerald-dashboard if exists
      var gerald = data.repos.find(function(r) { return r.full_name.includes('gerald-dashboard'); });
      if (gerald) select.value = gerald.full_name;
    } catch (err) {
      alert('Failed to load repos: ' + err.message);
    }
  };

  window.showConnectedState = function(username) {
    document.getElementById('github-auth-progress').style.display = 'none';
    document.getElementById('github-connected').style.display = 'block';
    document.getElementById('github-username').textContent = '@' + username;
  };

  window.disconnectGitHub = async function() {
    if (!confirm('Disconnect GitHub account?')) return;
    
    try {
      await fetch('/setup/api/github/disconnect', { method: 'POST' });
      window.resetGitHubUI();
    } catch (err) {
      alert('Failed to disconnect: ' + err.message);
    }
  };

  window.resetGitHubUI = function() {
    document.getElementById('github-not-connected').style.display = 'block';
    document.getElementById('github-auth-progress').style.display = 'none';
    document.getElementById('github-connected').style.display = 'none';
  };

  // Check GitHub status on page load
  window.checkGitHubStatus = async function() {
    try {
      const res = await fetch('/setup/api/github/status');
      const data = await res.json();
      if (data.connected) {
        window.showConnectedState(data.username);
        window.loadRepos();
      }
    } catch (err) {
      console.error('Failed to check GitHub status:', err);
    }
  };

  // ==============================
  // Codex CLI Authentication
  // ==============================
  window.startCodexAuth = async function() {
    document.getElementById('codex-not-connected').style.display = 'none';
    document.getElementById('codex-auth-progress').style.display = 'block';

    try {
      const res = await fetch('/setup/api/codex/start-auth', { method: 'POST' });
      const data = await res.json();
      
      if (!res.ok || !data.verification_uri) {
        alert('Failed to start Codex authentication: ' + (data.error || 'Unknown error'));
        window.resetCodexUI();
        return;
      }

      document.getElementById('codex-user-code').textContent = data.user_code;
      document.getElementById('codex-verify-link').href = data.verification_uri;

      // Poll for completion (Codex will write to ~/.codex/auth.json when complete)
      window.pollCodexAuth();
    } catch (err) {
      alert('Error: ' + err.message);
      window.resetCodexUI();
    }
  };

  window.pollCodexAuth = async function() {
    const maxAttempts = 60; // 5 minutes
    let attempts = 0;

    const interval = setInterval(async () => {
      attempts++;
      
      try {
        const res = await fetch('/setup/api/codex/status');
        const data = await res.json();

        if (data.authenticated) {
          clearInterval(interval);
          document.getElementById('codex-auth-progress').style.display = 'none';
          document.getElementById('codex-connected').style.display = 'block';
        } else if (attempts >= maxAttempts) {
          clearInterval(interval);
          alert('Authentication timeout. Please try again.');
          window.resetCodexUI();
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 5000); // Check every 5 seconds
  };

  window.disconnectCodex = async function() {
    if (!confirm('Disconnect Codex CLI?')) return;
    
    try {
      await fetch('/setup/api/codex/disconnect', { method: 'POST' });
      window.resetCodexUI();
    } catch (err) {
      alert('Failed to disconnect: ' + err.message);
    }
  };

  window.resetCodexUI = function() {
    document.getElementById('codex-not-connected').style.display = 'block';
    document.getElementById('codex-auth-progress').style.display = 'none';
    document.getElementById('codex-connected').style.display = 'none';
  };

  window.checkCodexStatus = async function() {
    try {
      const res = await fetch('/setup/api/codex/status');
      const data = await res.json();
      
      if (data.authenticated) {
        document.getElementById('codex-not-connected').style.display = 'none';
        document.getElementById('codex-connected').style.display = 'block';
      }
    } catch (err) {
      console.error('Failed to check Codex status:', err);
    }
  };

  // ==============================
  // Claude Code CLI Authentication
  // ==============================
  window.showClaudeInstructions = function() {
    document.getElementById('claude-not-connected').style.display = 'none';
    document.getElementById('claude-instructions').style.display = 'block';
  };

  window.hideClaudeInstructions = function() {
    document.getElementById('claude-instructions').style.display = 'none';
    document.getElementById('claude-not-connected').style.display = 'block';
  };

  window.checkClaudeStatus = async function() {
    try {
      const res = await fetch('/setup/api/claude/status');
      const data = await res.json();
      
      if (data.authenticated) {
        document.getElementById('claude-instructions').style.display = 'none';
        document.getElementById('claude-connected').style.display = 'block';
        if (data.account) {
          document.getElementById('claude-account').textContent = data.account;
        }
        alert('✓ Claude Code is authenticated!');
      } else {
        alert('Claude Code is not yet authenticated. Please follow the instructions.');
      }
    } catch (err) {
      alert('Error checking status: ' + err.message);
    }
  };

  window.disconnectClaude = async function() {
    if (!confirm('Disconnect Claude Code CLI?')) return;
    
    try {
      await fetch('/setup/api/claude/disconnect', { method: 'POST' });
      window.resetClaudeUI();
    } catch (err) {
      alert('Failed to disconnect: ' + err.message);
    }
  };

  window.resetClaudeUI = function() {
    document.getElementById('claude-not-connected').style.display = 'block';
    document.getElementById('claude-instructions').style.display = 'none';
    document.getElementById('claude-connected').style.display = 'none';
  };

  // Initialize everything
  initCollapsibles();
  refreshStatus();
  window.checkGitHubStatus();
  window.checkCodexStatus();
  window.checkClaudeStatus();
})();
