/**
 * Sonic Recon AI — shared panel renderer for all CyberScan tools.
 */
(function (global) {
  'use strict';

  const ARC_LEN = Math.PI * 40;

  function esc(s) {
    if (s == null) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  function riskLabelForScore(score) {
    if (score == null) return 'Info';
    if (score <= 30) return 'Low';
    if (score <= 60) return 'Medium';
    if (score <= 85) return 'High';
    return 'Critical';
  }

  function colorForScore(score) {
    if (score == null) return '#06b6d4';
    if (score <= 30) return '#00ffb2';
    if (score <= 60) return '#febc2e';
    if (score <= 85) return '#ff8c42';
    return '#ff4444';
  }

  function impactClass(impact) {
    const n = Number(impact) || 0;
    if (n >= 20) return 'sonic-impact-high';
    if (n > 0) return 'sonic-impact-med';
    return 'sonic-impact-zero';
  }

  function severityClass(sev) {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 'sonic-sev-critical';
    if (s === 'high') return 'sonic-sev-high';
    if (s === 'medium') return 'sonic-sev-medium';
    if (s === 'low') return 'sonic-sev-low';
    return 'sonic-sev-info';
  }

  function animateGauge(pathEl, valueEl, riskLbl, targetScore) {
    if (!pathEl || !valueEl) return;
    const end = Math.max(0, Math.min(100, Number(targetScore) || 0));
    const color = colorForScore(end);
    pathEl.style.stroke = color;
    pathEl.style.strokeDasharray = `0 ${ARC_LEN}`;
    if (riskLbl) {
      riskLbl.textContent = riskLabelForScore(end);
      riskLbl.style.color = color;
    }
    let start = null;
    const dur = 1100;
    function frame(t) {
      if (!start) start = t;
      const p = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      const cur = Math.round(end * eased);
      valueEl.textContent = cur;
      const dash = (cur / 100) * ARC_LEN;
      pathEl.style.strokeDasharray = `${dash} ${ARC_LEN}`;
      if (p < 1) requestAnimationFrame(frame);
      else {
        valueEl.textContent = end;
        pathEl.style.strokeDasharray = `${(end / 100) * ARC_LEN} ${ARC_LEN}`;
      }
    }
    requestAnimationFrame(frame);
  }

  /**
   * @param {HTMLElement} mount - container (contents replaced)
   * @param {object} ai - ai_analysis from API
   */
  function renderSonicReconPanel(mount, ai) {
    if (!mount || !ai) return;
    mount.innerHTML = '';

    const wrap = document.createElement('div');
    wrap.className = 'sonic-recon-panel';
    wrap.setAttribute('role', 'region');
    wrap.setAttribute('aria-label', 'Sonic Recon AI Analysis');

    const infoOnly = ai.informational === true || ai.score === null || ai.score === undefined;
    const scoreVal = infoOnly ? null : Number(ai.score);

    const header = document.createElement('div');
    header.className = 'sonic-recon-header';
    header.innerHTML =
      '<ion-icon name="shield-checkmark-outline" class="sonic-recon-shield"></ion-icon>' +
      '<span class="sonic-recon-title">Sonic Recon AI Analysis</span>' +
      '<span class="sonic-pulse-dot" aria-hidden="true"></span>';
    wrap.appendChild(header);

    const gaugeBlock = document.createElement('div');
    gaugeBlock.className = 'sonic-gauge-section';

    if (infoOnly) {
      gaugeBlock.innerHTML =
        '<div class="sonic-info-banner">' +
        '<p class="sonic-info-title">Qualitative assessment</p>' +
        '<p class="sonic-info-sub">No numeric threat score for this tool — review findings below.</p>' +
        '</div>';
    } else {
      const c = colorForScore(scoreVal);
      gaugeBlock.innerHTML =
        '<div class="sonic-gauge-wrap">' +
        '<svg class="sonic-gauge-svg" viewBox="0 0 100 54" aria-hidden="true">' +
        '<path class="sonic-gauge-track" d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10" stroke-linecap="round"/>' +
        '<path class="sonic-gauge-arc" d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="' +
        esc(c) +
        '" stroke-width="10" stroke-linecap="round" style="stroke-dasharray:0 ' +
        ARC_LEN +
        ';"/>' +
        '</svg>' +
        '<div class="sonic-gauge-center">' +
        '<div class="sonic-gauge-value">0</div>' +
        '<div class="sonic-gauge-sublabel">Threat Score</div>' +
        '<div class="sonic-gauge-risklabel">' +
        esc(riskLabelForScore(scoreVal)) +
        '</div>' +
        '</div></div>';
    }
    wrap.appendChild(gaugeBlock);

    const breakdown = ai.breakdown || [];
    if (breakdown.length) {
      const sec = document.createElement('div');
      sec.className = 'sonic-block';
      sec.innerHTML = '<h4 class="sonic-block-title">Score breakdown</h4>';
      const table = document.createElement('table');
      table.className = 'sonic-breakdown-table';
      table.innerHTML =
        '<thead><tr><th>Factor</th><th>Impact</th></tr></thead><tbody></tbody>';
      const tb = table.querySelector('tbody');
      breakdown.forEach(function (row) {
        const tr = document.createElement('tr');
        const imp = Number(row.impact) || 0;
        tr.innerHTML =
          '<td><span class="sonic-bd-detail">' +
          esc(row.factor) +
          '</span>' +
          (row.detail
            ? '<span class="sonic-bd-sub">' + esc(row.detail) + '</span>'
            : '') +
          '</td><td class="sonic-bd-impact ' +
          impactClass(imp) +
          '">+' +
          esc(imp) +
          '</td>';
        tb.appendChild(tr);
      });
      sec.appendChild(table);
      wrap.appendChild(sec);
    }

    const findings = ai.findings || [];
    if (findings.length) {
      const sec = document.createElement('div');
      sec.className = 'sonic-block';
      sec.innerHTML = '<h4 class="sonic-block-title">Findings</h4>';
      const list = document.createElement('div');
      list.className = 'sonic-findings-list';
      findings.forEach(function (f) {
        const row = document.createElement('div');
        row.className = 'sonic-finding-row';
        const imp = f.impact != null ? f.impact : 0;
        row.innerHTML =
          '<div class="sonic-finding-left">' +
          '<span class="sonic-dot ' +
          severityClass(f.severity) +
          '"></span>' +
          '<span class="sonic-finding-text">' +
          esc(f.text) +
          '</span></div>' +
          '<span class="sonic-impact-badge">' +
          (imp > 0 ? '+' + esc(imp) : '—') +
          '</span>';
        list.appendChild(row);
      });
      sec.appendChild(list);
      wrap.appendChild(sec);
    }

    const rem = ai.remediation || [];
    if (rem.length) {
      const sec = document.createElement('div');
      sec.className = 'sonic-block sonic-remediation-block';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-secondary sonic-remediation-toggle';
      btn.textContent = 'View remediation steps';
      const body = document.createElement('div');
      body.className = 'sonic-remediation-body';
      body.hidden = true;
      const ol = document.createElement('ol');
      ol.className = 'sonic-remediation-list';
      rem.forEach(function (r) {
        const li = document.createElement('li');
        li.className = 'sonic-remediation-step';
        let html = '<p class="sonic-rem-action">' + esc(r.action) + '</p>';
        if (r.code) {
          html += '<pre class="sonic-code"><code>' + esc(r.code) + '</code></pre>';
        }
        li.innerHTML = html;
        ol.appendChild(li);
      });
      body.appendChild(ol);
      btn.addEventListener('click', function () {
        body.hidden = !body.hidden;
        btn.textContent = body.hidden ? 'View remediation steps' : 'Hide remediation steps';
      });
      sec.appendChild(btn);
      sec.appendChild(body);
      wrap.appendChild(sec);
    }

    const foot = document.createElement('div');
    foot.className = 'sonic-recon-footer';
    foot.innerHTML =
      'Powered by Sonic Recon AI — NITECHSPARK · ' +
      '<a href="https://nitechspark.in" target="_blank" rel="noopener noreferrer">nitechspark.in</a>';
    wrap.appendChild(foot);

    mount.appendChild(wrap);

    if (!infoOnly) {
      const pathEl = wrap.querySelector('.sonic-gauge-arc');
      const numEl = wrap.querySelector('.sonic-gauge-value');
      const riskLbl = wrap.querySelector('.sonic-gauge-risklabel');
      setTimeout(function () {
        animateGauge(pathEl, numEl, riskLbl, scoreVal);
      }, 600);
    }
  }

  function applySidebarPortThreat(ai, riskMeter, riskValue, riskLabelEl) {
    if (!ai || ai.score == null || !riskMeter || !riskValue) return;
    const score = Math.max(0, Math.min(100, Number(ai.score)));
    const color = colorForScore(score);
    riskValue.textContent = score;
    riskMeter.style.stroke = color;
    const dash = (score / 100) * ARC_LEN;
    riskMeter.style.strokeDasharray = dash + ', ' + ARC_LEN;
    const sub = riskLabelEl || riskValue.nextElementSibling;
    if (sub) {
      sub.textContent = riskLabelForScore(score) + ' Risk';
      sub.style.color = color;
    }
  }

  function appendSonicToContainer(container, ai) {
    if (!container || !ai) return;
    container.querySelectorAll('.sonic-recon-mount').forEach(function (e) {
      e.remove();
    });
    const m = document.createElement('div');
    m.className = 'sonic-recon-mount';
    container.appendChild(m);
    renderSonicReconPanel(m, ai);
  }

  global.renderSonicReconPanel = renderSonicReconPanel;
  global.applySidebarPortThreat = applySidebarPortThreat;
  global.appendSonicToContainer = appendSonicToContainer;
  global.sonicEsc = esc;
})(typeof window !== 'undefined' ? window : this);
