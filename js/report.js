/**
 * report.js — Render del reporte de seguridad en el DOM
 *
 * Responsabilidad única: tomar los datos del scan y construir la UI.
 * No hace fetch, no tiene lógica de negocio — solo presentación.
 */

const PAGE_SIZE = 10; // CVEs por página

/**
 * Renderiza el reporte completo dado los resultados del scan.
 */
export function renderReport(data) {
  const { repoMeta, cveFindings, secretFindings, sensitiveFiles, aiSummary, score } = data;

  renderScoreBanner(score, cveFindings, secretFindings, sensitiveFiles);
  renderAISummary(aiSummary);
  renderCVEs(cveFindings);
  renderSecrets(secretFindings);
  renderSensitiveFiles(sensitiveFiles);
  renderTimestamp(repoMeta);
}

// ── Score Banner ─────────────────────────────────────────────

function renderScoreBanner(score, cves, secrets, files) {
  const valueEl  = document.getElementById('score-value');
  const gradeEl  = document.getElementById('score-grade');
  const ringFill = document.getElementById('score-ring-fill');
  const statsEl  = document.getElementById('score-stats');

  // Fix: asignar el número correctamente
  valueEl.textContent = String(score);

  const { grade, color } = getGrade(score);
  gradeEl.textContent   = grade;
  gradeEl.style.color   = color;
  ringFill.style.stroke = color;

  // Animación del anillo — circumference = 2π × 50 ≈ 314
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  requestAnimationFrame(() => {
    setTimeout(() => {
      ringFill.style.strokeDashoffset = String(offset);
    }, 120);
  });

  // Stat chips
  statsEl.innerHTML = [
    { label: 'CVEs',    value: cves.length,    cls: cves.length    ? 'stat-critical' : '' },
    { label: 'Secrets', value: secrets.length, cls: secrets.length ? 'stat-high'     : '' },
    { label: 'Files',   value: files.length,   cls: files.length   ? 'stat-medium'   : '' },
  ].map(s => `
    <div class="stat-chip ${s.cls}">
      <span class="stat-chip-value">${s.value}</span>
      <span class="stat-chip-label">${s.label}</span>
    </div>
  `).join('');
}

function getGrade(score) {
  if (score >= 90) return { grade: 'Excellent',       color: '#52C41A' };
  if (score >= 75) return { grade: 'Good',            color: '#73D13D' };
  if (score >= 60) return { grade: 'Needs Attention', color: '#FAAD14' };
  if (score >= 40) return { grade: 'At Risk',         color: '#FF8C00' };
  return               { grade: 'Critical Risk',     color: '#FF4D4F' };
}

// ── AI Summary ───────────────────────────────────────────────

export function renderAISummary(text) {
  const el = document.getElementById('ai-summary-text');
  el.innerHTML = '';
  el.textContent = text || 'AI analysis unavailable. Add a Groq API key in Config.';
}

// ── CVEs — paginado ──────────────────────────────────────────

function renderCVEs(findings) {
  document.getElementById('cve-count').textContent = findings.length;
  const bodyEl = document.getElementById('cve-body');

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No vulnerable dependencies detected.</p>';
    return;
  }

  let page = 0;

  function renderPage() {
    const start   = page * PAGE_SIZE;
    const end     = start + PAGE_SIZE;
    const slice   = findings.slice(start, end);
    const total   = findings.length;
    const hasNext = end < total;
    const hasPrev = page > 0;

    const items = slice.map(f => `
      <div class="cve-item">
        <span class="cve-severity sev-${f.severity}">${f.severity}</span>
        <div>
          <span class="cve-package">${escHtml(f.package)}</span>
          <span class="cve-version"> @${escHtml(f.version)}</span>
          <div class="cve-title">${escHtml(truncate(f.title, 80))}</div>
        </div>
        <span class="cve-ecosystem">${escHtml(f.ecosystem)}</span>
        <span class="cve-id">
          <a href="${escHtml(f.url)}" target="_blank" rel="noopener">${escHtml(f.id)}</a>
        </span>
      </div>
    `).join('');

    const pagination = `
      <div class="pagination">
        <button class="page-btn" id="cve-prev" ${hasPrev ? '' : 'disabled'}>← Prev</button>
        <span class="page-info">${start + 1}–${Math.min(end, total)} of ${total}</span>
        <button class="page-btn" id="cve-next" ${hasNext ? '' : 'disabled'}>Next →</button>
      </div>
    `;

    bodyEl.innerHTML = `<div class="cve-list">${items}</div>${pagination}`;

    document.getElementById('cve-prev')?.addEventListener('click', () => { page--; renderPage(); });
    document.getElementById('cve-next')?.addEventListener('click', () => { page++; renderPage(); });
  }

  renderPage();
}

// ── Secrets — colapsable ──────────────────────────────────────

function renderSecrets(findings) {
  document.getElementById('secrets-count').textContent = findings.length;
  const bodyEl = document.getElementById('secrets-body');

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No secrets detected in scanned configuration files.</p>';
    return;
  }

  // Mostrar primeros 5, colapsar el resto
  renderCollapsible(bodyEl, findings, (f) => `
    <div class="secret-item">
      <span class="secret-icon">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </span>
      <div class="secret-info">
        <div class="secret-type">${escHtml(f.type)}</div>
        <div class="secret-file">${escHtml(f.file)} · line ${f.lineNumber}</div>
        <span class="secret-match">${escHtml(f.match)}</span>
      </div>
      <span class="cve-severity sev-${f.severity}" style="align-self:flex-start;flex-shrink:0;">${f.severity}</span>
    </div>
  `, 'secrets-list');
}

// ── Sensitive Files — colapsable ──────────────────────────────

function renderSensitiveFiles(findings) {
  document.getElementById('files-count').textContent = findings.length;
  const bodyEl = document.getElementById('files-body');

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No sensitive files found in repository.</p>';
    return;
  }

  renderCollapsible(bodyEl, findings, (f) => `
    <div class="file-item">
      <span class="file-severity sev-${f.severity}">${f.severity}</span>
      <span class="file-path">${escHtml(f.path)}</span>
      <span class="file-reason">${escHtml(truncate(f.reason, 60))}</span>
    </div>
  `, 'files-list');
}

// ── Collapsible helper ────────────────────────────────────────

function renderCollapsible(container, items, template, listClass, initialCount = 5) {
  const visible  = items.slice(0, initialCount);
  const hidden   = items.slice(initialCount);
  const hasMore  = hidden.length > 0;

  const visibleHtml = visible.map(template).join('');
  const hiddenHtml  = hidden.map(template).join('');

  container.innerHTML = `
    <div class="${listClass}">${visibleHtml}</div>
    ${hasMore ? `
      <div class="${listClass} collapsible-extra hidden" id="extra-${listClass}">${hiddenHtml}</div>
      <button class="btn-show-more" id="toggle-${listClass}">
        Show ${hidden.length} more ▾
      </button>
    ` : ''}
  `;

  if (hasMore) {
    const btn   = document.getElementById(`toggle-${listClass}`);
    const extra = document.getElementById(`extra-${listClass}`);
    let open    = false;

    btn.addEventListener('click', () => {
      open = !open;
      extra.classList.toggle('hidden', !open);
      btn.textContent = open ? 'Show less ▴' : `Show ${hidden.length} more ▾`;
    });
  }
}

// ── Timestamp ────────────────────────────────────────────────

function renderTimestamp(repoMeta) {
  const el  = document.getElementById('report-timestamp');
  const now = new Date().toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
  el.textContent = `Scanned ${repoMeta.full_name} · ${now}`;
}

// ── Score Calculator ──────────────────────────────────────────

export function calculateScore(cveFindings, secretFindings, sensitiveFiles) {
  let score = 100;

  for (const f of cveFindings) {
    if (f.severity === 'CRITICAL')     score -= 18;
    else if (f.severity === 'HIGH')    score -= 10;
    else if (f.severity === 'MEDIUM')  score -= 5;
    else                               score -= 2;
  }

  for (const f of secretFindings) {
    if (f.severity === 'CRITICAL')     score -= 20;
    else if (f.severity === 'HIGH')    score -= 12;
    else                               score -= 6;
  }

  for (const f of sensitiveFiles) {
    if (f.severity === 'CRITICAL')     score -= 15;
    else if (f.severity === 'HIGH')    score -= 8;
    else if (f.severity === 'MEDIUM')  score -= 3;
    else                               score -= 1;
  }

  return Math.max(0, Math.min(100, score));
}

// ── Helpers ───────────────────────────────────────────────────

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.slice(0, max) + '…' : str;
}

