/**
 * report.js — Render del reporte de seguridad en el DOM
 *
 * Responsabilidad única: tomar los datos del scan y construir la UI.
 * No hace fetch, no tiene lógica de negocio — solo presentación.
 */

/**
 * Renderiza el reporte completo dado los resultados del scan.
 * @param {object} data
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

  valueEl.textContent = score;

  // Color y label según score
  const { grade, color } = getGrade(score);
  gradeEl.textContent    = grade;
  gradeEl.style.color    = color;
  ringFill.style.stroke  = color;

  // Animación del anillo: circumference = 2π × 50 ≈ 314
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  // Slight delay para que la animación sea visible al montar
  requestAnimationFrame(() => {
    setTimeout(() => {
      ringFill.style.strokeDashoffset = offset;
    }, 100);
  });

  // Stat chips
  const criticalCVEs    = cves.filter(f => f.severity === 'CRITICAL').length;
  const highCVEs        = cves.filter(f => f.severity === 'HIGH').length;
  const criticalSecrets = secrets.filter(f => f.severity === 'CRITICAL').length;
  const criticalFiles   = files.filter(f => f.severity === 'CRITICAL').length;

  const stats = [
    { label: 'CVEs',    value: cves.length,    cls: cves.length    ? 'stat-critical' : '' },
    { label: 'Secrets', value: secrets.length, cls: secrets.length ? 'stat-high'     : '' },
    { label: 'Files',   value: files.length,   cls: files.length   ? 'stat-medium'   : '' },
  ];

  statsEl.innerHTML = stats.map(s => `
    <div class="stat-chip ${s.cls}">
      <span class="stat-chip-value">${s.value}</span>
      <span class="stat-chip-label">${s.label}</span>
    </div>
  `).join('');
}

function getGrade(score) {
  if (score >= 90) return { grade: 'Excellent',        color: '#52C41A' };
  if (score >= 75) return { grade: 'Good',             color: '#73D13D' };
  if (score >= 60) return { grade: 'Needs Attention',  color: '#FAAD14' };
  if (score >= 40) return { grade: 'At Risk',          color: '#FF8C00' };
  return               { grade: 'Critical Risk',      color: '#FF4D4F' };
}

// ── AI Summary ───────────────────────────────────────────────

export function renderAISummary(text) {
  const el = document.getElementById('ai-summary-text');
  el.innerHTML = ''; // limpiar skeleton
  el.textContent = text || 'AI analysis unavailable. Add a Groq API key in Config.';
}

// ── CVEs ─────────────────────────────────────────────────────

function renderCVEs(findings) {
  const countEl = document.getElementById('cve-count');
  const bodyEl  = document.getElementById('cve-body');

  countEl.textContent = findings.length;

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No vulnerable dependencies detected.</p>';
    return;
  }

  const items = findings.map(f => `
    <div class="cve-item">
      <span class="cve-severity sev-${f.severity}">${f.severity}</span>
      <div>
        <span class="cve-package">${escHtml(f.package)}</span>
        <span class="cve-version"> @${escHtml(f.version)}</span>
        <div style="font-size:0.7rem;color:var(--text-muted);margin-top:2px;">${escHtml(truncate(f.title, 80))}</div>
      </div>
      <span style="font-size:0.7rem;color:var(--text-muted);">${escHtml(f.ecosystem)}</span>
      <span class="cve-id">
        <a href="${escHtml(f.url)}" target="_blank" rel="noopener">${escHtml(f.id)}</a>
      </span>
    </div>
  `).join('');

  bodyEl.innerHTML = `<div class="cve-list">${items}</div>`;
}

// ── Secrets ──────────────────────────────────────────────────

function renderSecrets(findings) {
  const countEl = document.getElementById('secrets-count');
  const bodyEl  = document.getElementById('secrets-body');

  countEl.textContent = findings.length;

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No secrets detected in scanned configuration files.</p>';
    return;
  }

  const items = findings.map(f => `
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
      <span class="cve-severity sev-${f.severity}" style="align-self:flex-start;">${f.severity}</span>
    </div>
  `).join('');

  bodyEl.innerHTML = `<div class="secrets-list">${items}</div>`;
}

// ── Sensitive Files ───────────────────────────────────────────

function renderSensitiveFiles(findings) {
  const countEl = document.getElementById('files-count');
  const bodyEl  = document.getElementById('files-body');

  countEl.textContent = findings.length;

  if (!findings.length) {
    bodyEl.innerHTML = '<p class="empty-state">No sensitive files found in repository.</p>';
    return;
  }

  const items = findings.map(f => `
    <div class="file-item">
      <span class="file-severity sev-${f.severity}">${f.severity}</span>
      <span class="file-path">${escHtml(f.path)}</span>
      <span class="file-reason">${escHtml(truncate(f.reason, 60))}</span>
    </div>
  `).join('');

  bodyEl.innerHTML = `<div class="files-list">${items}</div>`;
}

// ── Timestamp ────────────────────────────────────────────────

function renderTimestamp(repoMeta) {
  const el = document.getElementById('report-timestamp');
  const now = new Date().toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
  el.textContent = `Scanned ${repoMeta.full_name} · ${now}`;
}

// ── Score Calculator ──────────────────────────────────────────

/**
 * Calcula el security score del 0 al 100.
 * Penaliza más fuerte los findings de mayor severidad.
 */
export function calculateScore(cveFindings, secretFindings, sensitiveFiles) {
  let score = 100;

  // CVEs
  for (const f of cveFindings) {
    if (f.severity === 'CRITICAL') score -= 18;
    else if (f.severity === 'HIGH')     score -= 10;
    else if (f.severity === 'MEDIUM')   score -= 5;
    else                                score -= 2;
  }

  // Secrets
  for (const f of secretFindings) {
    if (f.severity === 'CRITICAL') score -= 20;
    else if (f.severity === 'HIGH')     score -= 12;
    else                                score -= 6;
  }

  // Sensitive files
  for (const f of sensitiveFiles) {
    if (f.severity === 'CRITICAL') score -= 15;
    else if (f.severity === 'HIGH')     score -= 8;
    else if (f.severity === 'MEDIUM')   score -= 3;
    else                                score -= 1;
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
