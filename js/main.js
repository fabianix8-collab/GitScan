/**
 * main.js — Orquestador principal de GitScan
 *
 * Responsabilidades:
 *  - Gestión del estado de la UI (hero → pipeline → report)
 *  - Configuración persistente en localStorage
 *  - Coordinar el pipeline de análisis en orden
 *  - Error handling global
 */

import { GitHubClient, parseGitHubUrl, GitHubError } from './github.js';
import { parseDependencies }                          from './scanner/deps.js';
import { scanSecrets }                                from './scanner/secrets.js';
import { scanSensitiveFiles }                         from './scanner/sensitive.js';
import { queryOSV, normalizeOSVResults }              from './osv.js';
import { generateRiskSummary, GroqError }             from './groq.js';
import { renderReport, renderAISummary, calculateScore } from './report.js';

// ── Constantes ───────────────────────────────────────────────

const STORAGE_KEY = 'gitscan_config';

const PIPELINE_STEPS = [
  { id: 'fetch-meta',   label: 'Fetching repository metadata' },
  { id: 'fetch-tree',   label: 'Mapping file tree' },
  { id: 'scan-files',   label: 'Scanning sensitive files' },
  { id: 'fetch-deps',   label: 'Reading dependency manifests' },
  { id: 'scan-secrets', label: 'Detecting exposed secrets' },
  { id: 'query-osv',    label: 'Querying CVE database and fetching details' },
  { id: 'ai-analysis',  label: 'Generating AI risk summary' },
];

// ── Estado de la aplicación ───────────────────────────────────

let config = loadConfig();

// ── Boot ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  bindUIEvents();
  applyConfigToModal();
  updateConfigIndicator();
});

// ── Event bindings ────────────────────────────────────────────

function bindUIEvents() {
  // Scan
  document.getElementById('btn-scan').addEventListener('click', handleScan);
  document.getElementById('input-repo-url').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleScan();
  });

  // Demo chips
  document.querySelectorAll('.demo-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.getElementById('input-repo-url').value = chip.dataset.url;
      handleScan();
    });
  });

  // Scan again / retry
  document.getElementById('btn-scan-again').addEventListener('click', resetToHero);
  document.getElementById('btn-error-retry').addEventListener('click', resetToHero);

  // Config modal
  document.getElementById('btn-open-config').addEventListener('click', openConfig);
  document.getElementById('btn-close-config').addEventListener('click', closeConfig);
  document.getElementById('btn-save-config').addEventListener('click', saveConfig);
  document.getElementById('btn-clear-config').addEventListener('click', clearConfig);

  // Cerrar modal al clickear el overlay
  document.getElementById('modal-config').addEventListener('click', e => {
    if (e.target.id === 'modal-config') closeConfig();
  });

  // Escape para cerrar modal
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeConfig();
  });
}

// ── Scan pipeline ─────────────────────────────────────────────

async function handleScan() {
  const rawInput = document.getElementById('input-repo-url').value.trim();
  if (!rawInput) {
    showToast('Paste a GitHub repository URL first.', 'error');
    return;
  }

  const parsed = parseGitHubUrl(rawInput);
  if (!parsed) {
    showToast('Could not parse that URL. Try: github.com/owner/repo', 'error');
    return;
  }

  const { owner, repo } = parsed;

  showSection('pipeline');
  document.getElementById('pipeline-repo-label').textContent = `${owner}/${repo}`;
  initPipelineSteps();

  try {
    const github = new GitHubClient(config.githubToken || null);

    // ── Step 1: Repo metadata ────────────────────────────────
    setStep('fetch-meta', 'running');
    const repoMeta = await github.getRepo(owner, repo);
    setStep('fetch-meta', 'done');

    // ── Step 2: File tree ────────────────────────────────────
    setStep('fetch-tree', 'running');
    const branch    = repoMeta.default_branch;
    const fileTree  = await github.getFileTree(owner, repo, branch);
    const filePaths = fileTree.map(f => f.path);
    setStep('fetch-tree', 'done');
    setProgress(28);

    // ── Step 3: Sensitive files (solo paths, 0 API calls extra) ──
    setStep('scan-files', 'running');
    const sensitiveFiles = scanSensitiveFiles(filePaths);
    setStep('scan-files', 'done');
    setProgress(42);

    // ── Step 4: Dependency manifests ─────────────────────────
    setStep('fetch-deps', 'running');
    const depFiles     = await github.getDependencyFiles(owner, repo, branch, filePaths);
    const dependencies = parseDependencies(depFiles);
    setStep('fetch-deps', 'done');
    setProgress(56);

    // ── Step 5: Secrets scan ──────────────────────────────────
    setStep('scan-secrets', 'running');
    const configFiles    = await github.getConfigFiles(owner, repo, branch, filePaths);
    const secretFindings = scanSecrets(configFiles);
    setStep('scan-secrets', 'done');
    setProgress(70);

    // ── Step 6: OSV CVE lookup ────────────────────────────────
    setStep('query-osv', 'running');
    let cveFindings = [];
    if (dependencies.length) {
      const osvResults = await queryOSV(dependencies);
      cveFindings      = normalizeOSVResults(osvResults);
    }
    setStep('query-osv', 'done');
    setProgress(85);

    // ── Step 7: AI analysis ───────────────────────────────────
    setStep('ai-analysis', 'running');
    const score = calculateScore(cveFindings, secretFindings, sensitiveFiles);

    let aiSummary;
    try {
      aiSummary = await generateRiskSummary(config.groqKey || null, {
        repoMeta, cveFindings, secretFindings, sensitiveFiles, score,
      });
    } catch (err) {
      if (err instanceof GroqError) {
        console.warn('[GitScan] Groq error, using fallback:', err.message);
        aiSummary = err.message + '\n\nFallback: ' + buildFallbackText(cveFindings, secretFindings, sensitiveFiles);
      } else {
        throw err;
      }
    }
    setStep('ai-analysis', 'done');
    setProgress(100);

    // ── Render report ────────────────────────────────────────
    await sleep(400); // pequeña pausa para que el 100% sea visible
    showSection('report');
    renderReport({ repoMeta, cveFindings, secretFindings, sensitiveFiles, aiSummary, score });

  } catch (err) {
    console.error('[GitScan] Scan failed:', err);
    showError(err);
  }
}

function buildFallbackText(cves, secrets, files) {
  const parts = [];
  if (cves.length)     parts.push(`${cves.length} CVE(s) found.`);
  if (secrets.length)  parts.push(`${secrets.length} secret(s) detected.`);
  if (files.length)    parts.push(`${files.length} sensitive file(s) exposed.`);
  return parts.length ? parts.join(' ') : 'No significant findings.';
}

// ── Pipeline UI helpers ───────────────────────────────────────

function initPipelineSteps() {
  const container = document.getElementById('pipeline-steps');
  container.innerHTML = PIPELINE_STEPS.map(step => `
    <div class="pipeline-step" id="step-${step.id}">
      <span class="step-icon pending" id="icon-${step.id}">○</span>
      <span class="step-label" id="label-${step.id}">${step.label}</span>
    </div>
  `).join('');
  setProgress(0);
  document.getElementById('pipeline-status').textContent = 'Running...';
}

function setStep(id, state) {
  const icon  = document.getElementById(`icon-${id}`);
  const label = document.getElementById(`label-${id}`);
  if (!icon) return;

  icon.className = `step-icon ${state}`;

  if (state === 'running') {
    icon.textContent  = '▶';
    label.className   = 'step-label active';
    document.getElementById('pipeline-status').textContent = PIPELINE_STEPS.find(s => s.id === id)?.label + '...';
  } else if (state === 'done') {
    icon.textContent  = '✓';
    label.className   = 'step-label done';
  } else if (state === 'error') {
    icon.textContent  = '✕';
    label.className   = 'step-label';
  }
}

function setProgress(pct) {
  document.getElementById('pipeline-bar').style.width = `${pct}%`;
}

// ── Section management ────────────────────────────────────────

function showSection(name) {
  const sections = ['hero', 'pipeline', 'report', 'error'];
  sections.forEach(s => {
    const el = document.getElementById(`section-${s}`);
    if (el) el.classList.toggle('hidden', s !== name);
  });
}

function resetToHero() {
  document.getElementById('input-repo-url').value = '';
  showSection('hero');
  document.getElementById('btn-scan').disabled = false;
}

function showError(err) {
  showSection('error');

  let message = 'Scan failed.';
  let detail  = err.message || 'An unexpected error occurred.';

  if (err instanceof GitHubError) {
    if (err.code === 'NOT_FOUND')   message = 'Repository not found.';
    if (err.code === 'RATE_LIMIT')  message = 'GitHub API rate limit exceeded.';
    if (err.code === 'FORBIDDEN')   message = 'Access denied.';
  }

  document.getElementById('error-message').textContent = message;
  document.getElementById('error-detail').textContent  = detail;
}

// ── Config ────────────────────────────────────────────────────

function loadConfig() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch {
    return {};
  }
}

function applyConfigToModal() {
  if (config.githubToken) document.getElementById('input-github-token').value = config.githubToken;
  if (config.groqKey)     document.getElementById('input-groq-key').value     = config.groqKey;
}

function updateConfigIndicator() {
  const btn = document.getElementById('btn-open-config');
  const hasKeys = config.githubToken || config.groqKey;
  btn.style.borderColor = hasKeys ? 'rgba(0, 217, 255, 0.4)' : '';
  btn.style.color       = hasKeys ? 'var(--cyan)' : '';
}

function openConfig() {
  document.getElementById('modal-config').classList.remove('hidden');
}

function closeConfig() {
  document.getElementById('modal-config').classList.add('hidden');
}

function saveConfig() {
  config.githubToken = document.getElementById('input-github-token').value.trim() || null;
  config.groqKey     = document.getElementById('input-groq-key').value.trim()     || null;

  localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  updateConfigIndicator();
  closeConfig();
  showToast('API keys saved.', 'success');
}

function clearConfig() {
  if (!confirm('Clear all saved API keys?')) return;
  config = {};
  localStorage.removeItem(STORAGE_KEY);
  document.getElementById('input-github-token').value = '';
  document.getElementById('input-groq-key').value     = '';
  updateConfigIndicator();
  closeConfig();
  showToast('Keys cleared.', 'success');
}

// ── Toast ─────────────────────────────────────────────────────

let toastTimer;

function showToast(message, type = '') {
  const el = document.getElementById('toast');
  el.textContent  = message;
  el.className    = `toast ${type}`;
  el.classList.remove('hidden');

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 3000);
}

// ── Utilities ─────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
