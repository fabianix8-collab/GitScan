/**
 * groq.js — Análisis IA con Groq
 *
 * Llama directamente a la API de Groq desde el browser.
 * Genera un resumen de riesgo ejecutivo basado en los findings del scan.
 */

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL        = 'llama3-8b-8192'; // rápido, gratuito, suficiente para este task

/**
 * Genera un resumen de riesgo en lenguaje natural para el reporte.
 *
 * @param {string} groqKey - API key del usuario
 * @param {object} scanData - Resultado consolidado del scan
 * @returns {string} Texto del análisis
 */
export async function generateRiskSummary(groqKey, scanData) {
  if (!groqKey) {
    return buildFallbackSummary(scanData);
  }

  const prompt = buildPrompt(scanData);

  const res = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${groqKey}`,
    },
    body: JSON.stringify({
      model:      MODEL,
      max_tokens: 400,
      temperature: 0.3, // baja temperatura = respuestas más consistentes y factuales
      messages: [
        {
          role: 'system',
          content: `You are a senior application security engineer writing concise executive risk summaries.
Your summaries are factual, specific, and actionable. You write in plain English without jargon padding.
You never say "I" or "we". You never start with "Based on". Maximum 4 sentences.
Focus on: what the highest risks are, what an attacker could do with these findings, and the single most important remediation action.`,
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    if (res.status === 401) throw new GroqError('Invalid Groq API key. Check your key in Config.', 'AUTH');
    if (res.status === 429) throw new GroqError('Groq rate limit reached. Try again in a moment.', 'RATE_LIMIT');
    throw new GroqError(err.error?.message || `Groq API error: ${res.status}`, 'API_ERROR');
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content?.trim() || buildFallbackSummary(scanData);
}

// ── Prompt builder ───────────────────────────────────────────

function buildPrompt(scanData) {
  const { repoMeta, cveFindings, secretFindings, sensitiveFiles, score } = scanData;

  const lines = [
    `Repository: ${repoMeta.full_name}`,
    `Language: ${repoMeta.language || 'Unknown'}`,
    `Stars: ${repoMeta.stargazers_count} | Forks: ${repoMeta.forks_count}`,
    `Security Score: ${score}/100`,
    '',
  ];

  if (cveFindings.length) {
    const critical = cveFindings.filter(f => f.severity === 'CRITICAL');
    const high     = cveFindings.filter(f => f.severity === 'HIGH');
    lines.push(`CVE Findings: ${cveFindings.length} total (${critical.length} CRITICAL, ${high.length} HIGH)`);
    // Incluir los top 3 más severos para el análisis
    cveFindings.slice(0, 3).forEach(f => {
      lines.push(`  - ${f.package}@${f.version}: ${f.id} [${f.severity}] — ${f.title}`);
    });
    lines.push('');
  } else {
    lines.push('CVE Findings: 0 (no vulnerable dependencies detected)');
    lines.push('');
  }

  if (secretFindings.length) {
    lines.push(`Exposed Secrets: ${secretFindings.length} detected`);
    secretFindings.slice(0, 3).forEach(f => {
      lines.push(`  - ${f.type} [${f.severity}] in ${f.file}:${f.lineNumber}`);
    });
    lines.push('');
  } else {
    lines.push('Exposed Secrets: 0 detected');
    lines.push('');
  }

  if (sensitiveFiles.length) {
    const critical = sensitiveFiles.filter(f => f.severity === 'CRITICAL');
    lines.push(`Sensitive Files: ${sensitiveFiles.length} exposed (${critical.length} CRITICAL)`);
    sensitiveFiles.slice(0, 3).forEach(f => {
      lines.push(`  - ${f.path} [${f.severity}]: ${f.reason}`);
    });
    lines.push('');
  } else {
    lines.push('Sensitive Files: 0 detected');
    lines.push('');
  }

  lines.push('Write a 3-4 sentence executive risk summary for this security report.');

  return lines.join('\n');
}

// ── Fallback (sin Groq key) ──────────────────────────────────

function buildFallbackSummary(scanData) {
  const { cveFindings, secretFindings, sensitiveFiles } = scanData;

  if (!cveFindings.length && !secretFindings.length && !sensitiveFiles.length) {
    return 'No significant security issues were detected in this repository. The dependency ecosystem appears clean against known CVEs, no secrets were found in scanned configuration files, and no sensitive files are exposed in the repository tree. Continue monitoring as new vulnerabilities are disclosed regularly.';
  }

  const parts = [];

  if (secretFindings.some(f => f.severity === 'CRITICAL')) {
    parts.push(`${secretFindings.length} exposed secret(s) were detected — including credentials that should be rotated immediately.`);
  } else if (secretFindings.length) {
    parts.push(`${secretFindings.length} potential secret(s) were found in configuration files and should be reviewed.`);
  }

  const criticalCVEs = cveFindings.filter(f => f.severity === 'CRITICAL');
  if (criticalCVEs.length) {
    parts.push(`${criticalCVEs.length} CRITICAL CVE(s) were identified in project dependencies, representing active exploitation risk.`);
  } else if (cveFindings.length) {
    parts.push(`${cveFindings.length} dependency vulnerability/vulnerabilities were found and should be patched.`);
  }

  if (sensitiveFiles.filter(f => f.severity === 'CRITICAL').length) {
    parts.push('Critical configuration files are exposed in the repository and may contain live credentials.');
  }

  parts.push('Add a Groq API key in Config to enable AI-powered analysis and prioritized remediation guidance.');

  return parts.join(' ');
}

export class GroqError extends Error {
  constructor(message, code) {
    super(message);
    this.name  = 'GroqError';
    this.code  = code;
  }
}
