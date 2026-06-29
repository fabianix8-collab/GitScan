/**
 * osv.js — Cliente para OSV.dev (Open Source Vulnerabilities)
 *
 * Usa el endpoint /v1/querybatch para resolver todos los paquetes
 * en una sola llamada HTTP — eficiente y respetuoso con rate limits.
 *
 * Docs: https://google.github.io/osv.dev/api/
 */

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE    = 1000; // límite del endpoint

/**
 * Consulta vulnerabilidades para un array de dependencias.
 * @param {{ name: string, version: string, ecosystem: string }[]} dependencies
 * @returns {{ dependency, vulnerabilities }[]} solo deps con vulns
 */
export async function queryOSV(dependencies) {
  if (!dependencies.length) return [];

  // Filtrar deps sin versión — OSV necesita versión para hacer match exacto
  const queryable = dependencies.filter(d => d.version && d.name);

  // Partir en batches si el repo tiene muchas dependencias
  const batches = chunk(queryable, BATCH_SIZE);
  const allResults = [];

  for (const batch of batches) {
    const results = await fetchBatch(batch);
    allResults.push(...results);
  }

  // Filtrar solo los que tienen vulnerabilidades
  return allResults
    .map((result, i) => ({
      dependency:      queryable[i],
      vulnerabilities: result.vulns || [],
    }))
    .filter(r => r.vulnerabilities.length > 0);
}

async function fetchBatch(deps) {
  const body = {
    queries: deps.map(dep => ({
      version: dep.version,
      package: {
        name:      dep.name,
        ecosystem: dep.ecosystem,
      },
    })),
  };

  const res = await fetch(OSV_BATCH_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`OSV.dev API error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  return data.results || [];
}

/**
 * Normaliza los resultados de OSV en un formato plano para el reporte.
 * Extrae el CVE/GHSA más relevante de cada finding.
 */
export function normalizeOSVResults(results) {
  const findings = [];

  for (const { dependency, vulnerabilities } of results) {
    for (const vuln of vulnerabilities) {
      const severity = extractSeverity(vuln);
      const id       = extractPrimaryId(vuln);
      const title    = vuln.summary || 'No description available';
      const url      = buildUrl(id);

      findings.push({
        package:    dependency.name,
        version:    dependency.version,
        ecosystem:  dependency.ecosystem,
        id,
        severity,
        title,
        url,
      });
    }
  }

  // Deduplicar por package+id y ordenar por severidad
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  const seen = new Set();

  return findings
    .filter(f => {
      const key = `${f.package}:${f.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4));
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Extrae la severidad del objeto de vuln OSV.
 * OSV puede tenerla en database_specific, severity array, o CVSS.
 */
function extractSeverity(vuln) {
  // Intentar desde el array severity estándar
  if (vuln.severity?.length) {
    for (const s of vuln.severity) {
      if (s.type === 'CVSS_V3' && s.score) {
        const score = parseFloat(s.score);
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        return 'LOW';
      }
    }
  }

  // Fallback desde database_specific (GitHub Security Advisory)
  const ghsa = vuln.database_specific?.severity;
  if (ghsa) {
    const upper = ghsa.toUpperCase();
    if (['CRITICAL','HIGH','MEDIUM','LOW'].includes(upper)) return upper;
  }

  return 'UNKNOWN';
}

/**
 * Prioriza IDs: CVE > GHSA > primer alias disponible
 */
function extractPrimaryId(vuln) {
  const aliases = vuln.aliases || [];
  const cve  = aliases.find(a => a.startsWith('CVE-'));
  const ghsa = aliases.find(a => a.startsWith('GHSA-'));
  return cve || ghsa || vuln.id || 'UNKNOWN';
}

function buildUrl(id) {
  if (id.startsWith('CVE-'))  return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  if (id.startsWith('OSV-'))  return `https://osv.dev/vulnerability/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function chunk(array, size) {
  const chunks = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}
