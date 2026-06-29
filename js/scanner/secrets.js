/**
 * scanner/secrets.js — Detección de secrets por regex en archivos de configuración
 *
 * Opera sobre contenido ya descargado — no hace fetch adicionales.
 * Principio de diseño: alto precision > alto recall.
 * Falsos positivos destruyen la credibilidad de la herramienta.
 */

/**
 * Cada regla define:
 *  - id:        identificador único
 *  - type:      nombre legible del tipo de secret
 *  - pattern:   regex que matchea el valor del secret
 *  - severity:  CRITICAL | HIGH | MEDIUM
 *  - entropy:   si true, verifica entropía mínima para reducir falsos positivos
 */
const SECRET_RULES = [
  // ── Cloud Providers ────────────────────────────────────────
  {
    id: 'aws-access-key',
    type: 'AWS Access Key ID',
    pattern: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/,
    severity: 'CRITICAL',
    entropy: false, // el prefijo AKIA ya es muy específico
  },
  {
    id: 'aws-secret-key',
    type: 'AWS Secret Access Key',
    pattern: /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|AWS_SECRET(?:_ACCESS)?_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    severity: 'CRITICAL',
    entropy: true,
  },
  {
    id: 'gcp-service-account',
    type: 'GCP Service Account Key',
    pattern: /"type"\s*:\s*"service_account"/,
    severity: 'CRITICAL',
    entropy: false,
  },
  {
    id: 'azure-conn-string',
    type: 'Azure Connection String',
    pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/,
    severity: 'CRITICAL',
    entropy: false,
  },

  // ── Tokens de servicios conocidos ──────────────────────────
  {
    id: 'github-token',
    type: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36}/,
    severity: 'CRITICAL',
    entropy: false,
  },
  {
    id: 'github-oauth',
    type: 'GitHub OAuth Token',
    pattern: /gho_[A-Za-z0-9]{36}/,
    severity: 'CRITICAL',
    entropy: false,
  },
  {
    id: 'github-actions',
    type: 'GitHub Actions Token',
    pattern: /ghs_[A-Za-z0-9]{36}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'slack-token',
    type: 'Slack Token',
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'slack-webhook',
    type: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'stripe-live',
    type: 'Stripe Live Secret Key',
    pattern: /sk_live_[A-Za-z0-9]{24,}/,
    severity: 'CRITICAL',
    entropy: false,
  },
  {
    id: 'stripe-test',
    type: 'Stripe Test Key',
    pattern: /sk_test_[A-Za-z0-9]{24,}/,
    severity: 'MEDIUM',
    entropy: false,
  },
  {
    id: 'sendgrid',
    type: 'SendGrid API Key',
    pattern: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'twilio-sid',
    type: 'Twilio Account SID',
    pattern: /AC[a-f0-9]{32}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'twilio-token',
    type: 'Twilio Auth Token',
    pattern: /(?:twilio[_\-.]?auth[_\-.]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']?([a-f0-9]{32})["']?/i,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'mailgun',
    type: 'Mailgun API Key',
    pattern: /key-[0-9a-f]{32}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'heroku-api',
    type: 'Heroku API Key',
    pattern: /[hH]eroku[^A-Za-z0-9][^\n]*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/,
    severity: 'HIGH',
    entropy: false,
  },
  {
    id: 'npm-token',
    type: 'npm Auth Token',
    pattern: /(?:npm[_\-.]?token|NPM_TOKEN|\/\/registry\.npmjs\.org\/:_authToken)\s*[=:]\s*["']?([A-Za-z0-9_\-]{36,})["']?/i,
    severity: 'HIGH',
    entropy: false,
  },

  // ── Credenciales de base de datos ──────────────────────────
  {
    id: 'db-connection-string',
    type: 'Database Connection String with Password',
    pattern: /(?:mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^:]+:([^@\s]{8,})@/i,
    severity: 'CRITICAL',
    entropy: true,
  },
  {
    id: 'db-password-env',
    type: 'Database Password in Environment Variable',
    pattern: /(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD)\s*=\s*["']?([^\s"'#]{8,})["']?/i,
    severity: 'HIGH',
    entropy: true,
  },

  // ── JWT y claves genéricas de alta entropía ─────────────────
  {
    id: 'jwt-secret',
    type: 'JWT Secret',
    pattern: /(?:jwt[_\-.]?secret|JWT_SECRET|jwt[_\-.]?key)\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{32,})["']?/i,
    severity: 'HIGH',
    entropy: true,
  },
  {
    id: 'private-key-header',
    type: 'Private Key (PEM format)',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'CRITICAL',
    entropy: false,
  },
  {
    id: 'generic-api-key',
    type: 'Generic API Key Assignment',
    pattern: /(?:api[_\-.]?key|API_KEY|apikey|secret[_\-.]?key)\s*[=:]\s*["']([A-Za-z0-9_\-]{32,})["']/i,
    severity: 'MEDIUM',
    entropy: true,
  },
];

// Líneas a ignorar (comentarios, ejemplos, placeholders)
const IGNORE_PATTERNS = [
  /^\s*#/,
  /^\s*\/\//,
  /^\s*\*/,
  /example|sample|placeholder|your[_\-]?key|your[_\-]?secret|xxx+|test[_\-]?key|fake[_\-]?key|dummy/i,
  /\$\{[^}]+\}/,   // Variables de template como ${MY_KEY}
  /\$\([^)]+\)/,   // Variables de shell como $(command)
  /<[A-Z_]+>/,     // Placeholders como <API_KEY>
];

/**
 * Calcula la entropía de Shannon de un string.
 * Valor alto (~4+) sugiere que no es un placeholder.
 */
function shannonEntropy(str) {
  if (!str || str.length < 8) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function shouldIgnoreLine(line) {
  return IGNORE_PATTERNS.some(p => p.test(line));
}

/**
 * Escanea el contenido de archivos buscando secrets.
 * @param {{ path: string, content: string }[]} files
 * @returns {{ type, file, line, lineNumber, match, severity }[]}
 */
export function scanSecrets(files) {
  const findings = [];

  for (const { path, content } of files) {
    if (!content) continue;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (shouldIgnoreLine(line)) continue;

      for (const rule of SECRET_RULES) {
        const match = line.match(rule.pattern);
        if (!match) continue;

        // Verificar entropía si la regla lo requiere
        if (rule.entropy) {
          const captured = match[1] || match[0];
          if (shannonEntropy(captured) < 3.5) continue;
        }

        // Redactar el match para no exponer el secret completo en el reporte
        const rawMatch = match[0].substring(0, 60);
        const redacted = redactSecret(rawMatch);

        findings.push({
          id:         rule.id,
          type:       rule.type,
          severity:   rule.severity,
          file:       path,
          lineNumber: i + 1,
          match:      redacted,
        });

        break; // una regla por línea es suficiente
      }
    }
  }

  // Ordenar por severidad y deduplicar por tipo+archivo
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  const seen = new Set();
  return findings
    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
    .filter(f => {
      const key = `${f.id}:${f.file}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

/**
 * Redacta el match mostrando solo el inicio y el tipo,
 * sin exponer el secret completo.
 */
function redactSecret(raw) {
  if (raw.length <= 12) return '***';
  const visible = raw.substring(0, 8);
  return `${visible}${'*'.repeat(Math.min(raw.length - 8, 16))}`;
}
