/**
 * scanner/sensitive.js — Detección de archivos sensibles por nombre/ruta
 *
 * No lee el contenido de los archivos — trabaja solo sobre el árbol de paths.
 * Esto lo hace eficiente (cero API calls extra) y seguro.
 */

/**
 * Mapa de patrones de archivos sensibles con severidad y razón.
 * Ordenado de mayor a menor severidad.
 */
const SENSITIVE_PATTERNS = [
  // CRITICAL — Credenciales directas
  { pattern: /^\.env$/,                  severity: 'CRITICAL', reason: 'Environment variables file — may contain API keys, DB passwords, secrets' },
  { pattern: /\.env\.(local|prod|production|staging|development)$/, severity: 'CRITICAL', reason: 'Environment-specific config — likely contains live credentials' },
  { pattern: /^\.env\.(?!example$|sample$|template$|dist$)\w+$/, severity: 'CRITICAL', reason: 'Environment variables file variant' },
  { pattern: /^\.?htpasswd$/,           severity: 'CRITICAL', reason: 'Apache password file — contains hashed credentials' },
  { pattern: /id_rsa$/,                  severity: 'CRITICAL', reason: 'RSA private key' },
  { pattern: /id_dsa$/,                  severity: 'CRITICAL', reason: 'DSA private key' },
  { pattern: /id_ecdsa$/,               severity: 'CRITICAL', reason: 'ECDSA private key' },
  { pattern: /id_ed25519$/,             severity: 'CRITICAL', reason: 'Ed25519 private key' },
  { pattern: /\.pem$/,                   severity: 'CRITICAL', reason: 'PEM certificate/key file' },
  { pattern: /\.p12$/,                   severity: 'CRITICAL', reason: 'PKCS#12 keystore — contains private keys and certificates' },
  { pattern: /\.pfx$/,                   severity: 'CRITICAL', reason: 'PFX certificate file — contains private key' },
  { pattern: /\.key$/,                   severity: 'CRITICAL', reason: 'Private key file' },
  { pattern: /\.keystore$/,             severity: 'CRITICAL', reason: 'Java keystore file' },
  { pattern: /google-services\.json$/,  severity: 'CRITICAL', reason: 'Firebase credentials — contains API keys and project config' },
  { pattern: /GoogleService-Info\.plist$/, severity: 'CRITICAL', reason: 'Firebase iOS credentials' },
  { pattern: /service[_-]?account.*\.json$/, severity: 'CRITICAL', reason: 'GCP/Firebase service account — full API access credentials' },

  // HIGH — Configuración con posibles secretos
  { pattern: /^secrets?\.(json|yml|yaml|toml)$/, severity: 'HIGH', reason: 'Explicit secrets file' },
  { pattern: /credentials?(\.json|\.yml|\.yaml)?$/, severity: 'HIGH', reason: 'Credentials file' },
  { pattern: /^config\/(database|db)\.(yml|yaml)$/, severity: 'HIGH', reason: 'Database configuration with potential credentials' },
  { pattern: /^database\.yml$/,         severity: 'HIGH', reason: 'Rails database config — may contain DB credentials' },
  { pattern: /wp-config\.php$/,         severity: 'HIGH', reason: 'WordPress config — contains DB credentials' },
  { pattern: /LocalSettings\.php$/,     severity: 'HIGH', reason: 'MediaWiki config — contains DB credentials' },
  { pattern: /\.aws\/(credentials|config)$/, severity: 'HIGH', reason: 'AWS credentials file' },
  { pattern: /\.?azure\/credentials$/,  severity: 'HIGH', reason: 'Azure credentials' },
  { pattern: /terraform\.tfvars$/,      severity: 'HIGH', reason: 'Terraform variables — may contain cloud credentials' },
  { pattern: /\.?kubeconfig$/,          severity: 'HIGH', reason: 'Kubernetes config — contains cluster access credentials' },

  // MEDIUM — Información de configuración que puede ser sensible
  { pattern: /^\.?htaccess$/,           severity: 'MEDIUM', reason: 'Apache server config — may expose server structure' },
  { pattern: /^docker-compose\.override\.yml$/, severity: 'MEDIUM', reason: 'Docker Compose override — may expose local config and ports' },
  { pattern: /^\.npmrc$/,               severity: 'MEDIUM', reason: 'npm config — may contain npm auth tokens' },
  { pattern: /^\.pypirc$/,              severity: 'MEDIUM', reason: 'PyPI config — may contain upload credentials' },
  { pattern: /^\.gem\/credentials$/,   severity: 'MEDIUM', reason: 'RubyGems credentials' },
  { pattern: /^\.?netrc$/,              severity: 'MEDIUM', reason: '.netrc file — contains FTP/HTTP credentials' },
  { pattern: /backup.*\.(sql|db|dump)$/, severity: 'MEDIUM', reason: 'Database backup — may contain sensitive data' },
  { pattern: /\.(sql|db)$/,             severity: 'MEDIUM', reason: 'Database file committed to repository' },
  { pattern: /^shadow$/,                severity: 'MEDIUM', reason: 'Unix shadow password file' },
  { pattern: /^passwd$/,                severity: 'MEDIUM', reason: 'Unix passwd file' },

  // LOW — Información estructural potencialmente útil para atacantes
  { pattern: /\.log$/,                  severity: 'LOW', reason: 'Log file — may contain sensitive runtime info or stack traces' },
  { pattern: /error[_-]?log$/,         severity: 'LOW', reason: 'Error log file' },
  { pattern: /access[_-]?log$/,        severity: 'LOW', reason: 'Access log — may reveal internal routes and user behavior' },
];

/**
 * Escanea el árbol de archivos del repositorio buscando archivos sensibles.
 * @param {string[]} filePaths - Array de paths del árbol del repo
 * @returns {Array} Findings con { path, severity, reason }
 */
export function scanSensitiveFiles(filePaths) {
  const findings = [];
  const seen = new Set(); // evitar duplicados si un archivo matchea múltiples patrones

  for (const filePath of filePaths) {
    const fileName = filePath.split('/').pop();

    for (const { pattern, severity, reason } of SENSITIVE_PATTERNS) {
      if (seen.has(filePath)) break;

      if (pattern.test(fileName) || pattern.test(filePath)) {
        findings.push({ path: filePath, severity, reason });
        seen.add(filePath);
      }
    }
  }

  // Ordenar por severidad
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  return findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

/**
 * Cuenta findings por severidad para el score banner
 */
export function countBySeverity(findings) {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
}
