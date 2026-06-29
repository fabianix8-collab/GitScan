/**
 * github.js — GitHub REST API client
 *
 * Responsabilidades:
 *  - Autenticar requests con token opcional del usuario
 *  - Obtener metadata, árbol de archivos, y contenido selectivo
 *  - Rate limit check y error handling semántico
 */

const GITHUB_API = 'https://api.github.com';
const RAW_GITHUB  = 'https://raw.githubusercontent.com';

export class GitHubClient {
  constructor(token = null) {
    this.token = token;
    this.headers = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(token && { 'Authorization': `Bearer ${token}` }),
    };
  }

  /**
   * GET wrapper con error handling centralizado
   */
  async #get(url) {
    const res = await fetch(url, { headers: this.headers });

    if (res.status === 404) {
      throw new GitHubError('Repository not found or is private.', 'NOT_FOUND');
    }
    if (res.status === 403) {
      const remaining = res.headers.get('X-RateLimit-Remaining');
      if (remaining === '0') {
        const reset = res.headers.get('X-RateLimit-Reset');
        const resetDate = new Date(reset * 1000).toLocaleTimeString();
        throw new GitHubError(
          `GitHub API rate limit exceeded. Resets at ${resetDate}. Add a GitHub token in Config to increase the limit.`,
          'RATE_LIMIT'
        );
      }
      throw new GitHubError('GitHub API access forbidden.', 'FORBIDDEN');
    }
    if (!res.ok) {
      throw new GitHubError(`GitHub API error: ${res.status} ${res.statusText}`, 'API_ERROR');
    }

    return res.json();
  }

  /**
   * Retorna metadata del repositorio
   */
  async getRepo(owner, repo) {
    return this.#get(`${GITHUB_API}/repos/${owner}/${repo}`);
  }

  /**
   * Retorna el árbol completo de archivos (todos los paths, sin contenido)
   * Usa el tree recursivo para una sola llamada a la API.
   */
  async getFileTree(owner, repo, branch) {
    const data = await this.#get(
      `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
    );
    if (data.truncated) {
      console.warn('[GitScan] File tree truncated — repository is very large.');
    }
    // Retornar solo blobs (archivos), no trees (directorios)
    return data.tree.filter(item => item.type === 'blob');
  }

  /**
   * Obtiene el contenido raw de un archivo específico.
   * Lanzar error si el archivo supera el límite de tamaño para evitar
   * leer archivos binarios grandes innecesariamente.
   */
  async getRawFile(owner, repo, branch, path, maxBytes = 500_000) {
    const url = `${RAW_GITHUB}/${owner}/${repo}/${branch}/${path}`;
    const res = await fetch(url, {
      headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
    });

    if (!res.ok) return null;

    const contentLength = res.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > maxBytes) {
      console.warn(`[GitScan] Skipping large file: ${path}`);
      return null;
    }

    return res.text();
  }

  /**
   * Obtiene el package manifest de dependencias para un ecosistema específico.
   * Solo lee archivos conocidos de dependencias — no hace fetch de todo el repo.
   */
  async getDependencyFiles(owner, repo, branch, filePaths) {
    const DEPENDENCY_FILES = [
      'package.json', 'package-lock.json',
      'requirements.txt', 'Pipfile', 'Pipfile.lock',
      'pom.xml', 'build.gradle',
      'Gemfile', 'Gemfile.lock',
      'go.mod', 'go.sum',
      'Cargo.toml', 'Cargo.lock',
      'composer.json', 'composer.lock',
    ];

    const found = filePaths.filter(p =>
      DEPENDENCY_FILES.some(dep => p === dep || p.endsWith(`/${dep}`))
    );

    const results = await Promise.allSettled(
      found.slice(0, 6).map(async (path) => {
        const content = await this.getRawFile(owner, repo, branch, path);
        return { path, content };
      })
    );

    return results
      .filter(r => r.status === 'fulfilled' && r.value.content)
      .map(r => r.value);
  }

  /**
   * Obtiene archivos de configuración pequeños para análisis de secrets.
   * Límite estricto de archivos para no desperdiciar rate limit.
   */
  async getConfigFiles(owner, repo, branch, filePaths) {
    const CONFIG_PATTERNS = [
      /\.env(\.\w+)?$/,
      /^\.?config\.(js|json|yml|yaml)$/,
      /^(docker-compose|\.travis|\.circleci|appveyor)\.ya?ml$/,
      /^\.?github\/workflows\/.+\.ya?ml$/,
      /^(settings|config|configuration)\.(py|js|json|php|rb)$/,
      /^app\.(py|js|rb)$/,
      /^main\.(py|js|go)$/,
    ];

    const found = filePaths.filter(p =>
      CONFIG_PATTERNS.some(pattern => pattern.test(p.split('/').pop()) || pattern.test(p))
    );

    const results = await Promise.allSettled(
      found.slice(0, 10).map(async (path) => {
        const content = await this.getRawFile(owner, repo, branch, path, 100_000);
        return { path, content };
      })
    );

    return results
      .filter(r => r.status === 'fulfilled' && r.value.content)
      .map(r => r.value);
  }
}

export class GitHubError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'GitHubError';
    this.code = code;
  }
}

/**
 * Parsea una URL de GitHub y retorna { owner, repo }
 * Acepta formatos:
 *   - https://github.com/owner/repo
 *   - github.com/owner/repo
 *   - owner/repo
 */
export function parseGitHubUrl(input) {
  const clean = input.trim().replace(/\/$/, '');
  const match = clean.match(/(?:github\.com\/)?([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)/);
  if (!match) return null;
  return { owner: match[1], repo: match[2] };
}
