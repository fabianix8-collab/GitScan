/**
 * scanner/deps.js — Parser de manifests de dependencias
 *
 * Soporta: package.json, requirements.txt, Pipfile, go.mod,
 *          Gemfile.lock, composer.json, Cargo.toml, pom.xml
 *
 * Retorna un array normalizado de { name, version, ecosystem }
 * listo para enviar al batch endpoint de OSV.dev.
 */

/**
 * Punto de entrada principal.
 * Recibe los archivos de dependencias descargados por GitHubClient.
 * @param {{ path: string, content: string }[]} files
 * @returns {{ name: string, version: string, ecosystem: string }[]}
 */
export function parseDependencies(files) {
  const all = [];

  for (const { path, content } of files) {
    const filename = path.split('/').pop();
    try {
      const parsed = parseByFilename(filename, content);
      all.push(...parsed);
    } catch (err) {
      console.warn(`[deps] Failed to parse ${path}:`, err.message);
    }
  }

  // Deduplicar por name+ecosystem
  const seen = new Set();
  return all.filter(dep => {
    const key = `${dep.ecosystem}:${dep.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function parseByFilename(filename, content) {
  switch (filename) {
    case 'package.json':      return parsePackageJson(content);
    case 'package-lock.json': return parsePackageLockJson(content);
    case 'requirements.txt':  return parseRequirementsTxt(content);
    case 'Pipfile':           return parsePipfile(content);
    case 'Pipfile.lock':      return parsePipfileLock(content);
    case 'go.mod':            return parseGoMod(content);
    case 'Gemfile.lock':      return parseGemfileLock(content);
    case 'composer.json':     return parseComposerJson(content);
    case 'Cargo.toml':        return parseCargoToml(content);
    case 'Cargo.lock':        return parseCargoLock(content);
    default:
      if (filename.endsWith('pom.xml')) return parsePomXml(content);
      return [];
  }
}

// ── npm / Node.js ────────────────────────────────────────────

function parsePackageJson(content) {
  const pkg = JSON.parse(content);
  const deps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };
  return Object.entries(deps).map(([name, version]) => ({
    name,
    version: cleanSemver(version),
    ecosystem: 'npm',
  }));
}

function parsePackageLockJson(content) {
  const lock = JSON.parse(content);
  const packages = lock.packages || lock.dependencies || {};
  return Object.entries(packages)
    .filter(([name]) => name && name !== '')
    .map(([name, info]) => ({
      name: name.replace(/^node_modules\//, ''),
      version: info.version || '',
      ecosystem: 'npm',
    }))
    .filter(d => d.name && d.version);
}

// ── Python ───────────────────────────────────────────────────

function parseRequirementsTxt(content) {
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith('-'))
    .map(line => {
      // Formats: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg[extra]==1.0
      const match = line.match(/^([a-zA-Z0-9_.\-\[\]]+?)\s*[=~><!\s]+\s*([0-9][0-9a-zA-Z._-]*)/);
      if (!match) return { name: line.split(/[=><!\s]/)[0].split('[')[0].trim(), version: '', ecosystem: 'PyPI' };
      return {
        name: match[1].split('[')[0].trim(),
        version: match[2],
        ecosystem: 'PyPI',
      };
    })
    .filter(d => d.name);
}

function parsePipfile(content) {
  const results = [];
  let inPackages = false;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '[packages]' || trimmed === '[dev-packages]') { inPackages = true; continue; }
    if (trimmed.startsWith('[')) { inPackages = false; continue; }
    if (!inPackages) continue;
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*=\s*["']?([0-9][^"'\s]*)["']?/);
    if (match) results.push({ name: match[1], version: match[2], ecosystem: 'PyPI' });
  }
  return results;
}

function parsePipfileLock(content) {
  const lock = JSON.parse(content);
  const results = [];
  for (const section of ['default', 'develop']) {
    const pkgs = lock[section] || {};
    for (const [name, info] of Object.entries(pkgs)) {
      results.push({ name, version: (info.version || '').replace('==', ''), ecosystem: 'PyPI' });
    }
  }
  return results;
}

// ── Go ───────────────────────────────────────────────────────

function parseGoMod(content) {
  const results = [];
  let inRequire = false;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('require (')) { inRequire = true; continue; }
    if (inRequire && trimmed === ')') { inRequire = false; continue; }
    const single = trimmed.match(/^require\s+(\S+)\s+v([0-9][^\s]*)/);
    if (single) { results.push({ name: single[1], version: single[2], ecosystem: 'Go' }); continue; }
    if (inRequire) {
      const match = trimmed.match(/^(\S+)\s+v([0-9][^\s]*)/);
      if (match) results.push({ name: match[1], version: match[2], ecosystem: 'Go' });
    }
  }
  return results;
}

// ── Ruby ─────────────────────────────────────────────────────

function parseGemfileLock(content) {
  const results = [];
  let inSpecs = false;
  for (const line of content.split('\n')) {
    if (line.trim() === 'specs:') { inSpecs = true; continue; }
    if (inSpecs && !line.startsWith('  ')) { inSpecs = false; continue; }
    if (!inSpecs) continue;
    const match = line.match(/^\s{4}([a-zA-Z0-9_.-]+)\s+\(([0-9][^)]*)\)/);
    if (match) results.push({ name: match[1], version: match[2], ecosystem: 'RubyGems' });
  }
  return results;
}

// ── PHP ──────────────────────────────────────────────────────

function parseComposerJson(content) {
  const pkg = JSON.parse(content);
  const deps = { ...pkg.require, ...pkg['require-dev'] };
  return Object.entries(deps)
    .filter(([name]) => name !== 'php' && !name.startsWith('ext-'))
    .map(([name, version]) => ({
      name,
      version: cleanSemver(version),
      ecosystem: 'Packagist',
    }));
}

// ── Rust ─────────────────────────────────────────────────────

function parseCargoToml(content) {
  const results = [];
  let inDeps = false;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.match(/^\[(dependencies|dev-dependencies|build-dependencies)\]/)) { inDeps = true; continue; }
    if (trimmed.startsWith('[') && !trimmed.includes('dependencies')) { inDeps = false; continue; }
    if (!inDeps || !trimmed || trimmed.startsWith('#')) continue;
    const simple = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']([0-9][^"']+)["']/);
    if (simple) { results.push({ name: simple[1], version: simple[2], ecosystem: 'crates.io' }); continue; }
    const table = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*["']([^"']+)["']/);
    if (table) results.push({ name: table[1], version: cleanSemver(table[2]), ecosystem: 'crates.io' });
  }
  return results;
}

function parseCargoLock(content) {
  const results = [];
  let current = null;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '[[package]]') { if (current) results.push(current); current = {}; continue; }
    if (!current) continue;
    const name    = trimmed.match(/^name\s*=\s*"([^"]+)"/);
    const version = trimmed.match(/^version\s*=\s*"([^"]+)"/);
    if (name)    current.name = name[1];
    if (version) current.version = version[1];
  }
  if (current?.name) results.push(current);
  return results.filter(d => d.name && d.version).map(d => ({ ...d, ecosystem: 'crates.io' }));
}

// ── Java / Maven ─────────────────────────────────────────────

function parsePomXml(content) {
  const results = [];
  const depRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<${}]+)<\/version>)?[\s\S]*?<\/dependency>/g;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    const [, groupId, artifactId, version] = match;
    if (groupId && artifactId && !groupId.includes('${')) {
      results.push({
        name: `${groupId.trim()}:${artifactId.trim()}`,
        version: version?.trim() || '',
        ecosystem: 'Maven',
      });
    }
  }
  return results;
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Limpia prefijos de versión semántica como ^, ~, >=, etc.
 * OSV.dev necesita versiones limpias para hacer match exacto.
 */
function cleanSemver(version = '') {
  return version.replace(/^[\^~>=<*]+/, '').trim().split(' ')[0] || version;
}
