# [GitScan](https://fabianix8-collab.github.io/gitscan/)

AI-powered security analyzer for public GitHub repositories.

Paste a repo URL → get a security report covering vulnerable dependencies, exposed secrets, and sensitive files — in seconds.

![Security Score](https://img.shields.io/badge/status-live-00D9FF?style=flat-square&labelColor=0A0E1A)
![Stack](https://img.shields.io/badge/stack-Vanilla%20JS%20%2B%20Groq%20%2B%20OSV.dev-00D9FF?style=flat-square&labelColor=0A0E1A)

---

## What it detects

| Category | Method |
|---|---|
| **Dependency CVEs** | OSV.dev batch API — npm, PyPI, Go, Maven, RubyGems, Cargo, Packagist |
| **Exposed secrets** | Regex + entropy analysis across config files |
| **Sensitive files** | 40+ patterns matched against the repository file tree |
| **Risk summary** | Groq LLM (Llama 3) generates an executive-level analysis |

## Architecture

```
Browser
├── GitHub REST API     → file tree + dependency manifests + config files
├── OSV.dev /querybatch → single batch call for all packages
├── Groq API            → AI risk summary (direct, no proxy)
└── Local analysis      → secrets regex + sensitive file detection
```

No backend. No server. All analysis runs client-side or hits public APIs directly.

## Stack

- **Vanilla JS (ES6 modules)** — no build step, no framework overhead
- **GitHub REST API** — file tree and selective content fetching
- **OSV.dev** — open-source CVE database, free, no auth required
- **Groq** — LLM inference (Llama 3 8B), bring your own key
- **GitHub Pages** — static hosting via Actions CI/CD

## Running locally

```bash
git clone https://github.com/fabianix8-collab/gitscan.git
cd gitscan

# Serve with any static file server (ES modules require HTTP, not file://)
npx serve .
# or
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Configuration

Click **Config** in the top-right corner to set your API keys. Keys are stored in `localStorage` — never sent anywhere except the respective APIs.

| Key | Required | Purpose |
|---|---|---|
| GitHub PAT | Optional | Increases rate limit from 60 to 5,000 req/hr |
| Groq API Key | Optional | Enables AI risk summary |

[Generate a GitHub token →](https://github.com/settings/tokens/new?scopes=public_repo&description=GitScan)  
[Get a free Groq key →](https://console.groq.com/keys)

## Project structure

```
gitscan/
├── index.html
├── css/
│   └── main.css
├── js/
│   ├── main.js           # Orchestrator — UI state + pipeline
│   ├── github.js         # GitHub API client
│   ├── osv.js            # OSV.dev batch CVE lookup
│   ├── groq.js           # Groq AI analysis
│   ├── report.js         # DOM renderer + score calculator
│   └── scanner/
│       ├── deps.js       # Dependency manifest parser (8 formats)
│       ├── secrets.js    # Regex + entropy secret detection
│       └── sensitive.js  # Sensitive file path detection
└── .github/workflows/
    └── deploy.yml        # Auto-deploy to GitHub Pages
```

## Roadmap

- [ ] PDF export of the security report
- [ ] SAST patterns (hardcoded IPs, insecure functions, SQL injection vectors)
- [ ] Historical scan comparison
- [ ] Badge generation for repositories

---

Built by [Fabian](https://github.com/fabianix8-collab) · Part of a cybersecurity portfolio targeting the Chilean market
