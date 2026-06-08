# @riskradar/cli

A thin, standalone supply-chain scanner over `@riskradar/core`. Scans a project
folder (npm + PyPI) against the real OSV database and tags each finding with the
**reachability (VEX-lite)** signal, so you fix what's actually imported first.

## Usage

```bash
# Published on npm, run from anywhere
npx riskradar-cli scan ./my-app
npx riskradar-cli scan . --fail-on high
npx riskradar-cli scan . --json > findings.json

# From this monorepo
pnpm scan:cli /absolute/path/to/project
```

Options:

- `--json`: machine-readable output.
- `--fail-on <critical|high|medium|low>`: exit non-zero when a finding at or
  above that severity exists (for CI gating). Default: never fails.
- `NO_COLOR=1`: disable ANSI colors.

It queries the live OSV API / OSV-Scanner. No network → no findings. RiskRadar
never fabricates results.

## Reachability tag

| Tag | Meaning |
|---|---|
| `reachable` | The vulnerable package is imported in your first-party source, fix first. |
| `likely unused` | A direct npm dep that is never imported, de-prioritized (VEX-lite). |
| `transitive` | Pulled in by a parent dependency, not a first-party import. |
| `unknown` | Couldn't determine (e.g. PyPI install-name ≠ import-name). |

## Building a self-contained binary (for publishing)

The published `bin` is a single bundled file at `dist/index.js` (core is bundled
in, so the package has no runtime workspace dependency):

```bash
pnpm cli:bundle           # → apps/cli/dist/index.js (esbuild, ESM, node18+)
node apps/cli/dist/index.js scan ./my-app   # verify
```

## Publishing a new version

The published package (`riskradar-cli` on npm) is a single bundled file with no
runtime dependencies (core is inlined). To cut a new version, bundle, then
publish a clean manifest (name `riskradar-cli`, no workspace deps):

```bash
pnpm cli:bundle                  # → apps/cli/dist/index.js
# stage dist/ + README + LICENSE + a deps-free package.json, then:
npm publish --access public      # requires npm login as the package owner
```
