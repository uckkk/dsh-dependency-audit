// dsh-dependency-audit — 依赖安全审计（DeepSeek Harness）。
// 扫描项目依赖：① 通过 OSV.dev 查询已知漏洞；② 对比 npm registry 检测过期依赖。
// 需要网络（OSV.dev 与 npm registry）。纯 Node，无其它外部服务。
import { defineTool } from "@deepseek-ai/dsh-tools";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const name = "依赖安全审计";
const inject = ["tools"];

const OSV_URL = "https://api.osv.dev/v1/querybatch";
const NPM_REG = "https://registry.npmjs.org";
const MAX_DEPS = 200;

// ── 依赖读取与版本解析 ───────────────────────────────────────────────────
async function readDeps(root) {
  const pkgPath = join(root, "package.json");
  let pkg;
  try { pkg = JSON.parse(await readFile(pkgPath, "utf8")); }
  catch { throw new Error(`未找到 package.json：${pkgPath}`); }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const out = [];
  for (const [name, range] of Object.entries(deps)) {
    if (out.length >= MAX_DEPS) break;
    out.push({ name, range, version: await resolveInstalled(root, name) });
  }
  return out;
}

async function resolveInstalled(root, name) {
  const isScoped = name.startsWith("@");
  const paths = isScoped
    ? (() => { const [scope, rest] = name.split("/"); return [join(root, "node_modules", scope, rest, "package.json")]; })()
    : [join(root, "node_modules", name, "package.json")];
  for (const p of paths) {
    try { return JSON.parse(await readFile(p, "utf8")).version ?? null; } catch {}
  }
  return null;
}

// ── OSV 漏洞查询 ────────────────────────────────────────────────────────
function severityOf(vuln) {
  const ds = vuln.database_specific?.severity;
  if (typeof ds === "string" && ds) return ds.toUpperCase();
  const sev = Array.isArray(vuln.severity) ? vuln.severity : [];
  let max = 0;
  for (const s of sev) {
    const score = typeof s.score === "string" ? parseFloat(s.score) : s.score;
    if (typeof score === "number" && score > max) max = score;
  }
  if (max >= 9) return "CRITICAL";
  if (max >= 7) return "HIGH";
  if (max >= 4) return "MEDIUM";
  if (max > 0) return "LOW";
  return "UNKNOWN";
}

function fixedVersion(vuln) {
  for (const a of vuln.affected || []) {
    for (const r of a.ranges || []) {
      for (const e of r.events || []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return null;
}

async function osvQuery(packages) {
  const queries = packages.filter((p) => p.version).map((p) => ({ package: { ecosystem: "npm", name: p.name }, version: p.version }));
  if (queries.length === 0) return [];
  const res = await fetch(OSV_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries }),
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) throw new Error(`OSV 查询失败（HTTP ${res.status}）`);
  const data = await res.json();
  return data.results || [];
}

async function fetchVulnDetail(id) {
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${id}`, { signal: AbortSignal.timeout(15000) });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── 过期依赖检测 ────────────────────────────────────────────────────────
function diffLevel(cur, latest) {
  const [a, b] = [cur, latest].map((v) => v.replace(/^[^0-9]*/, "").split(".").map(Number));
  if (a[0] !== b[0]) return "major";
  if (a[1] !== b[1]) return "minor";
  return "patch";
}

async function checkOutdated(packages) {
  const outdated = [];
  for (const p of packages) {
    if (!p.version) continue;
    let meta = null;
    try {
      const res = await fetch(`${NPM_REG}/${p.name}/latest`, { signal: AbortSignal.timeout(15000) });
      if (res.ok) meta = await res.json();
    } catch {}
    if (meta?.version && meta.version !== p.version) {
      outdated.push({ name: p.name, current: p.version, latest: meta.version, level: diffLevel(p.version, meta.version) });
    }
  }
  return outdated;
}

async function apply(ctx, _config) {
  ctx.tools.register(defineTool({
    name: "audit_vulnerabilities",
    description:
      "扫描项目依赖的已知安全漏洞：读取 package.json 的 dependencies/devDependencies 及其已安装版本，批量查询 OSV.dev 漏洞数据库，返回每个受影响依赖的漏洞 ID、严重级、摘要与修复版本。用于发布前/日常安全自查。`root` 传项目根目录，默认当前工作目录。需联网访问 osv.dev。",
    parameters: {
      root: { type: "string", description: "项目根目录（含 package.json 与 node_modules）。默认当前工作目录。" },
    },
    output: {
      schema: {
        type: "object", additionalProperties: false,
        properties: {
          totalDeps: { type: "integer", required: true },
          checkedDeps: { type: "integer", required: true },
          vulnerabilityCount: { type: "integer", required: true },
          vulnerabilities: {
            type: "array", required: true,
            items: {
              type: "object", additionalProperties: false,
              properties: {
                name: { type: "string", required: true },
                version: { type: "string", required: true },
                id: { type: "string", required: true },
                severity: { type: "string", required: true },
                summary: { type: "string", required: true },
                fixed: { type: "string", required: true },
              },
            },
          },
        },
      },
      render: (_args, value) => [{
        type: "text",
        text: `依赖漏洞审计：${value.checkedDeps}/${value.totalDeps} 个依赖已检查，发现 ${value.vulnerabilityCount} 个漏洞。\n${value.vulnerabilities.slice(0, 30).map((v) => `  - [${v.severity}] ${v.name}@${v.version} → ${v.id}${v.fixed ? `（修复于 ${v.fixed}）` : ""}: ${v.summary}`).join("\n") || "  （无已知漏洞）"}`,
      }],
    },
    execute: async (args) => {
      const root = args.root || process.cwd();
      const deps = await readDeps(root);
      const results = await osvQuery(deps);
      // 收集 vuln id → 包 映射（去重）
      const vulnPkgs = new Map();
      results.forEach((r, i) => {
        for (const vuln of r.vulns || []) {
          if (vuln.id && !vulnPkgs.has(vuln.id)) vulnPkgs.set(vuln.id, { name: deps[i].name, version: deps[i].version });
        }
      });
      // 拉取详情（并发，上限 40）
      const ids = [...vulnPkgs.keys()].slice(0, 40);
      const details = await Promise.all(ids.map(fetchVulnDetail));
      const vulnerabilities = [];
      ids.forEach((id, i) => {
        const pkg = vulnPkgs.get(id);
        const d = details[i];
        vulnerabilities.push({
          name: pkg.name,
          version: pkg.version,
          id,
          severity: d ? severityOf(d) : "UNKNOWN",
          summary: (d?.summary || "").slice(0, 200),
          fixed: d ? fixedVersion(d) || "" : "",
        });
      });
      vulnerabilities.sort((a, b) => b.severity.localeCompare(a.severity));
      return {
        totalDeps: deps.length,
        checkedDeps: deps.filter((d) => d.version).length,
        vulnerabilityCount: vulnerabilities.length,
        vulnerabilities,
      };
    },
  }));

  ctx.tools.register(defineTool({
    name: "audit_outdated",
    description:
      "检测项目依赖是否过期：对比已安装版本与 npm registry 最新版，返回每个过期依赖的当前版本、最新版本与升级幅度（major/minor/patch）。用于判断哪些依赖需要升级。`root` 传项目根目录，默认当前工作目录。需联网访问 npm registry。",
    parameters: {
      root: { type: "string", description: "项目根目录。默认当前工作目录。" },
    },
    output: {
      schema: {
        type: "object", additionalProperties: false,
        properties: {
          outdatedCount: { type: "integer", required: true },
          outdated: {
            type: "array", required: true,
            items: {
              type: "object", additionalProperties: false,
              properties: {
                name: { type: "string", required: true },
                current: { type: "string", required: true },
                latest: { type: "string", required: true },
                level: { type: "string", required: true },
              },
            },
          },
        },
      },
      render: (_args, value) => [{
        type: "text",
        text: `过期依赖 ${value.outdatedCount} 个：\n${value.outdated.slice(0, 50).map((o) => `  - ${o.name}: ${o.current} → ${o.latest}（${o.level}）`).join("\n") || "  （全部为最新）"}`,
      }],
    },
    execute: async (args) => {
      const root = args.root || process.cwd();
      const deps = await readDeps(root);
      const outdated = await checkOutdated(deps);
      return { outdatedCount: outdated.length, outdated };
    },
  }));
}

export { apply, inject, name };
