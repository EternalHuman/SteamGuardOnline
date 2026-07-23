import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fallbackDeployUrl = "https://3cf77373.steamguardonline.pages.dev";
const deployUrl = process.env.SGO_FIXED_DEPLOY_URL || process.env.CF_PAGES_URL || fallbackDeployUrl;
const sourceRepository = "https://github.com/EternalHuman/SteamGuardOnline";

const criticalFiles = [
  { path: "public/index.html", publicPath: "/index.html", label: "index.html" },
  { path: "public/app.js", publicPath: "/app.js", label: "app.js" },
  { path: "public/crypto.js", publicPath: "/crypto.js", label: "crypto.js" },
  { path: "public/styles.css", publicPath: "/styles.css", label: "styles.css" },
  { path: "public/_headers", publicPath: null, label: "Cloudflare _headers" },
  { path: "public/_redirects", publicPath: null, label: "Cloudflare _redirects" },
  { path: "public/_routes.json", publicPath: "/_routes.json", label: "_routes.json" },
  { path: "functions/api/[[path]].js", publicPath: null, label: "Pages Function /api" },
];

function git(args, fallback = "") {
  try {
    return execFileSync("git", args, {
      cwd: rootDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return fallback;
  }
}

function isDirtyStatusLine(line) {
  const filePath = line.slice(3).trim().replaceAll("\\", "/");
  return filePath !== "public/version.json";
}

async function hashFile(file) {
  const absolutePath = path.join(rootDir, file.path);
  const bytes = await readFile(absolutePath);
  return {
    ...file,
    bytes: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

const commit = git(["rev-parse", "HEAD"], "unknown");
const status = git(["status", "--porcelain"], "");
const dirty = status.split(/\r?\n/).filter(Boolean).some(isDirtyStatusLine);
const files = await Promise.all(criticalFiles.map(hashFile));

const manifest = {
  version: 1,
  project: "SteamGuardOnline",
  deployUrl,
  sourceRepository,
  commit,
  commitShort: commit === "unknown" ? "unknown" : commit.slice(0, 12),
  commitUrl: commit === "unknown" ? sourceRepository : `${sourceRepository}/commit/${commit}`,
  gitDirty: dirty,
  generatedAt: new Date().toISOString(),
  hashAlgorithm: "SHA-256",
  files,
};

await writeFile(path.join(rootDir, "public/version.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
