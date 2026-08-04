#!/usr/bin/env node
// Checks contributed skills against the Detection Skills specification:
// https://detectionskills.io/spec
//
// Run locally with `npm run validate`, or `npm run validate -- --base main`
// to also check the per-pull-request file limit.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKILLS_DIR = path.join(ROOT, "skills");

const SKILL_FILE = "SKILL.md";
const SLUG_RE = /^[a-z0-9](?:-?[a-z0-9]){0,63}$/;
// Skill directory names are free-ish text ("MFA Fatigue Baseline") but ASCII-only,
// starting and ending on a letter/digit (closing paren allowed at the end).
const DIR_NAME_RE = /^(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9 ()._-]{0,62}[A-Za-z0-9)])$/;
const WINDOWS_RESERVED = new Set([
  "con", "prn", "aux", "nul",
  ...Array.from({ length: 9 }, (_, i) => `com${i + 1}`),
  ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`),
]);
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LABEL_RE = /^[a-z0-9][a-z0-9-]*$/;
const TYPES = ["triage", "investigation", "tuning"];

const MAX_FILE_BYTES = 131_072;
const MAX_NAME_CHARS = 120;
const MAX_DESCRIPTION_CHARS = 1024;
const MAX_LABELS = 16;
const MAX_LABEL_CHARS = 32;
const MAX_AUTHOR_CHARS = 128;
const MAX_CHANGED_SKILLS_PER_PR = 15;

const problems = [];
const warnings = [];
const fail = (file, message) => problems.push(`${file}: ${message}`);
const warn = (file, message) => warnings.push(`${file}: ${message}`);

// Frontmatter is delimited by lines of exactly `---`.
function split(text) {
  const normalized = text.replace(/\r\n/g, "\n");
  if (!normalized.startsWith("---\n")) {
    return { error: "must begin with a line of --- followed by YAML frontmatter" };
  }
  const close = /\n---[ \t]*(?:\n|$)/.exec(normalized.slice(3));
  if (!close) return { error: "frontmatter is not closed by a line of ---" };
  return {
    fmText: normalized.slice(4, 3 + close.index + 1),
    body: normalized.slice(3 + close.index + close[0].length),
  };
}

// The URL identifier is derived from the directory name: lowercase, runs of
// anything outside a-z0-9 become one hyphen. "MFA Fatigue Baseline" ->
// "mfa-fatigue-baseline".
function slugFromDirName(dir) {
  if (!DIR_NAME_RE.test(dir)) {
    return { error: "directory name must be 1-64 characters of letters, digits, spaces, ()._- and start and end with a letter or digit" };
  }
  if (dir.includes("  ")) return { error: "directory name contains consecutive spaces" };
  if (WINDOWS_RESERVED.has(dir.split(".")[0].trimEnd().toLowerCase())) {
    return { error: "directory name is a reserved device name on Windows" };
  }
  const slug = dir.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (!SLUG_RE.test(slug) || WINDOWS_RESERVED.has(slug)) {
    return { error: `derived identifier "${slug}" is not usable` };
  }
  return { slug };
}

function checkFile(rel, expectedType) {
  const absolute = path.join(ROOT, rel);
  if (statSync(absolute).size > MAX_FILE_BYTES) {
    return fail(rel, `larger than ${MAX_FILE_BYTES} bytes`);
  }

  const { fmText, body, error } = split(readFileSync(absolute, "utf8"));
  if (error) return fail(rel, error);

  let fm;
  try {
    fm = YAML.parse(fmText);
  } catch (err) {
    return fail(rel, `frontmatter is not valid YAML: ${err.message.split("\n")[0]}`);
  }
  if (fm === null || typeof fm !== "object" || Array.isArray(fm)) {
    return fail(rel, "frontmatter must be a YAML map of fields");
  }

  const { name, description, type, version, metadata } = fm;

  if (typeof name !== "string" || name.trim().length < 1 || name.trim().length > MAX_NAME_CHARS) {
    fail(rel, `name must be a string of 1-${MAX_NAME_CHARS} characters`);
  } else if (/[\r\n]/.test(name)) {
    fail(rel, "name must be a single line");
  }

  if (
    typeof description !== "string" ||
    description.trim().length < 1 ||
    description.trim().length > MAX_DESCRIPTION_CHARS
  ) {
    fail(rel, `description must be a string of 1-${MAX_DESCRIPTION_CHARS} characters`);
  }

  if (typeof type !== "string" || !TYPES.includes(type)) {
    fail(rel, `type must be one of: ${TYPES.join(", ")}`);
  } else if (type !== expectedType) {
    fail(rel, `type "${type}" does not match its skills/${expectedType}/ folder`);
  }
  if (typeof version !== "string" || !SEMVER_RE.test(version)) {
    fail(rel, "version must be a semantic version string, e.g. 1.0.0");
  }

  if (metadata !== undefined) {
    if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
      fail(rel, "metadata must be a map");
    } else {
      const { labels, author } = metadata;
      if (labels !== undefined) {
        if (!Array.isArray(labels)) {
          fail(rel, "metadata.labels must be a list");
        } else if (labels.length > MAX_LABELS) {
          fail(rel, `metadata.labels may contain at most ${MAX_LABELS} labels`);
        } else {
          for (const label of labels) {
            if (
              typeof label !== "string" ||
              label.length > MAX_LABEL_CHARS ||
              !LABEL_RE.test(label)
            ) {
              fail(rel, `label must be lowercase alphanumeric with hyphens: ${JSON.stringify(label)}`);
            }
          }
        }
      }
      if (author !== undefined && (typeof author !== "string" || author.length > MAX_AUTHOR_CHARS)) {
        fail(rel, `metadata.author must be a string of at most ${MAX_AUTHOR_CHARS} characters`);
      }
    }
  }

  if (body.trim().length === 0) fail(rel, "the skill has no body content after the frontmatter");
}

let dirents = [];
try {
  dirents = readdirSync(SKILLS_DIR, { withFileTypes: true });
} catch (err) {
  problems.push(
    err.code === "ENOENT" ? "skills/ directory is missing" : `skills/ is unreadable: ${err.code}`
  );
}

// skills/<type>/<directory name>/SKILL.md. Derived identifiers must be
// unique across ALL type folders — two directories that lowercase-hyphenate
// to the same identifier are both rejected, whichever came first.
const slugClaims = new Map(); // slug -> [path, ...]
let skillCount = 0;
for (const typeEntry of dirents) {
  if (!typeEntry.isDirectory() || !TYPES.includes(typeEntry.name)) {
    fail(`skills/${typeEntry.name}`, `skills are grouped by type: skills/<${TYPES.join("|")}>/<skill name>/${SKILL_FILE}`);
    continue;
  }
  const type = typeEntry.name;
  for (const entry of readdirSync(path.join(SKILLS_DIR, type), { withFileTypes: true })) {
    const rel = `skills/${type}/${entry.name}`;
    if (!entry.isDirectory()) {
      fail(rel, `each skill is a directory containing ${SKILL_FILE}`);
      continue;
    }
    const derived = slugFromDirName(entry.name);
    if (derived.error) {
      fail(rel, derived.error);
      continue;
    }
    if (!slugClaims.has(derived.slug)) slugClaims.set(derived.slug, []);
    slugClaims.get(derived.slug).push(rel);
    skillCount++;

    const contents = readdirSync(path.join(SKILLS_DIR, type, entry.name), { withFileTypes: true });
    const skillFile = contents.find((c) => c.name === SKILL_FILE);
    if (!skillFile) {
      fail(rel, `must contain ${SKILL_FILE}`);
      continue;
    }
    if (!skillFile.isFile()) {
      fail(`${rel}/${SKILL_FILE}`, "must be a regular file");
      continue;
    }
    // Supporting files (references/, assets/, scripts/) are part of the standard but
    // are not published yet, so a skill that relies on them would not work.
    for (const extra of contents) {
      if (extra.name !== SKILL_FILE) {
        warn(
          `${rel}/${extra.name}`,
          `only ${SKILL_FILE} is published today — supporting files are on the roadmap`
        );
      }
    }
    checkFile(`${rel}/${SKILL_FILE}`, type);
  }
}

for (const [slug, paths] of slugClaims) {
  if (paths.length > 1) {
    for (const p of paths) {
      fail(p, `identifier "${slug}" is claimed by more than one skill directory (${paths.join(", ")})`);
    }
  }
}

const baseIndex = process.argv.indexOf("--base");
if (baseIndex !== -1 && process.argv[baseIndex + 1]) {
  const base = process.argv[baseIndex + 1];
  if (!/^[A-Za-z0-9._/-]+$/.test(base)) {
    problems.push(`not a usable git ref: ${base}`);
  } else {
    const diff = execFileSync(
      "git",
      ["diff", "-z", "--name-only", `${base}...HEAD`, "--", "skills/"],
      { cwd: ROOT, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }
    );
    const changed = diff.split("\0").filter(Boolean);
    if (changed.length > MAX_CHANGED_SKILLS_PER_PR) {
      problems.push(
        `${changed.length} skill files changed — please split this into pull requests of at most ${MAX_CHANGED_SKILLS_PER_PR}`
      );
    }
  }
}

if (warnings.length > 0) {
  console.error(`⚠ ${warnings.length} warning(s):\n`);
  for (const warning of warnings) console.error(`  ${warning}`);
  console.error("");
}
if (problems.length > 0) {
  console.error(`✗ ${problems.length} problem(s):\n`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error("\nSee https://detectionskills.io/spec for the format.");
  process.exit(1);
}
console.log(`✓ ${skillCount} skill(s) match the specification`);
