"""
漏洞检测 Prompts 库

设计原则：
1. 每个 prompt 都要求模型输出严格 JSON，方便程序解析
2. 要求模型在不确定时返回空列表，不要硬编（明确告诉它"宁可漏报不要乱报"）
3. 让模型给出推理链，方便人类复核
4. 自验证 prompt 与初次发现 prompt 不同，目的是"质疑"自己的发现
"""

# === 阶段 1a: 大仓库目录粗筛（两段式 triage 的第一段） ===
TRIAGE_DIRS_PROMPT = """You are an expert application security researcher planning a code audit.

This is a LARGE repository, so we'll do triage in two passes. In this first pass, you must pick the DIRECTORIES (subprojects, packages, or top-level folders) most likely to contain exploitable vulnerabilities.

Each directory below comes with:
- file_count: number of source files inside
- risk_score: heuristic keyword-based score (higher = more likely security-sensitive)
- keywords: hit keywords found in paths inside (~prefix means matched on directory name)

DIRECTORY OVERVIEW:
{dir_summary}

PROJECT METADATA:
{metadata}

Pick up to {max_dirs} directories worth deep-scanning. Prefer directories that:
- Handle untrusted input (web routes, parsers, file uploads, command execution)
- Implement auth, sessions, permissions, crypto
- Bridge the application to the OS or network
- Are NOT pure UI/styling/fixture/test code

Respond with ONLY a JSON object (no markdown fences):
{{
  "project_summary": "1-3 sentence summary of what this project does and its threat model",
  "languages": ["..."],
  "frameworks": ["..."],
  "selected_dirs": [
    {{"path": "packages/cli/src", "reason": "command execution + extension loading", "priority": "high"}},
    ...
  ]
}}

priority is one of: high | medium | low."""


# === 阶段 1: 项目侦察后，让模型规划要重点分析的文件 ===
TRIAGE_PROMPT = """You are an expert application security researcher.

Below is the file tree of a code repository. Your task is to plan a security review.

Identify the files MOST LIKELY to contain real, exploitable vulnerabilities. Focus on:
- Web request handlers / API endpoints / routers
- Authentication / authorization / session management
- File upload, download, path manipulation
- Database query construction (SQL, NoSQL)
- Command / subprocess execution
- Deserialization (pickle, YAML, XML, JSON)
- Template rendering (SSTI)
- Network calls (SSRF)
- Cryptography use
- Configuration loading from user input
- Anything parsing untrusted input

IGNORE: tests, docs, examples, third-party vendored code, generated code, build artifacts, type declarations (.d.ts), minified bundles.

Some files are annotated with `*risk=N` — that's a heuristic hint from path keywords. Treat it as a weak prior, not gospel. Use your own judgement based on file names and paths.

FILE TREE:
{file_tree}

PROJECT METADATA:
{metadata}

Respond with ONLY a JSON object (no markdown fences):
{{
  "project_summary": "1-3 sentence summary of what this project does and its threat model",
  "languages": ["python", "javascript", ...],
  "frameworks": ["flask", "express", ...],
  "high_risk_files": [
    {{"path": "src/api/upload.py", "reason": "handles file upload", "vuln_classes": ["path_traversal", "rce"]}},
    ...
  ]
}}

CRITICAL: Use the EXACT path strings as they appear in the file tree above (relative paths). Do NOT add "./" or leading slashes. Pick up to {max_files} of the highest-priority files. You MUST select at least a few files unless the repo is genuinely empty of risky code — if everything looks low-risk, still pick the top 3-5 most plausible candidates. Quality over quantity."""


# === 阶段 2: 对单个文件做漏洞扫描 ===
SCAN_PROMPT = """You are an expert application security researcher hunting for REAL, EXPLOITABLE vulnerabilities in open-source code.

You are reviewing this file: {file_path}
Project context: {project_summary}
Suspected vulnerability classes for this file (focus here, but you may report others): {vuln_classes}

Vulnerability classes you should consider:
- path_traversal: ../ in file ops, unvalidated user-controlled paths
- sqli: string-concatenated SQL, unparameterized queries
- command_injection: shell=True with user input, os.system, exec with user data
- rce: code injection, eval/exec on untrusted input, unsafe deserialization (pickle, yaml.load)
- ssrf: server-side request from user-controlled URL without allowlist
- xxe: XML parsing with external entities enabled
- authz: missing auth check, IDOR, broken access control
- authn: hardcoded credentials, weak token generation, broken session
- xss: unescaped output to HTML, dangerouslySetInnerHTML
- open_redirect: redirect to user-controlled URL
- ssti: user input in template
- race_condition: TOCTOU on filesystem
- crypto: weak algorithm, hardcoded key, predictable IV
- memory_safety: buffer overflow, use-after-free (C/C++/unsafe Rust)
- prototype_pollution: __proto__ assignment from user input
- regex_dos: catastrophic backtracking patterns

CRITICAL RULES — read carefully:
1. Report ONLY vulnerabilities you can trace from a USER-CONTROLLED source to a DANGEROUS sink in this file (or via clearly-named imported helpers).
2. If input is validated, sanitized, or the function is internal-only, DO NOT report it.
3. Each finding must cite specific line numbers and the exact suspect code.
4. If unsure, OMIT the finding. False positives waste reviewer time.
5. Never invent functions or imports that aren't shown. Quote actual code only.
6. Style/best-practice issues are NOT vulnerabilities — only report exploitable bugs.

FILE CONTENT (with line numbers):
{file_content}

Respond with ONLY a JSON object (no markdown fences):
{{
  "findings": [
    {{
      "vuln_type": "path_traversal",
      "severity": "high",
      "title": "User-controlled filename concatenated into open() without normalization",
      "line_start": 42,
      "line_end": 47,
      "code_snippet": "exact code from the file",
      "source": "where untrusted input enters (e.g. request.args['file'])",
      "sink": "the dangerous operation (e.g. open(path))",
      "data_flow": ["line 38: read user param", "line 42: concat into path", "line 47: open()"],
      "exploit_scenario": "Attacker sends ?file=../../etc/passwd and reads arbitrary files",
      "reasoning": "Step-by-step why this is exploitable, including why no sanitizer prevents it",
      "confidence": 0.85
    }}
  ]
}}

If no real vulnerabilities found, return {{"findings": []}}. Empty is BETTER than wrong."""


# === 阶段 3: 自验证 - 让同一个模型质疑自己的发现 ===
SELF_VERIFY_PROMPT = """You previously reported the following potential vulnerability. Now act as a skeptical senior reviewer who wants to REJECT false positives.

Your job: try hard to find reasons this is NOT actually exploitable.

REPORTED FINDING:
- Vulnerability type: {vuln_type}
- File: {file_path}
- Lines: {line_start}-{line_end}
- Title: {title}
- Original reasoning: {discovery_reasoning}
- Exploit scenario: {exploit_scenario}
- Data flow claim: {data_flow}

ACTUAL CODE (with line numbers, including surrounding context):
{file_content}

Carefully check:
1. Is the "source" really user-controlled in production code paths? Or only in tests / internal?
2. Is there a sanitizer, validator, allowlist, or framework-level protection that was missed?
3. Is the "sink" actually dangerous, or does the library handle it safely?
4. Could the function only be called by authenticated admins (lowering severity but not eliminating)?
5. Is the data flow real or did the previous analysis hallucinate connections?
6. Does the code shown actually contain the lines/calls mentioned, or were they invented?

Respond with ONLY a JSON object:
{{
  "verdict": "confirmed" | "rejected" | "uncertain",
  "confidence": 0.0,
  "reasoning": "Detailed explanation of your verification, including what specifically rules in or rules out the bug",
  "missed_sanitizer": "name of any sanitizer/validator you found that the original analysis missed, or null",
  "severity_adjusted": "critical" | "high" | "medium" | "low",
  "adjusted_title": "An accurate title if the original was misleading, else same as original"
}}

If verdict is "uncertain", lean toward "rejected". We can always re-review."""


# === 阶段 4: 交叉验证 - 用不同模型或不同视角再次验证 ===
CROSS_REVIEW_PROMPT = """You are a senior penetration tester reviewing a vulnerability report drafted by a junior researcher. The triage team also confirmed it. Your job is the FINAL gate before this gets reported upstream.

VULNERABILITY REPORT TO REVIEW:
- Type: {vuln_type}
- File: {file_path}
- Lines: {line_start}-{line_end}
- Title: {title}
- Junior researcher's reasoning: {discovery_reasoning}
- Self-verification reasoning: {verification_reasoning}
- Claimed data flow: {data_flow}
- Exploit scenario: {exploit_scenario}

CODE (verify the claims against this):
{file_content}

Independently determine:
1. Does the cited code in the file actually match what's claimed? (No hallucinated lines.)
2. Is the data flow from untrusted source to dangerous sink real and unblocked?
3. Could you actually write a working exploit? Sketch it.
4. What is the realistic impact if exploited?
5. Is the assigned severity appropriate?

Respond with ONLY a JSON object:
{{
  "final_verdict": "confirmed" | "rejected",
  "confidence": 0.0,
  "reasoning": "Your independent analysis",
  "exploit_sketch": "Concrete steps to exploit, or 'not exploitable because ...'",
  "real_severity": "critical" | "high" | "medium" | "low",
  "real_impact": "What an attacker actually achieves"
}}"""


# === 阶段 5: 修复方案与最终报告生成 ===
REPORT_PROMPT = """You are writing a vulnerability disclosure report that will be submitted to the open-source project's maintainers. It must be accurate, professional, and actionable.

VULNERABILITY DATA:
- Type: {vuln_type}
- Severity: {severity}
- File: {file_path}
- Lines: {line_start}-{line_end}
- Title: {title}
- Project: {repo_name}
- Discovery reasoning: {discovery_reasoning}
- Verification reasoning: {verification_reasoning}
- Cross-review reasoning: {cross_review_reasoning}
- Exploit scenario / sketch: {exploit_sketch}
- Real impact: {real_impact}

VULNERABLE CODE:
{code_snippet}

Write a complete vulnerability report in Markdown. It will be pasted into a GitHub issue or security advisory. Include these sections:

# [Severity] Title

## Summary
One-paragraph plain-English explanation a maintainer can grasp in 30 seconds.

## Affected Component
File path, function name, line range.

## Vulnerability Details
What it is (link to CWE if applicable), why it's dangerous in this specific code, technical explanation.

## Proof of Concept
A concrete exploit example — a request, payload, or call sequence. Use code blocks. Mark as illustrative if not run.

## Impact
What an attacker achieves. Be specific: data exfiltration scope, privilege gained, etc.

## Discovery & Verification Process
Briefly explain how this was found (automated AI-assisted code review) and how it was verified (self-review + cross-review). Include the reviewers' key reasoning so the maintainer can re-check it without taking it on faith.

## Recommended Fix
Provide a concrete code patch in a diff or replacement block. Explain why this fix is sufficient. If there are multiple acceptable fixes (e.g., allowlist vs normalize-and-check), mention them.

## References
CWE IDs, OWASP categories, related CVEs.

Be honest about uncertainty. Do not exaggerate severity. Output ONLY the Markdown — no preamble."""


# === 文件级别预筛 - 可选的轻量分类器 ===
QUICK_TRIAGE_PROMPT = """You are doing a fast first-pass triage on a code file to decide if a deep security review is worth running.

File: {file_path}

Sample of file content (first {sample_size} lines):
{sample}

In one short JSON response, answer:
{{
  "worth_deep_scan": true | false,
  "reason": "short reason",
  "likely_vuln_classes": ["..."],
  "is_test_or_fixture": true | false
}}"""
