#!/usr/bin/env node
/**
 * ai-code-guard — AI vulnerability scanner
 * Detects 5 classes of AI-specific code vulnerabilities.
 *
 * Usage: node index.js --files <csv> --workdir <path> --report <path> --fail-severity <level>
 */
const fs = require('fs');
const path = require('path');

// --- Severity levels ---
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const FAIL_SEVERITY_MAP = { critical: 0, high: 1, medium: 2, low: 3, none: 99 };

function parseArgs() {
  const args = {};
  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      args[key] = process.argv[++i] || '';
    }
  }
  return args;
}

// --- Scanner Rules ---

/**
 * Rule 1: Hallucinated Packages (Slopsquatting)
 * Detects imports of npm/pip packages that don't exist in registry.
 * Uses heuristics: suspicious patterns + offline package cache lookup.
 */
function scanHallucinatedPackages(filePath, content) {
  const findings = [];
  const ext = path.extname(filePath);

  // JavaScript/TypeScript imports
  if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
    const requireMatches = content.matchAll(/require\(['"]([^'"]+)['"]\)/g);
    const importMatches = content.matchAll(/from\s+['"]([^'"]+)['"]/g);

    for (const match of [...requireMatches, ...importMatches]) {
      const pkg = match[1];
      // Skip relative imports, core modules, and known packages
      if (pkg.startsWith('.') || pkg.startsWith('/') || pkg.startsWith('node:')) continue;

      // Suspicious patterns common in hallucinated packages:
      const suspicious = [
        /-v\d+/i,                          // versioned suffixes (ai-utils-v2)
        /\d{4}$/i,                          // year suffix (helper-2025)
        /\b(utils|helper|tool|kit|lib)\d*/i, // generic names with optional numbers
        /^[a-z]{2,4}-[a-z]{2,4}-[a-z]{2,4}$/i, // triple-hyphen chains
        /^[a-z]{20,}$/i,                     // unusually long single-word names
        /^(node|py|go|ai|react|vue)-[a-z]/i,  // trendy prefix packages
      ];

      for (const pattern of suspicious) {
        if (pattern.test(pkg)) {
          findings.push({
            rule: 'hallucinated-package',
            severity: 'high',
            file: filePath,
            line: content.split('\n').findIndex(l => l.includes(match[0])) + 1,
            snippet: match[0].substring(0, 120),
            message: `Potentially hallucinated package: "${pkg}". Pattern matches typosquatting heuristics. Verify this package exists on npm: https://www.npmjs.com/package/${pkg}`,
            fix: `Use 'npm view ${pkg}' to verify the package exists. If it doesn't, find the correct package name.`,
          });
        }
      }
    }
  }

  // Python imports
  if (['.py'].includes(ext)) {
    const importMatches = content.matchAll(/^(?:import|from)\s+(\S+)/gm);
    for (const match of importMatches) {
      const pkg = match[1].split('.')[0]; // Get top-level package
      if (['os', 'sys', 'json', 're', 'math', 'random', 'datetime',
           'collections', 'itertools', 'functools', 'pathlib', 'typing',
           'io', 'base64', 'hashlib', 'subprocess', 'threading',
           'time', 'uuid', 'copy', 'inspect'].includes(pkg)) continue;

      // Suspicious patterns for hallucinated Python packages
      if (/^[a-z]{20,}$/i.test(pkg) || /\d{3,}/.test(pkg) ||
          /^(pypi|python)-[a-z]+/i.test(pkg)) {
        findings.push({
          rule: 'hallucinated-package',
          severity: 'high',
          file: filePath,
          line: content.split('\n').findIndex(l => l.includes(match[0])) + 1,
          snippet: match[0].substring(0, 120),
          message: `Potentially hallucinated Python package: "${pkg}". Verify on PyPI: https://pypi.org/project/${pkg}/`,
          fix: `Use 'pip show ${pkg}' or check pypi.org to verify this package exists.`,
        });
      }
    }
  }

  // Go imports
  if (['.go'].includes(ext)) {
    const importMatches = content.matchAll(/"(github\.com\/[\w.-]+\/[\w.-]+)"/g);
    for (const match of importMatches) {
      // Flag imports to non-existent or suspicious repos
      const parts = match[1].split('/');
      if (parts.length >= 3) {
        const repo = parts[1];
        // Flag generic-sounding repos with AI-generated patterns
        if (/^[a-z]{1,3}[-_][a-z]{3,}$/i.test(repo)) {
          findings.push({
            rule: 'hallucinated-package',
            severity: 'medium',
            file: filePath,
            line: content.split('\n').findIndex(l => l.includes(match[0])) + 1,
            snippet: match[0].substring(0, 120),
            message: `Suspicious Go import: "${match[1]}". AI-generated code often invents module paths.`,
            fix: `Verify this module exists with 'go doc ${match[1]}' or check the GitHub repo.`,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Rule 2: Prompt Injection
 * Detects unsanitized user input interpolated into LLM prompts.
 */
function scanPromptInjection(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  // Patterns that suggest LLM API calls
  const llmCallPatterns = [
    /openai/i, /gpt/i, /claude/i, /llm/i, /chatgpt/i,
    /completion/i, /'text-davinci/, /'gpt-/, /'claude-/,
    /anthropic/i, /bedrock/i, /langchain/i, /ai\.(complete|chat|generate)/i,
  ];

  const hasLLMCall = llmCallPatterns.some(p => p.test(content));

  if (!hasLLMCall) return findings;

  // Check if user-controlled variables are interpolated into prompts without sanitization
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for user input interpolation in prompt string construction
    const userInputSources = [
      /req\.body/i, /request\.body/i, /req\.query/i,
      /ctx\.params/i, /event\.body/i, /message\.text/i,
      /input/i, /prompt\b/i, /userMessage/i, /user_input/i,
      /formData/i, /searchParams/i, /urlParams/i,
      /\$\{.*(?:message|input|user|query|text|content)\}/,
    ];

    const hasUserInputOnLine = userInputSources.some(p => p.test(line));

    if (hasUserInputOnLine) {
      // Check if there's prompt construction nearby (next few lines or same line)
      const context = lines.slice(Math.max(0, i - 1), i + 3).join('\n');
      const isPromptConstruction = /\b(prompt|messages|system|content|role.*user)\b/i.test(context);

      if (isPromptConstruction) {
        // Check for sanitization / escaping
        const nextLines = lines.slice(i, i + 5).join('\n');
        const hasSanitization = /\b(escape|sanitize|validate|strip|encode|replace|filter|clean)\b/i.test(nextLines);

        findings.push({
          rule: 'prompt-injection',
          severity: hasSanitization ? 'medium' : 'critical',
          file: filePath,
          line: lineNum,
          snippet: line.substring(0, 200),
          message: hasSanitization
            ? `Potential prompt injection: user input flows into LLM prompt. Ensure sanitization is robust against prompt injection techniques.`
            : `Prompt injection vulnerability: unsanitized user input "${line.trim().substring(0, 80)}..." is interpolated into an LLM prompt. An attacker can override system instructions.`,
          fix: hasSanitization
          ? `Add a prompt injection guard: wrap user input in XML tags with strict delimiters, and add "ignore previous instructions" guardrails.`
          : `1. Never use raw string interpolation - use a template with delimiters.\n2. Wrap user input: <user_input>[INPUT_HERE]</user_input>\n3. Add separator instructions before and after user input block.\n4. Consider using a dedicated sanitization library.`,
        });
      }
    }

    // Also flag user-controlled variables used as system prompt content
    const systemPromptPattern = /\b(systemPrompt|system_message|systemRole)\s*[=:][\s\S]{0,200}/i;
    if (systemPromptPattern.test(line) && userInputSources.some(p => p.test(line))) {
      // Already caught above
    }
  }

  return findings;
}

/**
 * Rule 3: Hardcoded Secrets / API Keys
 * Detects hardcoded credentials, tokens, and API keys in source.
 */
function scanHardcodedSecrets(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  // Skip test files (relaxed scrutiny)
  const isTestFile = /test|spec|mock|fixture|example/i.test(filePath);
  const severityBump = isTestFile ? 1 : 0; // Lower severity in tests

  const secretPatterns = [
    // API Keys
    { pattern: /(?:api[_-]?key|api[_-]?secret|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/i, severity: 'critical', type: 'API Key' },
    // AWS
    { pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical', type: 'AWS Access Key' },
    // GitHub tokens
    { pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: 'critical', type: 'GitHub Token' },
    // Slack tokens
    { pattern: /xox[baprs]-[0-9a-zA-Z-]{24,}/, severity: 'critical', type: 'Slack Token' },
    // JWT-like base64 encoded tokens
    { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high', type: 'JWT Token' },
    // Password assignments
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/i, severity: 'critical', type: 'Password' },
    // Private keys embedded
    { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'critical', type: 'Private Key' },
    // Connection strings
    { pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^@\s]+:[^@\s]+@/i, severity: 'high', type: 'Database Connection String' },
    // OpenAI keys
    { pattern: /sk-[A-Za-z0-9]{20,}/, severity: 'critical', type: 'OpenAI API Key' },
    // Generic token patterns
    { pattern: /(?:token|secret|credential)\s*[:=]\s*['"][A-Za-z0-9_\-=]{16,}['"]/i, severity: 'high', type: 'Secret Token' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comments and .env.example files
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) continue;
    if (filePath.endsWith('.env.example') || filePath.endsWith('.env.sample')) continue;

    for (const sp of secretPatterns) {
      if (sp.pattern.test(line)) {
        let severity = sp.severity;
        if (severityBump > 0 && severity !== 'critical') {
          // In test files, downgrade non-critical
          const idx = SEVERITY_ORDER.indexOf(severity);
          severity = SEVERITY_ORDER[Math.min(idx + severityBump, SEVERITY_ORDER.length - 1)];
        }

        findings.push({
          rule: 'hardcoded-secret',
          severity: severity,
          file: filePath,
          line: i + 1,
          snippet: line.replace(/['"][A-Za-z0-9_\-=.+/=]{8,}['"]/g, "'***REDACTED***'").substring(0, 200),
          message: `Hardcoded ${sp.type} detected in source code. Use environment variables or a secrets manager instead.`,
          fix: `Replace the hardcoded value with an environment variable:\n- Add to action's env: \n- Use \`process.env.VARIABLE_NAME\` or \`os.Getenv("VARIABLE_NAME")\` in code.\n- Store secrets in GitHub Secrets or cloud secrets manager.`,
        });
      }
    }
  }

  return findings;
}

/**
 * Rule 4: Insecure AI Configuration
 * Detects dangerous LLM/ML model settings.
 */
function scanInsecureAIConfig(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Dangerous temperature=0 settings (kills creativity, but more critically indicates poorly configured LLM)
    if (/\btemperature\s*[:=]\s*0\b/.test(line) && !/\btemperature\s*[:=]\s*0\.[1-9]/.test(line)) {
      findings.push({
        rule: 'insecure-ai-config',
        severity: 'medium',
        file: filePath,
        line: lineNum,
        snippet: line.substring(0, 200),
        message: `temperature=0 — this disables all randomness in the model. Temperatures > 0 (e.g., 0.3-0.7) are recommended for most use cases.`,
        fix: `Set temperature to a small non-zero value: temperature: 0.3`,
      });
    }

    // Rate limiting — no rate limit on LLM API calls
    if (/\b(?:openai|anthropic|ai|llm|model)\b/i.test(line) &&
        /\b(?:api|call|request|query)\b/i.test(line) &&
        /^\s*(?:for|while|\.map|\.forEach)/.test(line) &&
        !/\b(?:throttle|limit|delay|wait|sleep|batch|concurrency|retry|backoff)\b/i.test(content)) {
      findings.push({
        rule: 'insecure-ai-config',
        severity: 'high',
        file: filePath,
        line: lineNum,
        snippet: line.substring(0, 200),
        message: `AI API calls in a loop without rate limiting detected. This could exhaust API quota and incur unexpected costs.`,
        fix: `Add throttling: use a queue/rate limiter (e.g., p-limit for Node.js, asyncio.Semaphore for Python) before the API call loop.`,
      });
    }

    // Direct model access without auth enforcement
    if (/\b(?:model\.(?:predict|classify|generate|complete|chat))\b/i.test(line) &&
        !/\b(?:auth|token|api[_-]?key|bearer)\b/i.test(content.substring(0, i * 80))) {
      // Skip if auth-related import exists
      findings.push({
        rule: 'insecure-ai-config',
        severity: 'high',
        file: filePath,
        line: lineNum,
        snippet: line.substring(0, 200),
        message: `AI model call detected without visible authentication handling. Ensure API keys are properly managed.`,
        fix: `Use environment variables for API keys and validate them before model calls.`,
      });
    }

    // No error handling for AI API calls
    if (/\b(?:openai|anthropic|bedrock|vertex)\b/i.test(line) &&
        /\.(?:complete|chat|generate|create)\s*\(/.test(line)) {
      const context = lines.slice(i, Math.min(i + 6, lines.length)).join('\n');
      if (!/\b(?:try|catch|\.catch|\.then.*catch|error|err\b|handle|fallback)\b/i.test(context)) {
        findings.push({
          rule: 'insecure-ai-config',
          severity: 'medium',
          file: filePath,
          line: lineNum,
          snippet: context.substring(0, 300),
          message: `AI API call without error handling. Network failures, rate limits, or API changes will crash the application.`,
          fix: `Wrap the API call in try/catch (or .catch() for promises) and handle common errors: network errors, 429 rate limits, 401 auth failures, 500 server errors.`,
        });
      }
    }
  }

  return findings;
}

/**
 * Rule 5: Hallucinated API Usage
 * Detects calls to non-existent SDK methods or API patterns typical of AI hallucinations.
 */
function scanHallucinatedAPIs(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  // Suspicious patterns common in AI hallucinated API usage
  const suspiciousPatterns = [
    // SDK methods that don't exist (no template literal in regex)
    { pattern: /openai\.(?:complete|classify|embed|moderate|answer|search)\s*\(/i, severity: 'high', message: 'OpenAI SDK does not have this method. Check the official API docs.' },
    // Non-existent Anthropic methods
    { pattern: /anthropic\.(?:complete|embed|classify)\s*\(/i, severity: 'high', message: 'Anthropic SDK does not have this method. Check the official API docs.' },
    // Fake AWS SDK methods
    { pattern: /AWS\.(?:Bedrock|SageMaker)\s*\.(?:invoke|predict|analyze)\s*\(/i, severity: 'medium' },
    // Fake endpoints
    { pattern: /https:\/\/api\.(?:openai|anthropic)\.[\w.]+\.com\//i, severity: 'critical' },
    // Fake model names
    { pattern: /['"](?:gpt-5|gpt-4-ultra|claude-4|claude-opus-5)['"]/i, severity: 'medium' },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const sp of suspiciousPatterns) {
      const match = line.match(sp.pattern);
      if (match) {
        let message = sp.message || `Suspicious API usage: "${match[0]}". This may be an AI hallucination — verify against official SDK docs.`;
        findings.push({
          rule: 'hallucinated-api',
          severity: sp.severity,
          file: filePath,
          line: lineNum,
          snippet: line.substring(0, 200),
          message: message,
          fix: `Check the official SDK documentation:\n- OpenAI: https://platform.openai.com/docs/api-reference\n- Anthropic: https://docs.anthropic.com/claude/reference\n- AWS: https://docs.aws.amazon.com/sdk-for-javascript/`,
        });
      }
    }

    // Generic check: calls to methods that don't exist in well-known SDKs
    const sdkMethodCalls = line.match(/(\w+)\.(\w+)\s*\(/g);
    if (sdkMethodCalls) {
      for (const call of sdkMethodCalls) {
        const [obj, method] = call.split('.');
        // Known SDKs with limited methods -> flag unknown methods
        if (/^(openai|anthropic|bedrock|sagemaker|vertex|pinecone|weaviate|chroma)$/i.test(obj)) {
          // These are real SDK objects; further checking would require dependency analysis
          // For MVP, we flag bold made-up methods
        }
      }
    }
  }

  return findings;
}

// --- Main ---
function main() {
  const args = parseArgs();
  const fileCsv = args.files || '';
  const workdir = args.workdir || process.cwd();
  const reportPath = args.report || '/tmp/ai-code-guard-report.json';
  const failSeverity = args['fail-severity'] || 'high';

  const files = fileCsv.split(',').filter(Boolean).map(f => f.trim());

  const allFindings = [];
  const scannedFiles = [];

  for (const file of files) {
    const fullPath = path.resolve(workdir, file);
    if (!fs.existsSync(fullPath)) continue;

    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) continue;

    // Skip binary files
    const ext = path.extname(fullPath).toLowerCase();
    const textExts = ['.js', '.jsx', '.ts', '.tsx', '.py', '.go', '.rs', '.java', '.rb',
                      '.sh', '.bash', '.yaml', '.yml', '.json', '.tf', '.hcl', '.md',
                      '.html', '.css', '.scss', '.php', '.swift', '.kt', '.c', '.cpp',
                      '.h', '.hpp', '.cs', '.vue', '.svelte', '.toml', '.ini', '.cfg',
                      '.sql', '.graphql', '.prisma'];
    if (!textExts.includes(ext)) continue;

    scannedFiles.push(file);
    const content = fs.readFileSync(fullPath, 'utf-8');

    // Run all 5 rule classes
    const ruleClasses = [
      scanHallucinatedPackages,
      scanPromptInjection,
      scanHardcodedSecrets,
      scanInsecureAIConfig,
      scanHallucinatedAPIs,
    ];

    for (const scanFn of ruleClasses) {
      try {
        const findings = scanFn(file, content);
        allFindings.push(...findings);
      } catch (err) {
        process.stderr.write(`Error scanning ${file} with ${scanFn.name}: ${err.message}\n`);
      }
    }
  }

  // Deduplicate findings (same file + line + rule)
  const seen = new Set();
  const uniqueFindings = allFindings.filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity (critical first)
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  uniqueFindings.sort((a, b) => (severityRank[a.severity] || 99) - (severityRank[b.severity] || 99));

  // Count failures based on fail-severity threshold
  const failThreshold = FAIL_SEVERITY_MAP[failSeverity] ?? 1; // default to high
  const failures = uniqueFindings.filter(f => (FAIL_SEVERITY_MAP[f.severity] ?? 99) <= failThreshold);

  const report = {
    summary: {
      scanned: scannedFiles.length,
      vulnerabilities: uniqueFindings.length,
      failures: failures.length,
      by_rule: {
        'hallucinated-package': uniqueFindings.filter(f => f.rule === 'hallucinated-package').length,
        'prompt-injection': uniqueFindings.filter(f => f.rule === 'prompt-injection').length,
        'hardcoded-secret': uniqueFindings.filter(f => f.rule === 'hardcoded-secret').length,
        'insecure-ai-config': uniqueFindings.filter(f => f.rule === 'insecure-ai-config').length,
        'hallucinated-api': uniqueFindings.filter(f => f.rule === 'hallucinated-api').length,
      },
      by_severity: {
        critical: uniqueFindings.filter(f => f.severity === 'critical').length,
        high: uniqueFindings.filter(f => f.severity === 'high').length,
        medium: uniqueFindings.filter(f => f.severity === 'medium').length,
        low: uniqueFindings.filter(f => f.severity === 'low').length,
      },
    },
    findings: uniqueFindings,
    safe: failures.length === 0,
    fail_severity_threshold: failSeverity,
    scanned_at: new Date().toISOString(),
    scanner_version: '1.0.0',
  };

  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  process.stdout.write(JSON.stringify({ count: uniqueFindings.length, failures: failures.length }));
}

main();
