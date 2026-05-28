#!/usr/bin/env node
/**
 * Post AI Code Guard findings as PR comments.
 */
const fs = require('fs');
const https = require('https');

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

function githubRequest(owner, repo, token, method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: `/repos/${owner}/${repo}/${endpoint}`,
      method: method,
      headers: {
        'Authorization': `token ${token}`,
        'User-Agent': 'ai-code-guard-action',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function formatCommentBody(report) {
  const { summary, findings } = report;

  let body = `## 🛡️ AI Code Guard — Scan Results\n\n`;

  if (summary.vulnerabilities === 0) {
    body += `**✅ No AI-specific vulnerabilities found.** (${summary.scanned} files scanned)\n`;
    return body;
  }

  body += `**${summary.vulnerabilities}** vulnerability(ies) found across **${summary.scanned}** files.\n\n`;

  // Summary table
  body += `### Summary\n\n`;
  body += `| Severity | Count |\n|----------|------:|\n`;
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    if (summary.by_severity[sev] > 0) {
      body += `| **${sev.charAt(0).toUpperCase() + sev.slice(1)}** | ${summary.by_severity[sev]} |\n`;
    }
  }
  body += `\n`;

  // By rule
  body += `| Rule | Count |\n|------|------:|\n`;
  const ruleLabels = {
    'hallucinated-package': 'Hallucinated Packages',
    'prompt-injection': 'Prompt Injection',
    'hardcoded-secret': 'Hardcoded Secrets',
    'insecure-ai-config': 'Insecure AI Config',
    'hallucinated-api': 'Hallucinated API Usage',
  };
  for (const [rule, count] of Object.entries(summary.by_rule)) {
    const label = ruleLabels[rule] || rule.replace(/^semgrep:/, 'Semgrep: ');
    body += `| ${label} | ${count} |\n`;
  }
  body += `\n`;

  // Top findings
  const criticalAndHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 10);
  if (criticalAndHigh.length > 0) {
    body += `### Top Findings\n\n`;
    for (const f of criticalAndHigh) {
      const emoji = f.severity === 'critical' ? '🔴' : '🟠';
      const shortFile = f.file.split('/').pop();
      body += `**${emoji} ${f.severity.toUpperCase()}** — \`${f.file}:${f.line}\`\n\n`;
      body += `${f.message}\n\n`;
      if (f.fix) {
        body += `<details>\n<summary>💡 Fix Suggestion</summary>\n\n\`\`\`\n${f.fix}\n\`\`\`\n\n</details>\n\n`;
      }
      body += `---\n\n`;
    }
  }

  if (findings.length > 10) {
    body += `\n*...and ${findings.length - 10} more findings. Full report available in action artifacts.*\n`;
  }

  body += `\n---\n<sup>🤖 [AI Code Guard](https://github.com/tcflying/ai-code-guard) v1.0.0</sup>`;

  return body;
}

async function main() {
  const args = parseArgs();

  const reportPath = args.report || '';
  const token = args.token || '';
  const repo = args.repo || '';
  const prNumber = args.pr || '0';

  if (!reportPath || !token || !repo || prNumber === '0') {
    process.stderr.write('Missing required args: --report, --token, --repo, --pr\n');
    process.exit(1);
  }

  if (!fs.existsSync(reportPath)) {
    process.stderr.write(`Report not found: ${reportPath}\n`);
    process.exit(1);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

  // Don't post if no findings (action will have a clean run anyway)
  if (report.summary.vulnerabilities === 0 && report.summary.scanned > 0) {
    process.stdout.write('No vulnerabilities to report. Skipping PR comment.\n');
    // Post a clean bill of health if we want — optional
    return;
  }

  const [owner, repoName] = repo.split('/');

  const body = formatCommentBody(report);

  // Post as PR review comment
  try {
    const commentBody = {
      body: body,
      event: report.safe ? 'APPROVE' : 'COMMENT',
    };

    const result = await githubRequest(owner, repoName, token, 'POST',
      `pulls/${prNumber}/reviews`, commentBody);

    process.stdout.write(`Posted PR review on #${prNumber}\n`);
  } catch (err) {
    process.stderr.write(`Error posting PR comment: ${err.message}\n`);
    // Try posting as an issue comment instead
    try {
      const commentBody = { body: body };
      const result = await githubRequest(owner, repoName, token, 'POST',
        `issues/${prNumber}/comments`, commentBody);
      process.stdout.write(`Posted issue comment on #${prNumber} (fallback)\n`);
    } catch (err2) {
      process.stderr.write(`Fallback comment also failed: ${err2.message}\n`);
    }
  }
}

main().catch(err => {
  process.stderr.write(`Fatal error: ${err.message}\n`);
  process.exit(1);
});
