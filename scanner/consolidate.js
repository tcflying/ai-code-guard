#!/usr/bin/env node
/**
 * Consolidate AI scanner results with Semgrep results.
 */
const fs = require('fs');

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

function parseSemgrepResults(semgrepPath) {
  if (!fs.existsSync(semgrepPath)) {
    process.stderr.write(`Semgrep results not found at ${semgrepPath}\n`);
    return [];
  }

  try {
    const raw = fs.readFileSync(semgrepPath, 'utf-8');
    const data = JSON.parse(raw);
    const findings = [];

    if (data.results) {
      for (const r of data.results) {
        // Map semgrep severity
        const sev = (r.extra?.severity || 'warning').toLowerCase();
        const severity = sev === 'warning' ? 'medium' : sev === 'error' ? 'high' : sev;

        findings.push({
          rule: 'semgrep:' + (r.check_id || 'unknown'),
          severity: severity,
          file: r.path || '',
          line: r.start?.line || 0,
          snippet: r.lines?.substring(0, 200) || '',
          message: r.extra?.message || `Semgrep rule '${r.check_id}' triggered`,
          fix: r.extra?.metadata?.fix || `Review line ${r.start?.line} in ${r.path}`,
        });
      }
    }
    return findings;
  } catch (err) {
    process.stderr.write(`Error parsing Semgrep output: ${err.message}\n`);
    return [];
  }
}

function main() {
  const args = parseArgs();
  const scannerReportPath = args['scanner-report'] || '/tmp/ai-code-guard-report.json';
  const semgrepPath = args['semgrep-report'] || '/tmp/semgrep-results.json';
  const outputPath = args.output || scannerReportPath;
  const failSeverity = args['fail-severity'] || 'high';

  // Load scanner results
  let scannerReport = { summary: { scanned: 0, vulnerabilities: 0, failures: 0, by_rule: {}, by_severity: {} }, findings: [] };
  if (fs.existsSync(scannerReportPath)) {
    try {
      scannerReport = JSON.parse(fs.readFileSync(scannerReportPath, 'utf-8'));
    } catch (e) {
      process.stderr.write(`Error reading scanner report: ${e.message}\n`);
    }
  }

  // Load semgrep results
  const semgrepFindings = parseSemgrepResults(semgrepPath);

  // Merge findings
  const allFindings = [...(scannerReport.findings || []), ...semgrepFindings];

  // Deduplicate
  const seen = new Set();
  const uniqueFindings = allFindings.filter(f => {
    const key = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Recalculate summary
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  uniqueFindings.sort((a, b) => (severityRank[a.severity] || 99) - (severityRank[b.severity] || 99));

  const failThreshold = { critical: 0, high: 1, medium: 2, low: 3, none: 99 }[failSeverity] ?? 1;
  const failures = uniqueFindings.filter(f => (severityRank[f.severity] ?? 99) <= failThreshold);

  const byRule = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of uniqueFindings) {
    byRule[f.rule] = (byRule[f.rule] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  const report = {
    summary: {
      scanned: scannerReport.summary.scanned || 0,
      vulnerabilities: uniqueFindings.length,
      failures: failures.length,
      by_rule: byRule,
      by_severity: bySeverity,
    },
    findings: uniqueFindings,
    safe: failures.length === 0,
    fail_severity_threshold: failSeverity,
    scanned_at: new Date().toISOString(),
    scanner_version: '1.0.0',
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  process.stdout.write(`Consolidated: ${uniqueFindings.length} findings, ${failures.length} failures`);
}

main();
