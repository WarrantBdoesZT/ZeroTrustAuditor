using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Reports
{
    public class ReportRenderer
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() }
        };

        // ── JSON ──────────────────────────────────────────────────────────────

        public void WriteJson(AuditReport report, string path)
        {
            File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts), Encoding.UTF8);
            Console.WriteLine($"[+] JSON: {path}");
        }

        // ── CSV ───────────────────────────────────────────────────────────────

        public void WriteCsv(AuditReport report, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Host,Module,CheckName,Severity,RiskScore,Description,Evidence,Remediation");

            foreach (var f in report.Findings)
            {
                sb.AppendLine(string.Join(",",
                    Q(f.Id), Q(f.Host), Q(f.Module), Q(f.CheckName),
                    Q(f.Severity.ToString()), f.RiskScore.ToString("F1"),
                    Q(f.Description), Q(f.Evidence), Q(f.RemediationGuidance)));
            }

            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            Console.WriteLine($"[+] CSV:  {path}");
        }

        private static string Q(string s) =>
            "\"" + s.Replace("\"", "\"\"").Replace("\n", " ") + "\"";

        // ── HTML ──────────────────────────────────────────────────────────────

        public void WriteHtml(AuditReport report, string path)
        {
            var critical = report.Findings.Count(f => f.Severity == Severity.Critical);
            var high     = report.Findings.Count(f => f.Severity == Severity.High);
            var medium   = report.Findings.Count(f => f.Severity == Severity.Medium);
            var low      = report.Findings.Count(f => f.Severity == Severity.Low);
            var total    = report.Findings.Count;

            var sb = new StringBuilder();
            sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZeroTrustAuditor Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#f4f5f7;color:#1d2330;font-size:14px;line-height:1.6}
header{background:#1d2330;color:#fff;padding:24px 32px}
header h1{font-size:20px;font-weight:600}
header p{opacity:.6;font-size:12px;margin-top:4px}
.summary{display:flex;gap:12px;padding:20px 32px;flex-wrap:wrap}
.card{background:#fff;border-radius:8px;padding:16px 20px;flex:1;min-width:120px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}
.card .num{font-size:28px;font-weight:700}
.card .lbl{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.c-crit{color:#dc2626}.c-high{color:#ea580c}.c-med{color:#d97706}
.c-low{color:#16a34a}.c-info{color:#6b7280}
.findings{padding:0 32px 48px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
      overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th{background:#f9fafb;padding:9px 12px;text-align:left;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;color:#6b7280;border-bottom:1px solid #e5e7eb}
td{padding:9px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top;font-size:12px}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600}
.bC{background:#fee2e2;color:#991b1b}
.bH{background:#ffedd5;color:#9a3412}
.bM{background:#fef3c7;color:#92400e}
.bL{background:#dcfce7;color:#166534}
.bI{background:#f3f4f6;color:#374151}
.host{font-family:monospace;font-size:11px;background:#f3f4f6;padding:1px 5px;border-radius:3px}
.ev{font-family:monospace;font-size:10px;background:#f9fafb;padding:4px 6px;border-radius:3px;
    white-space:pre-wrap;word-break:break-all;max-height:60px;overflow-y:auto}
footer{text-align:center;padding:16px;font-size:11px;color:#9ca3af}
</style>
</head>
<body>
<header>
  <h1>ZeroTrustAuditor v2.0 -- Report</h1>
""");
            sb.AppendLine($"  <p>Domain: {WebUtility.HtmlEncode(report.Domain)} &nbsp;|&nbsp;" +
                          $" Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm} UTC &nbsp;|&nbsp;" +
                          $" Hosts: {report.TargetHosts.Length} &nbsp;|&nbsp;" +
                          $" Report ID: {report.ReportId}</p>");
            sb.Append("""
</header>
<div class="summary">
""");
            sb.AppendLine(Card("Critical", critical, "c-crit"));
            sb.AppendLine(Card("High",     high,     "c-high"));
            sb.AppendLine(Card("Medium",   medium,   "c-med"));
            sb.AppendLine(Card("Low",      low,      "c-low"));
            sb.AppendLine(Card("Total",    total,    "c-info"));
            sb.Append("""
</div>
<div class="findings">
<table>
<thead><tr>
  <th>Severity</th><th>Score</th><th>Host</th><th>Check</th>
  <th>Description</th><th>Evidence</th><th>Remediation</th>
</tr></thead>
<tbody>
""");
            foreach (var f in report.Findings)
            {
                var bc = f.Severity switch
                {
                    Severity.Critical => "bC", Severity.High => "bH",
                    Severity.Medium   => "bM", Severity.Low  => "bL", _ => "bI"
                };
                sb.AppendLine($"""
<tr>
  <td><span class="badge {bc}">{WebUtility.HtmlEncode(f.Severity.ToString())}</span></td>
  <td><strong>{f.RiskScore:F1}</strong></td>
  <td><span class="host">{WebUtility.HtmlEncode(f.Host)}</span></td>
  <td>{WebUtility.HtmlEncode(f.CheckName)}</td>
  <td>{WebUtility.HtmlEncode(f.Description)}</td>
  <td><div class="ev">{WebUtility.HtmlEncode(f.Evidence)}</div></td>
  <td>{WebUtility.HtmlEncode(f.RemediationGuidance)}</td>
</tr>
""");
            }
            sb.Append("""
</tbody></table>
</div>
<footer>ZeroTrustAuditor v2.0 -- read-only, non-destructive assessment</footer>
</body></html>
""");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            Console.WriteLine($"[+] HTML: {path}");
        }

        private static string Card(string label, int count, string cls) =>
            $"<div class=\"card\"><div class=\"num {cls}\">{count}</div>" +
            $"<div class=\"lbl\">{label}</div></div>";
    }
}
