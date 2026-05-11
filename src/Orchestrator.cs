using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Checks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor
{
    public class Orchestrator
    {
        private readonly AuditConfig _config;

        public Orchestrator(AuditConfig config)
        {
            _config = config;
        }

        public async Task<AuditReport> RunAsync(
            string[] hosts, string domain, CancellationToken ct = default)
        {
            // Apply host exclusions
            var excluded = _config.Audit.ExcludeHosts
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var scopedHosts = hosts.Where(h => !excluded.Contains(h)).ToArray();

            if (scopedHosts.Length < hosts.Length)
                Console.WriteLine($"[*] Excluded {hosts.Length - scopedHosts.Length} host(s) per config.");

            if (scopedHosts.Length > _config.Audit.MaxHostsPerRun)
                throw new InvalidOperationException(
                    $"Host count ({scopedHosts.Length}) exceeds config.audit.maxHostsPerRun " +
                    $"({_config.Audit.MaxHostsPerRun}). Narrow your scope or raise the limit.");

            Console.WriteLine($"[*] Starting audit -- {scopedHosts.Length} host(s), domain '{domain}'");

            using var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(_config.Audit.ParallelModuleTimeoutSeconds));
            using var linked  = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

            // Skip modules from config
            var skip = _config.Audit.SkipModules
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var tasks = new List<Task<List<Finding>>>();

            if (!skip.Contains("AdAuditor") && !skip.Contains("AD"))
            {
                Console.WriteLine("[*] Launching: AdAuditor");
                tasks.Add(RunSafe("AdAuditor",
                    () => new AdAuditor(_config, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("ProtocolProbe") && !skip.Contains("Protocol"))
            {
                Console.WriteLine("[*] Launching: ProtocolProbe");
                tasks.Add(RunSafe("ProtocolProbe",
                    () => new ProtocolProbe(_config, scopedHosts).RunAsync(), linked.Token));
            }

            if (!skip.Contains("LateralPathAnalyzer") && !skip.Contains("Lateral"))
            {
                Console.WriteLine("[*] Launching: LateralPathAnalyzer");
                tasks.Add(RunSafe("LateralPathAnalyzer",
                    () => new LateralPathAnalyzer(_config, scopedHosts, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("ShareAuditor") && !skip.Contains("Shares"))
            {
                Console.WriteLine("[*] Launching: ShareAuditor");
                tasks.Add(RunSafe("ShareAuditor",
                    () => new ShareAuditor(_config, scopedHosts, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("SegmentationChecker") && !skip.Contains("Segmentation"))
            {
                Console.WriteLine("[*] Launching: SegmentationChecker");
                tasks.Add(RunSafe("SegmentationChecker",
                    () => new SegmentationChecker(_config, scopedHosts).RunAsync(), linked.Token));
            }

            var results     = await Task.WhenAll(tasks);
            var allFindings = results.SelectMany(r => r).ToList();

            Console.WriteLine($"[*] Raw findings: {allFindings.Count}");

            var report = Aggregate(allFindings, scopedHosts, domain);

            Console.WriteLine($"[+] Audit complete. Unique findings: {report.Findings.Count}");
            foreach (var (sev, count) in report.SeveritySummary.Where(kv => kv.Value > 0))
                Console.WriteLine($"    {sev,-15} {count}");

            return report;
        }

        private static async Task<List<Finding>> RunSafe(
            string name, Func<Task<List<Finding>>> fn, CancellationToken ct)
        {
            try
            {
                return await fn();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] {name} failed: {ex.Message}");
                return new List<Finding>();
            }
        }

        private AuditReport Aggregate(List<Finding> all, string[] hosts, string domain)
        {
            // Apply check exclusions
            var excluded = _config.Audit.ExcludeChecks
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var eligible = all.Where(f => !excluded.Contains(f.CheckName)).ToList();

            // Deduplicate: same Host + CheckName, keep highest severity
            var deduped = eligible
                .GroupBy(f => $"{f.Host}|{f.CheckName}")
                .Select(g => g.OrderByDescending(f => f.Severity).First())
                .ToList();

            // Base risk scores
            foreach (var f in deduped)
                f.RiskScore = _config.Severity.GetBaseScore(f.Severity);

            // Cross-correlation boosts
            if (_config.Correlation.Enabled)
            {
                var byHost = deduped.GroupBy(f => f.Host)
                    .ToDictionary(g => g.Key, g => g.ToList());

                foreach (var hostFindings in byHost.Values)
                {
                    var checks = hostFindings.Select(f => f.CheckName).ToHashSet();

                    foreach (var rule in _config.Correlation.Rules)
                    {
                        if (!checks.Contains(rule.CheckA) || !checks.Contains(rule.CheckB))
                            continue;

                        var fa = hostFindings.First(f => f.CheckName == rule.CheckA);
                        var fb = hostFindings.First(f => f.CheckName == rule.CheckB);

                        fa.RiskScore = Math.Min(_config.Severity.MaxScore,
                            fa.RiskScore + rule.RiskBoost);
                        fb.RiskScore = Math.Min(_config.Severity.MaxScore,
                            fb.RiskScore + rule.RiskBoost);

                        if (!fa.RelatedFindingIds.Contains(fb.Id)) fa.RelatedFindingIds.Add(fb.Id);
                        if (!fb.RelatedFindingIds.Contains(fa.Id)) fb.RelatedFindingIds.Add(fa.Id);
                        fa.Tags["correlationRule"] = rule.Name;
                        fb.Tags["correlationRule"] = rule.Name;
                    }
                }
            }

            var summary = new Dictionary<Severity, int>();
            foreach (Severity s in Enum.GetValues(typeof(Severity)))
                summary[s] = deduped.Count(f => f.Severity == s);

            return new AuditReport
            {
                TargetHosts     = hosts,
                Domain          = domain,
                Findings        = deduped.OrderByDescending(f => f.RiskScore).ToList(),
                SeveritySummary = summary,
            };
        }
    }
}
