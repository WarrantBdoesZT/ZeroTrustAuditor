using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
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

            // Reachability pre-check: surfaces WHY a host produced no findings
            // instead of letting registry/SMB access failures pass silently.
            var reachabilityFindings = await CheckHostReachabilityAsync(scopedHosts);

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
            var allFindings = results.SelectMany(r => r).Concat(reachabilityFindings).ToList();

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
            var sw = Stopwatch.StartNew();
            try
            {
                var result = await fn();
                sw.Stop();
                Console.WriteLine($"[✓] {name} complete: {result.Count} finding(s) ({sw.Elapsed.TotalSeconds:F1}s)");
                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                Console.Error.WriteLine($"[!] {name} failed after {sw.Elapsed.TotalSeconds:F1}s: {ex.Message}");
                return new List<Finding>();
            }
        }

        // ── Host reachability pre-check ────────────────────────────────────────
        // Registry and SMB access failures are silent by design in the individual
        // checks (a closed port or a locked-down host looks identical to "nothing
        // to report"). This pass tells the user WHICH hosts couldn't be read from
        // and WHY, so a clean report can be trusted instead of just assumed.

        private async Task<List<Finding>> CheckHostReachabilityAsync(string[] hosts)
        {
            var smbPort = _config.Network.AdminPorts.TryGetValue("SMB", out var p) ? p : 445;
            var timeoutMs = _config.Network.PortProbeTimeoutMs;

            var probes = hosts.Select(async host =>
            {
                bool smbOpen = await IsTcpOpenAsync(host, smbPort, timeoutMs);
                bool regOpen = IsRemoteRegistryOpen(host);
                return (Host: host, SmbOpen: smbOpen, RegOpen: regOpen);
            });

            var results = await Task.WhenAll(probes);
            var reachable = results.Count(r => r.SmbOpen || r.RegOpen);

            Console.WriteLine($"[*] Host reachability: {reachable}/{hosts.Length} host(s) " +
                "responded to SMB and/or Remote Registry");

            var findings = new List<Finding>();

            foreach (var r in results)
            {
                if (!r.RegOpen)
                {
                    Console.WriteLine($"    [!] {r.Host}: Remote Registry not accessible -- " +
                        "ProtocolProbe and parts of SegmentationChecker will report nothing for this host.");
                    findings.Add(new Finding
                    {
                        Host                = r.Host,
                        Module              = "Orchestrator",
                        CheckName           = "REMOTE_REGISTRY_UNREACHABLE",
                        Severity            = Severity.Informational,
                        Description         = $"Could not read the remote registry on '{r.Host}'. " +
                            "ProtocolProbe (SMB signing, NTLMv1, RDP NLA, DCOM, WinRM) and the registry-based " +
                            "checks in SegmentationChecker will silently report zero findings for this host -- " +
                            "that does NOT mean the host is compliant, it means it could not be read.",
                        Evidence            = "RegistryKey.OpenRemoteBaseKey failed or returned no accessible key.",
                        RemediationGuidance = "Verify the Remote Registry service is running on the target " +
                            "(GPO: Computer Configuration > Windows Settings > System Services > Remote Registry > " +
                            "Automatic) and that the auditing account has network access to the host.",
                    });
                }

                if (!r.SmbOpen)
                {
                    Console.WriteLine($"    [!] {r.Host}: SMB (445) unreachable -- " +
                        "ShareAuditor and LateralPathAnalyzer will report nothing for this host.");
                    findings.Add(new Finding
                    {
                        Host                = r.Host,
                        Module              = "Orchestrator",
                        CheckName           = "SMB_UNREACHABLE",
                        Severity            = Severity.Informational,
                        Description         = $"Could not reach '{r.Host}' on TCP port 445 (SMB). " +
                            "ShareAuditor (SYSVOL/share ACLs) and LateralPathAnalyzer (local admin overlap, LAPS) " +
                            "will silently report zero findings for this host -- that does NOT mean the host is " +
                            "clean, it means it was unreachable.",
                        Evidence            = $"TCP connect to {r.Host}:{smbPort} did not complete within {timeoutMs}ms.",
                        RemediationGuidance = "Verify network connectivity and that a firewall between the audit " +
                            "workstation and this host is not blocking port 445.",
                    });
                }
            }

            return findings;
        }

        private static async Task<bool> IsTcpOpenAsync(string host, int port, int timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(timeoutMs);
                var completed   = await Task.WhenAny(connectTask, timeoutTask);
                return completed == connectTask && client.Connected;
            }
            catch { return false; }
        }

        private static bool IsRemoteRegistryOpen(string host)
        {
            try
            {
                using var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine, host, Microsoft.Win32.RegistryView.Registry64);
                return reg != null;
            }
            catch { return false; }
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
