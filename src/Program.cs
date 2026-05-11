using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor
{
    /// <summary>
    /// ZeroTrustAuditor v2.0 -- Pure C# Zero Trust misconfiguration assessment.
    ///
    /// Usage:
    ///   ZeroTrustAuditor.exe --hosts host1,host2 --domain corp.local
    ///   ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local
    ///   ZeroTrustAuditor.exe --hosts host1 --domain corp.local --config audit-config.json
    ///
    /// No PowerShell. No external processes. No WMI/CIM.
    /// Pure .NET 8 with System.DirectoryServices, Registry, and TCP.
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            PrintBanner();

            var opts = ParseArgs(args);
            if (opts == null) return 1;

            Directory.CreateDirectory(opts.OutputDir);

            var config = AuditConfigLoader.Load(opts.ConfigPath);
            var orchestrator = new Orchestrator(config);
            var renderer     = new ReportRenderer();
            var siem         = new SiemRenderer(config);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            try
            {
                var report  = await orchestrator.RunAsync(opts.Hosts, opts.Domain, cts.Token);
                var stamp   = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                var formats = config.Output.Formats
                    .Select(f => f.ToLowerInvariant()).ToHashSet();

                if (formats.Contains("json"))
                    renderer.WriteJson(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.json"));

                if (formats.Contains("csv"))
                    renderer.WriteCsv(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.csv"));

                if (formats.Contains("html"))
                    renderer.WriteHtml(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.html"));

                if (formats.Contains("splunk"))
                    siem.WriteSplunkHec(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.splunk.json"));

                if (formats.Contains("sentinel"))
                    siem.WriteSentinelJson(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.sentinel.json"));

                if (formats.Contains("cef"))
                    siem.WriteCef(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.cef"));

                Console.WriteLine($"\n[+] Reports written to: {Path.GetFullPath(opts.OutputDir)}");
                return 0;
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("\n[!] Audit cancelled.");
                return 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"\n[!] Fatal error: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace);
                return 3;
            }
        }

        // ── Arg parsing ───────────────────────────────────────────────────────

        record Options(
            string[]  Hosts,
            string    Domain,
            string    OutputDir,
            string?   ConfigPath);

        static Options? ParseArgs(string[] args)
        {
            string? hostsArg    = null;
            string? hostsFile   = null;
            string? domain      = null;
            string  outputDir   = "./reports";
            string? configPath  = null;

            for (int i = 0; i < args.Length - 1; i++)
                switch (args[i].ToLowerInvariant())
                {
                    case "--hosts":      hostsArg   = args[++i]; break;
                    case "--hosts-file": hostsFile  = args[++i]; break;
                    case "--domain":     domain     = args[++i]; break;
                    case "--output":     outputDir  = args[++i]; break;
                    case "--config":     configPath = args[++i]; break;
                }

            if (domain == null)
            {
                Console.Error.WriteLine(
                    "Usage: ZeroTrustAuditor.exe " +
                    "(--hosts h1,h2 | --hosts-file file.txt) " +
                    "--domain corp.local [--output ./reports] [--config audit-config.json]");
                return null;
            }

            string[] hosts;

            if (hostsFile != null)
            {
                if (!File.Exists(hostsFile))
                {
                    Console.Error.WriteLine($"[!] Hosts file not found: {hostsFile}");
                    return null;
                }
                hosts = File.ReadAllLines(hostsFile)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith('#'))
                    .ToArray();
            }
            else if (hostsArg != null)
            {
                hosts = hostsArg.Split(',',
                    StringSplitOptions.RemoveEmptyEntries |
                    StringSplitOptions.TrimEntries);
            }
            else
            {
                Console.Error.WriteLine("[!] Specify --hosts or --hosts-file.");
                return null;
            }

            if (hosts.Length == 0)
            {
                Console.Error.WriteLine("[!] No hosts resolved from input.");
                return null;
            }

            Console.WriteLine($"[*] Hosts in scope: {hosts.Length}");
            return new Options(hosts, domain, outputDir, configPath);
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(
                "  ZeroTrustAuditor v2.0 | Pure C# Zero Trust Assessment\n" +
                "  No PowerShell. No WMI. No external processes.\n");
            Console.ResetColor();
        }
    }
}
