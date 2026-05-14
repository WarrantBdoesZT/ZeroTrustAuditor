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
    ///   ZeroTrustAuditor.exe --hosts host1 --domain corp.local --skip-modules AdAuditor,ShareAuditor
    ///
    /// --skip-modules accepts a comma-separated list of module names to skip:
    ///   AdAuditor, ProtocolProbe, LateralPathAnalyzer, ShareAuditor, SegmentationChecker
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

            // Apply CLI skip-modules on top of whatever is in config
            var config = AuditConfigLoader.Load(opts.ConfigPath);
            if (opts.SkipModules.Length > 0)
            {
                foreach (var m in opts.SkipModules)
                    if (!config.Audit.SkipModules.Contains(m, StringComparer.OrdinalIgnoreCase))
                        config.Audit.SkipModules.Add(m);

                Console.WriteLine($"[*] Skipping modules (--skip-modules): {string.Join(", ", opts.SkipModules)}");
            }

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
            string?   ConfigPath,
            string[]  SkipModules);

        static Options? ParseArgs(string[] args)
        {
            string? hostsArg     = null;
            string? hostsFile    = null;
            string? domain       = null;
            string  outputDir    = "./reports";
            string? configPath   = null;
            string? skipModules  = null;

            // Fix: use args.Length (not args.Length - 1) so the last flag is never skipped.
            // Each value flag consumes args[i] (the flag) and args[++i] (the value),
            // so the bounds check inside the switch handles the edge case safely.
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--hosts":
                        if (i + 1 < args.Length) hostsArg    = args[++i]; break;
                    case "--hosts-file":
                        if (i + 1 < args.Length) hostsFile   = args[++i]; break;
                    case "--domain":
                        if (i + 1 < args.Length) domain      = args[++i]; break;
                    case "--output":
                        if (i + 1 < args.Length) outputDir   = args[++i]; break;
                    case "--config":
                        if (i + 1 < args.Length) configPath  = args[++i]; break;
                    case "--skip-modules":
                        if (i + 1 < args.Length) skipModules = args[++i]; break;
                }
            }

            if (domain == null)
            {
                Console.Error.WriteLine(
                    "\nUsage:\n" +
                    "  ZeroTrustAuditor.exe --hosts h1,h2 --domain corp.local\n" +
                    "  ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local\n" +
                    "\nOptional flags:\n" +
                    "  --output   ./reports          Output directory (default: ./reports)\n" +
                    "  --config   audit-config.json  Config file path\n" +
                    "  --skip-modules AdAuditor,ShareAuditor\n" +
                    "             Comma-separated list of modules to skip.\n" +
                    "             Valid names: AdAuditor, ProtocolProbe,\n" +
                    "             LateralPathAnalyzer, ShareAuditor, SegmentationChecker");
                return null;
            }

            // Resolve host list
            string[] hosts;

            if (hostsFile != null)
            {
                // Resolve relative paths from the current working directory
                var resolvedPath = Path.IsPathRooted(hostsFile)
                    ? hostsFile
                    : Path.Combine(Directory.GetCurrentDirectory(), hostsFile);

                if (!File.Exists(resolvedPath))
                {
                    Console.Error.WriteLine($"[!] Hosts file not found: {resolvedPath}");
                    Console.Error.WriteLine($"    Current directory: {Directory.GetCurrentDirectory()}");
                    return null;
                }

                hosts = File.ReadAllLines(resolvedPath)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith("//"))
                    .ToArray();

                Console.WriteLine($"[*] Hosts file: {resolvedPath}");
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
                Console.Error.WriteLine("[!] No hosts resolved from input. Check the file is not empty and has no BOM.");
                return null;
            }

            Console.WriteLine($"[*] Hosts in scope: {hosts.Length}");
            foreach (var h in hosts)
                Console.WriteLine($"    {h}");

            // Parse skip-modules list
            var skipList = skipModules == null
                ? Array.Empty<string>()
                : skipModules.Split(',',
                    StringSplitOptions.RemoveEmptyEntries |
                    StringSplitOptions.TrimEntries);

            return new Options(hosts, domain, outputDir, configPath, skipList);
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
