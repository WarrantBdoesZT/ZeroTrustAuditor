using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Shared helpers available to all check classes.
    /// All methods are pure .NET -- no PowerShell, no external processes.
    /// </summary>
    public abstract class CheckBase
    {
        protected readonly AuditConfig Config;
        protected readonly int PortTimeoutMs;

        protected CheckBase(AuditConfig config)
        {
            Config = config;
            PortTimeoutMs = config.Network.PortProbeTimeoutMs;
        }

        // ── Finding factory ───────────────────────────────────────────────────

        protected Finding MakeFinding(
            string host,
            string checkName,
            Severity severity,
            string description,
            string evidence,
            string remediation,
            string module = "")
        {
            return new Finding
            {
                Host                = host,
                Module              = module.Length > 0 ? module : GetType().Name,
                CheckName           = checkName,
                Severity            = severity,
                Description         = description,
                Evidence            = evidence,
                RemediationGuidance = remediation,
                DiscoveredAt        = DateTime.UtcNow,
            };
        }

        // ── Port probe ────────────────────────────────────────────────────────

        /// <summary>
        /// TCP SYN check -- non-blocking, respects timeout.
        /// Returns true if the port accepts a connection.
        /// </summary>
        protected async Task<bool> IsPortOpenAsync(string host, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(PortTimeoutMs);
                var completed   = await Task.WhenAny(connectTask, timeoutTask);
                return completed == connectTask && client.Connected;
            }
            catch { return false; }
        }

        protected async Task<Dictionary<string, bool>> ProbePortsAsync(
            string host, Dictionary<string, int> ports)
        {
            var results = new Dictionary<string, bool>();
            var tasks   = new Dictionary<string, Task<bool>>();

            foreach (var kv in ports)
                tasks[kv.Key] = IsPortOpenAsync(host, kv.Value);

            foreach (var kv in tasks)
                results[kv.Key] = await kv.Value;

            return results;
        }

        // ── Remote registry ───────────────────────────────────────────────────

        /// <summary>
        /// Read a DWORD or string value from a remote registry key.
        /// Returns null on any error (host unreachable, key missing, access denied).
        /// </summary>
        protected static object? GetRemoteReg(
            string computer, string subKey, string valueName,
            Microsoft.Win32.RegistryHive hive = Microsoft.Win32.RegistryHive.LocalMachine)
        {
            try
            {
                using var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(
                    hive, computer, Microsoft.Win32.RegistryView.Registry64);
                using var key = reg.OpenSubKey(subKey, false);
                return key?.GetValue(valueName);
            }
            catch { return null; }
        }

        protected static int? GetRemoteRegInt(string computer, string subKey, string valueName)
        {
            var v = GetRemoteReg(computer, subKey, valueName);
            return v == null ? null : Convert.ToInt32(v);
        }

        // ── Console helpers ───────────────────────────────────────────────────

        protected void Log(string msg) =>
            Console.WriteLine($"[{GetType().Name}] {msg}");
    }
}
