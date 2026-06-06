using System;
using System.Collections.Generic;
using System.Linq;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor
{
    /// <summary>
    /// Builds a lateral movement graph from the collected findings, then computes
    /// the shortest (lowest-weight) attack paths from low-privilege footholds to
    /// high-value targets (Domain Controllers, Domain Admins).
    ///
    /// This is BloodHound-style analysis performed defensively and openly:
    /// it consumes only the read-only findings already gathered, and produces
    /// a graph that shows defenders exactly which misconfigurations chain
    /// together into a domain-compromise path.
    /// </summary>
    public class PathGraphBuilder
    {
        private readonly AuditConfig _config;
        private readonly Dictionary<string, GraphNode> _nodes = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<GraphEdge> _edges = new();

        // Edge weights: lower = easier for an attacker = more dangerous.
        // These reflect how reliable / low-effort each technique is in practice.
        private static readonly Dictionary<EdgeType, double> EdgeWeights = new()
        {
            [EdgeType.AdminTo]            = 1.0,  // direct admin = trivial
            [EdgeType.SharesLocalAdmin]  = 1.5,  // shared local admin password
            [EdgeType.HasSession]        = 2.0,  // credential theft from session
            [EdgeType.CanPSRemote]       = 2.0,
            [EdgeType.CanRDP]            = 2.5,
            [EdgeType.MemberOf]          = 1.0,  // group membership is automatic
            [EdgeType.CanDCSync]         = 1.0,  // game over if reachable
            [EdgeType.HasUnconstrained]  = 2.0,
            [EdgeType.CanKerberoast]     = 3.0,  // requires offline cracking
            [EdgeType.CanASREPRoast]     = 3.0,
            [EdgeType.WriteableShare]    = 3.5,
            [EdgeType.ContainsCredential]= 2.5,
        };

        private static readonly Dictionary<EdgeType, string> EdgeMitre = new()
        {
            [EdgeType.AdminTo]            = "T1078.002",
            [EdgeType.SharesLocalAdmin]  = "T1021.002",
            [EdgeType.HasSession]        = "T1003",
            [EdgeType.CanPSRemote]       = "T1021.006",
            [EdgeType.CanRDP]            = "T1021.001",
            [EdgeType.MemberOf]          = "T1078.002",
            [EdgeType.CanDCSync]         = "T1003.006",
            [EdgeType.HasUnconstrained]  = "T1558.001",
            [EdgeType.CanKerberoast]     = "T1558.003",
            [EdgeType.CanASREPRoast]     = "T1558.004",
            [EdgeType.WriteableShare]    = "T1021.002",
            [EdgeType.ContainsCredential]= "T1003",
        };

        public PathGraphBuilder(AuditConfig config)
        {
            _config = config;
        }

        public LateralMovementGraph Build(
            List<Finding> findings, string[] hosts, string domain)
        {
            // 1. Create computer nodes for every host in scope
            foreach (var host in hosts)
                AddComputerNode(host, domain);

            // 2. Always create the domain / DC high-value target node
            var dcNode = AddNode(
                $"DOMAIN:{domain}", domain, NodeType.DomainController,
                tier: 0, highValue: true);
            dcNode.Attributes["role"] = "Domain root / Tier 0 target";

            // 3. Translate findings into nodes + edges
            foreach (var f in findings)
                TranslateFinding(f, domain);

            // 4. Compute critical attack paths
            var paths = ComputeCriticalPaths(domain);

            return new LateralMovementGraph
            {
                Nodes         = _nodes.Values.ToList(),
                Edges         = _edges,
                CriticalPaths = paths,
                Domain        = domain,
            };
        }

        // ── Node helpers ────────────────────────────────────────────────────────

        private GraphNode AddComputerNode(string host, string domain)
        {
            var isDc = LooksLikeDc(host);
            var node = AddNode(
                $"COMPUTER:{host}", host,
                isDc ? NodeType.DomainController : NodeType.Computer,
                tier: isDc ? 0 : GuessTier(host),
                highValue: isDc);
            return node;
        }

        private GraphNode AddNode(
            string id, string label, NodeType type, int tier, bool highValue)
        {
            if (_nodes.TryGetValue(id, out var existing))
            {
                // Upgrade tier / high-value if this is a stronger classification
                if (tier < existing.Tier) existing.Tier = tier;
                if (highValue) existing.IsHighValue = true;
                return existing;
            }

            var node = new GraphNode
            {
                Id = id, Label = label, Type = type,
                Tier = tier, IsHighValue = highValue
            };
            _nodes[id] = node;
            return node;
        }

        private GraphNode AddUserNode(string sam, string domain, bool highValue = false)
        {
            return AddNode($"USER:{sam}", sam, NodeType.User,
                tier: highValue ? 0 : 2, highValue: highValue);
        }

        private void AddEdge(
            string sourceId, string targetId, EdgeType type, string reason)
        {
            // Avoid duplicate identical edges
            if (_edges.Any(e =>
                e.Source.Equals(sourceId, StringComparison.OrdinalIgnoreCase) &&
                e.Target.Equals(targetId, StringComparison.OrdinalIgnoreCase) &&
                e.Type == type))
                return;

            _edges.Add(new GraphEdge
            {
                Source = sourceId,
                Target = targetId,
                Type   = type,
                Weight = EdgeWeights.GetValueOrDefault(type, 3.0),
                Reason = reason,
                Mitre  = EdgeMitre.GetValueOrDefault(type, ""),
            });
        }

        // ── Finding translation ──────────────────────────────────────────────────

        private void TranslateFinding(Finding f, string domain)
        {
            var host     = f.Host;
            var computer = $"COMPUTER:{host}";
            var dc       = $"DOMAIN:{domain}";

            switch (f.CheckName)
            {
                case "LOCAL_ADMIN_OVERLAP":
                {
                    // Evidence: "Account=svc_x; Hosts=SRV01, SRV02, SRV03"
                    var account = ExtractKv(f.Evidence, "Account");
                    var hostsCsv = ExtractKv(f.Evidence, "Hosts");
                    if (string.IsNullOrEmpty(account)) break;

                    var user = AddUserNode(account, domain);
                    var overlapHosts = hostsCsv.Split(',', StringSplitOptions.TrimEntries)
                        .Where(h => h.Length > 0).ToArray();

                    // The account is admin on each host -> AdminTo edges
                    foreach (var h in overlapHosts)
                    {
                        AddComputerNode(h, domain);
                        AddEdge(user.Id, $"COMPUTER:{h}", EdgeType.AdminTo,
                            $"{account} has local admin on {h}");
                    }

                    // Each host shares this admin with every other -> SharesLocalAdmin
                    for (int i = 0; i < overlapHosts.Length; i++)
                        for (int j = 0; j < overlapHosts.Length; j++)
                            if (i != j)
                                AddEdge($"COMPUTER:{overlapHosts[i]}",
                                        $"COMPUTER:{overlapHosts[j]}",
                                        EdgeType.SharesLocalAdmin,
                                        $"Shared local admin '{account}' enables hop");
                    break;
                }

                case "DOMAIN_GROUP_LOCAL_ADMIN":
                {
                    // Evidence: "LocalGroup=Administrators; Member=CORP\\Helpdesk; Type=Group"
                    var member = ExtractKv(f.Evidence, "Member");
                    if (string.IsNullOrEmpty(member)) break;
                    var group = AddNode($"GROUP:{member}", member, NodeType.Group,
                        tier: 2, highValue: false);
                    AddEdge(group.Id, computer, EdgeType.AdminTo,
                        $"Group {member} grants local admin on {host}");
                    break;
                }

                case "KERBEROASTABLE_SPN":
                {
                    var sam = ExtractKv(f.Evidence, "SamAccountName");
                    if (string.IsNullOrEmpty(sam)) break;
                    var isAdmin = f.Severity == Severity.Critical;
                    var svc = AddNode($"USER:{sam}", sam, NodeType.ServiceAccount,
                        tier: isAdmin ? 0 : 2, highValue: isAdmin);
                    // Any authenticated foothold can Kerberoast this account
                    AddEdge(computer, svc.Id, EdgeType.CanKerberoast,
                        $"{sam} is Kerberoastable -- crack offline for its password");
                    if (isAdmin)
                        AddEdge(svc.Id, dc, EdgeType.MemberOf,
                            $"{sam} is privileged (AdminCount=1) -> path to domain");
                    break;
                }

                case "ASREP_ROASTABLE":
                {
                    var sam = ExtractKv(f.Evidence, "SamAccountName");
                    if (string.IsNullOrEmpty(sam)) break;
                    var isAdmin = f.Severity == Severity.Critical;
                    var acct = AddNode($"USER:{sam}", sam, NodeType.User,
                        tier: isAdmin ? 0 : 2, highValue: isAdmin);
                    AddEdge(computer, acct.Id, EdgeType.CanASREPRoast,
                        $"{sam} is AS-REP roastable -- request hash without auth");
                    if (isAdmin)
                        AddEdge(acct.Id, dc, EdgeType.MemberOf,
                            $"{sam} is privileged -> path to domain");
                    break;
                }

                case "UNCONSTRAINED_DELEGATION":
                {
                    var sam = ExtractKv(f.Evidence, "SamAccountName");
                    if (string.IsNullOrEmpty(sam)) break;
                    var acct = AddNode($"USER:{sam}", sam, NodeType.User, tier:1, highValue:false);
                    // Unconstrained delegation -> can capture TGTs -> impersonate to DC
                    AddEdge(acct.Id, dc, EdgeType.HasUnconstrained,
                        $"{sam} has unconstrained delegation -- capture a DC TGT to compromise domain");
                    AddEdge(computer, acct.Id, EdgeType.HasSession,
                        $"Coerce a privileged session to {sam} on {host}");
                    break;
                }

                case "DCSYNC_ACE":
                {
                    var principal = ExtractKv(f.Evidence, "Principal");
                    if (string.IsNullOrEmpty(principal)) break;
                    var p = AddNode($"USER:{principal}", principal, NodeType.User,
                        tier:1, highValue:false);
                    AddEdge(p.Id, dc, EdgeType.CanDCSync,
                        $"{principal} has DCSync rights -- replicate all password hashes");
                    break;
                }

                case "BROAD_RDP_ACCESS":
                {
                    var members = ExtractKv(f.Evidence, "RemoteDesktopUsers members");
                    foreach (var m in SplitMembers(members))
                    {
                        var g = AddNode($"GROUP:{m}", m, NodeType.Group, tier:2, highValue:false);
                        AddEdge(g.Id, computer, EdgeType.CanRDP,
                            $"{m} can RDP to {host}");
                    }
                    break;
                }

                case "BROAD_WINRM_ACCESS":
                {
                    var member = ExtractKv(f.Evidence, "RemoteManagementUsers member");
                    if (string.IsNullOrEmpty(member)) break;
                    var g = AddNode($"GROUP:{member}", member, NodeType.Group, tier:2, highValue:false);
                    AddEdge(g.Id, computer, EdgeType.CanPSRemote,
                        $"{member} can WinRM/PSRemote to {host}");
                    break;
                }

                case "SMB_SIGNING_DISABLED":
                {
                    // NTLM relay target -- any coerced auth can be relayed here.
                    // Mark the computer so path scoring treats it as relay-reachable.
                    if (_nodes.TryGetValue(computer, out var n))
                        n.Attributes["smbRelayTarget"] = "true";
                    break;
                }

                case "OPEN_SMB_SHARE_WRITE":
                case "SYSVOL_WRITE_PERMISSION":
                {
                    var principal = ExtractKv(f.Evidence, "Principal");
                    if (string.IsNullOrEmpty(principal)) principal = "Authenticated Users";
                    var g = AddNode($"GROUP:{principal}", principal, NodeType.Group,
                        tier:2, highValue:false);
                    // Writable SYSVOL = code exec on every domain machine
                    if (f.CheckName == "SYSVOL_WRITE_PERMISSION")
                        AddEdge(g.Id, dc, EdgeType.WriteableShare,
                            $"{principal} can write SYSVOL -- plant a malicious GPO script run domain-wide");
                    else
                        AddEdge(g.Id, computer, EdgeType.WriteableShare,
                            $"{principal} can write a share on {host}");
                    break;
                }
            }
        }

        // ── Path computation (Dijkstra shortest path) ────────────────────────────

        private List<AttackPath> ComputeCriticalPaths(string domain)
        {
            var paths = new List<AttackPath>();

            // Targets = all high-value nodes (DC + privileged accounts)
            var targets = _nodes.Values
                .Where(n => n.IsHighValue)
                .Select(n => n.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (targets.Count == 0) return paths;

            // Sources = low-privilege footholds: tier-2 computers and non-privileged groups/users
            var sources = _nodes.Values
                .Where(n => !n.IsHighValue &&
                            (n.Type == NodeType.Computer ||
                             n.Type == NodeType.Group ||
                             n.Type == NodeType.User))
                .Select(n => n.Id)
                .ToList();

            // Build adjacency list
            var adjacency = new Dictionary<string, List<GraphEdge>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in _edges)
            {
                if (!adjacency.TryGetValue(e.Source, out var list))
                    adjacency[e.Source] = list = new List<GraphEdge>();
                list.Add(e);
            }

            foreach (var source in sources)
            {
                var (path, found) = Dijkstra(source, targets, adjacency);
                if (found && path.Hops.Count > 0)
                    paths.Add(path);
            }

            // Deduplicate by end node, keep shortest; rank by risk
            var best = paths
                .GroupBy(p => p.StartNode + "->" + p.EndNode)
                .Select(g => g.OrderBy(p => p.TotalWeight).First())
                .OrderByDescending(p => p.RiskScore)
                .ThenBy(p => p.HopCount)
                .Take(25)
                .ToList();

            return best;
        }

        private (AttackPath path, bool found) Dijkstra(
            string start, HashSet<string> targets,
            Dictionary<string, List<GraphEdge>> adjacency)
        {
            var dist  = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) { [start] = 0 };
            var prev  = new Dictionary<string, GraphEdge>(StringComparer.OrdinalIgnoreCase);
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var queue = new PriorityQueue<string, double>();
            queue.Enqueue(start, 0);

            string? reached = null;

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                if (!visited.Add(current)) continue;

                if (targets.Contains(current)) { reached = current; break; }

                if (!adjacency.TryGetValue(current, out var edges)) continue;
                foreach (var edge in edges)
                {
                    var nd = dist[current] + edge.Weight;
                    if (!dist.TryGetValue(edge.Target, out var existing) || nd < existing)
                    {
                        dist[edge.Target] = nd;
                        prev[edge.Target] = edge;
                        queue.Enqueue(edge.Target, nd);
                    }
                }
            }

            if (reached == null) return (new AttackPath(), false);

            // Reconstruct path
            var hops = new List<PathHop>();
            var cursor = reached;
            while (prev.TryGetValue(cursor, out var edge))
            {
                hops.Insert(0, new PathHop
                {
                    From     = NodeLabel(edge.Source),
                    To       = NodeLabel(edge.Target),
                    EdgeType = edge.Type,
                    Reason   = edge.Reason,
                    Mitre    = edge.Mitre,
                });
                cursor = edge.Source;
            }

            var totalWeight = dist[reached];
            var riskScore   = ScorePath(hops.Count, totalWeight, reached);

            return (new AttackPath
            {
                StartNode   = NodeLabel(start),
                EndNode     = NodeLabel(reached),
                Hops        = hops,
                TotalWeight = Math.Round(totalWeight, 2),
                RiskScore   = riskScore,
                Summary     = BuildSummary(start, reached, hops),
            }, true);
        }

        // ── Scoring & helpers ─────────────────────────────────────────────────────

        private double ScorePath(int hopCount, double weight, string endNodeId)
        {
            // Fewer hops + lower weight + DC target = higher risk.
            // Base 10, subtract for each hop and weight unit, floor at 1.
            double score = 10.0;
            score -= (hopCount - 1) * 1.2;   // each extra hop reduces urgency slightly
            score -= weight * 0.4;
            if (_nodes.TryGetValue(endNodeId, out var n) &&
                n.Type == NodeType.DomainController)
                score += 2.0;                // reaching a DC is maximally bad
            return Math.Max(1.0, Math.Min(10.0, Math.Round(score, 1)));
        }

        private string BuildSummary(string start, string end, List<PathHop> hops)
        {
            var startLabel = NodeLabel(start);
            var endLabel   = NodeLabel(end);
            return $"{startLabel} can reach {endLabel} in {hops.Count} hop(s) " +
                   $"via {string.Join(" -> ", hops.Select(h => h.EdgeType))}";
        }

        private string NodeLabel(string id) =>
            _nodes.TryGetValue(id, out var n) ? n.Label : id;

        private static string ExtractKv(string evidence, string key)
        {
            // Evidence format: "Key1=value1; Key2=value2"
            foreach (var part in evidence.Split(';'))
            {
                var idx = part.IndexOf('=');
                if (idx <= 0) continue;
                var k = part[..idx].Trim();
                if (k.Equals(key, StringComparison.OrdinalIgnoreCase))
                    return part[(idx + 1)..].Trim();
            }
            return string.Empty;
        }

        private static IEnumerable<string> SplitMembers(string csv) =>
            csv.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        private bool LooksLikeDc(string host)
        {
            var h = host.ToLowerInvariant();
            return h.Contains("dc") || h.StartsWith("dc") ||
                   h.Contains("addc") || h.Contains("domaincontroller");
        }

        private int GuessTier(string host)
        {
            var h = host.ToLowerInvariant();
            if (h.Contains("srv") || h.Contains("server") || h.Contains("sql") ||
                h.Contains("web") || h.Contains("db") || h.Contains("app"))
                return 1;
            return 2;
        }
    }
}
