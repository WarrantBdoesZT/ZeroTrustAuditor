using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Node types in the lateral movement graph.
    /// </summary>
    public enum NodeType
    {
        Computer,        // A host (workstation or server)
        DomainController,// A DC -- Tier 0 target
        User,            // A domain user account
        Group,           // A domain or local group
        ServiceAccount,  // An account with an SPN (service account)
    }

    /// <summary>
    /// Edge types -- the "verb" describing how a source node reaches a target node.
    /// Each maps to a real lateral movement or privilege escalation technique.
    /// </summary>
    public enum EdgeType
    {
        AdminTo,            // principal has local admin on a computer
        MemberOf,           // principal is a member of a group
        CanRDP,             // principal can RDP to a computer
        CanPSRemote,        // principal can WinRM/PSRemote to a computer
        HasSession,         // a privileged session exists on a computer (cred exposure)
        CanKerberoast,      // a service account is Kerberoastable from here
        CanASREPRoast,      // an account is AS-REP roastable
        HasUnconstrained,   // a computer/account has unconstrained delegation
        CanDCSync,          // principal has DCSync rights against the domain
        SharesLocalAdmin,   // two computers share the same local admin (lateral hop)
        WriteableShare,     // principal can write to a share used by the target
        ContainsCredential, // a computer stores credentials for the target principal
    }

    /// <summary>
    /// A node in the lateral movement graph.
    /// </summary>
    public class GraphNode
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;        // unique key, e.g. "COMPUTER:SRV01"

        [JsonPropertyName("label")]
        public string Label { get; set; } = string.Empty;     // display name

        [JsonPropertyName("type")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public NodeType Type { get; set; }

        [JsonPropertyName("tier")]
        public int Tier { get; set; } = 2;                    // 0=DC/Tier0, 1=server, 2=workstation/user

        [JsonPropertyName("isHighValue")]
        public bool IsHighValue { get; set; }                 // DC, Domain Admin, etc.

        [JsonPropertyName("attributes")]
        public Dictionary<string, string> Attributes { get; set; } = new();
    }

    /// <summary>
    /// A directed edge: Source --(Type)--> Target.
    /// </summary>
    public class GraphEdge
    {
        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        [JsonPropertyName("target")]
        public string Target { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public EdgeType Type { get; set; }

        [JsonPropertyName("weight")]
        public double Weight { get; set; } = 1.0;             // lower = easier to traverse

        [JsonPropertyName("reason")]
        public string Reason { get; set; } = string.Empty;    // human-readable explanation

        [JsonPropertyName("mitre")]
        public string Mitre { get; set; } = string.Empty;     // MITRE technique for this hop
    }

    /// <summary>
    /// A computed attack path -- an ordered sequence of nodes from a low-privilege
    /// foothold to a high-value target.
    /// </summary>
    public class AttackPath
    {
        [JsonPropertyName("startNode")]
        public string StartNode { get; set; } = string.Empty;

        [JsonPropertyName("endNode")]
        public string EndNode { get; set; } = string.Empty;

        [JsonPropertyName("hops")]
        public List<PathHop> Hops { get; set; } = new();

        [JsonPropertyName("totalWeight")]
        public double TotalWeight { get; set; }

        [JsonPropertyName("riskScore")]
        public double RiskScore { get; set; }                 // 0-10, higher = more dangerous

        [JsonPropertyName("hopCount")]
        public int HopCount => Hops.Count;

        [JsonPropertyName("summary")]
        public string Summary { get; set; } = string.Empty;   // one-line narrative
    }

    /// <summary>
    /// A single hop within an attack path.
    /// </summary>
    public class PathHop
    {
        [JsonPropertyName("from")]
        public string From { get; set; } = string.Empty;

        [JsonPropertyName("to")]
        public string To { get; set; } = string.Empty;

        [JsonPropertyName("edgeType")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public EdgeType EdgeType { get; set; }

        [JsonPropertyName("reason")]
        public string Reason { get; set; } = string.Empty;

        [JsonPropertyName("mitre")]
        public string Mitre { get; set; } = string.Empty;
    }

    /// <summary>
    /// The complete lateral movement graph plus computed paths.
    /// This is what gets serialized to JSON and rendered to the interactive HTML.
    /// </summary>
    public class LateralMovementGraph
    {
        [JsonPropertyName("nodes")]
        public List<GraphNode> Nodes { get; set; } = new();

        [JsonPropertyName("edges")]
        public List<GraphEdge> Edges { get; set; } = new();

        [JsonPropertyName("paths")]
        public List<AttackPath> CriticalPaths { get; set; } = new();

        [JsonPropertyName("generatedAt")]
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("domain")]
        public string Domain { get; set; } = string.Empty;
    }
}
