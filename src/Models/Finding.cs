using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    public enum Severity { Critical, High, Medium, Low, Informational }

    public class Finding
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
        public string Host { get; set; } = string.Empty;
        public string Module { get; set; } = string.Empty;
        public string CheckName { get; set; } = string.Empty;
        public Severity Severity { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string RemediationGuidance { get; set; } = string.Empty;
        public Dictionary<string, string> Tags { get; set; } = new();
        public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
        public List<string> RelatedFindingIds { get; set; } = new();
        public double RiskScore { get; set; }
    }

    public class AuditReport
    {
        public string ReportId { get; set; } = Guid.NewGuid().ToString();
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public string[] TargetHosts { get; set; } = Array.Empty<string>();
        public string Domain { get; set; } = string.Empty;
        public List<Finding> Findings { get; set; } = new();
        public Dictionary<Severity, int> SeveritySummary { get; set; } = new();
        public string AuditorVersion { get; set; } = "2.0.0";
    }
}
