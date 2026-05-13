# ZeroTrustAuditor v2.0

> Read-only Zero Trust misconfiguration assessment for Windows Active Directory environments.
> Pure C# — no PowerShell, no WMI, no external processes.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![.NET](https://img.shields.io/badge/.NET-8.0-purple)
![Language](https://img.shields.io/badge/language-C%23-239120)
![License](https://img.shields.io/badge/license-MIT-green)
![Mode](https://img.shields.io/badge/mode-read--only-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)

---

## What it does

ZeroTrustAuditor v2.0 runs five parallel audit checks against scoped Windows hosts and an Active Directory domain. It produces correlated findings with MITRE ATT&CK mappings, severity scores, and specific remediation guidance. All checks are read-only — no exploitation, no credential capture, no lateral movement.

## Architecture

Pure .NET 8 using `System.DirectoryServices`, `Microsoft.Win32.RegistryKey`, `System.Net.Sockets.TcpClient`, and `System.Security.AccessControl`. No PowerShell. No WMI. No external processes. Compiles to a self-contained single executable.

## Checks (37 total)

| Module | Key checks |
|---|---|
| **AdAuditor** | Kerberoastable SPNs, AS-REP roasting, unconstrained delegation, DCSync ACEs, AdminSDHolder orphans, stale privileged accounts, nested DA groups, Protected Users gaps |
| **ProtocolProbe** | SMB signing, NTLMv1, WinRM encryption, RDP NLA, DCOM permissions, SSH configuration |
| **LateralPathAnalyzer** | Local admin group composition, cross-host admin overlap, RDP/WinRM group breadth, LAPS deployment |
| **ShareAuditor** | Over-permissive SMB share ACLs, NTFS write permissions, SYSVOL write access |
| **SegmentationChecker** | Admin port reachability, Windows Firewall state, WEF configuration, Security log size |

## Quick start

```powershell
# Build
dotnet publish ZeroTrustAuditor.csproj --configuration Release --runtime win-x64 --self-contained true --output .\dist

# Run
.\dist\ZeroTrustAuditor.exe --hosts SRV01,SRV02,DC01 --domain corp.local
```

## Required permissions

Domain User account + local read access on target hosts. No local admin required for most checks.

## HOW-TO GUIDE

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZeroTrustAuditor v2.0 -- How-To Guide</title>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#7d8590;--accent:#58a6ff;--green:#3fb950;
  --yellow:#d29922;--red:#f85149;--purple:#bc8cff;--orange:#ffa657;
  --mono:'Cascadia Code','Fira Code',Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --r:6px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:var(--sans);font-size:14px;line-height:1.75;
     color:var(--text);background:var(--bg)}
.layout{display:flex;min-height:100vh}

/* Nav */
nav{position:fixed;top:0;left:0;width:252px;height:100vh;
    background:var(--bg2);border-right:1px solid var(--border);
    overflow-y:auto;padding:20px 0 40px;z-index:100}
.nav-logo{padding:0 18px 18px;border-bottom:1px solid var(--border);margin-bottom:12px}
.nav-logo .t{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--accent)}
.nav-logo .s{font-size:11px;color:var(--muted);margin-top:2px}
.nav-section{padding:8px 18px 3px;font-size:10px;font-weight:600;
             letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-top:10px}
nav a{display:block;padding:5px 18px 5px 26px;font-size:12px;color:var(--muted);
      text-decoration:none;border-left:2px solid transparent;transition:all .15s}
nav a:hover,nav a.active{color:var(--text);border-left-color:var(--accent);
                         background:rgba(88,166,255,.06)}

/* Main */
main{margin-left:252px;flex:1;padding:44px 52px 80px;max-width:960px}

/* Typography */
h1{font-family:var(--mono);font-size:26px;font-weight:600;color:var(--accent);
   letter-spacing:-.01em;margin-bottom:6px}
.sub{color:var(--muted);font-size:13px;font-weight:300;margin-bottom:36px;
     padding-bottom:20px;border-bottom:1px solid var(--border)}
h2{font-family:var(--mono);font-size:16px;font-weight:600;color:var(--text);
   margin:44px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border);
   scroll-margin-top:28px}
h2 .sn{color:var(--accent);margin-right:8px}
h3{font-size:13px;font-weight:600;color:var(--green);font-family:var(--mono);
   margin:20px 0 8px}
p{margin-bottom:12px;color:var(--text);font-weight:300;font-size:13.5px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* Code */
pre{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);
    padding:14px 16px;overflow-x:auto;margin:10px 0 16px;position:relative}
pre code{font-family:var(--mono);font-size:12px;color:var(--text);line-height:1.65}
.cp{position:absolute;top:7px;right:9px;background:var(--bg2);
    border:1px solid var(--border);border-radius:4px;color:var(--muted);
    font-family:var(--mono);font-size:10px;padding:2px 8px;cursor:pointer;transition:all .15s}
.cp:hover{color:var(--text);border-color:var(--accent)}
.cp.ok{color:var(--green);border-color:var(--green)}
code{font-family:var(--mono);font-size:12px;background:var(--bg3);
     border:1px solid var(--border);border-radius:3px;padding:1px 5px;color:var(--purple)}

/* Callouts */
.call{border-radius:var(--r);padding:12px 14px;margin:14px 0;
      border-left:3px solid;font-size:13px;font-weight:300}
.call.info{background:rgba(88,166,255,.07);border-color:var(--accent);color:#a5c8ff}
.call.warn{background:rgba(210,153,34,.07);border-color:var(--yellow);color:#e3c060}
.call.ok  {background:rgba(63,185,80,.07); border-color:var(--green); color:#7ee787}
.call.danger{background:rgba(248,81,73,.07);border-color:var(--red);color:#ffa198}
.call strong{font-weight:600}

/* Tables */
table{width:100%;border-collapse:collapse;margin:12px 0 18px;font-size:13px}
th{text-align:left;padding:7px 11px;background:var(--bg3);border:1px solid var(--border);
   font-family:var(--mono);font-size:11px;font-weight:600;color:var(--muted);
   text-transform:uppercase;letter-spacing:.06em}
td{padding:7px 11px;border:1px solid var(--border);color:var(--text);
   font-weight:300;vertical-align:top}
tr:nth-child(even) td{background:rgba(255,255,255,.02)}

/* Badges */
.badge{display:inline-block;padding:2px 7px;border-radius:10px;
       font-family:var(--mono);font-size:10px;font-weight:600;
       letter-spacing:.04em;text-transform:uppercase}
.bC{background:rgba(248,81,73,.15);color:#ff7b72}
.bH{background:rgba(255,123,0,.12);color:var(--orange)}
.bM{background:rgba(210,153,34,.12);color:var(--yellow)}
.bL{background:rgba(63,185,80,.12);color:var(--green)}
.bI{background:rgba(88,166,255,.12);color:var(--accent)}

/* Steps */
.steps{list-style:none;padding:0;margin:14px 0}
.steps li{display:flex;gap:12px;padding:9px 0;
           border-bottom:1px solid var(--border);font-size:13px;font-weight:300}
.steps li:last-child{border-bottom:none}
.num{flex-shrink:0;width:22px;height:22px;border-radius:50%;
     background:var(--accent);color:var(--bg);font-family:var(--mono);
     font-size:11px;font-weight:600;display:flex;align-items:center;
     justify-content:center;margin-top:1px}

/* Check grid */
.cgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}
.ccard{background:var(--bg2);border:1px solid var(--border);
       border-radius:var(--r);padding:10px 12px}
.ccard .cn{font-family:var(--mono);font-size:10px;color:var(--purple);margin-bottom:3px}
.ccard .cd{font-size:11px;color:var(--muted);font-weight:300}

/* Flow */
.flow{display:flex;align-items:center;gap:0;margin:16px 0;overflow-x:auto;padding-bottom:4px}
.fs{flex-shrink:0;background:var(--bg2);border:1px solid var(--border);
    border-radius:var(--r);padding:7px 12px;font-family:var(--mono);
    font-size:11px;color:var(--text);text-align:center;min-width:90px}
.fs.hl{border-color:var(--accent);color:var(--accent)}
.fa{flex-shrink:0;color:var(--border);font-size:18px;padding:0 3px;line-height:1}

hr{border:none;border-top:1px solid var(--border);margin:28px 0}

/* Responsive */
@media(max-width:860px){
  nav{display:none}main{margin-left:0;padding:28px 20px 60px}
  .cgrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="layout">

<!-- Sidebar -->
<nav>
  <div class="nav-logo">
    <div class="t">ZeroTrustAuditor</div>
    <div class="s">v2.0 How-To Guide</div>
  </div>

  <div class="nav-section">Overview</div>
  <a href="#what">What this tool does</a>
  <a href="#arch">Architecture</a>
  <a href="#v2">Why v2.0 (pure C#)</a>

  <div class="nav-section">Build & Install</div>
  <a href="#prereqs">Prerequisites</a>
  <a href="#structure">Folder structure</a>
  <a href="#build">Build the tool</a>
  <a href="#verify">Verify the build</a>

  <div class="nav-section">Running Audits</div>
  <a href="#config">Configure audit-config.json</a>
  <a href="#run">Run your first audit</a>
  <a href="#results">Read the results</a>
  <a href="#permissions">Permissions required</a>

  <div class="nav-section">Real-World Use</div>
  <a href="#scope">Scoping an engagement</a>
  <a href="#siem">SIEM ingest</a>
  <a href="#remediation">Remediation workflow</a>

  <div class="nav-section">GitHub</div>
  <a href="#github-desc">Repo description</a>
  <a href="#github-upload">Upload to GitHub</a>

  <div class="nav-section">Reference</div>
  <a href="#checks">All checks</a>
  <a href="#troubleshoot">Troubleshooting</a>
</nav>

<!-- Main -->
<main>

<h1>ZeroTrustAuditor v2.0</h1>
<p class="sub">Complete how-to guide -- build, configure, run, and interpret results. Pure C# edition.</p>

<!-- WHAT -->
<h2 id="what"><span class="sn">01</span>What this tool does</h2>
<p>ZeroTrustAuditor is a read-only misconfiguration assessment tool for Windows Active Directory environments. It runs five parallel audit checks against a scoped list of hosts and produces structured findings with severity scores, MITRE ATT&amp;CK mappings, and specific remediation guidance.</p>
<p><strong>It does not exploit vulnerabilities, capture credentials, or make any changes to the environment.</strong> Every check is equivalent to reading configuration data that a domain user already has access to.</p>
<div class="cgrid">
  <div class="ccard"><div class="cn">AdAuditor</div><div class="cd">Kerberoasting, DCSync ACEs, delegation, stale accounts, nested DA groups</div></div>
  <div class="ccard"><div class="cn">ProtocolProbe</div><div class="cd">SMB signing, NTLMv1, WinRM, RDP NLA, DCOM, SSH via remote registry</div></div>
  <div class="ccard"><div class="cn">LateralPathAnalyzer</div><div class="cd">Local admin overlap, LAPS deployment, RDP/WinRM group breadth</div></div>
  <div class="ccard"><div class="cn">ShareAuditor</div><div class="cd">SMB/NTFS ACLs, SYSVOL write permissions, admin share exposure</div></div>
  <div class="ccard"><div class="cn">SegmentationChecker</div><div class="cd">Port reachability, Windows Firewall state, WEF config, log size</div></div>
</div>

<!-- ARCH -->
<h2 id="arch"><span class="sn">02</span>Architecture</h2>
<div class="flow">
  <div class="fs hl">Program.cs</div><div class="fa">&#8594;</div>
  <div class="fs hl">Orchestrator</div><div class="fa">&#8594;</div>
  <div class="fs">5 checks (parallel)</div><div class="fa">&#8594;</div>
  <div class="fs">Aggregator + Correlator</div><div class="fa">&#8594;</div>
  <div class="fs hl">JSON / HTML / CSV / Splunk / Sentinel / CEF</div>
</div>
<p>The orchestrator spawns all five check classes as parallel <code>async Task</code> operations. Each returns a <code>List&lt;Finding&gt;</code>. The aggregator deduplicates by host+check, applies cross-correlation risk boosts from <code>audit-config.json</code>, and renders all output formats.</p>
<p><strong>No PowerShell. No WMI. No CIM. No external processes.</strong> Every API call is pure .NET 8:</p>
<table>
  <thead><tr><th>Check</th><th>.NET API used</th></tr></thead>
  <tbody>
    <tr><td>AD queries (LDAP)</td><td><code>System.DirectoryServices.DirectorySearcher</code></td></tr>
    <tr><td>AD group membership</td><td><code>System.DirectoryServices.AccountManagement</code></td></tr>
    <tr><td>Remote registry</td><td><code>Microsoft.Win32.RegistryKey.OpenRemoteBaseKey()</code></td></tr>
    <tr><td>Port probing</td><td><code>System.Net.Sockets.TcpClient</code></td></tr>
    <tr><td>Share/NTFS ACLs</td><td><code>System.Security.AccessControl.DirectoryInfo.GetAccessControl()</code></td></tr>
    <tr><td>DNS resolution</td><td><code>System.Net.Dns.GetHostAddressesAsync()</code></td></tr>
  </tbody>
</table>

<!-- V2 -->
<h2 id="v2"><span class="sn">03</span>Why v2.0 (pure C#)</h2>
<p>v1.0 used a C# orchestrator that spawned PowerShell 5.1 child processes to run <code>.ps1</code> modules. This caused three categories of persistent failures:</p>
<table>
  <thead><tr><th>v1 Problem</th><th>v2 Fix</th></tr></thead>
  <tbody>
    <tr><td><code>CimCmdlets</code> incompatible with PS Core runspace</td><td>No CIM/WMI at all -- pure registry reads</td></tr>
    <tr><td>UTF-8 em-dash encoding errors in PS 5.1</td><td>No PowerShell -- no encoding issues possible</td></tr>
    <tr><td>Line length parser bugs in PS 5.1 <code>-File</code> mode</td><td>No PowerShell -- no line length limits</td></tr>
    <tr><td><code>InitialSessionState.CreateDefault()</code> null path crash</td><td>No PS SDK dependency at all</td></tr>
    <tr><td>Module file replacement not taking effect</td><td>Everything compiled in -- no separate module files</td></tr>
  </tbody>
</table>

<hr/>

<!-- PREREQS -->
<h2 id="prereqs"><span class="sn">04</span>Prerequisites</h2>
<table>
  <thead><tr><th>Requirement</th><th>Minimum</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>.NET 8 SDK</td><td>8.0.x</td><td>Download SDK (not Runtime) from <a href="https://dot.net/8">dot.net/8</a></td></tr>
    <tr><td>Windows OS</td><td>Windows 10 1809+ or Server 2019+</td><td>Must be domain-joined or have network access to the target domain</td></tr>
    <tr><td>Domain User account</td><td>--</td><td>Read-only LDAP access; no elevated rights needed for most checks</td></tr>
    <tr><td>Remote Registry service</td><td>Running on targets</td><td>Required for NTLMv1, RDP NLA, WinRM, DCOM, and Firewall checks</td></tr>
    <tr><td>Internet access (build only)</td><td>--</td><td>NuGet restore needs nuget.org to download 3 packages once</td></tr>
  </tbody>
</table>
<p>Verify .NET 8 SDK is installed:</p>
<pre><button class="cp" onclick="cp(this)">copy</button><code>dotnet --version
# Must show 8.x.x -- if not, install from dot.net/8 (choose SDK, not Runtime)</code></pre>

<!-- STRUCTURE -->
<h2 id="structure"><span class="sn">05</span>Folder structure</h2>
<p>Create this exact structure. Every file comes from the Claude conversation above.</p>
<pre><code>C:\Dev\ZTAuditorV2\                      &lt;-- project root
&#9500;&#9472;&#9472; ZeroTrustAuditor.csproj
&#9500;&#9472;&#9472; audit-config.json
&#9500;&#9472;&#9472; README.md
&#9500;&#9472;&#9472; .gitignore
&#9492;&#9472;&#9472; src\
    &#9500;&#9472;&#9472; Program.cs
    &#9500;&#9472;&#9472; Orchestrator.cs
    &#9500;&#9472;&#9472; Models\
    &#9474;   &#9500;&#9472;&#9472; Finding.cs
    &#9474;   &#9492;&#9472;&#9472; AuditConfig.cs
    &#9500;&#9472;&#9472; Checks\
    &#9474;   &#9500;&#9472;&#9472; CheckBase.cs
    &#9474;   &#9500;&#9472;&#9472; AdAuditor.cs
    &#9474;   &#9500;&#9472;&#9472; ProtocolProbe.cs
    &#9474;   &#9500;&#9472;&#9472; LateralPathAnalyzer.cs
    &#9474;   &#9500;&#9472;&#9472; ShareAuditor.cs
    &#9474;   &#9492;&#9472;&#9472; SegmentationChecker.cs
    &#9492;&#9472;&#9472; Reports\
        &#9500;&#9472;&#9472; ReportRenderer.cs
        &#9492;&#9472;&#9472; SiemRenderer.cs</code></pre>
<div class="call info"><strong>Tip:</strong> Use a path with no spaces -- e.g. <code>C:\Dev\ZTAuditorV2</code>. Spaces in paths cause issues with some dotnet commands.</div>

<!-- BUILD -->
<h2 id="build"><span class="sn">06</span>Build the tool</h2>
<pre><button class="cp" onclick="cp(this)">copy</button><code>cd C:\Dev\ZTAuditorV2

# Restore NuGet packages (requires internet -- downloads ~1 MB total, one time only)
dotnet restore ZeroTrustAuditor.csproj

# Verify it compiles cleanly before publishing
dotnet build ZeroTrustAuditor.csproj --configuration Release
# Expected: Build succeeded. 0 Warning(s) 0 Error(s)

# Publish self-contained folder (recommended over single-file for this tool)
dotnet publish ZeroTrustAuditor.csproj `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output .\dist</code></pre>

<h3>Common build errors and fixes</h3>
<table>
  <thead><tr><th>Error</th><th>Fix</th></tr></thead>
  <tbody>
    <tr><td><code>CS0234: DirectoryServices does not exist</code></td><td>Run <code>dotnet restore</code> first. If it still fails, check internet access -- NuGet needs to download the System.DirectoryServices package.</td></tr>
    <tr><td><code>NETSDK1045: current SDK does not support .NET 8</code></td><td>Your SDK is older than 8.0. Reinstall from dot.net/8.</td></tr>
    <tr><td><code>error MSB3021: unable to copy audit-config.json</code></td><td><code>audit-config.json</code> must be in the project root next to the <code>.csproj</code> file.</td></tr>
    <tr><td><code>CS0246: type not found</code></td><td>A source file is missing. Check the folder structure above and confirm all 14 files are present.</td></tr>
  </tbody>
</table>

<!-- VERIFY -->
<h2 id="verify"><span class="sn">07</span>Verify the build</h2>
<pre><button class="cp" onclick="cp(this)">copy</button><code>cd .\dist

# Verify the exe exists and shows the banner
.\ZeroTrustAuditor.exe --help
# Expected: prints banner and usage

# Check dist folder contents
Get-ChildItem .\dist\ | Select-Object Name, Length</code></pre>
<p>The <code>dist\</code> folder will contain the exe, supporting DLLs, and <code>audit-config.json</code>. This is your distributable -- zip the whole folder to move it between machines.</p>

<hr/>

<!-- CONFIG -->
<h2 id="config"><span class="sn">08</span>Configure audit-config.json</h2>
<p>Open <code>dist\audit-config.json</code>. The defaults work for most runs. Key settings to review before your first scan:</p>
<pre><button class="cp" onclick="cp(this)">copy</button><code>{
  "audit": {
    "staleAccountThresholdDays": 90,    // days before an unused account is flagged
    "maxHostsPerRun": 500,              // safety cap -- reduce to 10 for small labs
    "parallelModuleTimeout": 300,       // seconds before a check is cancelled
    "excludeHosts": [],                 // hostnames to skip, e.g. ["honeypot01"]
    "excludeChecks": [],                // check names to suppress, e.g. ["SSH_CONFIG_UNREADABLE"]
    "skipModules": []                   // module names to skip, e.g. ["ShareAuditor"]
  },
  "output": {
    "formats": ["json", "html", "csv"] // remove splunk/sentinel/cef if not using a SIEM
  },
  "reporting": {
    "organizationName": "Acme Corp",
    "engagementName":   "Q4 2025 ZT Assessment",
    "auditorName":      "Your Name"
  }
}</code></pre>
<div class="call warn"><strong>Production note:</strong> Add your organization's custom privileged groups to <code>thresholds.privilegedGroups</code>. If you have groups like <code>Tier0-Admins</code> or <code>PAW-Users</code>, add them or those accounts will be missed by the stale account and Protected Users checks.</div>

<!-- RUN -->
<h2 id="run"><span class="sn">09</span>Run your first audit</h2>
<pre><button class="cp" onclick="cp(this)">copy</button><code>cd C:\Dev\ZTAuditorV2\dist

# Basic run -- comma-separated hosts
.\ZeroTrustAuditor.exe --hosts SRV01,SRV02,DC01 --domain corp.local

# With explicit config and output path
.\ZeroTrustAuditor.exe `
    --hosts SRV01,SRV02,DC01 `
    --domain corp.local `
    --config .\audit-config.json `
    --output .\reports

# From a hosts file (one hostname per line, # = comment)
.\ZeroTrustAuditor.exe `
    --hosts-file .\targets.txt `
    --domain corp.local `
    --output .\reports</code></pre>

<h3>Targets file format</h3>
<pre><code># targets.txt
# Domain Controllers
DC01
DC02

# Tier-1 Servers
SRV01
SRV02
SRV03

# Workstation sample
WS01
# WS02   &lt;-- commented out</code></pre>

<div class="call ok"><strong>First run tip:</strong> Start with 2-3 hosts you control to verify connectivity and that findings flow through. Scale up to the full scope after validating output.</div>

<h3>Expected console output</h3>
<pre><code>  ZeroTrustAuditor v2.0 | Pure C# Zero Trust Assessment
  No PowerShell. No WMI. No external processes.

[*] Hosts in scope: 3
[*] Config loaded: .\audit-config.json
[*] Starting audit -- 3 host(s), domain 'corp.local'
[*] Launching: AdAuditor
[*] Launching: ProtocolProbe
[*] Launching: LateralPathAnalyzer
[*] Launching: ShareAuditor
[*] Launching: SegmentationChecker
[AdAuditor] Auditing domain: corp.local
[AdAuditor] CHECK 1 - Kerberoastable SPNs
...
[+] Audit complete. Unique findings: 24
    Critical        3
    High            9
    Medium          8
    Low             4
[+] JSON: .\reports\audit-20260511-120000.json
[+] CSV:  .\reports\audit-20260511-120000.csv
[+] HTML: .\reports\audit-20260511-120000.html</code></pre>

<!-- RESULTS -->
<h2 id="results"><span class="sn">10</span>Read the results</h2>
<p>Open the HTML report in any browser. It shows a severity dashboard at the top and a full findings table ordered by risk score (highest first).</p>
<h3>Severity model</h3>
<table>
  <thead><tr><th>Severity</th><th>Base score</th><th>Meaning</th><th>SLA target</th></tr></thead>
  <tbody>
    <tr><td><span class="badge bC">Critical</span></td><td>9.0</td><td>Direct path to domain compromise or mass lateral movement</td><td>24-48 hours</td></tr>
    <tr><td><span class="badge bH">High</span></td><td>7.0</td><td>Significant misconfiguration enabling targeted attack</td><td>7 days</td></tr>
    <tr><td><span class="badge bM">Medium</span></td><td>5.0</td><td>Defense-in-depth gap; exploitable in combination</td><td>30 days</td></tr>
    <tr><td><span class="badge bL">Low</span></td><td>3.0</td><td>Best-practice deviation; next hardening cycle</td><td>90 days</td></tr>
    <tr><td><span class="badge bI">Info</span></td><td>1.0</td><td>Connectivity note or manual review item</td><td>Review only</td></tr>
  </tbody>
</table>
<h3>Correlated findings</h3>
<p>Findings with a risk score <em>above</em> their base severity (e.g. a High at 9.0 instead of 7.0) have been boosted by a correlation rule -- two misconfigs on the same host that together form a more dangerous attack chain. The <code>correlationRule</code> field in the JSON identifies which rule fired.</p>
<h3>Reading priority</h3>
<ul class="steps">
  <li><div class="num">1</div><div>Correlated Critical findings first (score above 9.0). These are complete attack chains.</div></li>
  <li><div class="num">2</div><div>DC-specific findings. Any finding on a Domain Controller is implicitly higher risk.</div></li>
  <li><div class="num">3</div><div>Group findings by CheckName to spot systemic issues. SMB_SIGNING_DISABLED on 40 hosts = a GPO problem, not a per-host problem.</div></li>
  <li><div class="num">4</div><div>Review Informational findings for scope gaps (hosts that were unreachable or had access denied).</div></li>
</ul>

<!-- PERMISSIONS -->
<h2 id="permissions"><span class="sn">11</span>Permissions required</h2>
<table>
  <thead><tr><th>Check</th><th>Required permission</th><th>If missing</th></tr></thead>
  <tbody>
    <tr><td>All AD checks</td><td>Domain User (read-only LDAP)</td><td>Check skipped with logged message</td></tr>
    <tr><td>Registry checks (NTLMv1, RDP, WinRM, DCOM, Firewall)</td><td>Remote Registry service running on target</td><td>Returns null -- no finding emitted</td></tr>
    <tr><td>Local group membership (LateralPath)</td><td>AccountManagement API access to target machine</td><td>HOST_UNREACHABLE Informational finding</td></tr>
    <tr><td>Share/NTFS ACLs (ShareAuditor)</td><td>Network read access to UNC paths</td><td>Share skipped silently</td></tr>
    <tr><td>Port probing (Segmentation)</td><td>Network connectivity only</td><td>Port marked closed</td></tr>
  </tbody>
</table>
<h3>Enable Remote Registry on targets (via GPO)</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code># GPO path: Computer Configuration -> Windows Settings -> System Services
# Service: Remote Registry
# Startup type: Automatic

# Or enable directly on a single target for testing:
Invoke-Command -ComputerName SRV01 -ScriptBlock {
    Set-Service RemoteRegistry -StartupType Automatic
    Start-Service RemoteRegistry
}</code></pre>

<hr/>

<!-- SCOPE -->
<h2 id="scope"><span class="sn">12</span>Scoping an engagement</h2>
<p>Generate a host list from Active Directory using the included PowerShell helper <code>Get-AuditTargets.ps1</code> (available in the v1 modules folder), or build one manually. For real environments, scope in tiers:</p>
<pre><button class="cp" onclick="cp(this)">copy</button><code># Tier 0 -- Domain Controllers (always include)
# Get all DCs:
(Get-ADDomainController -Filter *).HostName | Out-File .\tier0.txt

# Tier 1 -- Servers by OU
Get-ADComputer -Filter { OperatingSystem -like "*Server*" } `
    -SearchBase "OU=Servers,DC=corp,DC=local" `
    -Properties DNSHostName |
    Select-Object -ExpandProperty DNSHostName |
    Out-File .\tier1.txt

# Run each tier separately
.\ZeroTrustAuditor.exe --hosts-file .\tier0.txt --domain corp.local --output .\reports\tier0
.\ZeroTrustAuditor.exe --hosts-file .\tier1.txt --domain corp.local --output .\reports\tier1</code></pre>

<!-- SIEM -->
<h2 id="siem"><span class="sn">13</span>SIEM ingest</h2>
<p>Enable additional output formats in <code>audit-config.json</code>:</p>
<pre><button class="cp" onclick="cp(this)">copy</button><code>"output": {
  "formats": ["json", "html", "csv", "splunk", "sentinel", "cef"]
}</code></pre>

<h3>Splunk HEC</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code># Push the generated .splunk.json file to Splunk HEC
$token = Read-Host "Splunk HEC token" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($token))

Invoke-RestMethod `
    -Uri "https://splunk-hec.corp.local:8088/services/collector/event" `
    -Method POST `
    -Headers @{ Authorization = "Splunk $plain" } `
    -ContentType "application/json" `
    -InFile ".\reports\audit-*.splunk.json"

# Search in Splunk:
# index=zero_trust_audit severity=Critical | table dest, check_name, risk_score, mitre_technique</code></pre>

<h3>Microsoft Sentinel</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code># Ingest the .sentinel.json file via the Log Analytics Data Collector API
# Or ingest via AMA (Azure Monitor Agent) custom log collection

# KQL query after ingest:
# ZeroTrustAuditFinding_CL
# | where Severity_s in ("Critical", "High")
# | project TimeGenerated, Host_s, CheckName_s, RiskScore_d, MitreTechnique_s
# | order by RiskScore_d desc</code></pre>

<!-- REMEDIATION -->
<h2 id="remediation"><span class="sn">14</span>Remediation workflow</h2>
<pre><button class="cp" onclick="cp(this)">copy</button><code># Import CSV and group by CheckName for systemic remediation
$findings = Import-Csv ".\reports\audit-*.csv"

# Show systemic issues grouped by check
$findings |
    Group-Object CheckName |
    Sort-Object { ($_.Group[0].RiskScore -as [double]) } -Descending |
    Select-Object Name, Count, @{n='Severity';e={$_.Group[0].Severity}} |
    Format-Table -AutoSize

# Export Critical findings for immediate action
$findings |
    Where-Object { $_.Severity -eq 'Critical' } |
    Export-Csv ".\reports\critical-$(Get-Date -f yyyyMMdd).csv" -NoTypeInformation</code></pre>

<div class="call info"><strong>Re-audit after remediation:</strong> Re-run the tool against the same scope 2-4 weeks after remediation to confirm findings are closed. The timestamped report naming makes it easy to diff two runs.</div>

<hr/>

<!-- GITHUB DESC -->
<h2 id="github-desc"><span class="sn">15</span>GitHub repo description</h2>
<p>Paste the following into the GitHub repo description field (the short one-line box under the repo name, limited to 350 characters):</p>
<pre><button class="cp" onclick="cp(this)">copy</button><code>Read-only Zero Trust misconfiguration assessment for Windows Active Directory. Pure C# -- no PowerShell, no WMI. Audits AD, SMB signing, NTLMv1, RDP NLA, DCOM, LAPS, share ACLs, and network segmentation. MITRE ATT&CK mapped findings with Splunk/Sentinel/CEF output.</code></pre>

<h3>GitHub Topics (paste into the Topics field)</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code>active-directory zero-trust security-audit dotnet csharp mitre-attack lateral-movement smb kerberos windows blue-team siem splunk sentinel misconfiguration penetration-testing</code></pre>

<h3>README badges (paste at top of README.md)</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code>![Platform](https://img.shields.io/badge/platform-Windows-blue)
![.NET](https://img.shields.io/badge/.NET-8.0-purple)
![Language](https://img.shields.io/badge/language-C%23-239120)
![License](https://img.shields.io/badge/license-MIT-green)
![Mode](https://img.shields.io/badge/mode-read--only-brightgreen)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)</code></pre>

<!-- GITHUB UPLOAD -->
<h2 id="github-upload"><span class="sn">16</span>Upload to GitHub</h2>
<p>You have two options. Option A (Git CLI) is the most reliable. Option B (GitHub web) works if you don't have Git installed.</p>

<h3>Option A -- Git CLI (recommended)</h3>
<ul class="steps">
  <li><div class="num">1</div><div>Install Git from <a href="https://git-scm.com">git-scm.com</a> if not already installed. Verify: <code>git --version</code></div></li>
  <li><div class="num">2</div><div>Go to <a href="https://github.com/new">github.com/new</a>, create a new repository named <code>ZeroTrustAuditor</code>. Set it to Public or Private. Do NOT initialize with README (you already have one).</div></li>
  <li><div class="num">3</div><div>Copy the repository URL shown on the page (e.g. <code>https://github.com/WarrantBdoesZT/ZeroTrustAuditor.git</code>)</div></li>
  <li><div class="num">4</div><div>Run the commands below from your project root.</div></li>
</ul>
<pre><button class="cp" onclick="cp(this)">copy</button><code>cd C:\Dev\ZTAuditorV2

# Initialize git repo
git init
git add .
git commit -m "Initial commit: ZeroTrustAuditor v2.0 pure C# edition"

# Connect to your GitHub repo (replace URL with yours)
git remote add origin https://github.com/WarrantBdoesZT/ZeroTrustAuditor.git
git branch -M main
git push -u origin main</code></pre>

<div class="call warn"><strong>Authentication:</strong> GitHub no longer accepts passwords for Git over HTTPS. When prompted, use a Personal Access Token (PAT). Create one at: GitHub Settings -> Developer Settings -> Personal Access Tokens -> Tokens (classic) -> Generate new token. Select the <code>repo</code> scope. Use the token as your password when Git prompts.</div>

<h3>Verify the upload</h3>
<pre><button class="cp" onclick="cp(this)">copy</button><code># Check all files were pushed
git log --oneline
git status

# Open the repo in your browser
start https://github.com/WarrantBdoesZT/ZeroTrustAuditor</code></pre>

<h3>Link to your GitHub Project board</h3>
<p>To link the repo to your existing Project at <code>https://github.com/users/WarrantBdoesZT/projects/1</code>:</p>
<ul class="steps">
  <li><div class="num">1</div><div>Go to your Project board at <a href="https://github.com/users/WarrantBdoesZT/projects/1">github.com/users/WarrantBdoesZT/projects/1</a></div></li>
  <li><div class="num">2</div><div>Click the three-dot menu (<code>...</code>) in the top right of the project board</div></li>
  <li><div class="num">3</div><div>Select <strong>Settings</strong></div></li>
  <li><div class="num">4</div><div>Under <strong>Linked repositories</strong>, click <strong>Link a repository</strong> and select <code>ZeroTrustAuditor</code></div></li>
  <li><div class="num">5</div><div>Issues and PRs from the repo will now appear in your project board</div></li>
</ul>

<h3>Option B -- GitHub web upload</h3>
<p>If you prefer not to use Git CLI:</p>
<ul class="steps">
  <li><div class="num">1</div><div>Go to <a href="https://github.com/new">github.com/new</a> and create a new repo. This time, <strong>do</strong> initialize with a README (you'll replace it).</div></li>
  <li><div class="num">2</div><div>In the new repo, click <strong>Add file -> Upload files</strong></div></li>
  <li><div class="num">3</div><div>Drag and drop your entire project folder. GitHub web supports folder uploads via drag-and-drop in Chrome/Edge.</div></li>
  <li><div class="num">4</div><div>Click <strong>Commit changes</strong></div></li>
</ul>
<div class="call warn"><strong>Limitation:</strong> GitHub web upload has a 25 MB file size limit per file and does not preserve nested folder structure well for large uploads. The Git CLI method is strongly preferred for a project with this many subfolders.</div>

<hr/>

<!-- CHECKS -->
<h2 id="checks"><span class="sn">17</span>All checks reference</h2>
<table>
  <thead><tr><th>Check name</th><th>Module</th><th>Severity</th><th>MITRE</th></tr></thead>
  <tbody>
    <tr><td><code>KERBEROASTABLE_SPN</code></td><td>AdAuditor</td><td><span class="badge bH">High</span> / <span class="badge bC">Critical*</span></td><td>T1558.003</td></tr>
    <tr><td><code>ASREP_ROASTABLE</code></td><td>AdAuditor</td><td><span class="badge bH">High</span> / <span class="badge bC">Critical*</span></td><td>T1558.004</td></tr>
    <tr><td><code>UNCONSTRAINED_DELEGATION</code></td><td>AdAuditor</td><td><span class="badge bC">Critical</span></td><td>T1558.001</td></tr>
    <tr><td><code>DCSYNC_ACE</code></td><td>AdAuditor</td><td><span class="badge bC">Critical</span></td><td>T1003.006</td></tr>
    <tr><td><code>MISSING_PROTECTED_USERS</code></td><td>AdAuditor</td><td><span class="badge bM">Medium</span></td><td>T1558</td></tr>
    <tr><td><code>STALE_PRIVILEGED_ACCOUNT</code></td><td>AdAuditor</td><td><span class="badge bH">High</span></td><td>T1078.002</td></tr>
    <tr><td><code>NESTED_GROUP_DA</code></td><td>AdAuditor</td><td><span class="badge bH">High</span></td><td>T1078.002</td></tr>
    <tr><td><code>ADMINCOUNT_ORPHAN</code></td><td>AdAuditor</td><td><span class="badge bM">Medium</span></td><td>T1078.002</td></tr>
    <tr><td><code>SMB_SIGNING_DISABLED</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span> / <span class="badge bC">Critical*</span></td><td>T1557.001</td></tr>
    <tr><td><code>NTLM_V1_ENABLED</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span> / <span class="badge bC">Critical*</span></td><td>T1557.001</td></tr>
    <tr><td><code>WINRM_UNENCRYPTED</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span></td><td>T1021.006</td></tr>
    <tr><td><code>WINRM_NO_HTTPS</code></td><td>ProtocolProbe</td><td><span class="badge bM">Medium</span></td><td>T1021.006</td></tr>
    <tr><td><code>RDP_NLA_DISABLED</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span></td><td>T1021.001</td></tr>
    <tr><td><code>RDP_WEAK_ENCRYPTION</code></td><td>ProtocolProbe</td><td><span class="badge bM">Medium</span></td><td>T1021.001</td></tr>
    <tr><td><code>DCOM_DEFAULT_LAUNCH_PERMISSION</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span></td><td>T1021.003</td></tr>
    <tr><td><code>DCOM_DEFAULT_ACCESS_PERMISSION</code></td><td>ProtocolProbe</td><td><span class="badge bM">Medium</span></td><td>T1021.003</td></tr>
    <tr><td><code>SSH_STRICT_MODES_DISABLED</code></td><td>ProtocolProbe</td><td><span class="badge bM">Medium</span></td><td>T1021</td></tr>
    <tr><td><code>SSH_PASSWORD_AUTH_ENABLED</code></td><td>ProtocolProbe</td><td><span class="badge bM">Medium</span></td><td>T1021</td></tr>
    <tr><td><code>SSH_PERMIT_ROOT_LOGIN</code></td><td>ProtocolProbe</td><td><span class="badge bH">High</span></td><td>T1021</td></tr>
    <tr><td><code>DOMAIN_GROUP_LOCAL_ADMIN</code></td><td>LateralPath</td><td><span class="badge bH">High</span></td><td>T1078.002</td></tr>
    <tr><td><code>LOCAL_ADMIN_OVERLAP</code></td><td>LateralPath</td><td><span class="badge bM">Medium</span> -- <span class="badge bC">Critical</span></td><td>T1021.002</td></tr>
    <tr><td><code>BROAD_RDP_ACCESS</code></td><td>LateralPath</td><td><span class="badge bM">Medium</span></td><td>T1021.001</td></tr>
    <tr><td><code>BROAD_WINRM_ACCESS</code></td><td>LateralPath</td><td><span class="badge bM">Medium</span></td><td>T1021.006</td></tr>
    <tr><td><code>LAPS_NOT_DEPLOYED</code></td><td>LateralPath</td><td><span class="badge bH">High</span></td><td>T1110</td></tr>
    <tr><td><code>OPEN_SMB_SHARE_WRITE</code></td><td>ShareAuditor</td><td><span class="badge bH">High</span></td><td>T1021.002</td></tr>
    <tr><td><code>OPEN_SMB_SHARE_READ</code></td><td>ShareAuditor</td><td><span class="badge bM">Medium</span></td><td>T1021.002</td></tr>
    <tr><td><code>ADMIN_SHARE_OVERPERMISSIVE</code></td><td>ShareAuditor</td><td><span class="badge bC">Critical</span></td><td>T1021.002</td></tr>
    <tr><td><code>SYSVOL_WRITE_PERMISSION</code></td><td>ShareAuditor</td><td><span class="badge bC">Critical</span></td><td>T1484.001</td></tr>
    <tr><td><code>CROSS_SEGMENT_ADMIN_PORT</code></td><td>Segmentation</td><td><span class="badge bH">High</span></td><td>T1021</td></tr>
    <tr><td><code>CROSS_SEGMENT_RDP</code></td><td>Segmentation</td><td><span class="badge bH">High</span></td><td>T1021.001</td></tr>
    <tr><td><code>WINDOWS_FIREWALL_DISABLED</code></td><td>Segmentation</td><td><span class="badge bH">High</span></td><td>T1562.004</td></tr>
    <tr><td><code>FIREWALL_LOGGING_DISABLED</code></td><td>Segmentation</td><td><span class="badge bM">Medium</span></td><td>T1562.006</td></tr>
    <tr><td><code>SECURITY_LOG_TOO_SMALL</code></td><td>Segmentation</td><td><span class="badge bL">Low</span></td><td>T1562.006</td></tr>
    <tr><td><code>WEF_NOT_CONFIGURED</code></td><td>Segmentation</td><td><span class="badge bM">Medium</span></td><td>T1562.006</td></tr>
  </tbody>
</table>
<p style="font-size:11px;color:var(--muted);margin-top:4px">* Severity escalates to Critical when AdminCount=1 (AD checks) or LmCompatibilityLevel &lt; 2 (NTLMv1).</p>

<!-- TROUBLESHOOT -->
<h2 id="troubleshoot"><span class="sn">18</span>Troubleshooting</h2>
<table>
  <thead><tr><th>Symptom</th><th>Likely cause</th><th>Fix</th></tr></thead>
  <tbody>
    <tr><td>AD checks produce 0 findings</td><td>Domain unreachable or account lacks LDAP access</td><td>Test: <code>nltest /dsgetdc:corp.local</code> from the audit workstation</td></tr>
    <tr><td>Registry checks return null (no NTLMv1/RDP findings)</td><td>Remote Registry service not running on targets</td><td>Enable via GPO or: <code>Start-Service RemoteRegistry</code> on target</td></tr>
    <tr><td>LateralPath shows all HOST_UNREACHABLE</td><td>AccountManagement API blocked -- firewall or no network path to target</td><td>Test: <code>Test-NetConnection SRV01 -Port 445</code></td></tr>
    <tr><td>ShareAuditor finds no shares</td><td>Audit account lacks UNC read access</td><td>Test: <code>dir \\SRV01\C$</code> from the audit workstation</td></tr>
    <tr><td>0 findings despite known misconfigs</td><td>Check is completing but returning clean results -- access denied is silent</td><td>Run with a test host you control and verify Remote Registry is running</td></tr>
    <tr><td>Build error: CS0234 DirectoryServices</td><td>NuGet restore did not download the package</td><td>Run <code>dotnet restore</code> with internet access, then rebuild</td></tr>
    <tr><td>Antivirus quarantines the exe</td><td>Self-contained .NET executables are sometimes flagged</td><td>Add a Defender exclusion or sign with your org's code-signing certificate</td></tr>
    <tr><td>Timeout errors on large host lists</td><td><code>parallelModuleTimeout</code> too low</td><td>Increase in audit-config.json: set to 600 for 100+ hosts</td></tr>
  </tbody>
</table>

</main>
</div>

<script>
function cp(btn) {
  const code = btn.parentElement.querySelector('code').innerText;
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'copied!'; btn.classList.add('ok');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('ok'); }, 2000);
  });
}
const sections = document.querySelectorAll('h2[id]');
const navLinks  = document.querySelectorAll('nav a');
const obs = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      navLinks.forEach(a => a.classList.remove('active'));
      const a = document.querySelector(`nav a[href="#${e.target.id}"]`);
      if (a) a.classList.add('active');
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
sections.forEach(s => obs.observe(s));
</script>
</body>
</html>
