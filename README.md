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
