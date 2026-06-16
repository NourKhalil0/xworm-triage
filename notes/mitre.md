# MITRE ATT&CK mapping

These are the techniques I saw in this sample. Each one links to what I found in the triage.

## The attack by phase

This shows the techniques in the order they happen on the victim machine.

```mermaid
flowchart LR
    P["Persistence<br/>T1053.005<br/>scheduled task"]:::s2 --> DE["Defense Evasion<br/>T1055.012 hollowing<br/>T1027 obfuscation<br/>T1140 decrypt in memory<br/>T1218 trusted tools"]:::s3
    DE --> DI["Discovery<br/>T1082 system info<br/>T1012 registry<br/>T1497.003 sandbox check"]:::s4
    DI --> C2["Command and Control<br/>T1071 protocol<br/>T1573 encrypted"]:::s5

    classDef s2 fill:#EA314C,stroke:#c8203a,color:#fff,font-weight:bold
    classDef s3 fill:#1F98B2,stroke:#177c92,color:#fff,font-weight:bold
    classDef s4 fill:#155EA4,stroke:#104a82,color:#fff,font-weight:bold
    classDef s5 fill:#134973,stroke:#0d3556,color:#fff,font-weight:bold
```

## The full list

| Tactic | Technique | ID | What I saw |
|--------|-----------|----|-----------|
| Persistence / Execution | Scheduled Task | T1053.005 | Makes a task that runs at logon (`SystemHealthMonitor`) |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 | Second stage injects the RAT into another process |
| Defense Evasion | Obfuscated Files or Information | T1027 | Fake names, borrowed library names, packed/obfuscated stages |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | Decrypts the second stage in memory at runtime |
| Defense Evasion | System Binary Proxy / Trusted Tools | T1218 / T1127 | Abuses `schtasks.exe` and `jsc.exe` (signed Windows tools) |
| Command and Control | Application Layer Protocol | T1071 | Beacons to the C2 over TCP |
| Command and Control | Encrypted Channel | T1573 | C2 traffic is AES-encrypted |
| Discovery | System Information Discovery | T1082 | Seen in sandbox behaviour |
| Discovery | Query Registry | T1012 | Seen in sandbox behaviour |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based | T1497.003 | Seen in sandbox behaviour |

Note: the discovery and sandbox-evasion items (T1082, T1012, T1497.003) came from the
dynamic sandbox run. The persistence, injection, and obfuscation items I confirmed myself
in dnSpy and Procmon.
