#!/usr/bin/env lua
--[[
NullSec ProcMon - Process Monitor & Analyzer
=============================================
Lua security tool demonstrating:
- Tables as primary data structure (safe by default)
- Metatables for type safety
- Coroutines for async monitoring
- Pattern matching for threat detection
- First-class functions for callbacks
- Nil-safe operations

Author: bad-antics
License: MIT
--]]

local VERSION = "1.0.0"

-- =============================================================================
-- Safe Types with Metatables
-- =============================================================================

--- Create a validated process record
local function Process(pid, name, cmdline, uid, ppid)
    local self = {
        pid = tonumber(pid) or 0,
        name = name or "unknown",
        cmdline = cmdline or "",
        uid = tonumber(uid) or 0,
        ppid = tonumber(ppid) or 0,
        start_time = os.time(),
        cpu_usage = 0,
        mem_usage = 0,
        threat_score = 0,
        flags = {}
    }
    
    -- Metatable for type safety
    setmetatable(self, {
        __tostring = function(p)
            return string.format("[%d] %s (ppid=%d, uid=%d)", 
                p.pid, p.name, p.ppid, p.uid)
        end,
        __index = function(_, key)
            return nil -- Safe nil for missing keys
        end
    })
    
    return self
end

--- Create a threat detection result
local function ThreatResult(level, category, description, process)
    return {
        level = level or "info",
        category = category or "unknown",
        description = description or "",
        process = process,
        timestamp = os.time()
    }
end

-- =============================================================================
-- Threat Patterns
-- =============================================================================

local SUSPICIOUS_NAMES = {
    -- Crypto miners
    ["xmrig"] = { level = "critical", category = "cryptominer" },
    ["minerd"] = { level = "critical", category = "cryptominer" },
    ["cpuminer"] = { level = "critical", category = "cryptominer" },
    ["cgminer"] = { level = "critical", category = "cryptominer" },
    ["ethminer"] = { level = "critical", category = "cryptominer" },
    
    -- Reverse shells
    ["nc"] = { level = "high", category = "netcat" },
    ["ncat"] = { level = "high", category = "netcat" },
    ["netcat"] = { level = "high", category = "netcat" },
    ["socat"] = { level = "medium", category = "netcat" },
    
    -- Recon tools (suspicious if unexpected)
    ["nmap"] = { level = "medium", category = "recon" },
    ["masscan"] = { level = "medium", category = "recon" },
    ["nikto"] = { level = "medium", category = "recon" },
    ["sqlmap"] = { level = "high", category = "exploit" },
    
    -- Post-exploitation
    ["mimikatz"] = { level = "critical", category = "credential_theft" },
    ["lazagne"] = { level = "critical", category = "credential_theft" },
    ["keylogger"] = { level = "critical", category = "keylogger" },
    
    -- Persistence
    ["crontab"] = { level = "low", category = "persistence" },
    ["at"] = { level = "low", category = "persistence" },
    
    -- Suspicious shells
    ["sh -i"] = { level = "high", category = "reverse_shell" },
    ["bash -i"] = { level = "high", category = "reverse_shell" },
    ["/dev/tcp"] = { level = "critical", category = "reverse_shell" },
    ["/dev/udp"] = { level = "critical", category = "reverse_shell" }
}

local SUSPICIOUS_CMDLINE_PATTERNS = {
    -- Encoded commands
    { pattern = "base64%s+%-d", level = "high", desc = "Base64 decode in command" },
    { pattern = "python.-%-c", level = "medium", desc = "Python one-liner" },
    { pattern = "perl.-%-e", level = "medium", desc = "Perl one-liner" },
    { pattern = "ruby.-%-e", level = "medium", desc = "Ruby one-liner" },
    
    -- Network activity
    { pattern = "curl.-|.-sh", level = "critical", desc = "Curl pipe to shell" },
    { pattern = "wget.-|.-sh", level = "critical", desc = "Wget pipe to shell" },
    { pattern = "curl.-|.-bash", level = "critical", desc = "Curl pipe to bash" },
    { pattern = "wget.-|.-bash", level = "critical", desc = "Wget pipe to bash" },
    
    -- Reverse shells
    { pattern = "bash.->&.-/dev/tcp", level = "critical", desc = "Bash reverse shell" },
    { pattern = "nc.-%-e.-/bin", level = "critical", desc = "Netcat reverse shell" },
    { pattern = "mkfifo", level = "high", desc = "Named pipe (possible reverse shell)" },
    
    -- Privilege escalation
    { pattern = "sudo.-NOPASSWD", level = "high", desc = "Sudo NOPASSWD manipulation" },
    { pattern = "chmod.-4755", level = "high", desc = "SUID bit setting" },
    { pattern = "chmod.-u%+s", level = "high", desc = "SUID bit setting" },
    
    -- Data exfiltration
    { pattern = "tar.-czf.-|.-curl", level = "high", desc = "Archive exfiltration" },
    { pattern = "zip.-|.-curl", level = "high", desc = "Archive exfiltration" },
    
    -- Anti-forensics
    { pattern = "history.-%-c", level = "medium", desc = "History clearing" },
    { pattern = "shred", level = "medium", desc = "Secure file deletion" },
    { pattern = "rm.-%-rf.-%/var%/log", level = "critical", desc = "Log deletion" }
}

-- =============================================================================
-- Process Reading (Linux /proc)
-- =============================================================================

--- Read file contents safely
local function read_file(path)
    local file = io.open(path, "r")
    if not file then return nil end
    local content = file:read("*a")
    file:close()
    return content
end

--- Parse /proc/[pid]/stat
local function parse_proc_stat(pid)
    local stat = read_file(string.format("/proc/%d/stat", pid))
    if not stat then return nil end
    
    -- Extract fields (handles names with spaces in parentheses)
    local fields = {}
    local name_start = stat:find("%(")
    local name_end = stat:find("%)")
    
    if name_start and name_end then
        fields.pid = tonumber(stat:sub(1, name_start - 2))
        fields.name = stat:sub(name_start + 1, name_end - 1)
        
        local rest = stat:sub(name_end + 2)
        local i = 1
        for field in rest:gmatch("%S+") do
            if i == 1 then fields.state = field
            elseif i == 2 then fields.ppid = tonumber(field)
            elseif i == 3 then fields.pgrp = tonumber(field)
            elseif i == 12 then fields.utime = tonumber(field)
            elseif i == 13 then fields.stime = tonumber(field)
            end
            i = i + 1
        end
    end
    
    return fields
end

--- Get process cmdline
local function get_cmdline(pid)
    local cmdline = read_file(string.format("/proc/%d/cmdline", pid))
    if not cmdline then return "" end
    return cmdline:gsub("%z", " "):gsub("^%s+", ""):gsub("%s+$", "")
end

--- Get process UID
local function get_uid(pid)
    local status = read_file(string.format("/proc/%d/status", pid))
    if not status then return 0 end
    local uid = status:match("Uid:%s+(%d+)")
    return tonumber(uid) or 0
end

--- List all process PIDs
local function list_pids()
    local pids = {}
    local handle = io.popen("ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$'")
    if handle then
        for line in handle:lines() do
            local pid = tonumber(line)
            if pid then table.insert(pids, pid) end
        end
        handle:close()
    end
    return pids
end

--- Get all processes
local function get_processes()
    local processes = {}
    for _, pid in ipairs(list_pids()) do
        local stat = parse_proc_stat(pid)
        if stat then
            local proc = Process(
                pid,
                stat.name,
                get_cmdline(pid),
                get_uid(pid),
                stat.ppid
            )
            processes[pid] = proc
        end
    end
    return processes
end

-- =============================================================================
-- Threat Analysis
-- =============================================================================

--- Analyze a single process for threats
local function analyze_process(proc)
    local threats = {}
    local score = 0
    
    -- Check process name
    local name_lower = proc.name:lower()
    for pattern, info in pairs(SUSPICIOUS_NAMES) do
        if name_lower:find(pattern, 1, true) then
            table.insert(threats, ThreatResult(
                info.level,
                info.category,
                "Suspicious process name: " .. proc.name,
                proc
            ))
            if info.level == "critical" then score = score + 100
            elseif info.level == "high" then score = score + 50
            elseif info.level == "medium" then score = score + 25
            else score = score + 10 end
        end
    end
    
    -- Check command line patterns
    local cmdline_lower = proc.cmdline:lower()
    for _, check in ipairs(SUSPICIOUS_CMDLINE_PATTERNS) do
        if cmdline_lower:find(check.pattern) then
            table.insert(threats, ThreatResult(
                check.level,
                "cmdline",
                check.desc .. ": " .. proc.cmdline:sub(1, 80),
                proc
            ))
            if check.level == "critical" then score = score + 100
            elseif check.level == "high" then score = score + 50
            elseif check.level == "medium" then score = score + 25
            else score = score + 10 end
        end
    end
    
    -- Check for root processes with network activity
    if proc.uid == 0 and (
        cmdline_lower:find("curl") or
        cmdline_lower:find("wget") or
        cmdline_lower:find("nc%s") or
        cmdline_lower:find("ncat")
    ) then
        table.insert(threats, ThreatResult(
            "high",
            "root_network",
            "Root process with network tool",
            proc
        ))
        score = score + 40
    end
    
    proc.threat_score = score
    return threats
end

--- Analyze all processes
local function analyze_all()
    local all_threats = {}
    local processes = get_processes()
    
    for _, proc in pairs(processes) do
        local threats = analyze_process(proc)
        for _, threat in ipairs(threats) do
            table.insert(all_threats, threat)
        end
    end
    
    -- Sort by severity
    local severity_order = { critical = 1, high = 2, medium = 3, low = 4, info = 5 }
    table.sort(all_threats, function(a, b)
        return (severity_order[a.level] or 5) < (severity_order[b.level] or 5)
    end)
    
    return all_threats, processes
end

-- =============================================================================
-- Monitoring with Coroutines
-- =============================================================================

--- Create a process monitor coroutine
local function create_monitor(interval, callback)
    return coroutine.create(function()
        local known_pids = {}
        
        while true do
            local current_processes = get_processes()
            local current_pids = {}
            
            -- Check for new processes
            for pid, proc in pairs(current_processes) do
                current_pids[pid] = true
                if not known_pids[pid] then
                    -- New process detected
                    local threats = analyze_process(proc)
                    if #threats > 0 or proc.threat_score > 0 then
                        callback("new_threat", proc, threats)
                    else
                        callback("new_process", proc, {})
                    end
                end
            end
            
            -- Check for terminated processes
            for pid, _ in pairs(known_pids) do
                if not current_pids[pid] then
                    callback("terminated", { pid = pid }, {})
                end
            end
            
            known_pids = current_pids
            coroutine.yield()
            
            -- Sleep between iterations
            os.execute("sleep " .. interval)
        end
    end)
end

-- =============================================================================
-- Output Formatting
-- =============================================================================

local COLORS = {
    reset = "\27[0m",
    red = "\27[31m",
    bright_red = "\27[91m",
    green = "\27[32m",
    yellow = "\27[33m",
    cyan = "\27[36m",
    gray = "\27[90m",
    bold = "\27[1m"
}

local function color(name)
    return COLORS[name] or ""
end

local function level_color(level)
    if level == "critical" then return color("bright_red")
    elseif level == "high" then return color("red")
    elseif level == "medium" then return color("yellow")
    elseif level == "low" then return color("cyan")
    else return color("green") end
end

local function print_banner()
    print([[

╔══════════════════════════════════════════════════════════════════╗
║            NullSec ProcMon - Process Monitor                     ║
╚══════════════════════════════════════════════════════════════════╝
]])
end

local function print_threat(threat)
    local c = level_color(threat.level)
    local r = color("reset")
    print(string.format("%s[%s]%s %s", 
        c, threat.level:upper(), r, threat.description))
    if threat.process then
        print(string.format("  PID: %d  Name: %s  UID: %d",
            threat.process.pid, threat.process.name, threat.process.uid))
        if threat.process.cmdline ~= "" then
            print(string.format("  %sCmdline: %s%s",
                color("gray"), threat.process.cmdline:sub(1, 100), r))
        end
    end
    print()
end

local function print_summary(threats, processes)
    local counts = { critical = 0, high = 0, medium = 0, low = 0 }
    for _, t in ipairs(threats) do
        counts[t.level] = (counts[t.level] or 0) + 1
    end
    
    local proc_count = 0
    for _ in pairs(processes) do proc_count = proc_count + 1 end
    
    print(string.rep("─", 70))
    print(string.format([[

SUMMARY
  Processes scanned:  %d
  Threats detected:   %d

  %sCritical:%s  %d
  %sHigh:%s      %d
  %sMedium:%s    %d
  %sLow:%s       %d
]],
        proc_count, #threats,
        color("bright_red"), color("reset"), counts.critical,
        color("red"), color("reset"), counts.high,
        color("yellow"), color("reset"), counts.medium,
        color("cyan"), color("reset"), counts.low
    ))
end

local function print_json(threats)
    print("{")
    print('  "threats": [')
    for i, t in ipairs(threats) do
        local comma = i < #threats and "," or ""
        print(string.format(
            '    {"level":"%s","category":"%s","pid":%d,"name":"%s"}%s',
            t.level, t.category,
            t.process and t.process.pid or 0,
            t.process and t.process.name or "",
            comma
        ))
    end
    print("  ]")
    print("}")
end

-- =============================================================================
-- CLI
-- =============================================================================

local function print_help()
    print([[

╔══════════════════════════════════════════════════════════════════╗
║            NullSec ProcMon - Process Monitor                     ║
╚══════════════════════════════════════════════════════════════════╝

USAGE:
    procmon [OPTIONS]

OPTIONS:
    -h, --help      Show this help
    -s, --scan      One-time scan (default)
    -m, --monitor   Continuous monitoring
    -j, --json      Output as JSON
    -q, --quiet     Only show threats

EXAMPLES:
    procmon                 One-time process scan
    procmon --monitor       Continuous monitoring
    procmon --json          JSON output
    procmon -q              Quiet mode (threats only)

]])
end

local function main(args)
    local mode = "scan"
    local json_output = false
    local quiet = false
    
    -- Parse arguments
    local i = 1
    while i <= #args do
        local arg = args[i]
        if arg == "-h" or arg == "--help" then
            print_help()
            return 0
        elseif arg == "-s" or arg == "--scan" then
            mode = "scan"
        elseif arg == "-m" or arg == "--monitor" then
            mode = "monitor"
        elseif arg == "-j" or arg == "--json" then
            json_output = true
        elseif arg == "-q" or arg == "--quiet" then
            quiet = true
        end
        i = i + 1
    end
    
    if mode == "scan" then
        if not json_output and not quiet then
            print_banner()
            print("Scanning processes...\n")
        end
        
        local threats, processes = analyze_all()
        
        if json_output then
            print_json(threats)
        else
            for _, threat in ipairs(threats) do
                print_threat(threat)
            end
            print_summary(threats, processes)
        end
        
        return #threats > 0 and (threats[1].level == "critical" and 2 or 1) or 0
        
    elseif mode == "monitor" then
        if not quiet then
            print_banner()
            print("Starting continuous monitoring... (Ctrl+C to stop)\n")
        end
        
        local monitor = create_monitor(2, function(event, proc, threats)
            if event == "new_threat" then
                for _, threat in ipairs(threats) do
                    print_threat(threat)
                end
            elseif event == "new_process" and not quiet then
                print(string.format("%s[NEW]%s %s",
                    color("green"), color("reset"), tostring(proc)))
            end
        end)
        
        -- Run monitor loop
        while coroutine.status(monitor) ~= "dead" do
            local ok, err = coroutine.resume(monitor)
            if not ok then
                io.stderr:write("Monitor error: " .. tostring(err) .. "\n")
                break
            end
        end
    end
    
    return 0
end

-- Run if executed directly
if arg then
    os.exit(main(arg))
end

return {
    Process = Process,
    analyze_process = analyze_process,
    analyze_all = analyze_all,
    get_processes = get_processes,
    create_monitor = create_monitor,
    VERSION = VERSION
}
