<#
.SYNOPSIS
Runs verbose traceroute diagnostics against one or more hosts.

.DESCRIPTION
Designed for Microsoft Defender for Endpoint Live Response RunScript usage.
Accepts a comma-separated host list and prints detailed output per host:
- DNS resolution details (when available)
- Raw tracert output
- Test-NetConnection detailed trace data (when available)

.PARAMETER HostsCsv
Comma-separated hosts to trace (for example: "8.8.8.8,1.1.1.1,example.com").

.PARAMETER MaxHops
Maximum number of hops for tracert.

.PARAMETER TimeoutMs
Per-hop timeout in milliseconds for tracert.

.PARAMETER NoDnsLookup
Disables DNS lookups during tracert by passing -d.

.EXAMPLE
.\Invoke-VerboseTraceroute.ps1 -HostsCsv "8.8.8.8,1.1.1.1,example.com"

.EXAMPLE
.\Invoke-VerboseTraceroute.ps1 "8.8.8.8,1.1.1.1"
#>
param(
    [Parameter(Position = 0)]
    [string]$HostsCsv = "",

    [int]$MaxHops = 30,

    [int]$TimeoutMs = 4000,

    [switch]$NoDnsLookup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($HostsCsv) -and $args.Count -gt 0) {
    $HostsCsv = ($args -join " ")
}

$targets = @($HostsCsv -split "[,;\s]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

if ($targets.Count -eq 0) {
    Write-Output "No valid hosts were provided."
    Write-Output "Pass -HostsCsv `"host1,host2,host3`"."
    exit 2
}

Write-Output "=== Verbose Traceroute Run ==="
Write-Output ("Start UTC: {0:o}" -f (Get-Date).ToUniversalTime())
Write-Output ("ComputerName: {0}" -f $env:COMPUTERNAME)
Write-Output ("User: {0}" -f [Environment]::UserName)
Write-Output ("Targets ({0}): {1}" -f $targets.Count, ($targets -join ", "))
Write-Output ("MaxHops: {0}" -f $MaxHops)
Write-Output ("TimeoutMs: {0}" -f $TimeoutMs)
Write-Output ("NoDnsLookup: {0}" -f [bool]$NoDnsLookup)

$failedTargets = New-Object System.Collections.Generic.List[string]

foreach ($target in $targets) {
    Write-Output ""
    Write-Output "=================================================================="
    Write-Output ("Target: {0}" -f $target)
    Write-Output ("Timestamp UTC: {0:o}" -f (Get-Date).ToUniversalTime())

    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        Write-Output "[DNS Resolution]"
        try {
            $dns = Resolve-DnsName -Name $target -Type A,AAAA -ErrorAction Stop
            $dns | Format-Table -AutoSize | Out-String -Width 4096 | Write-Output
        }
        catch {
            Write-Output ("DNS resolution failed: {0}" -f $_.Exception.Message)
        }
    }
    else {
        Write-Output "Resolve-DnsName is not available on this host."
    }

    Write-Output "[tracert]"
    $tracertArgs = @("-h", $MaxHops, "-w", $TimeoutMs)
    if ($NoDnsLookup) {
        $tracertArgs += "-d"
    }
    $tracertArgs += $target
    Write-Output ("Command: tracert.exe {0}" -f ($tracertArgs -join " "))

    try {
        $tracertOutput = & tracert.exe @tracertArgs 2>&1
        $tracertExit = $LASTEXITCODE
        $tracertOutput | ForEach-Object { Write-Output $_ }
        Write-Output ("tracert exit code: {0}" -f $tracertExit)
        if ($tracertExit -ne 0) {
            $failedTargets.Add($target)
        }
    }
    catch {
        Write-Output ("tracert execution failed: {0}" -f $_.Exception.Message)
        $failedTargets.Add($target)
        continue
    }

    if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
        Write-Output "[Test-NetConnection -TraceRoute -InformationLevel Detailed]"
        try {
            $tnc = Test-NetConnection -ComputerName $target -TraceRoute -InformationLevel Detailed -WarningAction SilentlyContinue
            $tnc | Format-List * | Out-String -Width 4096 | Write-Output
        }
        catch {
            Write-Output ("Test-NetConnection failed: {0}" -f $_.Exception.Message)
        }
    }
    else {
        Write-Output "Test-NetConnection is not available on this host."
    }
}

Write-Output ""
Write-Output "=== Run Complete ==="
Write-Output ("End UTC: {0:o}" -f (Get-Date).ToUniversalTime())

if ($failedTargets.Count -gt 0) {
    Write-Output ("Failed targets: {0}" -f ($failedTargets -join ", "))
    exit 1
}

Write-Output "All targets completed without tracert execution errors."
exit 0
