cls
Write-Host "==========================================="
Write-Host "           NO-STEALER FULL PIPELINE"
Write-Host "==========================================="

$ErrorActionPreference = "Stop"

# ------------------------------------------------
# PART 1 - LIVE BEHAVIOR SNAPSHOT
# ------------------------------------------------

Write-Host "`n[1] COLLECTING LIVE PROCESS SNAPSHOT..."

$results = @()
$wmiProcs = Get-CimInstance Win32_Process

Get-Process | ForEach-Object {

    try {

        $p = $_
        $item = [ordered]@{}

        $item.path = $p.Path

        $cmd = ($wmiProcs | Where-Object { $_.ProcessId -eq $p.Id }).CommandLine
        $item.cmd = if ($cmd) { $cmd } else { "" }

        $item.pid = $p.Id
        $item.ppid = ($wmiProcs | Where-Object { $_.ProcessId -eq $p.Id }).ParentProcessId

        try {
            $parent = Get-Process -Id $item.ppid -ErrorAction Stop
            $item.parent_name = $parent.ProcessName
            $item.parent_path = $parent.Path
        }
        catch {
            $item.parent_name = $null
            $item.parent_path = $null
        }

        $item.children = @()

        $childs = $wmiProcs | Where-Object { $_.ParentProcessId -eq $p.Id }
        foreach ($c in $childs) {
            $item.children += @{
                name = $c.Name
                path = $c.ExecutablePath
            }
        }

        $item.network = @()

        try {
            Get-NetTCPConnection -OwningProcess $p.Id |
            ForEach-Object {
                $item.network += @{
                    local  = "$($_.LocalAddress):$($_.LocalPort)"
                    remote = "$($_.RemoteAddress):$($_.RemotePort)"
                    status = $_.State
                }
            }
        }
        catch {}

        $item.dlls = @()

        try {
            $p.Modules | ForEach-Object {
                $item.dlls += $_.FileName
            }
        }
        catch {}

        $item.files = @("[!] Windows API handle limitation")

        $results += $item

    }
    catch {}
}

$liveOut = ".\live_behavior.json"
$results | ConvertTo-Json -Depth 6 | Out-File $liveOut -Encoding UTF8

Write-Host "[+] Saved: $liveOut"



# ------------------------------------------------
# PART 2 - STATIC PYTHON SCANNER
# ------------------------------------------------

Write-Host "`n[2] STATIC PYTHON STRING ANALYZER"

$file = Read-Host "Python file path"

if (-not (Test-Path $file)) {
    Write-Host "ERROR FILE NOT FOUND"
    exit
}

$bad = @(
 "requests.post","requests.get","httpx.post","urllib.request",
 "subprocess.call","subprocess.Popen","socket.socket",
 "base64.b64encode","eval","exec","marshal.loads","pickle.loads",
 "ctypes.windll","ctypes.WinDLL","win32api","win32clipboard","winreg",
 "GetAsyncKeyState","SetWindowsHookEx",
 "pyautogui.screenshot","pynput.keyboard",
 "discord.com/api","discordapp.com/api","token=","webhook",
 "schtasks","taskkill","powershell -enc","cmd.exe",
 "curl","wget","whoami","netstat","ipconfig"
)

$content = Get-Content $file -Raw

$found = @()
foreach ($b in $bad) {
    if ($content -match [regex]::Escape($b)) {
        $found += $b
    }
}

$total = $bad.Count
$hits  = $found.Count
$risk  = [math]::Min([math]::Round(($hits / $total) * 100,2),99)

$result = @{
    target_file = $file
    analyzed_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    total_strings = $total
    hit_count = $hits
    detected = $found
    risk_percent = $risk
}

$staticOut = ".\static_scan.json"
$result | ConvertTo-Json -Depth 4 | Out-File $staticOut

Write-Host "[+] Static results saved: $staticOut"



# ------------------------------------------------
# PART 3 - IOC LOADER
# ------------------------------------------------

Write-Host "`n[3] Loading IOC C2 list..."

if (!(Test-Path ".\c2.txt")) {
    Write-Host "ERROR: Missing c2.txt"
    exit
}

$IOC = Get-Content ".\c2.txt"



# ------------------------------------------------
# PART 4 - STEALER BEHAVIOR DB
# ------------------------------------------------

Write-Host "`n[4] Loading Stealer DB..."

$StealerDB = @()

if (Test-Path ".\stealers") {

    Get-ChildItem ".\stealers" -Filter "*.json" |
    ForEach-Object {
        $StealerDB += (Get-Content $_.FullName -Raw | ConvertFrom-Json)
    }

}
else {
    Write-Host "[!] No stealer DB folder found."
}



# ------------------------------------------------
# PART 5 - CORE ANALYZER
# ------------------------------------------------

function Match-C2IOC($Network) {

    $hits = @()

    foreach ($conn in $Network) {
        foreach ($ioc in $IOC) {
            if ($conn.remote -match [regex]::Escape($ioc)) {
                $hits += $ioc
            }
        }
    }

    return $hits
}

function Compare-Similarity($Process,$Stealer) {

    $Score   = 0
    $Matches = @()

    foreach ($dom in $Stealer.behaviors.network_domains) {
        if ($Process.network -match $dom) {
            $Score += 5
            $Matches += $dom
        }
    }

    foreach ($dll in $Stealer.behaviors.dlls) {
        if ($Process.dlls -contains $dll) {
            $Score += 3
            $Matches += $dll
        }
    }

    foreach ($str in $Stealer.static_strings) {
        if ($Process.static.detected -contains $str) {
            $Score += 4
            $Matches += $str
        }
    }

    return @{
        Score   = $Score
        Matches = $Matches
    }
}

function Get-RiskScore($Proc,$C2Matches) {

    $Risk = 0

    if ($C2Matches.Count -gt 0) { $Risk += 30 }
    if ($Proc.network -match "telegram|discord") { $Risk += 15 }
    if ($Proc.files -match "Login Data|INetCookies") { $Risk += 20 }

    if ($Proc.static.hit_count -gt 0) {
        $Risk += ($Proc.static.hit_count * 10)
    }

    if ($Proc.cmd -match "-enc|powershell|cmd") {
        $Risk += 10
    }

    return [Math]::Min($Risk,100)
}



# ------------------------------------------------
# PART 6 - FINAL CORRELATION
# ------------------------------------------------

Write-Host "`n[5] Performing correlation analysis..."

$Live    = Get-Content $liveOut   -Raw | ConvertFrom-Json
$Static  = Get-Content $staticOut -Raw | ConvertFrom-Json

foreach ($P in $Live) {
    $P | Add-Member -Name "static" -Value $Static -MemberType NoteProperty -Force
}

$Results = @()

foreach ($P in $Live) {

    $BestMatchScore = 0
    $BestFamily     = ""
    $BestPatterns   = @()

    $c2Matches = Match-C2IOC $P.network

    foreach ($S in $StealerDB) {

        $sim = Compare-Similarity $P $S

        if ($sim.Score -gt $BestMatchScore) {
            $BestMatchScore = $sim.Score
            $BestFamily     = $S.family
            $BestPatterns   = $sim.Matches
        }
    }

    $risk  = Get-RiskScore $P $c2Matches
    $final = [Math]::Round(($BestMatchScore * 0.6) + ($risk * 0.4),2)

    $verdict = switch ($final) {
        {$_ -ge 65 -or $c2Matches.Count -gt 0} { "STEALER" }
        {$_ -ge 40}                            { "HIGH RISK" }
        {$_ -ge 20}                            { "SUSPICIOUS" }
        default                                { "CLEAN" }
    }

    $Results += [PSCustomObject]@{
        process         = $P.path
        cmdline         = $P.cmd
        family_guess   = $BestFamily
        similarity     = $BestMatchScore
        risk_score     = $risk
        final_score    = $final
        c2_hits        = ($c2Matches -join ", ")
        matched_rules  = ($BestPatterns -join ", ")
        verdict        = $verdict
    }
}



# ------------------------------------------------
# PART 7 - SAVE FINAL REPORT
# ------------------------------------------------

$outFile = ".\NO_STEALER_RESULT.json"
$Results | ConvertTo-Json -Depth 6 | Out-File $outFile -Encoding UTF8

Write-Host "`n==========================================="
Write-Host "ANALYSIS COMPLETED"
Write-Host "Final report: $outFile"
Write-Host "==========================================="
