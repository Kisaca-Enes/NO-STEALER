Write-Host "===================================" -ForegroundColor Cyan
Write-Host "🛡️ NO-STEALER CORE ANALYZER w/ C2-INTEL" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Cyan

$ErrorActionPreference = "Stop"

# -------------------------
# ACTIVE PROCESS PYTHON STEALER STRING SCAN
# -------------------------

Write-Host "`n🔍 Aktif process'leri tarayıp şüpheli Python fonksiyonlarını kontrol ediyor..." -ForegroundColor Cyan

$bad = @(
"requests.post","requests.get","httpx.post","http.client","urllib.request",
"os.getenv","os.system","subprocess.call","subprocess.Popen","socket.socket",
"base64.b64decode","base64.b64encode","binascii.a2b_base64","binascii.b2a_base64",
"eval","exec","compile","marshal.loads","pickle.loads","builtins.__import__",
"getpass.getpass","input","open(","write(","read(","shutil.copyfile",
"zipfile.ZipFile","tempfile.gettempdir","tempfile.NamedTemporaryFile","os.remove",
"threading.Thread","multiprocessing.Process","platform.system","platform.node",
"ctypes.windll","ctypes.cdll","ctypes.WinDLL","win32api","win32gui","win32con",
"win32clipboard","winreg","win32com.client","WTSQuerySessionInformation",
"GetAsyncKeyState","SetWindowsHookEx","GetForegroundWindow","FindWindow","ShowWindow",
"pyautogui.screenshot","pyautogui.typewrite","pynput.keyboard","pynput.mouse",
"webbrowser.open","re.compile","email.mime","smtplib.SMTP","ftplib.FTP","dns.resolver",
"getmac.get_mac_address","requests.put","requests.delete","send_keys",
"clipboard.paste","clipboard.copy"
)

$processes = Get-Process | Where-Object {$_.Path -ne $null}
$all_results = @()

foreach ($proc in $processes) {
    $path = $proc.Path
    if (-not (Test-Path $path)) { continue }

    try { $content = Get-Content $path -Raw -ErrorAction Stop } catch { continue }

    $found = @()
    foreach ($b in $bad) {
        if ($content -match [regex]::Escape($b)) { $found += $b }
    }

    $hit_count   = $found.Count
    $total_bad   = $bad.Count
    $risk_percent = [math]::Min([math]::Round(($hit_count / $total_bad) * 100,2),99)

    $all_results += [PSCustomObject]@{
        process_name = $proc.ProcessName
        path         = $path
        pid          = $proc.Id
        hit_count    = $hit_count
        detected     = $found
        risk_percent = $risk_percent
    }
}

$outputPath = "$env:TEMP\active_process_analysis.json"
$all_results | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding utf8

Write-Host "`n📊 Python pattern analizi tamamlandı, JSON kaydedildi:" -ForegroundColor Green
Write-Host $outputPath

# ----------------------------
# LOAD FILES
# ----------------------------

$IOC = Get-Content ".\c2.txt"
$StealerDB = @()
Get-ChildItem ".\stealers" -Filter "*.json" | ForEach-Object {
    $StealerDB += (Get-Content $_.FullName -Raw | ConvertFrom-Json)
}

$Live = Get-Content ".\live_behavior.json" -Raw | ConvertFrom-Json
$Static = Get-Content ".\static_scan.json" -Raw | ConvertFrom-Json

# ----------------------------
# HELPER FUNCTIONS
# ----------------------------

function Match-C2IOC($Network){
    $hits = @()
    foreach($conn in $Network){
        foreach($ioc in $IOC){
            if($conn.remote -match [regex]::Escape($ioc)){ $hits += $ioc }
        }
    }
    return $hits
}

function Compare-Similarity($Process,$Stealer){
    $Score = 0
    $Matches = @()
    foreach($dom in $Stealer.behaviors.network_domains){
        if($Process.network -match $dom){ $Score += 5; $Matches += $dom }
    }
    foreach($dll in $Stealer.behaviors.dlls){
        if($Process.dlls -contains $dll){ $Score += 3; $Matches += $dll }
    }
    foreach($str in $Stealer.static_strings){
        if($Process.static.detected -contains $str){ $Score += 4; $Matches += $str }
    }
    return @{Score=$Score;Matches=$Matches}
}

function Get-RiskScore($Proc, $C2Matches){
    $Risk = 0
    if($C2Matches.Count -gt 0){ $Risk += 30 }
    if($Proc.network -match "telegram|discord"){ $Risk += 15 }
    if($Proc.files -match "Login Data|INetCookies"){ $Risk += 20 }
    if($Proc.static.hit_count -gt 0){ $Risk += ($Proc.static.hit_count * 10) }
    if($Proc.cmd -match "-enc|powershell|cmd"){ $Risk += 10 }
    return [Math]::Min($Risk,100)
}

# ----------------------------
# CORE ANALYSIS LOOP
# ----------------------------

$Results = @()
foreach($P in $Live){
    $staticHit = $Static | Where-Object {$_.path -eq $P.path}
    $P | Add-Member -Name "static" -Value $staticHit -MemberType NoteProperty -Force

    $c2Matches = Match-C2IOC $P.network
    $BestMatchScore = 0; $BestFamily = ""; $BestPatterns = @()

    foreach($S in $StealerDB){
        $sim = Compare-Similarity $P $S
        if($sim.Score -gt $BestMatchScore){
            $BestMatchScore = $sim.Score
            $BestFamily = $S.family
            $BestPatterns = $sim.Matches
        }
    }

    $risk = Get-RiskScore $P $c2Matches
    $final = [Math]::Round(($BestMatchScore*0.6)+($risk*0.4),2)

    $verdict = switch ($final) {
        {$_ -ge 65 -or $c2Matches.Count -gt 0} {"🛑 STEALER"}
        {$_ -ge 40} {"❗ HIGH RISK"}
        {$_ -ge 20} {"⚠️ SUSPICIOUS"}
        default {"✅ CLEAN"}
    }

    $Results += [PSCustomObject]@{
        process  = $P.path
        cmdline = $P.cmd
        family_guess = $BestFamily
        similarity_score = $BestMatchScore
        risk_score = $risk
        final_score = $final
        c2_hits = ($c2Matches -join ", ")
        matched_patterns = ($BestPatterns -join ", ")
        verdict = $verdict
    }
}

# ----------------------------
# SAVE OUTPUT
# ----------------------------

$outFile = ".\NO_STEALER_RESULT.json"
$Results | ConvertTo-Json -Depth 6 | Out-File $outFile -Encoding utf8

Write-Host "`n✅ ANALYSIS COMPLETED" -ForegroundColor Green
Write-Host "📄 Output: $outFile" -ForegroundColor Yellow

# -------------------------
# NO STEALER BEHAVIOR DUMP
# -------------------------

$results = @()
$wmiProcs = Get-CimInstance Win32_Process

Get-Process | ForEach-Object {
    $p = $_
    try {
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
            $item.children += @{ name = $c.Name; path = $c.ExecutablePath }
        }

        $item.network = @()
        try {
            Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction Stop | ForEach-Object {
                $item.network += @{ local = "$($_.LocalAddress):$($_.LocalPort)"; remote = "$($_.RemoteAddress):$($_.RemotePort)"; status = $_.State }
            }
        } catch {}

        $item.dlls = @()
        try { $p.Modules | ForEach-Object { $item.dlls += $_.FileName } } catch {}

        $item.files = @()
        $item.files += "[!] Windows API limitation - ProcMon needed for real file audit"

        $results += $item
    } catch {}
}

$outputPath = "$env:TEMP\no_stealer_dump.json"
$results | ConvertTo-Json -Depth 6 | Out-File $outputPath -Encoding UTF8

Write-Host "`n[+] NO-STEALER Behavior Snapshot Completed"
Write-Host "[+] JSON saved to: $outputPath"
