Write-Host "`n🔍 Aktif process'leri tarayıp şüpheli Python fonksiyonlarını kontrol ediyor..." -ForegroundColor Cyan

# Şüpheli fonksiyonlar / stringler
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

# Tüm aktif process'leri al
$processes = Get-Process | Where-Object {$_.Path -ne $null}

$all_results = @()

foreach ($proc in $processes) {
    $path = $proc.Path
    if (-not (Test-Path $path)) { continue }

    try {
        $content = Get-Content $path -Raw -ErrorAction Stop
    } catch {
        continue
    }

    $found = @()
    foreach ($b in $bad) {
        if ($content -match [regex]::Escape($b)) {
            $found += $b
        }
    }

    $hit_count = $found.Count
    $total_bad = $bad.Count
    $risk_percent = [math]::Min([math]::Round(($hit_count / $total_bad) * 100,2),99)

    $all_results += @{
        process_name  = $proc.ProcessName
        path          = $path
        pid           = $proc.Id
        hit_count     = $hit_count
        detected      = $found
        risk_percent  = $risk_percent
    }
}

$outputPath = "$env:TEMP\active_process_analysis.json"
$all_results | ConvertTo-Json -Depth 5 | Out-File $outputPath -Encoding utf8

Write-Host "`n📊 Analiz tamamlandı, JSON kaydedildi:" -ForegroundColor Green
Write-Host $outputPath
