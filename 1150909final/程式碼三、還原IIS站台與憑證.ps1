<#
.SYNOPSIS
    一鍵還原指定 IIS 站台繫結與舊憑證 (純 DPAPI 密文解密與站台精確過濾版)
#>

Add-Type -AssemblyName System.Security

function Write-RollbackLog([string]$msg, [string]$level = "INFO") {
    if (Get-Command Append-Log -ErrorAction SilentlyContinue) {
        Append-Log $msg $level
    } else {
        $color = switch ($level) {
            "FAIL"   { "Red" }
            "ACTION" { "Yellow" }
            "WARN"   { "DarkYellow" }
            "PASS"   { "Green" }
            "CHECK"  { "Cyan" }
            "RUN"    { "Magenta" }
            Default  { "White" }
        }
        Write-Host "[$level] $msg" -ForegroundColor $color
    }
}

function Unprotect-SecretDPAPI([string]$base64Cipher) {
    if ([string]::IsNullOrWhiteSpace($base64Cipher)) { return $null }
    try {
        $cipherBytes = [System.Convert]::FromBase64String($base64Cipher)
        $entropy = [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($cipherBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch {
        return $null
    }
}

$backupDir = "$env:ProgramData\IIS-Cert-Backup"

if (-not (Test-Path $backupDir)) {
    Write-RollbackLog "找不到任何備份目錄 ($backupDir)。" "FAIL"
    return
}

# 取得目標站台名稱 (由主控台選取帶入)
$targetSiteName = $Global:SelectedSiteInfo

if ([string]::IsNullOrWhiteSpace($targetSiteName)) {
    Write-RollbackLog "還原失敗: 未指定目標站台名稱，請先由主介面下拉選單選取正確的站台！" "FAIL"
    return
}

Write-RollbackLog "正在搜尋站台 [$targetSiteName] 的歷史備份快照..." "INFO"

# 依檔名模式篩選屬於該站台的手動備份或部署前自動備份
$candidateFiles = Get-ChildItem -Path $backupDir -Filter "*.json" | Where-Object {
    $_.Name -like "ManualBackup_${targetSiteName}_*.json" -or $_.Name -like "Backup_${targetSiteName}_*.json"
} | Sort-Object LastWriteTime -Descending

$selectedBackup = $null

# 深入讀取 JSON 進行站台名稱精準核對，防止站台名稱包含特殊字元或檔名衝突
foreach ($f in $candidateFiles) {
    try {
        $raw = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($raw.SiteName -eq $targetSiteName) {
            $selectedBackup = $f
            break
        }
    } catch {}
}

if (-not $selectedBackup) {
    Write-RollbackLog "在備份目錄中未找到站台 [$targetSiteName] 的任何專屬快照檔案！" "FAIL"
    Write-RollbackLog ">> 操作建議: 請確認該站台先前是否曾執行過「3. 手動快照備份」或「4. 建立自動排程」。" "ACTION"
    return
}

$data = Get-Content $selectedBackup.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$siteName = $data.SiteName

Write-RollbackLog "已找到該站台最新快照檔案: $($selectedBackup.Name)" "INFO"
Write-RollbackLog "即將將站台 [$siteName] 回復至快照時間: [$($data.BackupTime)]..." "RUN"

try {
    if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
        Write-RollbackLog "找不到 WebAdministration 模組，無法套用 IIS 站台還原。" "FAIL"
        return
    }

    Import-Module WebAdministration -ErrorAction Stop
    $targetSite = Get-Website -Name $siteName
    if (-not $targetSite) {
        Write-RollbackLog "本機 IIS 找不到站台 [$siteName]，無法套用繫結還原。" "FAIL"
        return
    }

    Write-RollbackLog "[1/2] 正在清除站台 [$siteName] 目前的繫結..." "INFO"
    $currentBindings = Get-WebBinding -Name $siteName
    foreach ($cb in $currentBindings) {
        Remove-WebBinding -Name $siteName -BindingInformation $cb.bindingInformation -Protocol $cb.protocol -ErrorAction SilentlyContinue
    }

    Write-RollbackLog "[2/2] 正在依據快照重建 [$siteName] 的原始繫結與 SSL 憑證..." "INFO"
    foreach ($b in $data.Bindings) {
        $ip = if ([string]::IsNullOrWhiteSpace($b.IPAddress) -or $b.IPAddress -eq "*") { "*" } else { $b.IPAddress }
        $hostHdr = if ($null -eq $b.HostHeader) { "" } else { $b.HostHeader }

        New-WebBinding -Name $siteName -IPAddress $ip -Port $b.Port -Protocol $b.Protocol -HostHeader $hostHdr -ErrorAction SilentlyContinue

        if ($b.Protocol -eq "https" -and (-not [string]::IsNullOrWhiteSpace($b.CertificateThumbprint))) {
            $store = if ([string]::IsNullOrWhiteSpace($b.CertificateStore)) { "My" } else { $b.CertificateStore }
            
            $existing = Get-Item "Cert:\LocalMachine\$store\$($b.CertificateThumbprint)" -ErrorAction SilentlyContinue
            if (-not $existing -and (![string]::IsNullOrWhiteSpace($b.PfxFile)) -and (Test-Path $b.PfxFile)) {
                $pwdSecret = Unprotect-SecretDPAPI $data.EncryptedPfxSecret

                if ([string]::IsNullOrWhiteSpace($pwdSecret)) {
                    Write-RollbackLog "資安防護阻斷: 無法解密快照 PFX 金鑰 (DPAPI 解密失敗或金鑰不存在)，終止匯入以防止未授權操作！" "FAIL"
                    return
                }

                $pwd = ConvertTo-SecureString -String $pwdSecret -Force -AsPlainText
                Import-PfxCertificate -FilePath $b.PfxFile -CertStoreLocation "Cert:\LocalMachine\$store" -Password $pwd | Out-Null
                Write-RollbackLog "已透過 DPAPI 還原憑證至 Cert:\LocalMachine\$store" "PASS"
            }

            $targetBinding = Get-WebBinding -Name $siteName -Port $b.Port -Protocol "https" | Where-Object {
                ($_.bindingInformation -split ':')[2] -eq $hostHdr
            }
            if ($targetBinding) {
                $targetBinding.AddSslCertificate($b.CertificateThumbprint, $store)
                if ($b.SslFlags) { $targetBinding.sslFlags = $b.SslFlags }
                Write-RollbackLog "已成功繫結 HTTPS 憑證 [指紋: $($b.CertificateThumbprint)]" "PASS"
            }
        }
    }

    Write-RollbackLog "==================================================================" "PASS"
    Write-RollbackLog "站台 [$siteName] 狀態與 SSL 憑證已全數還原成功！" "PASS"
    Write-RollbackLog "==================================================================" "PASS"
} catch {
    Write-RollbackLog "還原過程發生例外: $_" "FAIL"
}