# ==============================================================================
# [GSN 政府網路 Proxy 代理伺服器全域設定區塊]
# ==============================================================================
# $Global:GsnProxyServer = "http://proxy.gsn.gov.tw:3128"
# [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($Global:GsnProxyServer, $true)
# [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
# ==============================================================================

<#
.SYNOPSIS
    自動化透過 win-acme + Cloudflare DNS-01 申請 IIS 憑證並無縫併入排程
    (跨 Zone CNAME 委派安全驗證、外掛設定檔即用即刪、命令列零 Token 脫敏與純 DPAPI 安全防護版)
#>

# ==============================================================================
# [跨 Zone 權限隔離架構設定區塊]
# 若此處留空，可在封裝編譯時由 ps2exe 注入；亦可直接於此處填寫預設值。
# ==============================================================================
$ValidationZoneToken = ""                         # 驗證區專用 Token (僅具備驗證 Zone 之 DNS:Edit 權限)
$ValidationSubdomain = ""                         # 委派驗證子網域 (例: acme.teipei.gov.tw，若無 CNAME 委派請留空)
$ValidationZoneId    = ""                         # 驗證區 Zone ID (選填)
# ==============================================================================

Add-Type -AssemblyName System.Security
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# 優先解混淆取得編譯時注入之「驗證區專用 Token」與相關設定 (若注入為空則保留原變數值)
if ($Global:Embedded_Token -and $Global:Embedded_Key) {
    function Deobfuscate-MemoryString([string]$Cipher, [string]$Key) {
        if ([string]::IsNullOrWhiteSpace($Cipher)) { return "" }
        try {
            $cBytes = [System.Convert]::FromBase64String($Cipher)
            $kBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
            $outBytes = New-Object byte[] $cBytes.Length
            for ($i = 0; $i -lt $cBytes.Length; $i++) {
                $outBytes[$i] = $cBytes[$i] -bxor $kBytes[$i % $kBytes.Length]
            }
            return [System.Text.Encoding]::UTF8.GetString($outBytes)
        } catch { return "" }
    }
    $injectedToken     = Deobfuscate-MemoryString -Cipher $Global:Embedded_Token -Key $Global:Embedded_Key
    $injectedSubdomain = Deobfuscate-MemoryString -Cipher $Global:Embedded_ValidationZone -Key $Global:Embedded_Key
    $injectedZoneId    = Deobfuscate-MemoryString -Cipher $Global:Embedded_Zone -Key $Global:Embedded_Key

    if (-not [string]::IsNullOrWhiteSpace($injectedToken))     { $ValidationZoneToken = $injectedToken }
    if (-not [string]::IsNullOrWhiteSpace($injectedSubdomain)) { $ValidationSubdomain = $injectedSubdomain }
    if (-not [string]::IsNullOrWhiteSpace($injectedZoneId))    { $ValidationZoneId = $injectedZoneId }
}

$WacsPath = "C:\tools\win-acme\wacs.exe"
# 保留 60 秒緩衝：跳過本機 DNS 預檢後，此 60 秒是給 Cloudflare 公網 Anycast NS 同步的關鍵安全期
$DnsSleepSeconds = 60
$RenewalDays = 30
$MaxRetryAttempts = 3
$RetryCooldownSeconds = 20

$ContactEmail = if (-not [string]::IsNullOrWhiteSpace($Global:SelectedContactEmail)) {
    $Global:SelectedContactEmail
} else {
    $null
}

$isSuccess = $false
$global:backupFilePath = $null
$global:targetSiteName = $null
$global:dynamicBackupPassword = $null

$deployLockDir      = "$env:ProgramData\win-acme"
$deployLockFile     = Join-Path $deployLockDir ".deployment_completed.lock"
$cfConfigDir        = Join-Path $deployLockDir "CloudflarePlugin"
$cfDpapiFile        = Join-Path $cfConfigDir "cloudflare.dpapi"
$cfPluginConfigFile = Join-Path $cfConfigDir "cloudflare.json"

function Write-DeployLog([string]$msg, [string]$level = "INFO") {
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

function Write-Fault([string]$Layer, [string]$RootCause, [string]$Action) {
    Write-DeployLog "重大異常中斷 [$Layer]: $RootCause" "FAIL"
    Write-DeployLog ">> 操作建議: $Action" "ACTION"
}

# 存取控制 (ACL)：阻斷繼承，設定僅限 SYSTEM 與 Administrators 具備完整存取權限
function Set-SecureDirectoryAcl {
    param ([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
    Set-Acl -LiteralPath $Path $acl
}

function Protect-SecretDPAPI([string]$plainText) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)
    $entropy = [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Convert]::ToBase64String($encrypted)
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

# 動態輸出外掛專用設定檔 (僅於呼叫前釋放，受 ACL 鎖定保護)
function Export-TemporaryCloudflareConfig {
    param (
        [string]$ConfigDir,
        [string]$ConfigFile,
        [string]$Token
    )
    Set-SecureDirectoryAcl -Path $ConfigDir
    $jsonObj = [PSCustomObject]@{
        ApiToken = $Token
    }
    $jsonContent = $jsonObj | ConvertTo-Json -Depth 2
    [System.IO.File]::WriteAllText($ConfigFile, $jsonContent, [System.Text.Encoding]::UTF8)
    Write-DeployLog "已建立外掛暫存設定檔 ($ConfigFile)，權限僅限 SYSTEM/Administrators。" "PASS"
}

# 安全清理暫存設定檔 (覆寫後清除)
function Remove-TemporaryCloudflareConfig {
    param ([string]$ConfigFile)
    if (Test-Path -LiteralPath $ConfigFile) {
        try {
            [System.IO.File]::WriteAllText($ConfigFile, "{}", [System.Text.Encoding]::UTF8)
            Remove-Item -LiteralPath $ConfigFile -Force -ErrorAction SilentlyContinue
            Write-DeployLog "已安全刪除外掛暫存設定檔 ($ConfigFile)，磁碟不留明文憑據。" "PASS"
        } catch {
            Write-DeployLog "清理外掛設定檔時發生警告: $_" "WARN"
        }
    }
}

function Rotate-BackupsInternal {
    $backupDir = "$env:ProgramData\IIS-Cert-Backup"
    if (Test-Path $backupDir) {
        $jsonFiles = Get-ChildItem -Path $backupDir -Filter "*.json" | Sort-Object LastWriteTime -Descending
        if ($jsonFiles.Count -gt 10) {
            $filesToRemove = $jsonFiles | Select-Object -Skip 10
            foreach ($f in $filesToRemove) {
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($f.FullName)
                $matchingPfx = Join-Path $backupDir "$baseName.pfx"
                Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
                if (Test-Path $matchingPfx) {
                    Remove-Item $matchingPfx -Force -ErrorAction SilentlyContinue
                }
            }
            Write-DeployLog "已清理舊快照，保留最新 10 份安全備份。" "INFO"
        }
    }
}

function Ensure-WacsBypassPrecheck {
    $targetDir = Split-Path -Parent $WacsPath
    $targetFiles = @(
        Join-Path $targetDir "settings.json",
        Join-Path $targetDir "settings_default.json"
    )

    foreach ($file in $targetFiles) {
        if (Test-Path $file) {
            try {
                $jsonContent = Get-Content -Path $file -Raw -Encoding UTF8 | ConvertFrom-Json
                $modified = $false

                if ($jsonContent.Validation -and $jsonContent.Validation.PreValidateDns -ne $false) {
                    $jsonContent.Validation.PreValidateDns = $false
                    $modified = $true
                }

                if ($jsonContent.ScheduledTask -and $jsonContent.ScheduledTask.RenewalDays -ne $RenewalDays) {
                    $jsonContent.ScheduledTask.RenewalDays = $RenewalDays
                    $modified = $true
                }

                if ($modified) {
                    $jsonContent | ConvertTo-Json -Depth 15 | Set-Content -Path $file -Encoding UTF8
                    Write-DeployLog "已確認 $([System.IO.Path]::GetFileName($file)) 關閉 DNS 預檢 (PreValidateDns: false)。" "PASS"
                }
            } catch {}
        }
    }
}

function Complete-SecurityLockAndPurge {
    try {
        Set-SecureDirectoryAcl -Path $deployLockDir
        
        $lockInfo = [PSCustomObject]@{
            DeployedAt          = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            MachineName         = $env:COMPUTERNAME
            SiteName            = $global:targetSiteName
            ContactEmail        = $ContactEmail
            ValidationSubdomain = $ValidationSubdomain
            Status              = "Completed"
            TaskSchedule        = "Configured"
        } | ConvertTo-Json
        Set-Content -Path $deployLockFile -Value $lockInfo -Encoding UTF8 -Force
        Write-DeployLog "一次性部署標記已鎖定 (%ProgramData%\win-acme\.deployment_completed.lock)。" "PASS"
        Write-DeployLog "控制台部署入口已鎖定防呆，主程式保持完整供日常維運監控。" "PASS"
    } catch {
        Write-DeployLog "鎖定程序執行發生例外: $_" "WARN"
    }
}

function Backup-IISSiteState {
    param ([string]$SiteName)
    try {
        $backupDir = "$env:ProgramData\IIS-Cert-Backup"
        Set-SecureDirectoryAcl -Path $backupDir

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $backupDir "Backup_${SiteName}_${timestamp}.json"
        $pfxBackupFile = Join-Path $backupDir "Backup_${SiteName}_${timestamp}.pfx"

        $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        $sb = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt 32; $i++) {
            $sb.Append($charSet[$bytes[$i] % $charSet.Length]) | Out-Null
        }
        $global:dynamicBackupPassword = $sb.ToString()

        $site = Get-Website -Name $SiteName
        if (-not $site) { return $null }

        $bindings = Get-WebBinding -Name $SiteName
        $bindingList = @()
        $hasExportedPfx = $false

        foreach ($b in $bindings) {
            $rawCertHash = if ($b.protocol -eq "https") { $b.certificateHash } else { $null }
            $certStore   = if ($b.protocol -eq "https") { $b.certificateStoreName } else { $null }
            $sslFlags    = if ($b.protocol -eq "https") { $b.sslFlags } else { 0 }
            $thumbprint  = ""

            if ($rawCertHash) {
                if ($rawCertHash -is [byte[]]) {
                    $thumbprint = [System.BitConverter]::ToString($rawCertHash) -replace '-'
                } elseif ($rawCertHash -is [string]) {
                    $thumbprint = $rawCertHash -replace '[-:]'
                } else {
                    $thumbprint = ""
                }

                if (-not $hasExportedPfx) {
                    $cert = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
                    if ($cert -and $cert.HasPrivateKey) {
                        try {
                            $securePwd = ConvertTo-SecureString -String $global:dynamicBackupPassword -Force -AsPlainText
                            Export-PfxCertificate -Cert $cert -FilePath $pfxBackupFile -Password $securePwd | Out-Null
                            $hasExportedPfx = $true
                        } catch {}
                    }
                }
            }

            $bindingList += [PSCustomObject]@{
                Protocol               = $b.protocol
                BindingInformation    = $b.bindingInformation
                HostHeader            = ($b.bindingInformation -split ':')[2]
                Port                  = ($b.bindingInformation -split ':')[1]
                IPAddress             = ($b.bindingInformation -split ':')[0]
                CertificateThumbprint = $thumbprint
                CertificateStore      = $certStore
                SslFlags              = $sslFlags
                PfxFile               = if ($hasExportedPfx) { $pfxBackupFile } else { "" }
            }
        }

        $encryptedSecret = if ($hasExportedPfx) { Protect-SecretDPAPI $global:dynamicBackupPassword } else { "" }

        $snapshot = [PSCustomObject]@{
            SiteName              = $SiteName
            SiteId                = $site.id
            BackupTime            = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            EncryptedPfxSecret    = $encryptedSecret
            Bindings              = $bindingList
        }

        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8
        Write-DeployLog "站台 [$SiteName] 部署前原子快照建立成功 (DPAPI 密碼防護)！" "PASS"

        Rotate-BackupsInternal
        return $backupFile
    } catch {
        Write-Fault "備份機制異常" $_.Exception.Message "無法建立安全備份快照，終止部署程序。"
        return $null
    }
}

function Invoke-IISRestore {
    param ([string]$BackupPath)
    if (-not (Test-Path $BackupPath)) {
        Write-DeployLog "找不到快照檔案，無法執行自動復原。" "FAIL"
        return
    }

    try {
        Write-DeployLog "正在執行不可分割之安全復原 (Rollback)..." "WARN"
        $data = Get-Content $BackupPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $siteName = $data.SiteName

        Import-Module WebAdministration
        $currentBindings = Get-WebBinding -Name $siteName
        foreach ($cb in $currentBindings) {
            Remove-WebBinding -Name $siteName -BindingInformation $cb.bindingInformation -Protocol $cb.protocol -ErrorAction SilentlyContinue
        }

        foreach ($b in $data.Bindings) {
            $ip = if ([string]::IsNullOrWhiteSpace($b.IPAddress) -or $b.IPAddress -eq "*") { "*" } else { $b.IPAddress }
            $hostHdr = if ($null -eq $b.HostHeader) { "" } else { $b.HostHeader }

            New-WebBinding -Name $siteName -IPAddress $ip -Port $b.Port -Protocol $b.Protocol -HostHeader $hostHdr -ErrorAction SilentlyContinue

            if ($b.Protocol -eq "https" -and (-not [string]::IsNullOrWhiteSpace($b.CertificateThumbprint))) {
                $store = if ([string]::IsNullOrWhiteSpace($b.CertificateStore)) { "My" } else { $b.CertificateStore }
                
                $existingCert = Get-Item "Cert:\LocalMachine\$store\$($b.CertificateThumbprint)" -ErrorAction SilentlyContinue
                if (-not $existingCert -and (Test-Path $b.PfxFile)) {
                    $resolvedPwd = Unprotect-SecretDPAPI $data.EncryptedPfxSecret

                    if ([string]::IsNullOrWhiteSpace($resolvedPwd)) {
                        Write-Fault "安全還原攔截" "無法解密 PFX 金鑰 (DPAPI 解密失敗或金鑰不存在)" "終止匯入舊憑證。"
                        return
                    }

                    $secPwd = ConvertTo-SecureString -String $resolvedPwd -Force -AsPlainText
                    Import-PfxCertificate -FilePath $b.PfxFile -CertStoreLocation "Cert:\LocalMachine\$store" -Password $secPwd | Out-Null
                }

                $targetBinding = Get-WebBinding -Name $siteName -Port $b.Port -Protocol "https" | Where-Object {
                    ($_.bindingInformation -split ':')[2] -eq $hostHdr
                }
                if ($targetBinding) {
                    $targetBinding.AddSslCertificate($b.CertificateThumbprint, $store)
                    if ($b.SslFlags) { $targetBinding.sslFlags = $b.SslFlags }
                }
            }
        }
        Write-DeployLog "站台 [$siteName] 已成功回復至部署前原始狀態！" "PASS"
    } catch {
        Write-Fault "Rollback 還原失敗" $_.Exception.Message "請手動使用 IIS 管理員檢查站台繫結。"
    }
}

try {
    if (Test-Path $deployLockFile) {
        Write-Fault "防呆阻擋" "本執行檔任務已完成並鎖定！" "本套件僅供單次部署。若需為其他站台建立排程，請使用新發布之執行檔。"
        return
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Fault "權限不足" "未具備系統管理員身分" "請以系統管理員身分執行控制台。"
        return
    }

    if ([string]::IsNullOrWhiteSpace($ContactEmail)) {
        Write-Fault "缺少必要參數" "未設定自動換證異常通知信箱" "請於主介面填寫維運信箱後再執行部署。"
        return
    }

    if (-not (Test-Path $WacsPath)) {
        Write-Fault "環境缺失" "找不到 win-acme 核心: $WacsPath" "請先於主控台執行按鈕 1 安裝 win-acme。"
        return
    }

    Ensure-WacsBypassPrecheck

    $wacsFolder = Split-Path -Parent $WacsPath
    $cfPlugin = Get-ChildItem -Path $wacsFolder -Filter "*Cloudflare*.dll" -Recurse -ErrorAction SilentlyContinue
    if (-not $cfPlugin) {
        Write-Fault "外掛缺失" "未找到 Cloudflare DNS 驗證套件 DLL" "請在主控台重新安裝 win-acme 補齊外掛。"
        return
    }

    $wacsDataDir = "$env:ProgramData\win-acme"
    Set-SecureDirectoryAcl -Path $wacsDataDir

    # 若變數無效，嘗試自本機 DPAPI 密文還原憑據
    if ([string]::IsNullOrWhiteSpace($ValidationZoneToken)) {
        if (Test-Path $cfDpapiFile) {
            try {
                $encData = Get-Content -Path $cfDpapiFile -Raw -Encoding UTF8
                $decJson = Unprotect-SecretDPAPI $encData
                if (-not [string]::IsNullOrWhiteSpace($decJson)) {
                    $tokenObj = $decJson | ConvertFrom-Json
                    $ValidationZoneToken = $tokenObj.ValidationZoneToken
                    $ValidationSubdomain = $tokenObj.ValidationSubdomain
                    $ValidationZoneId    = $tokenObj.ValidationZoneId
                }
            } catch {}
        }
    }

    if ([string]::IsNullOrWhiteSpace($ValidationZoneToken)) {
        Write-Fault "資安原則限制" "未偵測到有效【驗證區專用 Token】" "編譯未注入密鑰、腳本無預設值且本機無 DPAPI 憑據，無法啟動驗證。"
        return
    }

    # 驗證 Token 活體狀態
    Write-DeployLog "正在驗證【驗證區專用 Token】權限狀態..." "CHECK"
    try {
        $tokenVerify = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/user/tokens/verify" `
            -Headers @{ "Authorization" = "Bearer $ValidationZoneToken" } -Method Get -TimeoutSec 10
            
        if ($tokenVerify.status -ne "active") {
            Write-Fault "API 授權" "驗證區專用 Token 狀態非 active ($($tokenVerify.status))" "Token 無效或已被撤銷。"
            return
        }
        Write-DeployLog "驗證區專用 Token 狀態正常 (Active)。" "PASS"
    } catch {
        Write-Fault "API 通訊" "無法連線 Cloudflare 驗證 Token: $_" "請確認出境網路 443 是否放行。"
        return
    }

    Import-Module WebAdministration
    $sites = Get-Website
    $validMenu = @()

    foreach ($site in $sites) {
        $hosts = @()
        foreach ($b in (Get-WebBinding -Name $site.Name)) {
            $h = ($b.bindingInformation -split ':')[2]
            if (-not [string]::IsNullOrWhiteSpace($h) -and $hosts -notcontains $h) {
                $hosts += $h
            }
        }
        if ($hosts.Count -gt 0) {
            $validMenu += [PSCustomObject]@{
                SiteId       = $site.id
                SiteName     = $site.Name
                HostList     = $hosts
                HostNamesStr = ($hosts -join ",")
            }
        }
    }

    if ($validMenu.Count -eq 0) {
        Write-Fault "IIS 配置" "未偵測到任何已綁定 Host Header 的站台" "請先至 IIS 站台繫結主機名稱 (Host Name)。"
        return
    }

    $selected = $null
    if (-not [string]::IsNullOrWhiteSpace($Global:SelectedSiteInfo)) {
        $selected = $validMenu | Where-Object { $_.SiteName -eq $Global:SelectedSiteInfo } | Select-Object -First 1
    }
    if (-not $selected) {
        $selected = $validMenu[0]
    }

    $inputDomains = $selected.HostNamesStr
    $targetSiteId = $selected.SiteId
    $global:targetSiteName = $selected.SiteName
    Write-DeployLog "確認目標 IIS 站台: [$($selected.SiteName)] (Site ID: $targetSiteId)" "PASS"
    Write-DeployLog "多網域 SAN 清單: [$inputDomains]" "PASS"
    if (-not [string]::IsNullOrWhiteSpace($ValidationSubdomain)) {
        Write-DeployLog "已啟用跨 Zone CNAME 委派: 所有驗證轉發至 [$ValidationSubdomain]" "PASS"
    } else {
        Write-DeployLog "未設定委派子網域: 將直接於目標網域 Zone 下進行驗證。" "INFO"
    }

    # 清理舊有的 renewal 組態
    if (Test-Path $wacsDataDir) {
        $oldRenewals = Get-ChildItem -Path $wacsDataDir -Filter "*.renewal.json" -Recurse -ErrorAction SilentlyContinue
        foreach ($orf in $oldRenewals) {
            try {
                $rawContent = Get-Content -Path $orf.FullName -Raw -Encoding UTF8
                if ($rawContent -match "`"SiteId`"\s*:\s*$targetSiteId\b" -or $rawContent -match [regex]::Escape($global:targetSiteName)) {
                    $oldObj = $rawContent | ConvertFrom-Json
                    $oldId = $oldObj.Id
                    if ($oldId) {
                        Write-DeployLog "清理站台 [$($global:targetSiteName)] 舊有續約註冊 (ID: $oldId)..." "INFO"
                        $cleanProc = [System.Diagnostics.Process]::Start("$WacsPath", "--cancel --id $oldId")
                        $cleanProc.WaitForExit(15000)
                    }
                }
            } catch {}
        }
    }

    # 部署前強制原子快照
    $global:backupFilePath = Backup-IISSiteState -SiteName $global:targetSiteName
    if (-not $global:backupFilePath) { return }

    # DPAPI 密文落地儲存憑據 (常態保存僅留 DPAPI 密文)
    Set-SecureDirectoryAcl -Path $cfConfigDir
    $cfCredentialPayload = [PSCustomObject]@{
        ValidationZoneToken = $ValidationZoneToken
        ValidationSubdomain = $ValidationSubdomain
        ValidationZoneId    = if ($ValidationZoneId) { $ValidationZoneId } else { "" }
        UpdatedAt           = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    } | ConvertTo-Json
    $encryptedPayload = Protect-SecretDPAPI -plainText $cfCredentialPayload
    Set-Content -Path $cfDpapiFile -Value $encryptedPayload -Encoding UTF8 -Force
    
    # 確保執行前不存在任何遺留的明文設定檔
    Remove-TemporaryCloudflareConfig -ConfigFile $cfPluginConfigFile
    Write-DeployLog "驗證區專用憑據已完成 DPAPI 密文加密收容。" "PASS"

    # ==============================================================================
    # 核心換證申請段落：外掛設定檔動態交付 + 純粹命令列 (脫敏)
    # ==============================================================================
    $currentAttempt = 1
    $isSuccess = $false

    while ($currentAttempt -le $MaxRetryAttempts -and -not $isSuccess) {
        Write-DeployLog "-----------------------------------------------------------------" "RUN"
        Write-DeployLog "[挑戰嘗試 $currentAttempt/$MaxRetryAttempts] 調度 win-acme 申請憑證 (外掛專用設定檔機制，命令列完全脫敏)..." "RUN"

        # 1. 於呼叫前動態建立外掛專用設定檔 (僅限特權 SYSTEM / Administrators 讀寫)
        Export-TemporaryCloudflareConfig -ConfigDir $cfConfigDir -ConfigFile $cfPluginConfigFile -Token $ValidationZoneToken

        try {
            # 2. 純粹命令列：徹底移除 --cloudflarednstoken 參數，Event 4688 與進程監視器無法側錄
            $wacsArgs = @(
                "--source", "manual",
                "--host", "$inputDomains",
                "--validation", "cloudflare",
                "--dnssleep", "$DnsSleepSeconds",
                "--store", "certificatestore",
                "--installation", "iis",
                "--emailaddress", "$ContactEmail",
                "--accepttos",
                "--renewaldays", "$RenewalDays",
                "--siteid", "$targetSiteId"
            )

            if (-not [string]::IsNullOrWhiteSpace($ValidationSubdomain)) {
                $wacsArgs += @("--cname", "$ValidationSubdomain")
            }

            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = $WacsPath
            $processInfo.Arguments = ($wacsArgs -join " ")
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true

            $p = [System.Diagnostics.Process]::Start($processInfo)
            while (-not $p.StandardOutput.EndOfStream) {
                $line = $p.StandardOutput.ReadLine()
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-DeployLog " [win-acme] $line" "INFO"
                }
            }
            $p.WaitForExit()
        } finally {
            # 3. 關鍵資安保障：wacs.exe 執行完畢（無論成敗）立即銷毀明文設定檔
            Remove-TemporaryCloudflareConfig -ConfigFile $cfPluginConfigFile
        }

        if ($p.ExitCode -eq 0) {
            Write-DeployLog "=================================================================" "PASS"
            Write-DeployLog "站台 [$($global:targetSiteName)] 多網域憑證簽發與 IIS 繫結成功！" "PASS"
            Write-DeployLog "全程採用專用設定檔隔離交付，進程監視器 (Event 4688) 無任何機敏外洩。" "PASS"
            Write-DeployLog "=================================================================" "PASS"
            $isSuccess = $true

            try {
                Write-DeployLog "正在檢查站台 [$($global:targetSiteName)] 之 HTTPS 部署就緒度與 Port 80 繫結..." "INFO"
                $httpsBindings = Get-WebBinding -Name $global:targetSiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

                if ($httpsBindings -and $httpsBindings.Count -gt 0) {
                    $httpBindings = Get-WebBinding -Name $global:targetSiteName -Protocol "http" -ErrorAction SilentlyContinue | Where-Object {
                        ($_.bindingInformation -split ':')[1] -eq "80"
                    }

                    if ($httpBindings) {
                        $removedCount = 0
                        foreach ($hb in $httpBindings) {
                            $bindingInfo = $hb.bindingInformation
                            Remove-WebBinding -Name $global:targetSiteName -BindingInformation $bindingInfo -Protocol "http" -ErrorAction SilentlyContinue
                            $removedCount++
                        }
                        Write-DeployLog "已成功主動移除 $removedCount 筆 Port 80 (HTTP) 繫結，落實全站純 HTTPS/Port 443 監聽與資安合規！" "PASS"
                    } else {
                        Write-DeployLog "站台目前未存在任何 Port 80 (HTTP) 繫結，無需清理。" "INFO"
                    }
                } else {
                    Write-DeployLog "防禦警告: 未偵測到就緒之 HTTPS (443) 繫結，為避免服務中斷暫不移除 Port 80！" "WARN"
                }
            } catch {
                Write-DeployLog "清理 Port 80 繫結時發生非致命警告: $($_.Exception.Message)" "WARN"
            }

            break
        } else {
            $errOut = $p.StandardError.ReadToEnd()
            Write-DeployLog "第 $currentAttempt 次簽發未完成 (ExitCode: $($p.ExitCode))。" "WARN"
            
            if ($currentAttempt -lt $MaxRetryAttempts) {
                Write-DeployLog "DNS 挑戰可能遭遇傳播延遲，系統將於 $RetryCooldownSeconds 秒後自動展開第 $($currentAttempt + 1) 次重試..." "WARN"
                Write-DeployLog "【重要提示】程序正在安全等待中，請勿關閉控制台或終止程式！" "ACTION"
                
                for ($sec = $RetryCooldownSeconds; $sec -gt 0; $sec--) {
                    if ($sec % 5 -eq 0 -or $sec -le 3) {
                        Write-DeployLog "等待 DNS 傳播同步中... 倒數 $sec 秒" "CHECK"
                    }
                    Start-Sleep -Seconds 1
                }
                $currentAttempt++
            } else {
                Write-Fault "憑證簽發失敗" "連續嘗試 $MaxRetryAttempts 次驗證未通過 ($errOut)" "請確認主網域 CNAME 是否已正確指派至驗證區，即將啟動還原。"
                break
            }
        }
    }

    if (-not $isSuccess) {
        if ($global:backupFilePath) { Invoke-IISRestore -BackupPath $global:backupFilePath }
        return
    }

} catch {
    Write-Fault "系統非預期例外" $_.Exception.Message "程序異常中斷，執行自動回復快照。"
    if ($global:backupFilePath) { Invoke-IISRestore -BackupPath $global:backupFilePath }
} finally {
    # 雙層保障：再次確保任何情況下明文設定檔均被拔除
    Remove-TemporaryCloudflareConfig -ConfigFile $cfPluginConfigFile

    $ValidationZoneToken = $null
    $wacsArgs = $null
    $Global:Embedded_Token = $null
    $Global:Embedded_Key   = $null
    $Global:Embedded_ValidationZone = $null
    $Global:Embedded_Zone  = $null
    [System.GC]::Collect()

    if ($isSuccess) {
        Complete-SecurityLockAndPurge
    }
}