<#
.SYNOPSIS
    將所有 PowerShell 模組整合並封裝為單一實體執行檔 (IIS-CertMaster.exe)
    支援跨 Zone CNAME 隔離驗證架構：
    - 若腳本內已預填「驗證區專用 Token」、「委派驗證子網域」或「Zone ID」，則直接注入。
    - 若為空白或佔位符號，封裝時提示管理員輸入；若直接按 Enter 略過亦不阻斷封裝（方便測試）。
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 自動安裝 ps2exe
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "[INFO] 正在安裝編譯模組 ps2exe..." -ForegroundColor Cyan
    Install-Module -Name ps2exe -Force -Scope CurrentUser
}

# 取得目錄
$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $CurrentDir) { $CurrentDir = (Get-Location).Path }

$MainScript     = [System.IO.Path]::Combine($CurrentDir, "IIS憑證自動管理工具.ps1")
$DeployScript   = [System.IO.Path]::Combine($CurrentDir, "部署IIS憑證.ps1")
$RollbackScript = [System.IO.Path]::Combine($CurrentDir, "還原IIS站台與憑證.ps1")
$OutputFile     = [System.IO.Path]::Combine($CurrentDir, "IIS-CertMaster.exe")

foreach ($file in @($MainScript, $DeployScript, $RollbackScript)) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Error "[ERROR] 找不到必要模組檔案：$file"
        Exit 1
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  IIS 憑證自動化控制台 - 跨 Zone CNAME 隔離版密鑰注入編譯器      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 讀取腳本內容進行預填偵測
$deployCode   = [System.IO.File]::ReadAllText($DeployScript, [System.Text.Encoding]::UTF8)
$mainCode     = [System.IO.File]::ReadAllText($MainScript, [System.Text.Encoding]::UTF8)
$rollbackCode = [System.IO.File]::ReadAllText($RollbackScript, [System.Text.Encoding]::UTF8)

# 輔助函式：自腳本代碼中萃取靜態變數值
function Extract-ScriptPresetValue([string]$code, [string]$varName) {
    if ($code -match "(?m)^\s*\`$$varName\s*=\s*[`"']([^`"']*)[`"']") {
        $val = $Matches[1].Trim()
        if ($val -notin @("", "YOUR_VALIDATION_TOKEN_HERE", "YOUR_CLOUDFLARE_API_TOKEN_HERE", "YOUR_VALIDATION_SUBDOMAIN_HERE", "YOUR_ZONE_ID_HERE")) {
            return $val
        }
    }
    return $null
}

$presetToken = Extract-ScriptPresetValue -code $deployCode -varName "ValidationZoneToken"
$presetSubdomain = Extract-ScriptPresetValue -code $deployCode -varName "ValidationSubdomain"
$presetZoneId = Extract-ScriptPresetValue -code $deployCode -varName "ValidationZoneId"

Write-Host "`n[資安配置 - 權限隔離架構檢查]" -ForegroundColor Yellow

# 1. 處理「驗證區專用 Token」（允許直接按 Enter 留空不阻斷封裝）
$SecureTokenInput = ""
if (-not [string]::IsNullOrWhiteSpace($presetToken)) {
    $masked = if ($presetToken.Length -gt 8) { $presetToken.Substring(0, 4) + "..." + $presetToken.Substring($presetToken.Length - 4) } else { "****" }
    Write-Host "[檢測完成] 部署腳本中已預設【驗證區專用 Token】: $masked" -ForegroundColor Green
    $SecureTokenInput = $presetToken
} else {
    $SecureTokenInput = Read-Host "請輸入【驗證區專用 Token】(選填/測試模式請直接按 Enter 略過)"
    if ([string]::IsNullOrWhiteSpace($SecureTokenInput)) {
        Write-Host ">> [提示] 未輸入 Token，本次封裝將以無密鑰/測試模式生成 EXE (未來可在腳本中設定或由 DPAPI 載入)。" -ForegroundColor DarkYellow
    }
}

# 2. 處理「委派驗證子網域」
$ValidationZoneInput = ""
if (-not [string]::IsNullOrWhiteSpace($presetSubdomain)) {
    Write-Host "[檢測完成] 部署腳本中已預設【委派驗證子網域】: $presetSubdomain" -ForegroundColor Green
    $ValidationZoneInput = $presetSubdomain
} else {
    $ValidationZoneInput = Read-Host "請輸入【委派驗證子網域】(例: acme.teipei.gov.tw，若無 CNAME 委派請直接按 Enter 略過)"
}

# 3. 處理「驗證區 Zone ID」
$SecureZoneInput = ""
if (-not [string]::IsNullOrWhiteSpace($presetZoneId)) {
    Write-Host "[檢測完成] 部署腳本中已預設【驗證區 Zone ID】: $presetZoneId" -ForegroundColor Green
    $SecureZoneInput = $presetZoneId
} else {
    $SecureZoneInput = Read-Host "請輸入【驗證區 Zone ID】(選填，若無請直接按 Enter 略過)"
}

# 金鑰混淆處理 (XOR + Base64)
$ObfuscationKey = [System.Guid]::NewGuid().ToString("N")
function Obfuscate-String([string]$PlainText, [string]$Key) {
    if ([string]::IsNullOrWhiteSpace($PlainText)) { return "" }
    $pBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $kBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $outBytes = New-Object byte[] $pBytes.Length
    for ($i = 0; $i -lt $pBytes.Length; $i++) {
        $outBytes[$i] = $pBytes[$i] -bxor $kBytes[$i % $kBytes.Length]
    }
    return [System.Convert]::ToBase64String($outBytes)
}

$EncTokenPayload      = Obfuscate-String -PlainText $SecureTokenInput -Key $ObfuscationKey
$EncValidationPayload = Obfuscate-String -PlainText $ValidationZoneInput -Key $ObfuscationKey
$EncZonePayload       = Obfuscate-String -PlainText $SecureZoneInput -Key $ObfuscationKey

Write-Host "`n[INFO] 正在載入模組腳本進行單元整合..." -ForegroundColor Cyan

# 採用單引號 Here-String 樣板，徹底避免變數預先展開
$templateRunner = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Global:Embedded_Key             = "__EMBEDDED_KEY__"
$Global:Embedded_Token           = "__EMBEDDED_TOKEN__"
$Global:Embedded_ValidationZone  = "__EMBEDDED_VALIDATION_ZONE__"
$Global:Embedded_Zone            = "__EMBEDDED_ZONE__"

function Run-DeploySubroutine {
__DEPLOY_CODE__
}

function Run-RollbackSubroutine {
__ROLLBACK_CODE__
}

# 進入主 GUI 常式
__MAIN_CODE__
'@

# 標籤置換
$consolidatedContent = $templateRunner.Replace("__EMBEDDED_KEY__", $ObfuscationKey)
$consolidatedContent = $consolidatedContent.Replace("__EMBEDDED_TOKEN__", $EncTokenPayload)
$consolidatedContent = $consolidatedContent.Replace("__EMBEDDED_VALIDATION_ZONE__", $EncValidationPayload)
$consolidatedContent = $consolidatedContent.Replace("__EMBEDDED_ZONE__", $EncZonePayload)
$consolidatedContent = $consolidatedContent.Replace("__DEPLOY_CODE__", $deployCode)
$consolidatedContent = $consolidatedContent.Replace("__ROLLBACK_CODE__", $rollbackCode)
$consolidatedContent = $consolidatedContent.Replace("__MAIN_CODE__", $mainCode)

$consolidatedScriptPath = [System.IO.Path]::Combine($CurrentDir, "ConsolidatedRunner.ps1")
[System.IO.File]::WriteAllText($consolidatedScriptPath, $consolidatedContent, [System.Text.Encoding]::UTF8)

Write-Host "[INFO] 正在透過 ps2exe 編譯為單一二進位 EXE 檔..." -ForegroundColor Cyan
Invoke-PS2EXE -InputFile $consolidatedScriptPath `
              -OutputFile $OutputFile `
              -Title "IIS SSL 自動化維運控制台 (跨 Zone 隔離版)" `
              -Description "IIS SSL 憑證自動化更新與工作排程管理工具" `
              -Company "Government Enterprise Infra" `
              -Product "IIS-CertMaster" `
              -Copyright "2026 Enterprise Security" `
              -RequireAdmin `
              -noConsole:$false `
              -DPIAware

# 清理編譯中介檔
if (Test-Path -LiteralPath $consolidatedScriptPath) {
    Remove-Item -LiteralPath $consolidatedScriptPath -Force
}

Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] 封裝成功完成！" -ForegroundColor Green
Write-Host " 輸出檔案: $OutputFile" -ForegroundColor Green
Write-Host " 提示: 若封裝時留空 Token，請確認正式執行時部署腳本已預填或本機已有 DPAPI 憑據。" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Green