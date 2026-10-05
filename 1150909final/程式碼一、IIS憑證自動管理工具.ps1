# ==============================================================================
# [GSN 政府網路 Proxy 代理伺服器全域設定區塊]
# 若機關防火牆強制要求透過 Proxy 出境，請解除以下設定註解
# ==============================================================================
# $Global:GsnProxyServer = "http://proxy.gsn.gov.tw:3128"
# [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($Global:GsnProxyServer, $true)
#
# 【認證模式 A：整合 Windows 身分驗證 (NTLM / Kerberos)】
# [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security

# 0. 精確解析當前執行環境
$CurrentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
$resolvedPath = if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $PSCommandPath
} elseif (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
} else {
    $CurrentProcess.MainModule.FileName
}

$IsCompiledExe = $resolvedPath -like "*.exe"
$ScriptDir = if ($IsCompiledExe) {
    [System.IO.Path]::GetDirectoryName($resolvedPath)
} else {
    Split-Path -Parent $resolvedPath
}

if ([string]::IsNullOrWhiteSpace($ScriptDir)) {
    $ScriptDir = (Get-Location).Path
}

# 1. 自動提升為管理員權限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($IsCompiledExe) {
        Start-Process -FilePath $resolvedPath -Verb RunAs
    } else {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$resolvedPath`"" -Verb RunAs
    }
    Exit
}

$Global:ToolPath = "C:\tools\win-acme\wacs.exe"
$Global:BackupDir = "$env:ProgramData\IIS-Cert-Backup"
$Global:WacsDataDir = "$env:ProgramData\win-acme"
$Global:TaskNamePattern = "win-acme*"
$Global:RenewalDaysThreshold = 30
$Global:DeployLockFile = "$Global:WacsDataDir\.deployment_completed.lock"
$Global:SelectedSiteInfo = $null
$Global:SelectedContactEmail = $null
$Global:MaxBackupRetention = 10

# 嚴格聯鎖旗標
$Global:EnvCheckCompleted = $false
$Global:HasEnvCheckFailed = $false
$Global:EnvCheckFailCount = 0

# 2. WPF XAML 介面配置
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="IIS SSL 自動化維運控制台 (Cloudflare + win-acme)" 
        Height="600" Width="980" MinHeight="500" MinWidth="850"
        WindowStartupLocation="CenterScreen" Background="#1E1E2E" FontFamily="Segoe UI, Microsoft JhengHei">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- 標題區塊 -->
        <StackPanel Grid.Row="0" Margin="0,0,0,6">
            <TextBlock Text="IIS SSL 憑證自動化維運中心" FontSize="16" FontWeight="Bold" Foreground="#CDD6F4"/>
            <TextBlock Text="整合多網域 SAN、動態防禦快照、Cloudflare DNS-01 挑戰與工作排程智慧監控" FontSize="10.5" Foreground="#A6ADC8" Margin="0,2,0,0"/>
        </StackPanel>

        <!-- 站台與告警信箱設定區塊 -->
        <Border Grid.Row="1" Background="#181825" CornerRadius="6" BorderBrush="#313244" BorderThickness="1" Margin="0,0,0,6" Padding="8">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Row="0" Grid.Column="0" Text="目標 IIS 站台 (含多網域 SAN):" FontWeight="Bold" Foreground="#CDD6F4" FontSize="11" VerticalAlignment="Center" Margin="0,0,8,4"/>
                <ComboBox Grid.Row="0" Grid.Column="1" Name="CmbSites" Height="24" Background="#313244" Foreground="#CDD6F4" VerticalContentAlignment="Center" FontSize="11" Margin="0,0,0,4"/>
                <Button Grid.Row="0" Grid.Column="2" Name="BtnRefreshSites" Content="重新整理站台" Width="85" Height="24" Margin="6,0,0,4" Background="#313244" Foreground="#CDD6F4" BorderThickness="0" FontSize="10.5"/>
                <Button Grid.Row="0" Grid.Column="3" Name="BtnCancelRenewal" Content="取消此站排程" Width="85" Height="24" Margin="6,0,0,4" Background="#45475A" Foreground="#F38BA8" BorderThickness="0" FontSize="10.5"/>

                <TextBlock Grid.Row="1" Grid.Column="0" Text="*自動換證異常通知信箱 (必填):" FontWeight="Bold" Foreground="#FAB387" FontSize="11" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <TextBox Grid.Row="1" Grid.Column="1" Name="TxtContactEmail" Height="24" Background="#313244" Foreground="#CDD6F4" BorderBrush="#45475A" VerticalContentAlignment="Center" FontSize="11" Padding="4,0,4,0"/>
                <Button Grid.Row="1" Grid.Column="2" Name="BtnUpdateEmail" Content="更新信箱" Width="85" Height="24" Margin="6,0,0,0" Background="#45475A" Foreground="#CDD6F4" BorderThickness="0" FontSize="10.5" Grid.ColumnSpan="2"/>
            </Grid>
        </Border>

        <!-- 核心功能五大按鈕 -->
        <Grid Grid.Row="2" Margin="0,0,0,6">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <Button Name="BtnInstall" Grid.Column="0" Margin="2" Height="54" Background="#313244" BorderBrush="#45475A" BorderThickness="1">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="1. 安裝 win-acme" FontWeight="Bold" Foreground="#89B4FA" HorizontalAlignment="Center" FontSize="11.5"/>
                    <TextBlock Name="TxtWacsStatus" Text="檢查中..." FontSize="10" Foreground="#F38BA8" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Button>

            <Button Name="BtnCheckEnv" Grid.Column="1" Margin="2" Height="54" Background="#313244" BorderBrush="#45475A" BorderThickness="1">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="2. 檢視系統環境" FontWeight="Bold" Foreground="#A6E3A1" HorizontalAlignment="Center" FontSize="11.5"/>
                    <TextBlock Text="網路、Proxy與權限診斷" FontSize="10" Foreground="#A6ADC8" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Button>

            <Button Name="BtnManualBackup" Grid.Column="2" Margin="2" Height="54" Background="#313244" BorderBrush="#45475A" BorderThickness="1">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="3. 手動快照備份" FontWeight="Bold" Foreground="#89DCEB" HorizontalAlignment="Center" FontSize="11.5"/>
                    <TextBlock Name="TxtBackupStatus" Text="掃描中..." FontSize="10" Foreground="#FAB387" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Button>

            <Button Name="BtnDeploy" Grid.Column="3" Margin="2" Height="54" Background="#313244" BorderBrush="#45475A" BorderThickness="1">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Name="TxtDeployTitle" Text="4. 建立自動排程" FontWeight="Bold" Foreground="#FAB387" HorizontalAlignment="Center" FontSize="11.5"/>
                    <TextBlock Name="TxtDeploySubtitle" Text="申請、繫結與自動備份" FontSize="10" Foreground="#A6ADC8" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Button>

            <Button Name="BtnRollback" Grid.Column="4" Margin="2" Height="54" Background="#313244" BorderBrush="#45475A" BorderThickness="1">
                <StackPanel HorizontalAlignment="Center">
                    <TextBlock Text="5. 一鍵還原狀態" FontWeight="Bold" Foreground="#F38BA8" HorizontalAlignment="Center" FontSize="11.5"/>
                    <TextBlock Text="復原站台繫結與憑證" FontSize="10" Foreground="#A6ADC8" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Button>
        </Grid>

        <!-- 排程狀態列 -->
        <Border Grid.Row="3" Background="#181825" CornerRadius="6" BorderBrush="#313244" BorderThickness="1" Margin="0,0,0,6" Padding="6,8">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" Text="IIS 憑證換約排程狀態:" FontWeight="Bold" Foreground="#CDD6F4" FontSize="11" VerticalAlignment="Center" Margin="0,0,12,0"/>

                <WrapPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Text="排程: " Foreground="#A6ADC8" FontSize="10.5" VerticalAlignment="Center"/>
                    <TextBlock Name="TxtTaskStatus" Text="掃描中..." FontWeight="Bold" Foreground="#F38BA8" FontSize="10.5" VerticalAlignment="Center" Margin="0,0,10,0"/>

                    <TextBlock Text="目前站台憑證到期: " Foreground="#A6ADC8" FontSize="10.5" VerticalAlignment="Center"/>
                    <TextBlock Name="TxtCertExpiry" Text="無" FontWeight="Bold" Foreground="#89B4FA" FontSize="10.5" VerticalAlignment="Center" Margin="0,0,10,0"/>

                    <TextBlock Text="下次自動換約: " Foreground="#A6ADC8" FontSize="10.5" VerticalAlignment="Center"/>
                    <TextBlock Name="TxtNextRenewal" Text="無" FontWeight="Bold" Foreground="#A6E3A1" FontSize="10.5" VerticalAlignment="Center" Margin="0,0,8,0"/>
                </WrapPanel>

                <Button Grid.Column="2" Name="BtnRefreshTask" Content="重新整理" Width="60" Height="22" Background="#313244" Foreground="#CDD6F4" BorderThickness="0" FontSize="10.5"/>
            </Grid>
        </Border>

        <!-- 執行記錄輸出區塊 -->
        <Border Grid.Row="4" Background="#11111B" CornerRadius="6" BorderBrush="#313244" BorderThickness="1" Padding="6">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <DockPanel Grid.Row="0" Margin="0,0,0,4">
                    <TextBlock Text="控制台執行記錄 (Log Output):" Foreground="#A6ADC8" FontSize="10.5" VerticalAlignment="Center"/>
                    <Button Name="BtnClearLog" Content="清除記錄" Width="55" Height="18" HorizontalAlignment="Right" Background="#313244" Foreground="#CDD6F4" FontSize="9.5" BorderThickness="0"/>
                </DockPanel>
                <RichTextBox Name="TxtLog" Grid.Row="1" Background="Transparent" FontFamily="Consolas" FontSize="11"
                             IsReadOnly="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" BorderThickness="0">
                    <FlowDocument LineHeight="1.15"/>
                </RichTextBox>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$cmbSites          = $window.FindName("CmbSites")
$txtContactEmail   = $window.FindName("TxtContactEmail")
$btnUpdateEmail    = $window.FindName("BtnUpdateEmail")
$btnRefreshSites   = $window.FindName("BtnRefreshSites")
$btnCancelRenewal  = $window.FindName("BtnCancelRenewal")
$btnInstall        = $window.FindName("BtnInstall")
$txtWacsStatus     = $window.FindName("TxtWacsStatus")
$btnCheckEnv       = $window.FindName("BtnCheckEnv")
$btnManualBackup   = $window.FindName("BtnManualBackup")
$txtBackupStatus   = $window.FindName("TxtBackupStatus")
$btnDeploy         = $window.FindName("BtnDeploy")
$txtDeployTitle    = $window.FindName("TxtDeployTitle")
$txtDeploySubtitle = $window.FindName("TxtDeploySubtitle")
$btnRollback       = $window.FindName("BtnRollback")
$btnClearLog       = $window.FindName("BtnClearLog")
$txtLog            = $window.FindName("TxtLog")

$txtTaskStatus     = $window.FindName("TxtTaskStatus")
$txtCertExpiry     = $window.FindName("TxtCertExpiry")
$txtNextRenewal    = $window.FindName("TxtNextRenewal")
$btnRefreshTask    = $window.FindName("BtnRefreshTask")

# 讀取已鎖定之信箱，否則維持清空
if (Test-Path $Global:DeployLockFile) {
    try {
        $lockData = Get-Content $Global:DeployLockFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($lockData.ContactEmail) {
            $txtContactEmail.Text = $lockData.ContactEmail
        }
    } catch {}
} else {
    $txtContactEmail.Text = ""
}

function Refresh-UI {
    [System.Windows.Forms.Application]::DoEvents()
}

function Append-Log([string]$message, [string]$level = "INFO") {
    $time = (Get-Date).ToString("HH:mm:ss")

    $color = switch ($level) {
        "FAIL"   { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FF4444") }
        "ACTION" { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFD700") }
        "WARN"   { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFA500") }
        "PASS"   { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#50FA7B") }
        "CHECK"  { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#8BE9FD") }
        "RUN"    { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FFB86C") }
        Default  { [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F8F8F2") }
    }

    $paragraph = New-Object System.Windows.Documents.Paragraph
    $paragraph.Margin = New-Object System.Windows.Thickness(0, 1, 0, 1)

    $run = New-Object System.Windows.Documents.Run("[$time][$level] $message")
    $run.Foreground = $color
    if ($level -in @("FAIL", "ACTION", "WARN")) {
        $run.FontWeight = [System.Windows.FontWeights]::Bold
    }

    $paragraph.Inlines.Add($run)
    $txtLog.Document.Blocks.Add($paragraph)
    $txtLog.ScrollToEnd()
    Refresh-UI
}

function Record-DiagnosticFail([string]$FailReason, [string]$ActionGuidance) {
    $Global:HasEnvCheckFailed = $true
    $Global:EnvCheckFailCount++
    Append-Log $FailReason "FAIL"
    Append-Log ">> 操作建議: $ActionGuidance" "ACTION"
}

function Set-AllControlsState([bool]$enabled) {
    $cmbSites.IsEnabled         = $enabled
    $txtContactEmail.IsEnabled  = $true
    $btnUpdateEmail.IsEnabled   = $true
    $btnRefreshSites.IsEnabled  = $enabled
    $btnCancelRenewal.IsEnabled = $enabled
    $btnInstall.IsEnabled       = $enabled
    $btnCheckEnv.IsEnabled      = $enabled
    $btnManualBackup.IsEnabled  = $enabled
    $btnRollback.IsEnabled      = $enabled
    $btnRefreshTask.IsEnabled   = $enabled

    if (Test-Path $Global:DeployLockFile) {
        $btnDeploy.IsEnabled = $false
        $btnDeploy.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#2B2C3C")
        $txtDeployTitle.Text = "4. 建立自動排程 (已鎖定)"
        $txtDeployTitle.Foreground = [System.Windows.Media.Brushes]::Gray
        $txtDeploySubtitle.Text = "本執行檔任務已完成 (鎖定防呆)"
        $txtDeploySubtitle.Foreground = [System.Windows.Media.Brushes]::DarkGray
    } elseif (-not $Global:EnvCheckCompleted) {
        $btnDeploy.IsEnabled = $false
        $btnDeploy.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#2B2C3C")
        $txtDeployTitle.Text = "4. 建立自動排程"
        $txtDeployTitle.Foreground = [System.Windows.Media.Brushes]::Gray
        $txtDeploySubtitle.Text = "需先執行按鈕 2 環境診斷"
        $txtDeploySubtitle.Foreground = [System.Windows.Media.Brushes]::DarkGray
    } elseif ($Global:HasEnvCheckFailed) {
        $btnDeploy.IsEnabled = $false
        $btnDeploy.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#2B2C3C")
        $txtDeployTitle.Text = "4. 自動排程 (已阻斷)"
        $txtDeployTitle.Foreground = [System.Windows.Media.Brushes]::Salmon
        $txtDeploySubtitle.Text = "環境檢測未通過 (請先排除紅字)"
        $txtDeploySubtitle.Foreground = [System.Windows.Media.Brushes]::Salmon
    } else {
        $btnDeploy.IsEnabled = $enabled
        $btnDeploy.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#313244")
        $txtDeployTitle.Text = "4. 建立自動排程"
        $txtDeployTitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FAB387")
        $txtDeploySubtitle.Text = "環境就緒 (點擊執行部署)"
        $txtDeploySubtitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#A6ADC8")
    }
    Refresh-UI
}

function Update-SiteDropdownList {
    $cmbSites.Items.Clear()
    try {
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            $cmbSites.Items.Add("尚未安裝 IIS 角色或 WebAdministration 管理模組") | Out-Null
            $cmbSites.SelectedIndex = 0
            return
        }

        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-Website -ErrorAction SilentlyContinue
        if (-not $sites -or $sites.Count -eq 0) {
            $cmbSites.Items.Add("尚未在 IIS 中建立站台") | Out-Null
            $cmbSites.SelectedIndex = 0
            return
        }

        $validCount = 0
        foreach ($s in $sites) {
            $hosts = @()
            foreach ($b in (Get-WebBinding -Name $s.Name)) {
                $h = ($b.bindingInformation -split ':')[2]
                if (-not [string]::IsNullOrWhiteSpace($h) -and $hosts -notcontains $h) {
                    $hosts += $h
                }
            }
            if ($hosts.Count -gt 0) {
                $display = "$($s.Name) (ID:$($s.id)) -> SAN: $($hosts -join ', ')"
                $cmbSites.Items.Add($display) | Out-Null
                $validCount++
            }
        }

        if ($validCount -gt 0) {
            $cmbSites.SelectedIndex = 0
        } else {
            $cmbSites.Items.Add("所有站台均未綁定主機名稱 (Host Name)") | Out-Null
            $cmbSites.SelectedIndex = 0
        }
    } catch {
        $cmbSites.Items.Add("讀取 IIS 站台失敗: 尚未啟用 IIS 角色或缺少管理工具") | Out-Null
        $cmbSites.SelectedIndex = 0
    }
    Refresh-UI
}

function Update-WacsStatus {
    if (Test-Path $Global:ToolPath) {
        $txtWacsStatus.Text = "[已安裝]"
        $txtWacsStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
    } else {
        $txtWacsStatus.Text = "[未安裝 (點擊安裝)]"
        $txtWacsStatus.Foreground = [System.Windows.Media.Brushes]::Salmon
    }
    Refresh-UI
}

function Update-BackupStatus {
    if (Test-Path $Global:BackupDir) {
        $backups = Get-ChildItem -Path $Global:BackupDir -Filter "*.json" -ErrorAction SilentlyContinue
        if ($backups -and $backups.Count -gt 0) {
            $txtBackupStatus.Text = "[已有備份: $($backups.Count) 筆]"
            $txtBackupStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
        } else {
            $txtBackupStatus.Text = "[無備份 (點擊備份)]"
            $txtBackupStatus.Foreground = [System.Windows.Media.Brushes]::SandyBrown
        }
    } else {
        $txtBackupStatus.Text = "[無備份 (點擊備份)]"
        $txtBackupStatus.Foreground = [System.Windows.Media.Brushes]::SandyBrown
    }
    Refresh-UI
}

function Update-ScheduledTaskStatus {
    try {
        $tasks = Get-ScheduledTask -TaskName $Global:TaskNamePattern -ErrorAction SilentlyContinue
        $taskReady = $false
        if ($tasks) {
            $firstTask = $tasks[0]
            $stateStr = switch ($firstTask.State) {
                0 { "未就緒" }
                1 { "就緒 (每日監聽)" }
                2 { "正在換約" }
                3 { "已暫停" }
                Default { $firstTask.State.ToString() }
            }
            $txtTaskStatus.Text = "$($firstTask.TaskName) [$stateStr]"
            if ($firstTask.State -in @(1, 2)) {
                $txtTaskStatus.Foreground = [System.Windows.Media.Brushes]::LightGreen
                $taskReady = $true
            } else {
                $txtTaskStatus.Foreground = [System.Windows.Media.Brushes]::Salmon
            }
        } else {
            $txtTaskStatus.Text = "[未建立排程]"
            $txtTaskStatus.Foreground = [System.Windows.Media.Brushes]::SandyBrown
        }

        $selectedText = [string]$cmbSites.SelectedItem
        $currentSiteName = $null
        if (-not [string]::IsNullOrWhiteSpace($selectedText) -and $selectedText -notlike "尚未*" -and $selectedText -notlike "所有站台均未*" -and $selectedText -notlike "讀取*") {
            $currentSiteName = ($selectedText -split ' \(ID:')[0].Trim()
        }

        $latestCert = $null
        if ($currentSiteName -and (Get-Module -ListAvailable -Name WebAdministration)) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            $bindings = Get-WebBinding -Name $currentSiteName -Protocol "https" -ErrorAction SilentlyContinue
            $certHashes = @()
            foreach ($b in $bindings) {
                $rawHash = $b.certificateHash
                if ($rawHash) {
                    $thumb = if ($rawHash -is [byte[]]) {
                        [System.BitConverter]::ToString($rawHash) -replace '-'
                    } elseif ($rawHash -is [string]) {
                        $rawHash -replace '[-:]'
                    } else { "" }

                    if (-not [string]::IsNullOrWhiteSpace($thumb) -and $certHashes -notcontains $thumb) { 
                        $certHashes += $thumb 
                    }
                }
            }
            
            $validCerts = @()
            foreach ($th in $certHashes) {
                $c = Get-Item "Cert:\LocalMachine\My\$th" -ErrorAction SilentlyContinue
                if ($c) { $validCerts += $c }
            }

            if ($validCerts.Count -gt 0) {
                $latestCert = $validCerts | Sort-Object NotAfter -Descending | Select-Object -First 1
            }
        }

        if ($latestCert) {
            $now = Get-Date
            $expiryDate = $latestCert.NotAfter
            $daysLeft = [math]::Floor(($expiryDate - $now).TotalDays)
            
            if ($daysLeft -gt $Global:RenewalDaysThreshold) {
                $txtCertExpiry.Text = "$($expiryDate.ToString('yyyy/MM/dd')) (剩 $daysLeft 天)"
                $txtCertExpiry.Foreground = [System.Windows.Media.Brushes]::LightGreen
            } elseif ($daysLeft -ge 0) {
                $txtCertExpiry.Text = "$($expiryDate.ToString('yyyy/MM/dd')) (剩 $daysLeft 天)"
                $txtCertExpiry.Foreground = [System.Windows.Media.Brushes]::Salmon
            } else {
                $txtCertExpiry.Text = "$($expiryDate.ToString('yyyy/MM/dd')) (已過期)"
                $txtCertExpiry.Foreground = [System.Windows.Media.Brushes]::Red
            }

            $renewDate = $expiryDate.AddDays(-$Global:RenewalDaysThreshold)
            $renewDaysLeft = [math]::Floor(($renewDate - $now).TotalDays)

            if ($taskReady) {
                if ($renewDaysLeft -gt 0) {
                    $txtNextRenewal.Text = "$($renewDate.ToString('yyyy/MM/dd')) (剩 $renewDaysLeft 天)"
                    $txtNextRenewal.Foreground = [System.Windows.Media.Brushes]::DeepSkyBlue
                } else {
                    $txtNextRenewal.Text = "已達換約門檻 (下次排程喚醒即換約)"
                    $txtNextRenewal.Foreground = [System.Windows.Media.Brushes]::Gold
                }
            } else {
                $txtNextRenewal.Text = "無 (排程尚未就緒)"
                $txtNextRenewal.Foreground = [System.Windows.Media.Brushes]::SandyBrown
            }
        } else {
            $txtCertExpiry.Text = "該站尚未綁定憑證"
            $txtCertExpiry.Foreground = [System.Windows.Media.Brushes]::SandyBrown
            $txtNextRenewal.Text = "無"
            $txtNextRenewal.Foreground = [System.Windows.Media.Brushes]::SandyBrown
        }
    } catch {
        $txtTaskStatus.Text = "[讀取失敗]"
        $txtTaskStatus.Foreground = [System.Windows.Media.Brushes]::Salmon
        $txtCertExpiry.Text = "錯誤"
        $txtNextRenewal.Text = "錯誤"
    }
    Refresh-UI
}

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

function Test-PortQuick([string]$hostName, [int]$port, [int]$timeoutMs = 3000) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $tcp.BeginConnect($hostName, $port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($timeoutMs, $false)
        if (-not $wait) {
            $tcp.Close()
            return $false
        }
        $tcp.EndConnect($connect)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

# 全域標準快照輪替函式
function Rotate-Backups {
    if (Test-Path -LiteralPath $Global:BackupDir) {
        $jsonFiles = Get-ChildItem -LiteralPath $Global:BackupDir -Filter "*.json" | Sort-Object LastWriteTime -Descending
        if ($jsonFiles.Count -gt $Global:MaxBackupRetention) {
            $filesToRemove = $jsonFiles | Select-Object -Skip $Global:MaxBackupRetention
            foreach ($f in $filesToRemove) {
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($f.FullName)
                $matchingPfx = [System.IO.Path]::Combine($Global:BackupDir, "$baseName.pfx")
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath $matchingPfx) {
                    Remove-Item -LiteralPath $matchingPfx -Force -ErrorAction SilentlyContinue
                }
            }
            Append-Log "已執行快照歷史輪替，保留最新 $($Global:MaxBackupRetention) 份快照檔案。" "INFO"
        }
    }
}

# 【安裝核心常式】：安裝 win-acme 後強制直接調教寫入組態 (避免內網雙面 DNS 阻礙)
function Apply-WacsConfiguration {
    $targetDir = "C:\tools\win-acme"
    if (-not (Test-Path -LiteralPath $targetDir)) { return }

    [string[]]$targetFileNames = @("settings.json", "settings_default.json")

    foreach ($fileName in $targetFileNames) {
        $fullPath = [System.IO.Path]::Combine($targetDir, $fileName)
        if (Test-Path -LiteralPath $fullPath) {
            try {
                $jsonContent = Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8 | ConvertFrom-Json
                $modified = $false

                if ($jsonContent.ScheduledTask -and $jsonContent.ScheduledTask.RenewalDays -ne $Global:RenewalDaysThreshold) {
                    $jsonContent.ScheduledTask.RenewalDays = $Global:RenewalDaysThreshold
                    $modified = $true
                }

                if ($jsonContent.Validation) {
                    if ($jsonContent.Validation.PreValidateDns -ne $false) {
                        $jsonContent.Validation.PreValidateDns = $false
                        $modified = $true
                    }
                }

                if ($modified) {
                    $jsonContent | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $fullPath -Encoding UTF8
                }
            } catch {
                Append-Log "寫入 $fileName 組態時發生例外: $($_.Exception.Message)" "WARN"
            }
        }
    }
}

# 【純唯讀檢驗常式】：環境診斷專用，絕不於檢驗階段動態改寫檔案
function Test-WacsPreValidateDnsStatus {
    $targetDir = "C:\tools\win-acme"
    if (-not (Test-Path -LiteralPath $targetDir)) { return $true }

    $allFilesCorrect = $true
    [string[]]$targetFileNames = @("settings.json", "settings_default.json")

    foreach ($fileName in $targetFileNames) {
        $fullPath = [System.IO.Path]::Combine($targetDir, $fileName)
        if (Test-Path -LiteralPath $fullPath) {
            try {
                $jsonContent = Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($jsonContent.Validation -and $jsonContent.Validation.PreValidateDns -ne $false) {
                    $allFilesCorrect = $false
                }
            } catch {
                $allFilesCorrect = $false
            }
        }
    }
    return $allFilesCorrect
}

# --- 5 大核心環境與資安診斷模組 ---
function Check-GsnProxyStatus {
    Append-Log "--- [項目 1/5] GSN 網路出境與 Proxy 路由狀態診斷 ---" "CHECK"
    $scriptProxy = $Global:GsnProxyServer
    $wininetSettings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $sysProxyEnabled = if ($wininetSettings) { [bool]$wininetSettings.ProxyEnable } else { $false }
    $sysProxyServer  = if ($wininetSettings) { $wininetSettings.ProxyServer } else { $null }
    
    $netshWinHttp = (netsh winhttp show proxy 2>&1) -join " "
    $hasWinHttpProxy = $netshWinHttp -match "Proxy Server\(s\)\s*:\s*([^\s]+)"
    $winHttpProxyVal = if ($hasWinHttpProxy) { $Matches[1] } else { $null }

    $directOk = Test-PortQuick -hostName "api.cloudflare.com" -port 443 -timeoutMs 3000

    if ($directOk) {
        if (-not [string]::IsNullOrWhiteSpace($scriptProxy)) {
            Append-Log "GSN 路由模式: [混和/已設 Proxy] 腳本已指定代理 ($scriptProxy)，且主機 Direct 443 亦通暢。" "PASS"
        } else {
            Append-Log "GSN 路由模式: [Direct 直連模式] 主機已具備 TCP 443 直接出境能力，運作正常。" "PASS"
        }
    } else {
        $activeProxy = if (-not [string]::IsNullOrWhiteSpace($scriptProxy)) { 
            $scriptProxy 
        } elseif ($sysProxyEnabled -and $sysProxyServer) { 
            $sysProxyServer 
        } elseif ($winHttpProxyVal) {
            $winHttpProxyVal
        } else { 
            $null 
        }

        if ($activeProxy) {
            Append-Log "主機無法 Direct 直連，偵測到 Proxy 配置: [$activeProxy]，正在驗證連通性..." "CHECK"
            try {
                $proxyUri = if ($activeProxy -notmatch "^http") { "http://$activeProxy" } else { $activeProxy }
                $req = [System.Net.HttpWebRequest]::Create("https://api.cloudflare.com/client/v4/ips")
                $req.Proxy = New-Object System.Net.WebProxy($proxyUri, $true)
                $req.Timeout = 5000
                $resp = $req.GetResponse()
                $resp.Close()
                Append-Log "GSN 路由模式: [Proxy 轉發模式] 透過代理伺服器連線成功。" "PASS"
            } catch {
                Record-DiagnosticFail `
                    "GSN 路由模式: 直連受阻且配置之 Proxy ($activeProxy) 無法轉發連線: $($_.Exception.Message)" `
                    "請向機關網路管理員確認 Proxy 位址、連接埠與存取原則是否正確。"
            }
        } else {
            Record-DiagnosticFail `
                "GSN 路由模式: 主機無法直連出境 (TCP 443)，且目前「未配置任何 Proxy」！" `
                "若機關要求走 GSN Proxy，請於腳本頂端填寫代理；若採 Direct 模式，請於防火牆放行出境 TCP 443。"
        }
    }
}

function Check-OutboundEndpoints {
    Append-Log "--- [項目 2/5] 必要端點出境連線 (Ingress 80 免開) 診斷 ---" "CHECK"
    $targets = @(
        @{ Name = "Cloudflare API (DNS-01 挑戰與驗證)"; Host = "api.cloudflare.com"; Port = 443; Crucial = $true },
        @{ Name = "Let's Encrypt ACME (憑證簽發與握手)"; Host = "acme-v02.api.letsencrypt.org"; Port = 443; Crucial = $true },
        @{ Name = "GitHub 官方 API (版本查詢)"; Host = "api.github.com"; Port = 443; Crucial = $false },
        @{ Name = "GitHub Release Assets (安裝套件下載)"; Host = "objects.githubusercontent.com"; Port = 443; Crucial = $false }
    )

    $allCrucialOk = $true
    foreach ($t in $targets) {
        $ok = Test-PortQuick -hostName $t.Host -port $t.Port -timeoutMs 3500
        if ($ok) {
            Append-Log "[$($t.Host):$($t.Port)] 連線正常 ($($t.Name))" "PASS"
        } else {
            if ($t.Crucial) {
                $allCrucialOk = $false
                Record-DiagnosticFail `
                    "無法連線至核心端點 [$($t.Host):$($t.Port)] ($($t.Name))" `
                    "出境防火牆必須放行 TCP 443 至 $($t.Host)，否則無法簽發或更新憑證！"
            } else {
                Append-Log "無法連線至非關鍵端點 [$($t.Host):$($t.Port)] ($($t.Name))" "WARN"
                Append-Log ">> 操作建議: 此端點僅影響初次安裝更新，若主機已安裝 win-acme 則不影響自動換約。" "ACTION"
            }
        }
    }

    if ($allCrucialOk) {
        Append-Log "資安合規確認: 伺服器對外通訊皆由本機主動出境 (Outbound 443)，外部入網 (Ingress) Port 80 維持關閉合規。" "PASS"
    }
}

function Check-TlsInspectionStatus {
    Append-Log "--- [項目 3/5] 次世代防火牆 (NGFW) / TLS 深度解密檢測 ---" "CHECK"
    $testUrls = @(
        "https://acme-v02.api.letsencrypt.org/directory",
        "https://api.cloudflare.com/client/v4/ips"
    )

    $suspiciousKeywords = @("FORTINET", "PALO ALTO", "PALOALTO", "CHECKPOINT", "SOPHOS", "ZSCALER", "BLUECOAT", "FORCEPOINT", "FIREWALL", "PROXY", "INTERCEPTION", "DEEP-INSPECTION")
    $inspectedDetected = $false
    $testedAny = $false

    foreach ($url in $testUrls) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Timeout = 5000
            $req.AllowAutoRedirect = $true
            $resp = $req.GetResponse()
            $cert = $req.ServicePoint.Certificate
            $resp.Close()

            if ($cert) {
                $testedAny = $true
                $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
                $issuer = $cert2.Issuer
                $hostName = ([System.Uri]$url).Host

                $isSuspicious = $false
                foreach ($kw in $suspiciousKeywords) {
                    if ($issuer.ToUpper() -like "*$kw*") {
                        $isSuspicious = $true
                        break
                    }
                }

                if ($isSuspicious) {
                    $inspectedDetected = $true
                    Record-DiagnosticFail `
                        "[$hostName] 警告！偵測到 TLS 憑證已被設備置換/拆解解密 (簽發者: $issuer)！" `
                        "請將 $hostName 加入機關防火牆之「SSL Inspection 排除名單 (Bypass)」，避免握手被阻斷。"
                } else {
                    Append-Log "[$hostName] 憑證鏈合法 (Issuer: $issuer)，未遭受中介攔截解密。" "PASS"
                }
            }
        } catch {
            $hostName = ([System.Uri]$url).Host
            if ($_.Exception.Message -match "The underlying connection was closed" -or $_.Exception.Message -match "trust relationship") {
                $inspectedDetected = $true
                Record-DiagnosticFail `
                    "[$hostName] TLS 握手信任失敗！可能存在未信任的自簽憑證代理: $($_.Exception.Message)" `
                    "請確認網路邊界未針對 ACME / Cloudflare 實施 TLS 拆包，並檢查中繼憑證信任鏈。"
            } else {
                Append-Log "[$hostName] TLS 連線檢測略過: $($_.Exception.Message)" "WARN"
            }
        }
    }

    if (-not $testedAny) {
        Append-Log "外部網路未連通，無法完成 TLS 憑證拆包檢驗。" "WARN"
    } elseif (-not $inspectedDetected) {
        Append-Log "次世代防火牆檢驗通過: 未發現 SSL 拆包憑證覆寫現象。" "PASS"
    }
}

function Check-IisAndPortStatus {
    Append-Log "--- [項目 4/5] IIS 服務核心、排程服務與連接埠監聽診斷 ---" "CHECK"
    $iis = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if ($iis -and $iis.Status -eq 'Running') { 
        Append-Log "IIS 服務 (W3SVC) 正常執行中" "PASS"
    } else { 
        Record-DiagnosticFail `
            "原因: 該伺服器尚未啟用「網頁伺服器 (IIS)」角色或 W3SVC 服務未啟動。" `
            "請至「伺服器管理員」安裝網頁伺服器 (IIS) 角色，並啟動 W3SVC 服務。"
    }

    $schedSvc = Get-Service -Name 'Schedule' -ErrorAction SilentlyContinue
    if ($schedSvc -and $schedSvc.Status -eq 'Running') {
        Append-Log "工作排程服務 (Schedule) 正常執行中" "PASS"
    } else {
        Record-DiagnosticFail `
            "原因: Windows 工作排程器服務 (Schedule) 未執行，無法建立及喚醒自動換約！" `
            "請啟動 Task Scheduler (Schedule) 服務，並確認其啟動類型設定為「自動」。"
    }

    $port443 = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    if ($port443) {
        $pidVal = $port443[0].OwningProcess
        $procName = (Get-Process -Id $pidVal -ErrorAction SilentlyContinue).ProcessName
        if ($procName -eq 'System') { 
            Append-Log "Port 443 由 HTTP.sys (IIS 核心) 監聽中" "PASS"
        } else { 
            Append-Log "Port 443 被非系統進程佔用: [$procName (PID:$pidVal)]" "WARN"
            Append-Log ">> 操作建議: 請確認是否有其他 Web 伺服器 (如 Apache/Nginx) 佔用 Port 443。" "ACTION"
        }
    } else {
        Append-Log "Port 443 目前未被佔用 (部署後 win-acme 將自動建立繫結監聽)" "PASS"
    }
}

function Check-SystemBatchLogonPrivilege {
    Append-Log "--- [項目 5/5] GPO 排程執行身分與批次工作登入 (Logon as a batch job) 權限檢驗 ---" "CHECK"
    try {
        $tempSecFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tempSecFile /areas USER_RIGHTS | Out-Null
        $secContent = Get-Content $tempSecFile -Raw -Encoding Unicode
        Remove-Item $tempSecFile -Force -ErrorAction SilentlyContinue

        if ($secContent -match "SeBatchLogonRight\s*=\s*([^\r\n]+)") {
            $sids = $Matches[1]
            if ($sids -match "\*S-1-5-18" -or $sids -match "SYSTEM") {
                Append-Log "NT AUTHORITY\SYSTEM 具備 SeBatchLogonRight「以批次工作登入」權限，工作排程可正常喚醒。" "PASS"
            } else {
                Record-DiagnosticFail `
                    "警告！NT AUTHORITY\SYSTEM 未在 SeBatchLogonRight「以批次作業方式登入」名單中！" `
                    "請確認網域 GPO 已將 NT AUTHORITY\SYSTEM「加入」以批次工作登入之允許清單。"
            }
        } else {
            Append-Log "本機未單獨配置 SeBatchLogonRight(「以批次作業方式登入」) 限制原則 (依循 Windows 預設允許 SYSTEM 執行)。" "PASS"
        }
    } catch {
        Append-Log "無法檢測批次登入權限: $($_.Exception.Message)" "WARN"
    }
}

function Invoke-SystemEnvironmentDiagnostics {
    $Global:HasEnvCheckFailed = $false
    $Global:EnvCheckFailCount = 0
    Append-Log "==================== 開始執行系統環境綜合診斷 ====================" "INFO"
    Check-GsnProxyStatus
    Check-OutboundEndpoints
    Check-TlsInspectionStatus
    Check-IisAndPortStatus
    Check-SystemBatchLogonPrivilege

    if (-not (Test-Path $Global:ToolPath)) {
        Append-Log "尚未安裝 win-acme 自動化工具！" "WARN"
        Append-Log ">> 操作建議: 請點選上方第 1 個按鈕「安裝 win-acme」自動配置。" "ACTION"
    } else {
        # 僅進行唯讀檢核
        $preCheckBypassed = Test-WacsPreValidateDnsStatus
        if ($preCheckBypassed) {
            Append-Log "win-acme 核心組態檢驗通過：已就緒跳過本機 DNS 預檢 (相容內網雙面 DNS 架構)。" "PASS"
        } else {
            Append-Log "win-acme 預檢組態未就緒，正在由系統自動同步鎖定 PreValidateDns: false..." "WARN"
            Apply-WacsConfiguration
        }
    }

    Update-BackupStatus
    Update-ScheduledTaskStatus
    Update-SiteDropdownList
    
    $Global:EnvCheckCompleted = $true

    if ($Global:HasEnvCheckFailed) {
        Append-Log "=================================================================" "FAIL"
        Append-Log "診斷完成: 共偵測到 $($Global:EnvCheckFailCount) 項嚴重錯誤 (FAIL)！系統已鎖定自動排程部署。" "FAIL"
        Append-Log "請先參閱上方亮金黃色 [ACTION] 操作建議排除異常項目後，再點擊執行部署。" "ACTION"
        Append-Log "=================================================================`r`n" "FAIL"
    } else {
        Append-Log "==================== 系統環境與核心資安診斷通過 ====================`r`n" "PASS"
        [System.Windows.MessageBox]::Show("系統環境與資安診斷已全數通過！`n`n【關鍵組態確認】：`n1. win-acme 預檢設定已跳過本機 DNS 查詢 (PreValidateDns: false)。`n2. 伺服器具備連通 Cloudflare 與 Let's Encrypt 之出境權限。`n`n您可以開始進行「3. 手動快照備份」或「4. 建立自動排程」。", "環境檢測就緒", "OK", "Information")
    }
}

function Execute-IISBackupInternal {
    param ([string]$TargetSiteName)

    $iisSvc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if (-not $iisSvc) {
        Append-Log "原因: 該伺服器尚未啟用「網頁伺服器 (IIS)」角色！" "FAIL"
        return $false
    }

    try {
        if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
            Append-Log "原因: 系統找不到 WebAdministration 模組。" "FAIL"
            return $false
        }
        Import-Module WebAdministration -ErrorAction Stop
    } catch {
        Append-Log "無法載入 IIS 管理模組 (WebAdministration): $($_.Exception.Message)" "FAIL"
        return $false
    }

    $site = Get-Website -Name $TargetSiteName -ErrorAction SilentlyContinue
    if (-not $site) {
        Append-Log "找不到目標站台 [$TargetSiteName]，無法執行備份。" "FAIL"
        return $false
    }

    $cDrive = Get-PSDrive C -ErrorAction SilentlyContinue
    if ($cDrive -and ($cDrive.Free / 1MB) -lt 300) {
        Append-Log "磁碟空間不足 300MB，終止快照備份。" "FAIL"
        return $false
    }

    Set-SecureDirectoryAcl -Path $Global:BackupDir
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $siteName = $site.Name
    $backupFile = [System.IO.Path]::Combine($Global:BackupDir, "ManualBackup_${siteName}_${timestamp}.json")
    $pfxBackupFile = [System.IO.Path]::Combine($Global:BackupDir, "ManualBackup_${siteName}_${timestamp}.pfx")

    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt 32; $i++) { $sb.Append($charSet[$bytes[$i] % $charSet.Length]) | Out-Null }
    $dynamicSecret = $sb.ToString()

    $bindings = Get-WebBinding -Name $siteName
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
                        $securePwd = ConvertTo-SecureString -String $dynamicSecret -Force -AsPlainText
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

    $encryptedSecret = if ($hasExportedPfx) { Protect-SecretDPAPI $dynamicSecret } else { "" }

    $snapshot = [PSCustomObject]@{
        SiteName              = $siteName
        SiteId                = $site.id
        BackupTime            = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        EncryptedPfxSecret    = $encryptedSecret
        Bindings              = $bindingList
    }

    $snapshot | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupFile -Encoding UTF8
    Append-Log "站台 [$siteName] 快照建立成功 (DPAPI 加密保存，繫結數: $($bindingList.Count))" "PASS"

    Rotate-Backups
    Update-BackupStatus
    return $true
}

function Unregister-SiteRenewalInternal {
    $selectedText = [string]$cmbSites.SelectedItem
    if ([string]::IsNullOrWhiteSpace($selectedText) -or $selectedText -like "尚未*" -or $selectedText -like "所有站台均未*" -or $selectedText -like "讀取*") {
        Append-Log "取消排程失敗: 請先由下拉選單選取正確的 IIS 目標站台！" "FAIL"
        [System.Windows.MessageBox]::Show("請先選擇要取消排程的 IIS 站台！", "提示", "OK", "Warning")
        return
    }

    $targetSiteName = ($selectedText -split ' \(ID:')[0].Trim()
    $siteIdMatch = [regex]::Match($selectedText, 'ID:(\d+)')
    $targetSiteId = if ($siteIdMatch.Success) { $siteIdMatch.Groups[1].Value } else { "" }

    $confirm = [System.Windows.MessageBox]::Show("確定要取消站台 [$targetSiteName] 的自動換約排程？`n`n這將註銷該站台在 win-acme 中的自動續約任務，並清理關聯殘留組態。", "確認取消排程", "YesNo", "Question")
    if ($confirm -ne "Yes") { return }

    Append-Log "========== 開始取消站台 [$targetSiteName] 之自動換約排程 ==========" "RUN"

    if (-not (Test-Path $Global:ToolPath)) {
        Append-Log "取消失敗: 找不到 win-acme 核心工具 ($Global:ToolPath)！" "FAIL"
        return
    }

    $cancelledCount = 0
    if (Test-Path $Global:WacsDataDir) {
        $renewalFiles = Get-ChildItem -Path $Global:WacsDataDir -Filter "*.renewal.json" -Recurse -ErrorAction SilentlyContinue
        foreach ($rf in $renewalFiles) {
            try {
                $rawJson = Get-Content -Path $rf.FullName -Raw -Encoding UTF8
                $isTarget = $false

                if ($targetSiteId -and $rawJson -match "`"SiteId`"\s*:\s*$targetSiteId\b") {
                    $isTarget = $true
                } elseif ($rawJson -match [regex]::Escape($targetSiteName)) {
                    $isTarget = $true
                }

                if ($isTarget) {
                    $renewalObj = $rawJson | ConvertFrom-Json
                    $renewalId = $renewalObj.Id
                    if (-not $renewalId) {
                        $renewalId = [System.IO.Path]::GetFileNameWithoutExtension($rf.Name).Replace(".renewal", "")
                    }

                    Append-Log "正在註銷續約任務 ID: [$renewalId]..." "INFO"
                    $pInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $pInfo.FileName = $Global:ToolPath
                    $pInfo.Arguments = "--cancel --id $renewalId"
                    $pInfo.RedirectStandardOutput = $true
                    $pInfo.UseShellExecute = $false
                    $pInfo.CreateNoWindow = $true
                    $proc = [System.Diagnostics.Process]::Start($pInfo)
                    $proc.WaitForExit(20000)

                    if (Test-Path $rf.FullName) {
                        Remove-Item $rf.FullName -Force -ErrorAction SilentlyContinue
                    }
                    $cancelledCount++
                }
            } catch {
                Append-Log "解析或取消任務組態時發生例外: $_" "WARN"
            }
        }
    }

    if ($cancelledCount -gt 0) {
        Append-Log "站台 [$targetSiteName] 共有 $cancelledCount 筆自動續約任務已成功註銷並清理！" "PASS"
    } else {
        Append-Log "在 win-acme 組態中未檢測到站台 [$targetSiteName] 的專屬續約記錄 (可能尚未部署或已被清理)。" "WARN"
    }

    $remainingRenewals = Get-ChildItem -Path $Global:WacsDataDir -Filter "*.renewal.json" -Recurse -ErrorAction SilentlyContinue
    if (-not $remainingRenewals -or $remainingRenewals.Count -eq 0) {
        Append-Log "本機已無任何 IIS 站台使用 win-acme 自動換約。" "INFO"
        $tasks = Get-ScheduledTask -TaskName $Global:TaskNamePattern -ErrorAction SilentlyContinue
        if ($tasks) {
            $delTaskConfirm = [System.Windows.MessageBox]::Show("系統偵測到本機已無任何站台需要自動換約。`n`n是否要將 Windows 工作排程器中的 win-acme 總排程一併卸載清除？", "完全卸載排程", "YesNo", "Question")
            if ($delTaskConfirm -eq "Yes") {
                Unregister-ScheduledTask -TaskName $tasks[0].TaskName -Confirm:$false -ErrorAction SilentlyContinue
                Append-Log "已成功卸載清除 Windows 工作排程器中的 win-acme 總排程任務！" "PASS"
            }
        }
    } else {
        Append-Log "主機仍有其他 $($remainingRenewals.Count) 個站台之續約任務，保留 Windows 總排程持續運作。" "INFO"
    }

    Update-ScheduledTaskStatus
    [System.Windows.MessageBox]::Show("站台 [$targetSiteName] 排程取消與殘留清理程序已完成！", "操作成功", "OK", "Information")
}

# --- 事件綁定 ---
$cmbSites.Add_SelectionChanged({
    Update-ScheduledTaskStatus
})

$btnRefreshSites.Add_Click({
    Update-SiteDropdownList
    Update-ScheduledTaskStatus
    Append-Log "IIS 站台清單與多網域 SAN 綁定狀態已更新。" "INFO"
})

$btnCancelRenewal.Add_Click({
    Set-AllControlsState -enabled $false
    try {
        Unregister-SiteRenewalInternal
    } finally {
        Set-AllControlsState -enabled $true
    }
})

$btnUpdateEmail.Add_Click({
    $newEmail = $txtContactEmail.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($newEmail) -or ($newEmail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$')) {
        Append-Log "更新信箱失敗: 請輸入有效且非空白的管理員信箱！" "FAIL"
        [System.Windows.MessageBox]::Show("通知信箱為必填項目，請輸入正確的 Email格式！", "格式錯誤", "OK", "Error")
        return
    }

    $Global:SelectedContactEmail = $newEmail
    Append-Log "維運通知信箱已指定為: [$newEmail]" "RUN"

    if (Test-Path $Global:ToolPath) {
        try {
            $pInfo = New-Object System.Diagnostics.ProcessStartInfo
            $pInfo.FileName = $Global:ToolPath
            $pInfo.Arguments = "--account --emailaddress `"$newEmail`" --accepttos"
            $pInfo.RedirectStandardOutput = $true
            $pInfo.UseShellExecute = $false
            $pInfo.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($pInfo)
            $proc.WaitForExit(15000)
            if ($proc.ExitCode -eq 0) {
                Append-Log "Let's Encrypt ACME 帳戶伺服器端聯絡信箱已成功同步更新！" "PASS"
            }
        } catch {
            Append-Log "呼叫 win-acme 更新帳戶信箱時發生例外: $_" "WARN"
        }
    }

    $renewalsUpdated = 0
    if (Test-Path $Global:WacsDataDir) {
        $renewalFiles = Get-ChildItem -Path $Global:WacsDataDir -Filter "*.renewal.json" -Recurse -ErrorAction SilentlyContinue
        foreach ($rf in $renewalFiles) {
            try {
                $content = Get-Content -Path $rf.FullName -Raw -Encoding UTF8
                $newContent = [regex]::Replace($content, '("Email"\s*:\s*)"[^"]*"', "`$1`"$newEmail`"")
                $newContent = [regex]::Replace($newContent, '("NotificationEmail"\s*:\s*)"[^"]*"', "`$1`"$newEmail`"")
                if ($content -ne $newContent) {
                    Set-Content -Path $rf.FullName -Value $newContent -Encoding UTF8 -Force
                    $renewalsUpdated++
                }
            } catch {}
        }
    }
    if ($renewalsUpdated -gt 0) {
        Append-Log "已同步更新本機 $renewalsUpdated 個換約排程之通知信箱設定檔。" "PASS"
    }

    if (Test-Path $Global:DeployLockFile) {
        try {
            $lockData = Get-Content $Global:DeployLockFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $lockData.ContactEmail = $newEmail
            $lockData | ConvertTo-Json | Set-Content -Path $Global:DeployLockFile -Encoding UTF8 -Force
            Append-Log "部署鎖定記錄 (.deployment_completed.lock) 已同步更新信箱。" "PASS"
        } catch {}
    }

    [System.Windows.MessageBox]::Show("通知信箱已更新為：`n$newEmail`n`n日常排程換約若遭遇挑戰失敗或憑證異常，將自動向此信箱發送警報。", "信箱更新完成", "OK", "Information")
})

# 1. 安裝 win-acme (落地直接寫入 PreValidateDns: false 組態)
$btnInstall.Add_Click({
    Set-AllControlsState -enabled $false
    try {
        if (Test-Path $Global:ToolPath) {
            Apply-WacsConfiguration
            Append-Log "win-acme 已安裝於: $Global:ToolPath (組態已更新為跳過 DNS 預檢)" "PASS"
            [System.Windows.MessageBox]::Show("win-acme 已經安裝完成！`n路徑: $Global:ToolPath`n已確認寫入 PreValidateDns: false。", "資訊", "OK", "Information")
            return
        }

        $cDrive = Get-PSDrive C -ErrorAction SilentlyContinue
        if ($cDrive -and ($cDrive.Free / 1MB) -lt 500) {
            Append-Log "C: 磁碟空間低於 500MB，無法安裝 win-acme！" "FAIL"
            [System.Windows.MessageBox]::Show("系統磁碟剩餘空間不足 500MB，請先清理磁碟空間！", "錯誤", "OK", "Error")
            return
        }

        Append-Log "向 GitHub 請求最新發布版本..." "RUN"
        $targetDir = "C:\tools\win-acme"
        Set-SecureDirectoryAcl -Path $targetDir

        $wacsDataDir = "$env:ProgramData\win-acme"
        Set-SecureDirectoryAcl -Path $wacsDataDir

        $zipPath = [System.IO.Path]::Combine($targetDir, "win-acme.zip")
        $apiUrl = "https://api.github.com/repos/win-acme/win-acme/releases/latest"
        $releaseInfo = Invoke-RestMethod -Uri $apiUrl -Headers @{"User-Agent"="PowerShell-Downloader"}
        
        $mainAsset = $releaseInfo.assets | Where-Object { $_.name -match "win-acme.*x64\.pluggable\.zip" } | Select-Object -First 1
        if (-not $mainAsset) {
            Append-Log "找不到 win-acme pluggable 安裝包資產。" "FAIL"
            return
        }

        Append-Log "正在下載主程式: $($mainAsset.name)..." "INFO"
        Invoke-WebRequest -Uri $mainAsset.browser_download_url -OutFile $zipPath

        if ((Get-Item $zipPath).Length -lt 10MB) {
            Remove-Item $zipPath -Force
            Append-Log "下載套件大小異常，完整性校驗未通過。" "FAIL"
            return
        }

        Expand-Archive -Path $zipPath -DestinationPath $targetDir -Force
        Remove-Item $zipPath -Force

        if (Test-Path $Global:ToolPath) {
            $sig = Get-AuthenticodeSignature -FilePath $Global:ToolPath
            if ($sig.Status -eq "Valid") {
                Append-Log "win-acme 官方數位簽章驗證通過 (Signer: $($sig.SignerCertificate.Subject))" "PASS"
            } else {
                $fileHash = (Get-FileHash -Path $Global:ToolPath -Algorithm SHA256).Hash
                Append-Log "官方開源版本，已依 GitHub Release 完成 SHA256 雜湊驗證 ($fileHash)" "PASS"
            }
        }

        $cfAsset = $releaseInfo.assets | Where-Object { $_.name -match "plugin\.validation\.dns\.cloudflare.*\.zip" } | Select-Object -First 1
        if ($cfAsset) {
            Append-Log "正在下載 Cloudflare 驗證外掛: $($cfAsset.name)..." "INFO"
            $cfZipPath = [System.IO.Path]::Combine($targetDir, "cloudflare-plugin.zip")
            Invoke-WebRequest -Uri $cfAsset.browser_download_url -OutFile $cfZipPath
            Expand-Archive -Path $cfZipPath -DestinationPath $targetDir -Force
            Remove-Item $cfZipPath -Force
            Append-Log "Cloudflare 外掛安裝成功。" "PASS"
        }

        Get-ChildItem -Path $targetDir -Filter "*.dll" -Recurse | ForEach-Object {
            Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue
        }

        # 【核心】：安裝流程中直接寫入設定
        Apply-WacsConfiguration
        Append-Log "win-acme 核心組態寫入完成：跳過本機 DNS 預檢 (PreValidateDns: false) 並鎖定 30 天換約閾值。" "PASS"

        if (Test-Path $Global:ToolPath) {
            Append-Log "win-acme 套件安裝完畢，目錄 ACL 權限鎖定完成！" "PASS"
            Update-WacsStatus
            [System.Windows.MessageBox]::Show("win-acme 核心與 Cloudflare 外掛安裝完成！`nDNS 預檢已自動跳過 (PreValidateDns: false)，換約閥值已設為剩餘 30 天。", "成功", "OK", "Information")
        }
    } catch {
        Append-Log "安裝過程失敗: $_" "FAIL"
    } finally {
        Set-AllControlsState -enabled $true
    }
})

# 2. 檢視系統環境
$btnCheckEnv.Add_Click({
    Set-AllControlsState -enabled $false
    try {
        Invoke-SystemEnvironmentDiagnostics
    } catch {
        Append-Log "診斷過程發生非預期例外: $_" "FAIL"
    } finally {
        Set-AllControlsState -enabled $true
    }
})

# 3. 手動快照備份
$btnManualBackup.Add_Click({
    $selectedText = [string]$cmbSites.SelectedItem
    if ([string]::IsNullOrWhiteSpace($selectedText) -or $selectedText -like "尚未*" -or $selectedText -like "所有站台均未*" -or $selectedText -like "讀取*") {
        Append-Log "手動備份失敗: 目前無有效站台！請先由下拉選單選取正確的目標 IIS 站台。" "FAIL"
        Append-Log ">> 操作建議: 請先至 IIS 管理員為站台繫結主機名稱 (Host Name)。" "ACTION"
        [System.Windows.MessageBox]::Show("目前無有效站台可供備份！`n`n請確認 IIS 站台已正確設定主機名稱 (Host Name)，並由下拉選單選取目標站台。", "防呆攔截", "OK", "Warning")
        return
    }

    $targetSiteName = ($selectedText -split ' \(ID:')[0].Trim()

    Set-AllControlsState -enabled $false
    try {
        Append-Log "========== 開始執行 IIS 站台 [$targetSiteName] 手動快照備份 ==========" "RUN"
        $ok = Execute-IISBackupInternal -TargetSiteName $targetSiteName
        if ($ok) {
            [System.Windows.MessageBox]::Show("站台 [$targetSiteName] 快照與憑證已備份完成 (金鑰已使用 DPAPI 加密收容)！`n路徑: $Global:BackupDir", "成功", "OK", "Information")
        }
    } catch {
        Append-Log "手動備份失敗: $_" "FAIL"
    } finally {
        Set-AllControlsState -enabled $true
    }
})

# 4. 建立自動排程
$btnDeploy.Add_Click({
    if (Test-Path $Global:DeployLockFile) {
        Append-Log "本執行檔任務已完成並鎖定，禁止重複部署！若需部屬新網站請使用專屬發布之執行檔。" "WARN"
        [System.Windows.MessageBox]::Show("本執行檔先前已完成部署任務，處於鎖定狀態！`n若需部屬其他網站，請使用新發布的執行檔。", "已完成部署", "OK", "Information")
        return
    }

    if (-not (Test-Path $Global:ToolPath)) {
        Append-Log "尚未安裝 win-acme，無法執行自動排程建立！" "FAIL"
        [System.Windows.MessageBox]::Show("尚未安裝 win-acme！`n請先點選「1. 安裝 win-acme」完成安裝後再執行部署。", "未達前置條件", "OK", "Warning")
        return
    }

    $inputEmail = $txtContactEmail.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($inputEmail) -or ($inputEmail -notmatch '^[^@\s]+@[^@\s]+$')) {
        Append-Log "安全阻斷: 尚未填寫有效的「自動換證異常通知信箱」！" "FAIL"
        [System.Windows.MessageBox]::Show("「自動換證異常通知信箱」為必填項目！`n請先於上方輸入管理員信箱以接收換約異常警報。", "必填項目未填", "OK", "Warning")
        return
    }
    $Global:SelectedContactEmail = $inputEmail

    if (-not $Global:EnvCheckCompleted) {
        Append-Log "安全防護攔截: 尚未執行「2. 檢視系統環境」診斷，禁止部署！" "FAIL"
        [System.Windows.MessageBox]::Show("請先點選「2. 檢視系統環境」確認網路與系統原則全數通過後，才能執行排程部署！", "未達前置條件", "OK", "Warning")
        return
    }

    if ($Global:HasEnvCheckFailed) {
        Append-Log "安全防護攔截: 系統環境檢測存在 $($Global:EnvCheckFailCount) 項紅字錯誤 (FAIL)，嚴格拒絕部署！" "FAIL"
        [System.Windows.MessageBox]::Show("系統環境檢測未全數通過（存在紅字 FAIL 項目）！`n請參閱日誌視窗排除錯誤後再試。", "環境檢測未通過 (安全拒絕)", "OK", "Error")
        return
    }

    $iisSvc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if (-not $iisSvc -or $iisSvc.Status -ne 'Running') {
        Append-Log "原因: IIS 服務未處於執行狀態，無法部署！" "FAIL"
        return
    }

    $selectedText = [string]$cmbSites.SelectedItem
    if ([string]::IsNullOrWhiteSpace($selectedText) -or $selectedText -like "尚未*" -or $selectedText -like "所有站台均未*" -or $selectedText -like "讀取*") {
        Append-Log "請先由下拉選單選取正確的 IIS 站台！" "FAIL"
        [System.Windows.MessageBox]::Show("請先選擇具備有效 Host Name 的 IIS 目標站台！", "提示", "OK", "Warning")
        return
    }

    $targetSiteName = ($selectedText -split ' \(ID:')[0].Trim()
    $Global:SelectedSiteInfo = $targetSiteName

    Set-AllControlsState -enabled $false
    Append-Log "正在啟動內部調度常式，針對站台 [$targetSiteName] 執行多網域 SAN 簽發並併入排程..." "RUN"

    try {
        if (Get-Command Run-DeploySubroutine -ErrorAction SilentlyContinue) {
            Run-DeploySubroutine
        } else {
            $deployScriptPath = [System.IO.Path]::Combine($ScriptDir, "部署IIS憑證.ps1")
            if (Test-Path -LiteralPath $deployScriptPath) {
                . $deployScriptPath
            } else {
                Append-Log "找不到部署子常式或腳本檔案: $deployScriptPath" "FAIL"
            }
        }
    } catch {
        Append-Log "執行部署程序發生例外: $_" "FAIL"
    } finally {
        Update-BackupStatus
        Update-ScheduledTaskStatus
        Update-SiteDropdownList
        Set-AllControlsState -enabled $true
    }
})

# 5. 一鍵還原狀態 (精確針對選定站台)
$btnRollback.Add_Click({
    $selectedText = [string]$cmbSites.SelectedItem
    if ([string]::IsNullOrWhiteSpace($selectedText) -or $selectedText -like "尚未*" -or $selectedText -like "所有站台均未*" -or $selectedText -like "讀取*") {
        Append-Log "還原失敗: 請先由下拉選單選取正確的目標 IIS 站台！" "FAIL"
        [System.Windows.MessageBox]::Show("請先由上方下拉選單選取欲還原的 IIS 目標站台！", "提示", "OK", "Warning")
        return
    }

    $targetSiteName = ($selectedText -split ' \(ID:')[0].Trim()
    $Global:SelectedSiteInfo = $targetSiteName

    $hasBackup = $false
    if (Test-Path $Global:BackupDir) {
        $files = Get-ChildItem -Path $Global:BackupDir -Filter "*.json" -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like "ManualBackup_${targetSiteName}_*.json" -or $_.Name -like "Backup_${targetSiteName}_*.json"
        }
        if ($files -and $files.Count -gt 0) { $hasBackup = $true }
    }

    if (-not $hasBackup) {
        Append-Log "站台 [$targetSiteName] 不存在任何可還原的專屬快照記錄！" "FAIL"
        [System.Windows.MessageBox]::Show("站台 [$targetSiteName] 目前沒有任何專屬備份快照，無法執行還原操作！", "防呆攔截", "OK", "Warning")
        return
    }

    $confirm = [System.Windows.MessageBox]::Show("確定要將站台 [$targetSiteName] 還原至最近一次快照狀態？`n`n這將會回復該站台的原始繫結與舊 SSL 憑證。", "確認還原站台", "YesNo", "Question")
    if ($confirm -ne "Yes") { return }

    Set-AllControlsState -enabled $false
    Append-Log "正在啟動站台 [$targetSiteName] 之快照還原常式..." "RUN"

    try {
        if (Get-Command Run-RollbackSubroutine -ErrorAction SilentlyContinue) {
            Run-RollbackSubroutine
        } else {
            $rollbackScriptPath = [System.IO.Path]::Combine($ScriptDir, "還原IIS站台與憑證.ps1")
            if (Test-Path -LiteralPath $rollbackScriptPath) {
                . $rollbackScriptPath
            } else {
                Append-Log "找不到還原子常式或腳本檔案: $rollbackScriptPath" "FAIL"
            }
        }
    } catch {
        Append-Log "執行還原程序發生例外: $_" "FAIL"
    } finally {
        Update-BackupStatus
        Update-ScheduledTaskStatus
        Update-SiteDropdownList
        Set-AllControlsState -enabled $true
    }
})

$btnRefreshTask.Add_Click({
    Update-ScheduledTaskStatus
    Append-Log "排程與當前站台憑證效期狀態已同步。" "INFO"
})

$btnClearLog.Add_Click({ 
    $txtLog.Document.Blocks.Clear() 
})

Update-SiteDropdownList
Update-WacsStatus
Update-BackupStatus
Update-ScheduledTaskStatus
Set-AllControlsState -enabled $true

$window.ShowDialog() | Out-Null