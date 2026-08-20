#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Reduces the background noise of a Windows 10/11 analysis guest.

.DESCRIPTION
    Removes/neuters the components that keep spawning processes while a sample is
    detonating. Every process family in the list below shows up in behavioural
    reports (and feeds signature false positives) even on an idle VM:

      MicrosoftEdgeUpdate.exe, MicrosoftEdgeUpdateSetup_*.exe,
      MicrosoftEdgeUpdateComRegisterShell.exe      -> Edge / WebView2 updater
      MusNotification.exe, MoUsoCoreWorker.exe,
      sc.exe start wuauserv, sc.exe start pushtoinstall registration,
      svchost.exe -s UsoSvc / -s WaaSMedicSvc      -> Windows Update stack
      devicecensus.exe, CompatTelRunner.exe        -> telemetry / census
      clipesu.exe                                  -> ESU licence validation
      svchost.exe -k WerSvcGroup, WerFault.exe     -> Windows Error Reporting
      svchost.exe -s WdiSystemHost/WdiServiceHost  -> diagnostic policy service
      svchost.exe -s PcaSvc                        -> program compat assistant
      svchost.exe -s dmwappushservice / -s SmsRouter
      svchost.exe -k UnistackSvcGroup              -> per-user sync/store services

    Uninstalling Edge and WebView2 only removes the first family. The rest are
    independent Windows features and have to be switched off separately, which is
    what the remaining sections of this script do.

.PARAMETER KeepEdge
    Do not uninstall Edge/WebView2. The updater service, its scheduled tasks and
    its update policies are still disabled, so the MicrosoftEdgeUpdate.exe family
    stops appearing. Use this when a package needs a Chromium browser in the guest.

.PARAMETER KeepUserServices
    Do not disable the per-user template services hosted in UnistackSvcGroup
    (CDPUserSvc, OneSyncSvc, UnistoreSvc, ...). These are the noisiest remaining
    svchost instances, but disabling them also breaks the Mail/People/notification
    stack, so skip this section if a package depends on it.

.NOTES
    Run this before taking the clean snapshot, and take a snapshot beforehand too
    so you can roll back. A guest with every one of these features stripped is
    itself a weak sandbox indicator, so drop the sections you do not need.

    Related reading:
      https://github.com/ntdevlabs/tiny11builder
      https://github.com/W4RH4WK/Debloat-Windows-10/tree/master
#>

[CmdletBinding()]
param(
    [switch]$KeepEdge,
    [switch]$KeepUserServices
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Set-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [ValidateSet("DWord", "QWord", "String", "ExpandString", "MultiString", "Binary")]
        [string]$Type = "DWord"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Disable-GuestService {
    param([Parameter(Mandatory = $true)][string[]]$Name)

    foreach ($service in $Name) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
        if (-not (Test-Path $key)) {
            Write-Verbose "  service not present: $service"
            continue
        }

        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        # sc.exe/Set-Service is refused for protected services such as WaaSMedicSvc,
        # writing Start=4 (SERVICE_DISABLED) directly always works.
        Set-RegValue -Path $key -Name "Start" -Value 4
        Write-Output "  disabled service: $service"
    }
}

function Disable-GuestTask {
    param(
        [Parameter(Mandatory = $true)][string]$TaskPath,
        [string]$TaskName = "*"
    )

    $tasks = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        $label = "$($task.TaskPath)$($task.TaskName)"
        try {
            Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
            Write-Output "  disabled task: $label"
        }
        catch {
            # Most UpdateOrchestrator/WindowsUpdate tasks are owned by TrustedInstaller
            # and refuse to be disabled. The matching service is disabled anyway.
            Write-Warning "  could not disable task: $label"
        }
    }
}

# ---------------------------------------------------------------------------
# Windows Defender
# ---------------------------------------------------------------------------
# Tamper Protection makes both of these no-ops. Turn it off in the Security
# Center UI first, otherwise Defender keeps scanning and deleting samples.
#   Get-MpComputerStatus   -> current state
#   Get-MpPreference       -> current preferences

Write-Output "Disabling Windows Defender features..."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1
try {
    Set-MpPreference -ExclusionPath C:\ -DisableRemovableDriveScanning $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction Stop
}
catch {
    Write-Warning "  Set-MpPreference failed, Tamper Protection is probably still enabled"
}
Disable-GuestService -Name @("WdNisSvc", "Sense", "SecurityHealthService", "wscsvc")
Disable-GuestTask -TaskPath "\Microsoft\Windows\Windows Defender\"

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
# https://www.alitajran.com/disable-windows-firewall-with-powershell/

Write-Output "Disabling Firewall..."
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

# ---------------------------------------------------------------------------
# SmartScreen and IE zone hardening
# ---------------------------------------------------------------------------
# https://stackoverflow.com/a/68843405

Write-Output "Disabling SmartScreen Filter..."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 0

Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "Security_HKLM_only" -Value 0
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2301" -Value 3

# ---------------------------------------------------------------------------
# Microsoft Edge, WebView2 and the Edge updater
# ---------------------------------------------------------------------------
# Source of MicrosoftEdgeUpdate.exe /svc /ping /regsvc /regserver, of
# MicrosoftEdgeUpdateSetup_X86_*.exe and of MicrosoftEdgeUpdateComRegisterShell.exe.
# The updater is installed and driven independently of Edge itself, so it has to
# be disabled explicitly even when Edge and WebView2 are gone: Windows Update and
# any Chromium-based installer will happily bring it back otherwise.
# https://superuser.com/a/1767126

Write-Output "Disabling the Edge updater..."

$edgeUpdateGuids = @{
    "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" = "Edge Stable"
    "{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" = "Edge Beta"
    "{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" = "Edge Dev"
    "{65C35B14-6C1D-4122-AC46-7148CC9D6497}" = "Edge Canary"
    "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" = "WebView2 Runtime"
}

# EdgeUpdate is a 32-bit process, so it reads policies from the WOW6432Node view.
foreach ($hive in @("HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate", "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\EdgeUpdate")) {
    Set-RegValue -Path $hive -Name "UpdateDefault" -Value 0
    Set-RegValue -Path $hive -Name "InstallDefault" -Value 0
    Set-RegValue -Path $hive -Name "AutoUpdateCheckPeriodMinutes" -Value 0
    Set-RegValue -Path $hive -Name "DoNotUpdateToEdgeWithChromium" -Value 1
    foreach ($guid in $edgeUpdateGuids.Keys) {
        Set-RegValue -Path $hive -Name "Update$guid" -Value 0
        Set-RegValue -Path $hive -Name "Install$guid" -Value 0
    }
}
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Value 1

Disable-GuestService -Name @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
Disable-GuestTask -TaskPath "\" -TaskName "MicrosoftEdgeUpdateTask*"

# Edge is 32-bit on x64 hosts and 64-bit on arm64 ones, look in both roots.
$edgeRoots = @("${env:ProgramFiles(x86)}\Microsoft", "$env:ProgramFiles\Microsoft")

$Process2Monitor = "MicrosoftEdgeUpdate"
For ($i = 0; $i -lt 5; $i++) {
    $ProcessesFound = Get-Process | Where-Object { $Process2Monitor -contains $_.Name } | Select-Object -ExpandProperty Name
    If ($ProcessesFound) { "Microsoft Edge updater running... Killing it" | Write-Host; Stop-Process -Name $Process2Monitor -Force; Break } else { "Microsoft Edge updater not running. Retrying in 1 second..." | Write-Host; Start-Sleep -Seconds 1 }
}

Write-Host "Waiting for Microsoft Edge update to finish (60s Timeout)"
For ($i = 0; $i -lt 60; $i++) {
    $ProcessesFound = Get-Process | Where-Object { $Process2Monitor -contains $_.Name } | Select-Object -ExpandProperty Name
    If ($ProcessesFound) { "Microsoft Edge updater running... waiting its finish..." | Write-Host; Start-Sleep -Seconds 1 } else { "Microsoft Edge updater finished." | Write-Host; Break }
}

if (-not $KeepEdge) {
    Write-Output "Uninstalling WebView2 and Edge..."

    # The system-level installer refuses to uninstall unless this is set.
    Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdateDev" -Name "AllowUninstall" -Value 1
    Set-RegValue -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev" -Name "AllowUninstall" -Value 1

    # WebView2 first: Edge's uninstaller leaves it behind, and it ships its own
    # copy of the updater.
    foreach ($setup in (Get-ChildItem -Path ($edgeRoots | ForEach-Object { "$_\EdgeWebView\Application\*\Installer\setup.exe" }) -ErrorAction SilentlyContinue)) {
        Write-Output "  running $($setup.FullName) --uninstall --msedgewebview"
        Start-Process -FilePath $setup.FullName -ArgumentList "--uninstall", "--msedgewebview", "--system-level", "--verbose-logging", "--force-uninstall" -Wait -NoNewWindow
    }

    foreach ($setup in (Get-ChildItem -Path ($edgeRoots | ForEach-Object { "$_\Edge\Application\*\Installer\setup.exe" }) -ErrorAction SilentlyContinue)) {
        Write-Output "  running $($setup.FullName) --uninstall"
        Start-Process -FilePath $setup.FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait -NoNewWindow
    }

    # The Edge appx stub relaunches the installer on first logon.
    Get-AppxPackage -AllUsers -Name "Microsoft.MicrosoftEdge*" -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -like "Microsoft.MicrosoftEdge*" } | ForEach-Object {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null
    }
}

# Whatever the uninstaller left behind must not be startable any more.
foreach ($root in $edgeRoots) {
    $updater = "$root\EdgeUpdate\MicrosoftEdgeUpdate.exe"
    if (Test-Path $updater) {
        Rename-Item -Path $updater -NewName MicrosoftEdgeUpdateDisabled.exe -Force
    }
}

# ---------------------------------------------------------------------------
# Windows Update / servicing stack
# ---------------------------------------------------------------------------
# Source of MusNotification.exe, MusNotificationUx.exe, MoUsoCoreWorker.exe,
# "sc.exe start wuauserv" and "sc.exe start pushtoinstall registration" under
# svchost -k netsvcs -s Schedule. Independent of Edge.

Write-Output "Disabling Windows Update..."
Disable-GuestService -Name @(
    "wuauserv"        # Windows Update
    "UsoSvc"          # Update Orchestrator, spawns MusNotification.exe
    "WaaSMedicSvc"    # Update Medic, re-enables the two above if it can
    "PushToInstall"   # target of "sc start pushtoinstall registration"
    "DoSvc"           # Delivery Optimization
    "BITS"
    "InstallService"  # Microsoft Store Install Service
)

Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisableUXWUAccess" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetUpdateNotificationLevel" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateNotificationLevel" -Value 2
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Value 1

# Delivery Optimization: "simple mode", no peering traffic in the pcap.
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 100

# Driver lookups on Windows Update whenever a device is enumerated.
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0

Disable-GuestTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\WindowsUpdate\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\InstallService\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\WaaSMedic\"

# Store app auto-update, another "sc start" / AppX install source.
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Name "AutoDownload" -Value 5
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

# ---------------------------------------------------------------------------
# Telemetry, census and licensing
# ---------------------------------------------------------------------------
# Source of devicecensus.exe, CompatTelRunner.exe and clipesu.exe.

Write-Output "Disabling telemetry via Group Policies"
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 0
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0

Disable-GuestService -Name @("DiagTrack", "dmwappushservice", "diagnosticshub.standardcollector.service", "DusmSvc")

Write-Host "Block scheduled telemetry tasks"
# See reference: https://answers.microsoft.com/en-us/windows/forum/windows_10-performance/permanently-disabling-windows-compatibility/6bf71583-81b0-4a74-ae2e-8fd73305aad1
Disable-GuestTask -TaskPath "\Microsoft\Windows\Application Experience\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Feedback\Siuf\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Device Information\"   # devicecensus.exe
Disable-GuestTask -TaskPath "\Microsoft\Windows\Clip\"                 # clipesu.exe
Disable-GuestTask -TaskPath "\Microsoft\Windows\Autochk\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Maintenance\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Servicing\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Flighting\*"
Disable-GuestTask -TaskPath "\" -TaskName "OneDrive*"

# ---------------------------------------------------------------------------
# Windows Error Reporting
# ---------------------------------------------------------------------------
# Source of svchost -k WerSvcGroup and of WerFault.exe popups that hold a crashed
# sample open until the analysis times out.

Write-Output "Disabling Windows Error Reporting..."
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "DontShowUI" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
Disable-GuestService -Name @("WerSvc", "wercplsupport")
Disable-GuestTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\"

# ---------------------------------------------------------------------------
# Diagnostic Policy Service
# ---------------------------------------------------------------------------
# Source of svchost -s WdiSystemHost and -s WdiServiceHost. Both are started by
# DPS, so disabling DPS removes the whole group.

Write-Output "Disabling diagnostics..."
Disable-GuestService -Name @("DPS", "WdiServiceHost", "WdiSystemHost")
Disable-GuestTask -TaskPath "\Microsoft\Windows\Diagnosis\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\DiskDiagnostic\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\MemoryDiagnostic\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\WDI\"

# ---------------------------------------------------------------------------
# Program Compatibility Assistant
# ---------------------------------------------------------------------------
# Source of svchost -s PcaSvc. It also pops the "this program didn't install
# correctly" dialog over the desktop mid-analysis.

Write-Output "Disabling Program Compatibility Assistant..."
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1
Set-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
Disable-GuestService -Name @("PcaSvc")

# ---------------------------------------------------------------------------
# Mobile broadband / device management services
# ---------------------------------------------------------------------------
# Source of svchost -s SmsRouter and -s dmwappushservice. Useless in a VM.

Write-Output "Disabling SMS router and device management push..."
Disable-GuestService -Name @("SmsRouter", "SEMgrSvc", "dmwappushservice")
Disable-GuestTask -TaskPath "\Microsoft\Windows\Management\Provisioning\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Workplace Join\"

# ---------------------------------------------------------------------------
# Per-user services (UnistackSvcGroup)
# ---------------------------------------------------------------------------
# Source of svchost -k UnistackSvcGroup. These are template services: the running
# instances are named <Template>_<luid>, so they must be disabled on the template
# key. Skipping them only costs a couple of idle svchost entries.

if (-not $KeepUserServices) {
    Write-Output "Disabling UnistackSvcGroup per-user services..."
    Disable-GuestService -Name @(
        "CDPUserSvc"
        "CDPSvc"
        "OneSyncSvc"
        "MessagingService"
        "PimIndexMaintenanceSvc"
        "UnistoreSvc"
        "UserDataSvc"
        "WpnUserService"
        "WpnService"
    )
}

# ---------------------------------------------------------------------------
# Automatic Maintenance
# ---------------------------------------------------------------------------
# The idle-time trigger behind most of the tasks above. Disabling it stops
# anything newly installed from sneaking back in through a maintenance window.

Write-Output "Disabling Automatic Maintenance..."
Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1
Disable-GuestTask -TaskPath "\Microsoft\Windows\TaskScheduler\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Defrag\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Chkdsk\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\SpacePort\"
Disable-GuestTask -TaskPath "\Microsoft\Windows\Windows Media Sharing\"

<#
# CAPE agent.py autoinstall
$jobname = "Recurring PowerShell Task"
$script =  "w32tm /resync"
$action = New-ScheduledTaskAction -Execute "$pshome\powershell.exe" -Argument  "$script"
$duration = ([timeSpan]::maxvalue)
$repeat = (New-TimeSpan -hours 3)
$trigger =New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration


$msg = "Enter the username and password that will run the task";
$credential = $Host.UI.PromptForCredential("Task username and password",$msg,"$env:userdomain\$env:username",$env:userdomain)
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
 Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -RunLevel Highest -User $username -Password $password -Settings $settings
#>

if (Test-Path "C:\Users\Default\AppData\Local\Microsoft\WindowsApp") {
    Write-Output "Remove WindowsApp to prevent MS StoreStartup"
    Remove-Item -path "C:\Users\Default\AppData\Local\Microsoft\WindowsApp" -recurse
}

Write-Output ""
Write-Output "Done. Reboot, let the VM idle for a few minutes, then confirm with:"
Write-Output "  Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Sort-Object Name"
Write-Output "before taking the clean snapshot."
