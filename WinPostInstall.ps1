##
# Script parameters
#
# Debug: Enable debugging output
# Extra: Run extra tweaks
# Reboot: Reboot the system
##
param (
	[switch]$Debug = $false,
	[switch]$Reboot = $false
)

$Version = "0.4"

$Logo = @"

###################################
             Windows 
			
        Post Install Script
		
 Version: $Version
###################################

"@

$WSLDistro = "Debian"

# Apps to install
$WingetAppList = @(
	"Mozilla.Firefox", 
	"GoLang.Go",
	"Python.Python.3.13",
	"Discord.Discord",
	"Element.Element",
	"Oracle.VirtualBox",
	"Notepad++.Notepad++",
	"Brave.Brave",
	"TheDocumentFoundation.LibreOffice",
	"7zip.7zip",
	"AppWork.JDownloader", 
	"Microsoft.VisualStudio.2022.Community",
	"Mozilla.Thunderbird",
	"Microsoft.WindowsTerminal",
	"Valve.Steam",
	"VideoLAN.VLC",
	"ShareX.ShareX",
	"Cygwin.Cygwin",
	"MSYS2.MSYS2",
	"vim.vim",
    "qBittorrent.qBittorrent",
	"Rainmeter.Rainmeter",
	"MullvadVPN.MullvadVPN",
	"OBSProject.OBSStudio",
	"Microsoft.Sysinternals.ProcessExplorer",
	"Microsoft.Sysinternals.TCPView",
	"Microsoft.Sysinternals.Autoruns",
	"KeePassXCTeam.KeePassXC",
	"AutoHotkey.AutoHotkey",
	"IDRIX.VeraCrypt",
	"TorProject.TorBrowser",
	"voidtools.Everything",
	"HandBrake.HandBrake",
	"OpenWhisperSystems.Signal",
	"OpenVPNTechnologies.OpenVPNConnect",
	"TeamViewer.TeamViewer",
	"VSCodium.VSCodium",
	"SumatraPDF.SumatraPDF"
)

# App Paths to add
$Paths = @(
	"C:\Windows\Microsoft.NET\Framework\v4.0.30319",
	"C:\Program Files (x86)\Vim\vim91"
)

##
# Global variables
# Path to the Applications to install and logfile path
##
$LogFile = "PostInstall.log"
$LogPath = (Get-Location).Path + "\" + $LogFile

function Write-Log {
    param (
        $Message
    )
	
	$Time = Get-Date -Format "dd/MM/yyyy - HH:mm"

    Write-Output "[$Time] [INFO] $Message" | Tee-Object -Append -FilePath $LogPath
}

function Write-DebugMsg {
	param (
        $Message
    )
	
	if($Debug) {
		$Time = Get-Date -Format "dd/MM/yyyy - HH:mm"
	
		Write-Output "[$Time] [DEBUG] $Message" | Tee-Object -Append -FilePath $LogPath
	}
}

function Run-AsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $IsAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

	if ($IsAdmin -eq $false)  {
		Write-Host "[ERROR] You need admin rights to run some of the functions - Exiting!"
		exit
	}
}

# Needed to get the Windows Update PS Module
function Install-NuGET {
    Install-PackageProvider -Name NuGet -Force
}

function Install-WindowsUpdates {
	Write-Log "Running Windows Update"
	
	# Windows Update PS Module
    Install-Module -Name PSWindowsUpdate -Force

	# Get all Updates
	Get-WindowsUpdate -Confirm -AcceptAll

	# Do all upgrades
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm -IgnoreReboot
}

function Run-Winutil {
	& ([scriptblock]::Create((irm "https://christitus.com/win"))) -RunDefaults -Silent
}

function Run-Debloat {
	# Source: https://github.com/Raphire/Win11Debloat

	Write-Log "Debloating Windows"

	# Execute external script directly
	& ([scriptblock]::Create((irm "https://win11debloat.raphi.re/"))) -RunDefaults -Silent
}

function Set-PowerSettings {
    Write-Log "Tweaking Power Management"

    # Set High Performance profile
    powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    
    # Disable monitor timeout
    powercfg.exe /change monitor-timeout-ac 0
    powercfg.exe /change monitor-timeout-dc 0

    # Disable standby timeout
    powercfg.exe /change standby-timeout-ac 0
    powercfg.exe /change standby-timeout-dc 0

    # Disable hibernate timeout
    powercfg.exe /change hibernate-timeout-ac 0
    powercfg.exe /change hibernate-timeout-dc 0

    # Disable hibernate
    powercfg.exe /hibernate off
}

function Install-winget-Updates {
    Write-Log "Updating via winget"

	# Upgrade everything
    winget upgrade --all --force --accept-package-agreements --accept-source-agreements
}

function Install-WingetApplications {
	foreach($app in $WingetAppList) {
		winget install --accept-package-agreements --accept-source-agreements --id $app
	}
}

function Alter-PathVariable {
	Write-Log "Adding PATH entries"
	
	foreach($path in $Paths) {
		$CurrentPATH = ([Environment]::GetEnvironmentVariable("PATH", 1)).Split(";")

        if($CurrentPATH.Contains($path)) {
            continue
        }

		$NewPATH = ($CurrentPATH + $Path) -Join ";"
        Write-Host $NewPATH
		[Environment]::SetEnvironmentVariable("PATH", $NewPATH, [EnvironmentVariableTarget]::User) 
	}
}

function Set-OEMInformation {
	Write-Log "Setting OEM information (Registry)"
	
    $OEMRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation"

    Set-ItemProperty -Path $OEMRegPath -Name Manufacturer -Value "Home Corp"
    Set-ItemProperty -Path $OEMRegPath -Name SupportPhone -Value "42"
    Set-ItemProperty -Path $OEMRegPath -Name Model -Value "PC"
    Set-ItemProperty -Path $OEMRegPath -Name SupportURL -Value "home.lan"
    Set-ItemProperty -Path $OEMRegPath -Name SupportHours -Value "Always" 
    Set-ItemProperty -Path $OEMRegPath -Name HelpCustomized -Value 0
}

function Disable-Telemetry {
	Write-Log "Disabling Telemetry"

	Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
	Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
	Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
	Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
	Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type Dword -Value 0
	Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type Dword -Value 1
}

function Install-WSL {
	dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
	dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

	wsl --install -d $WSLDistro
}

function Restart-System {
	Write-Log "Rebooting"
	
	Restart-Computer
}

function Set-ClockToUTCTime {
	Write-Log "Setting clock to UTC time"
	
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1 
	
	net start "Windows Time"
	w32tm /resync
}

function Disable-FastStartup {
	Write-Log "Disabling Fast Startup"
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

function Show-KnownExtensions {
	Write-Log "Showing known file extensions..."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

function Show-HiddenFiles {
	Write-Log "Showing hidden files"
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

function Disable-RecentFiles {
	Write-Log "Disable Recent Files (Explorer)"

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
}

function Disable-FrequentFiles {
	Write-Log "Disable Frequent Files (Explorer)"

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

function Show-SuperHiddenFiles {
	Write-Log "Showing super hidden files"
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1
}

function Enable-GodMode {
	Write-Log "Enabling God Mode (Desktop Shortcut)"

	if(Test-Path -Path "$HOME\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}") {
		return
	} else {
		New-Item -Path "$HOME\Desktop" -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType "Directory" | Out-Null
	}
}

function Display-Logo {
	Write-Host $Logo
}

##
# Script block
##
$script = {
	Run-AsAdmin

	Display-Logo
	
	Write-Log "Starting..."
	
	Write-DebugMsg $LogPath
	
	# Run debloat script
	Run-Debloat

	# Builtin functions
	Set-ClockToUTCTime
	Set-PowerSettings
	Install-WingetApplications
	Install-winget-Updates
	Install-NuGET
	Install-WindowsUpdates
	Alter-PathVariable
	Set-OEMInformation
	Disable-Telemetry
	Show-KnownExtensions
	Show-HiddenFiles
	Disable-FastStartup
	Disable-RecentFiles
	Disable-FrequentFiles
	Install-WSL
	Show-SuperHiddenFiles
	Enable-GodMode
	
	# Run winutil
	Run-Winutil
	
	Write-Log "Done!"

	if($Reboot) {
		Write-Log "Rebooting system"

		Restart-System
	}
}

##
# Main
##
Invoke-Command -Scriptblock $script