##
# Script parameters
#
# Debug: Enable debugging output
# Extra: Run extra tweaks
# Reboot: Reboot the system
##
param (
	[switch]$Debug = $false,
	[switch]$Extra = $false,
	[switch]$Reboot = $false
)

$Version = "0.1"

$Logo = @"

###################################
             Windows 
			
        Post Install Script
		
 Version: $Version
###################################

"@

# Apps to remove
$AppList = @(
    'Microsoft.3DBuilder',
	'Microsoft.Microsoft3DViewer',
	'Microsoft.Print3D',
	'Microsoft.Appconnector',
	'Microsoft.BingFinance',
	'Microsoft.BingNews',
	'Microsoft.BingSports',
	'Microsoft.BingTranslator',
	'Microsoft.BingWeather',
	'Microsoft.BingFoodAndDrink',
	'Microsoft.BingTravel',
	'Microsoft.BingHealthAndFitness',
	'Microsoft.FreshPaint',
	'Microsoft.MicrosoftOfficeHub',
	'Microsoft.WindowsFeedbackHub',
	'Microsoft.MicrosoftSolitaireCollection',
	'Microsoft.MicrosoftPowerBIForWindows',
	'Microsoft.MinecraftUWP',
	'Microsoft.MicrosoftStickyNotes',
	'Microsoft.NetworkSpeedTest',
	'Microsoft.Office.OneNote',
	'Microsoft.OneConnect',
	'Microsoft.People',
	'Microsoft.SkypeApp',
	'Microsoft.Wallet',
	'Microsoft.WindowsAlarms',
	'Microsoft.WindowsCamera',
	'Microsoft.windowscommunicationsapps',
	'Microsoft.WindowsMaps',
	'Microsoft.WindowsPhone',
	'Microsoft.WindowsSoundRecorder',
	'Microsoft.XboxApp',
	'Microsoft.XboxGameOverlay',
	'Microsoft.XboxIdentityProvider',
	'Microsoft.XboxSpeechToTextOverlay',
	'Microsoft.ZuneMusic',
	'Microsoft.ZuneVideo',
	'Microsoft.CommsPhone',
	'Microsoft.ConnectivityStore',
	'Microsoft.GetHelp',
	'Microsoft.Getstarted',
	'Microsoft.Messaging',
	'Microsoft.Office.Sway',
	'Microsoft.WindowsReadingList',
	'9E2F88E3.Twitter',
	'PandoraMediaInc.29680B314EFC2',
	'Flipboard.Flipboard',
	'ShazamEntertainmentLtd.Shazam',
	'king.com.CandyCrushSaga',
	'king.com.CandyCrushSodaSaga',
	'king.com.*',
	'ClearChannelRadioDigital.iHeartRadio',
	'4DF9E0F8.Netflix',
	'6Wunderkinder.Wunderlist',
	'Drawboard.DrawboardPDF',
	'2FE3CB00.PicsArt-PhotoStudio',
	'D52A8D61.FarmVille2CountryEscape',
	'TuneIn.TuneInRadio',
	'GAMELOFTSA.Asphalt8Airborne',
	'TheNewYorkTimes.NYTCrossword',
	'DB6EA5DB.CyberLinkMediaSuiteEssentials',
	'Facebook.Facebook',
	'flaregamesGmbH.RoyalRevolt2',
	'Playtika.CaesarsSlotsFreeCasino',
	'A278AB0D.MarchofEmpires',
	'KeeperSecurityInc.Keeper',
	'ThumbmunkeysLtd.PhototasticCollage',
	'XINGAG.XING',
	'89006A2E.AutodeskSketchBook',
	'D5EA27B7.Duolingo-LearnLanguagesforFree',
	'46928bounde.EclipseManager',
	'ActiproSoftwareLLC.562882FEEB491',
	'DolbyLaboratories.DolbyAccess',
	'A278AB0D.DisneyMagicKingdoms',
	'WinZipComputing.WinZipUniversal',
	'Microsoft.ScreenSketch',
	'Microsoft.XboxGamingOverlay',
	'Microsoft.Xbox.TCUI',
	'Microsoft.YourPhone',
	'HP Wolf Security',
	'HP Wolf Security Application Support for Sure Sense',
	'HP Wolf Security Application Support for Windows',
	'Hp Wolf Security - Console',
	'ExpressVPN',
	'ACGMediaPlayer',
    'ActiproSoftwareLLC',
    'AdobePhotoshopExpress',
    'Amazon.com.Amazon',
    'Asphalt8Airborne',
    'AutodeskSketchBook',
    'BubbleWitch3Saga',
    'CaesarsSlotsFreeCasino',
    'CandyCrush',
    'COOKINGFEVER',
    'CyberLinkMediaSuiteEssentials';
    'DisneyMagicKingdoms',
    'Dolby',
    'DrawboardPDF',
    'Duolingo-LearnLanguagesforFree',
    'EclipseManager',
    'Facebook',
    'FarmVille2CountryEscape',
    'FitbitCoach',
    'Flipboard',
    'HiddenCity',
    'Hulu',
	'iHeartRadio',
    'Keeper',
    'LinkedInforWindows',
    'MarchofEmpires',
    'Netflix',
    'NYTCrossword',
    'OneCalendar',
    'PandoraMediaInc',
    'PhototasticCollage',
    'PicsArt-PhotoStudio',
    'Plex',
    'PolarrPhotoEditorAcademicEdition',
    'RoyalRevolt',
    'Shazam',
    'Sidia.LiveWallpaper',
    'SlingTV',
    'Speed Test',
    'Sway',
    'TuneInRadio',
    'Twitter',
    'Viber',
    'WinZipUniversal',
    'Wunderlist',
    'XING'
)

##
# Global variables
# Path to the Applications to install and logfile path
##
$AppPath = "INSTALL"
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
    	Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
	}
}

function Remove-Apps {
    Write-Log "Removing unwatend Apps"

    foreach($App in $AppList) {
        Get-AppxPackage "*$App*" | Remove-AppxPackage -AllUsers -ErrorAction 'SilentlyContinue' | Out-Null
    }
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
    winget upgrade --all --silent --force --accept-package-agreements --accept-source-agreements | Out-Null
}

# Needed to get the Windows Update PS Module
function Install-NuGET {
    Install-PackageProvider -Name NuGet -Force | Out-Null
}

function Install-WindowsUpdates {
	Write-Log "Running Windows Update"
	
	# Windows Update PS Module
    Install-Module -Name PSWindowsUpdate -Force | Out-Null

	# Get all Updates
	Get-WindowsUpdate -Confirm -AcceptAll | Out-Null

	# Do all upgrades
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm -IgnoreReboot | Out-Null
}

function Set-OEMInformation {
	Write-Log "Setting OEM information (Registry)"
	
    $OEMRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation"

    Set-ItemProperty -Path $OEMRegPath -Name Manufacturer -Value "Some Corp"
    Set-ItemProperty -Path $OEMRegPath -Name SupportPhone -Value "111111"
    Set-ItemProperty -Path $OEMRegPath -Name Model -Value "System"
    Set-ItemProperty -Path $OEMRegPath -Name SupportURL -Value "test.example.com"
    Set-ItemProperty -Path $OEMRegPath -Name SupportHours -Value "Always" 
    Set-ItemProperty -Path $OEMRegPath -Name HelpCustomized -Value 0
}

function Install-Applications {
	Write-Log "Installing applications"
	
	if(Test-Path -Path $AppPath) {
		Get-ChildItem $AppPath | Foreach-Object {
			Start-Process $_.FullName
		}
	} else {
		Write-Log "No Applications installed!"
	}
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

function Disable-PSScriptExecution {
	Write-Log "Disabling Script execution"
	
	Set-ExecutionPolicy restricted
}

function Restart-System {
	Write-Log "Rebooting"
	
	Restart-Computer
}

##
# Special tweaks
##
function Disable-FastStartup {
	Write-Log "Disabling Fast Startup"
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

function Enable-AutoRebootOnCrash {
	Write-Log "Enabling automatic reboot on crash"
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1
}

function Show-KnownExtensions {
	Write-Log "Showing known file extensions..."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

function Show-HiddenFiles {
	Write-Log "Showing hidden files"
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}
##

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
	
	Remove-Apps
	Set-PowerSettings
	Install-Applications
	Install-winget-Updates
	Install-NuGET
	Install-WindowsUpdates
	Set-OEMInformation
	Disable-Telemetry
	Disable-PSScriptExecution

	if($Extra) {
		Write-Log "Running extra tasks..."

		##
		# Special tweaks:
		# Enable only if needed!
		##
		Disable-FastStartup
		Enable-AutoRebootOnCrash
		Show-KnownExtensions
		Show-HiddenFiles
	}
	
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