# WinPostInstall
A little Post Install PowerShell script that I made for myself.   
The script takes care of some commont tasks that most will do anyway after a fresh install.

## What does it do?
- Removes bloatware (Apps)
- Tweaks power management (Performance)
- Installs applications (From a directory called "INSTALL")
- Used winget to update installed applications
- Installs NuGET
- Runs Windows Update
- Alters OEM information
- Disables common telemetry settings
- Disables Fast Startup
- Enables reboot on crash
- Enables showing known file extensions
- Enables showing hidden files
- Disabling Recent Files (Explorer)
- Disabling Frequen Files (Explorer)
- Reboots the system
- Also, logs everything it does (WinPostInstall.log)

## Usage
1. Clone/Download this repository/archive
2. Execute the script
```
$> .\WinPostInstall.ps1
```
3. Done

## Hints
Make sure you have script execution allowd on the given system.
This can be done as follows:
```
$> Set-ExecutionPolicy unrestricted
```
The script will deactivate script execution when it is done.

## Why?
Because it was fun creating it!   
I know well that there are many other projects out there doing the same thing and more.   
It's all about learning something new and having fun while doing so - I think we can all agree on that!
