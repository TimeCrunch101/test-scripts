$NetExtenderMsiPath = ".\NetExtender-x64-10.2.341.msi" # Path to the MSI installer
$NetExtenderExePath = ".\NXSetupU-x64-10.2.341.exe"    # Path to the EXE installer
$NetExtenderProcessName = "NEGui"                     # Process name of SonicWALL NetExtender
$NetExtenderProductName = "SonicWALL NetExtender"     # Display name in Programs and Features
$InstallEXE = $true

function Uninstall-NetExtender {
    Write-Host "Checking for existing SonicWALL NetExtender installation..."

    $InstalledApps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                       'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
                      Where-Object { $_.DisplayName -like "*$NetExtenderProductName*" }

    if ($InstalledApps) {
        foreach ($App in $InstalledApps) {
            if ($App.PSChildName -match "^{.+}$") { # Check if PSChildName is a GUID
                Write-Host "Uninstalling $($App.DisplayName) (Version: $($App.DisplayVersion))"
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $($App.PSChildName) /quiet /norestart" -Wait
            } else {
                Write-Host "Skipping invalid MSI entry: $($App.PSChildName)"
            }
        }
    } else {
        Write-Host "No MSI-based installation of SonicWALL NetExtender found."
    }

    # Terminate any running processes
    $RunningProcesses = Get-Process -Name $NetExtenderProcessName -ErrorAction SilentlyContinue
    if ($RunningProcesses) {
        Write-Host "Terminating running NetExtender processes..."
        $RunningProcesses | Stop-Process -Force
    } else {
        Write-Host "No running NetExtender processes found."
    }

    # Look for EXE-based uninstaller
    $UninstallerPath = Get-ChildItem -Path "C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender" -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "uninst.exe" } |
                        Select-Object -ExpandProperty FullName -First 1

    if ($UninstallerPath) {
        Write-Host "Uninstalling EXE-based SonicWALL NetExtender..."
        Start-Process -FilePath $UninstallerPath -ArgumentList "/quiet" -Wait
    } else {
        Write-Host "No EXE-based uninstaller found."
    }
    return
}

# Remove NetExtender Driver
function Remove-NeDriver {
    $driversOutput = pnputil.exe /enum-drivers

    $driversLines = $driversOutput -split "`r?`n"

    $currentDriver = @{}
    $drivers = @()

    foreach ($line in $driversLines) {
        if ($line -match "^(Published Name|Original Name|Provider Name|Class Name|Class GUID|Driver Version|Signer Name):\s*(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $currentDriver[$key] = $value
        } elseif ($line -eq "") {
            if ($currentDriver.Count -gt 0) {
                $drivers += $currentDriver
                $currentDriver = @{}
            }
        }
    }
    if ($currentDriver.Count -gt 0) {
        $drivers += $currentDriver
    }
    foreach ($driver in $drivers) {
        if ($driver.ContainsKey("Original Name")) {
            if (($driver['Original Name']) -eq "wintun.inf") {
                Write-Host "Removing wintun.inf driver"
                Start-Process -FilePath "pnputil.exe" -ArgumentList "/delete-driver $($driver['Published Name']) /uninstall /force"
            }
        }
    }
    return
}

function Install-NetExtender {
    $fullPathMsiPath = Resolve-Path $NetExtenderMsiPath
    $fullExePath = Resolve-Path $NetExtenderExePath
    if (!$InstallEXE) {
        Write-Host "Installing the MSI version of SonicWALL NetExtender from $fullPathMsiPath"
        if (Test-Path $fullPathMsiPath) {
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $fullPathMsiPath /quiet /norestart" -Wait
            Write-Host "MSI installation complete."
            return
        } else {
            Write-Error "The provided MSI installer path does not exist: $fullPathMsiPath"
            exit 1
        }
    } else {
        Write-Host "Installing the EXE version of SonicWALL NetExtender from $fullExePath"
        if (Test-Path $fullExePath) {
            Start-Process -FilePath $fullExePath -ArgumentList "/S" -Wait
            Write-Host "EXE installation complete."
            return
        } else {
            Write-Error "The provided EXE installer path does not exist: $fullExePath"
            exit 1
        }
    }
}

try {
    Uninstall-NetExtender
    Remove-NeDriver
    Install-NetExtender
    Write-Host "NetExtender installation process completed successfully."
    exit 0
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}
