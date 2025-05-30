# build-hv.ps1 - Automate VM creation and unattended Windows installation using Hyper-V

# --- Configuration Section ---
$vmName     = "AutomatedWin10"
$vmMemory   = 4GB
$vhdPath    = "C:\ISO Folder\AutomatedWin10.vhdx"
$windowsISO = "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO  = "C:\ISO Folder\answer.iso"

# --- Ensure Execution Policy Allows Script Execution ---
try {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
} catch {
    Write-Warning "Failed to set execution policy: $_"
}

# --- Create VHDX ---
if (!(Test-Path $vhdPath)) {
    Write-Host "Creating 40 GB dynamic VHDX at: $vhdPath"
    New-VHD -Path $vhdPath -SizeBytes 40GB -Dynamic | Out-Null
} else {
    Write-Host "VHDX already exists at $vhdPath. Skipping creation."
}

# --- Create VM ---
if (!(Get-VM -Name $vmName -ErrorAction SilentlyContinue)) {
    Write-Host "Creating Generation 2 VM: $vmName"
    New-VM -Name $vmName -Generation 2 -MemoryStartupBytes $vmMemory -VHDPath $vhdPath | Out-Null
} else {
    Write-Warning "VM '$vmName' already exists. Please remove it before re-running this script."
    exit 1
}

# --- Disable Secure Boot ---
Write-Host "Disabling Secure Boot for VM: $vmName"
Set-VMFirmware -VMName $vmName -EnableSecureBoot Off

# --- Attach ISOs ---
Write-Host "Attaching Windows ISO and Answer File ISO..."
Add-VMDvdDrive -VMName $vmName -Path $windowsISO
Add-VMDvdDrive -VMName $vmName -Path $answerISO

# --- Start VM ---
Write-Host "Starting VM: $vmName"
Start-VM -Name $vmName

Write-Host "`nVM creation and setup complete. Installation should begin automatically."