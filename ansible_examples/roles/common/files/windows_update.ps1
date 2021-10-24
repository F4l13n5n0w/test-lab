
## Update Defender signature database:

Update-MpSignature
Get-MpComputerStatus | select *updated, *version


## Disable Defender sample submit function and cloud-based protection, this will stop Defender to send your payload to MS, but you will lose cloud-based proetection:

Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend


## Install windows updates

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\\Windows\\Temp\\log-$(hostname)-$(Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force 