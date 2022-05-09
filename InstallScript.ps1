param([String][Parameter(Mandatory=$true)]$computer,
 [String]$userName = "Myyntineuvottelija",
 [String]$adminPassword  = "boss100",
 [Switch]$help)

# OS Check
$os = switch ([Environment]::Is64BitOperatingSystem) {
    $true  { 64; break }
    $false { 32; break }
}

# -help
if ($help)
{
    Write-Host "Arguments:  -computer [name]
                            Set computer name, required

                            -user [name]
                            Default "Myyntineuvottelija"

                            -pw
                            Admin account password, default "boss100"
                            "
    Exit
}

# Admin Check
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host " Running as Admin" -ForegroundColor Green
}
else {
    Write-Host " Powershell needs to be ran as Administrator" -ForegroundColor Red
    Exit
}

function NewLocalUserFunc {
    [CmdletBinding()]
    param (
        [string] $newUser
    )    
    begin {
    }    
    process {
        $password = Read-Host -AsSecureString
        $userGroup = (Get-CimInstance -ClassName Win32_Group -Filter "SID = 'S-1-5-32-545'").Name
        if((Get-LocalUser $newUser).Enabled -eq $null ) {
            New-LocalUser -Name $NewUser -UserMayNotChangePassword -Password $password -PasswordNeverExpires
            Write-Host " $newUser local user created" -ForegroundColor Green  
        }
        else {
            Write-Host " $newUser already exists" -ForegroundColor Gray
        }
        if((Get-LocalGroupMember $userGroup).Name -contains "$computer\$newUser" -eq $null ) {
            Add-LocalGroupMember -Group $userGroup -Member $newUser
            Write-Host " $newUser added to $userGroup" -ForegroundColor Green
        }
        else {
            Write-Host " $newUser already in group $userGroup" -ForegroundColor Gray
        }
        }    
    end {
    }
}
function Register-NativeMethod
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$dll,
 
        # Param2 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]
        $methodSignature
    )
 
    $script:nativeMethods += [PSCustomObject]@{ Dll = $dll; Signature = $methodSignature; }
}

function Add-NativeMethods
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param($typeName = "NativeMethods")
 
    $nativeMethodsCode = $script:nativeMethods | ForEach-Object { "
        [DllImport(`"$($_.Dll)`")]
        public static extern $($_.Signature);
    " }
 
    Add-Type @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;
        public static class $typeName {
            $nativeMethodsCode
        }
"@
}

# User setup
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -force}
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -force}
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -force}

NewLocalUserFunc($userName)

$methodName = "UserEnvCP"
$script:nativeMethods = @();

Register-NativeMethod "userenv.dll" "int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
  [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,`
  [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath)";

Add-NativeMethods -typeName $methodName;

$localUser = New-Object System.Security.Principal.NTAccount("$userName");
$userSID = $localUser.Translate([System.Security.Principal.SecurityIdentifier]);
$sb = new-object System.Text.StringBuilder(260);
$pathLen = $sb.Capacity;

Write-Host " Creating user profile for $userName";
try
{
    [UserEnvCP]::CreateProfile($userSID.Value, $userName, $sb, $pathLen) | Out-Null;
}
catch
{
    Write-Error $_.Exception.Message;
    break;
}

$secureAdminPassword = $adminPassword | ConvertTo-SecureString -AsPlainText -Force
$admin = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE and SID like 'S-1-5-%-500'").Name
Get-LocalUser -Name $admin | Enable-LocalUser
Set-LocalUser -Name $admin -Password $secureAdminPassword
Write-Host " $admin local account enabled" -ForegroundColor Green

if ($env:USERNAME -eq $userName -Or $env:USERNAME -eq $admin)
{   
    Write-Host " Not disabling current account"  -ForegroundColor Gray
}   Else {
    Get-LocalUser -Name $env:USERNAME | Disable-LocalUser
    Write-Host  " Current account disabled"  -ForegroundColor Green
}

#Computer setup
if($env:computername -eq $computer)  {
    Write-Host " Computer name already set" -ForegroundColor Gray
}
else {
    Rename-Computer -Force -NewName "$computer"
    Write-Host " $computer set as computer name"  -ForegroundColor Green
}

#Installs
$Cred = New-Object System.Management.Automation.PSCredential ($userName, (new-object System.Security.SecureString))

$url = 
if(($os -eq "64") -And (Test-Path "$PSScriptRoot\Firefox Setup 99.0.1 x64.msi" -PathType Leaf))
{
    Write-Host " Installing Firefox" -ForeGroundcolor Gray
    Start-Process -Filepath "$PSScriptRoot\Firefox Setup 99.0.1 x64.msi" -ArgumentList /q -Wait
}
elseif(($os -eq "64") -And ((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet"))
{
    Write-Host " Connected" -ForegroundColor Green
    Write-Host " Installing Firefox" -ForeGroundcolor Gray
    Invoke-RestMethod -Uri "$url/Firefox Setup 99.0.1 x64.msi" -OutFile "$PSScriptRoot\Firefox Setup 99.0.1 x64.msi"
    Start-Process -Filepath "$PSScriptRoot\Firefox Setup 99.0.1 x64.msi" -ArgumentList /q -Wait
}
elseif(Test-Path "$PSScriptRoot\Firefox Setup 99.0.1 x86.msi")
{
    Write-Host " Installing Firefox" -ForeGroundcolor Gray
    Start-Process -Filepath "$PSScriptRoot\Firefox Setup 99.0.1 x86.msi" -ArgumentList /q -Wait
}
elseif(((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet"))
{
    Write-Host " Connected" -ForegroundColor Green
    Write-Host " Installing Firefox" -ForeGroundcolor Gray
    Invoke-RestMethod -Uri "$url/Firefox Setup 99.0.1 x86.msi" -OutFile "$PSScriptRoot\Firefox Setup 99.0.1 x86.msi"
    Start-Process -Filepath "$PSScriptRoot\Firefox Setup 99.0.1 x86.msi" -ArgumentList /q -Wait
}
else
{
    Write-Host " Skipping Firefox Setup" -ForegroundColor Red
}

if(Test-Path "$PSScriptRoot\RingoSetupTsto.exe")
{
    Write-Host " Installing Ringo `nUser path: C:\Users\$username `nComputer name: $computer" -ForegroundColor Gray
    Start-Process -Filepath "$PSScriptRoot\RingoSetupTsto.exe" -Wait -Credential Myyntineuvottelija
}
elseif(((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet"))
{
    Write-Host " Connected" -ForegroundColor Green
    Write-Host " Installing Ringo `nUser path: C:\Users\$username `nComputer name: $computer" -ForegroundColor Gray
    Invoke-RestMethod -Uri $url/RingoSetupTsto.exe -OutFile $PSScriptRoot\RingoSetupTsto.exe
    Start-Process -Filepath "$PSScriptRoot\RingoSetupTsto.exe" -Wait -Credential Myyntineuvottelija
}
else
{
    Write-Host " Skipping Ringo Setup" -ForegroundColor Red
}

if(Test-Path "$PSScriptRoot\drivers.exe")
{
    Write-Host " Installing Drivers" -ForegroundColor Gray
    Start-Process -Filepath "$PSScriptRoot\drivers.exe" -Wait
}
elseif(((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet"))
{
    Write-Host " Installing Drivers" -ForegroundColor Gray
    Invoke-RestMethod -Uri $url/drivers.exe -OutFile $PSScriptRoot\drivers.exe
    Start-Process -Filepath "$PSScriptRoot\drivers.exe" -Wait
}
else
{
    Write-Host " Skipping Driver Setup" -ForegroundColor Red
}

#Disable devices
Write-Host " Disabling Wireless network adapter" -ForegroundColor Gray
Get-WmiObject -class Win32_NetworkAdapter -namespace root\CIMV2 | Where-Object {$_.Name -match "Wireless"} | ForEach-Object {$_.Disable()}
Write-Host " Disabling Audio devices" -ForegroundColor Gray
Get-PnpDevice -class "MEDIA" -status OK -ErrorAction SilentlyContinue | ForEach-Object {Disable-PnpDevice -InstanceId $_.InstanceID -Confirm:$false}
Get-PnpDevice -class "AudioEndpoint" -status OK -ErrorAction SilentlyContinue | ForEach-Object {Disable-PnpDevice -InstanceId $_.InstanceID -Confirm:$false}


#Sound Scheme
$PatternSID = "S-1-5-21-\d+-\d+\-\d+\-\d+$"
 
# Get Username, SID, and location of ntuser.dat for all users
$ProfileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.PSChildName -match $PatternSID} | 
    Select-Object  @{name="SID";expression={$_.PSChildName}}, 
            @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
            @{name="Username";expression={$_.ProfileImagePath -replace "^(.*[\\\/])", ""}}
 
# Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
$LoadedHives = Get-ChildItem Registry::HKEY_USERS | Where-Object {$_.PSChildname -match $PatternSID} | Select-Object @{name="SID";expression={$_.PSChildName}}
 
# Get all users that are not currently logged
$UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select-Object @{name="SID";expression={$_.InputObject}}, UserHive, Username
 
# Loop through each profile on the machine
Foreach ($item in $ProfileList) {
    # Load User ntuser.dat if it"s not already loaded
    if ($item.SID -in $UnloadedHives.SID) {
        reg load HKU\$($Item.SID) $($Item.UserHive) | Out-Null
    }
 
    #####################################################################
    # This is where you can read/modify a users portion of the registry 
    New-ItemProperty registry::HKEY_USERS\$($Item.SID)\AppEvents\Schemes -Name "(Default)" -Value ".None" -Force | Out-Null
    Get-ItemProperty registry::HKEY_USERS\$($Item.SID)\AppEvents\Schemes\Apps | Get-ChildItem | Get-ChildItem | Where-Object {$_.PSChildName -eq ".Current"} | Set-ItemProperty -Name "(Default)" -Value " "

    # Unload ntuser.dat        
    if ($item.SID -in $UnloadedHives.SID) {
        ### Garbage collection and closing of ntuser.dat ###
        [gc]::Collect()
        reg unload HKU\$($Item.SID) | Out-Null
    }
}

#Power settings
#Get active power scheme
$activeScheme = cmd /c "powercfg /getactivescheme"
$regEx = "(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}"
$asGuid = [regex]::Match($activeScheme,$regEx).Value

#relative GUIDs for power settings
$powerAndLidGuid = "4f971e89-eebd-4455-a8de-9e59040e7347"
$lidClosedGuid = "5ca83367-6e45-459f-a27b-476b1d01c936"
$powerButtonGuid = "7648efa3-dd9c-4e3e-b566-50f929386280"

$displayGuid = "7516b95f-f776-4464-8c53-06167f40cc99"
$displayTimeoutGuid = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"

$sleepGuid = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
$sleepTimeoutGuid = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"
$hibernateTimeoutGuid = "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"

#DC Value // On Battery
cmd /c "powercfg /setdcvalueindex $asGuid $powerAndLidGuid $lidClosedGuid 1"
cmd /c "powercfg /setdcvalueindex $asGuid $powerAndLidGuid $powerButtonGuid 3"

#AC Value // Plugged in
cmd /c "powercfg /setacvalueindex $asGuid $powerAndLidGuid $lidClosedGuid 0"
cmd /c "powercfg /setacvalueindex $asGuid $powerAndLidGuid $powerButtonGuid 3"
cmd /c "powercfg /setacvalueindex $asGuid $displayGuid $displayTimeoutGuid 0"
cmd /c "powercfg /setacvalueindex $asGuid $sleepGuid $sleepTimeoutGuid 0"
cmd /c "powercfg /setacvalueindex $asGuid $sleepGuid $hibernateTimeoutGuid 0"

#apply settings
cmd /c "powercfg /s $asGuid"
Write-Host " Power settings changed" -ForegroundColor Green

#Confirm driver
if(Get-WmiObject Win32_PNPEntity | Where-Object {$_.Name -match "Huawei"} | Select-Object Name)  {
    Write-Host " Drivers confirmed" -ForegroundColor Green
}
else {
    Write-Host " Could not find driver install" -ForegroundColor Red
}

Set-ExecutionPolicy Restricted
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -force}
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -force}
if(Test-Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa") {
    Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -force}

Write-Host "Restart"
pause
Restart-Computer -Force
