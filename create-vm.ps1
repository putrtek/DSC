# Creating a Virtual Machine in Hyper-V Using PowerShell
# Taken from : https://mcpmag.com/articles/2017/03/09/creating-a-vm-in-hyperv-using-ps.aspx

#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1909\Win10_v1909.iso"

# Path where VHD file will be created
$VMName  = 'DSCWeb16' # Name of VM
$VhdPath = "C:\Users\putrt\Downloads\DSC\VirtualServers\$VMName\Virtual Hard Disks\$VMName.vhdx"
$VhdPath2 = "C:\Users\putrt\Downloads\DSC\VirtualServers\$VMName\Virtual Hard Disks\$VMName" + "_data.vhdx"

#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1809\win10_v1809.iso" 
#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1909\Win10_v1909.iso"
$ISOPath = "C:\Users\putrt\Downloads\MS_Svr2016\en_windows_server_2016_vl_x64_dvd_11636701.iso"

#######################################################
# See if a Switch named "Internal" already exists and assign True or False value to the Variable to track if it does or not
$InternalNetworkVirtualSwitchExists = ((Get-VMSwitch | where {$_.name -eq "Internal" -and $_.SwitchType -eq "Internal"}).count -ne 0)

# If statement to check if Internal Switch already exists. If it does write a message to the host 
# saying so and if not create Internal Virtual Switch
if ($InternalNetworkVirtualSwitchExists -eq "True")
{
write-host "< Internal Network >   ---- switch already Exists"
} 
else
{
New-VMSwitch -SwitchName "Internal"  -SwitchType Internal -Verbose
}

#########################################$$$$$$$$$$$$$$$$

# Create the BASE VM with a 60gb C:\ drive
$NewVMParam = @{
  Name = $VMName
  MemoryStartUpBytes = 1GB
  Path = "C:\ProgramData\Microsoft\Windows\Hyper-V"
  SwitchName =  "Internal"
  NewVHDPath =  $VhdPath
  NewVHDSizeBytes =  60GB
  ErrorAction =  'Stop'
  Verbose =  $True 
  }

$VM = New-VM @NewVMParam  
#---------------------------------

# Add some additional options
$SetVMParam = @{
  ProcessorCount =  1
  DynamicMemory =  $True
  MemoryMinimumBytes =  512MB
  MemoryMaximumBytes =  2Gb
  ErrorAction =  'Stop'
  PassThru =  $True
  Verbose =  $True
  }

$VM = $VM | Set-VM @SetVMParam 
#---------------------------------

<# Create a NEW 20GB VHD file this will be the E:\ drive
$NewVHDParam = @{
  Path = $VhdPath2
  Dynamic =  $True
  SizeBytes =  20GB
  ErrorAction =  'Stop'
  Verbose =  $True
  }

  $VHD = New-VHD @NewVHDParam  
 #---------------------------------#>
 # Create a NEW 10gb VHD file this will be the E:\ drive
 $vm = get-vm DSC2016SPAPP
 $VhdPath2 = "C:\Users\putrt\Downloads\DSC\VirtualServers\$($VM.Name)\Virtual Hard Disks\$($VM.Name)" + "_data2.vhdx"
 
    # create Initialize, format and assign Drve letter
    New-VHD -Path $VhdPath2 -Dynamic -SizeBytes 10GB -Verbose |
    Mount-VHD -Passthru  -Verbose |
    Initialize-Disk -PassThru -verbose |
    New-Partition -DriveLetter E -UseMaximumSize -verbose |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Data' -Confirm:$false –Force 
   
  # Add the new 20 GB VHD file to the VM #>
  $AddVMHDDParam = @{
  Path = $VhdPath2
  ControllerType =  'IDE'
  ControllerLocation =  1
  verbose = $True
  }
  $VM | Add-VMHardDiskDrive @AddVMHDDParam  
  #---------------------------------#>

  # Mount a ISO file to the DVD Drive for OS Build
  $VMDVDParam = @{
  VMName =  $VMName
  Path = $ISOPath
  ErrorAction =  'Stop'
  Verbose =  $True
  }

Set-VMDvdDrive @VMDVDParam  
#---------------------------------

# Set vlanID
Set-VMNetworkAdapterVlan -VMName $VMName  -Access -VlanId 2 -Verbose
#---------------------------------

Set-VMHost -EnableEnhancedSessionMode $True -Verbose

$VM | Start-VM -Verbose


<#####################################################
# MAKE IT SO ALL THE GUEsT can PING EACH OTHER after OS Loads
# All VM on the same subnet
# Turn on VLANID
# Put all VM's on the  'INTERNAL' network only 
# Set Default gateway and DNS to Domain Controller
# turn off firewall
# Enable remote desktop management
# Enable Hyper-v Guest Services for Copy/paste functionality
# add computer to the domain must be able to ping DC


$NewIPAddress = @{
    InterfaceIndex  = (Get-NetAdapter).InterfaceIndex
    #InterfaceAlias = "Ethernet"
    AddressFamily = "IPv4"
	IPAddress  = "172.16.0.43"
 	PrefixLength  = 16 # 255.255.0.0
    DefaultGateway  = "172.16.0.1"
    Verbose =  $True
  }
New-NetIPAddress @NewIPAddress  

Set-DNSClientServerAdress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses 172.16.0.1

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False # turn off firewall
add-computer –domainname adatum -Credential Adatum\administrator -restart –force
#####################################################>

<########################################
$vm = "DSC2016SPAPP"
Stop-VM $vm
Remove-VMHardDiskDrive $VM -ControllerType IDE -ControllerLocation 1
Remove-VM -Name $vm
REMOVE-
Remove-Item -Path "C:\Users\putrt\Downloads\DSC\VirtualServers\$vm" -recurse
#########################################>

