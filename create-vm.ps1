# Creating a Virtual Machine in Hyper-V Using PowerShell
# Taken from : https://mcpmag.com/articles/2017/03/09/creating-a-vm-in-hyperv-using-ps.aspx

#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1909\Win10_v1909.iso"

# Path where VHD file will be created
$VMName  = 'DSC2016Web' # Name of VM
$VhdPath = "C:\Users\putrt\Downloads\DSC\VirtualServers\$VMName\Virtual Hard Disks\$VMName.vhdx"
$VhdPath2 = "C:\Users\putrt\Downloads\DSC\VirtualServers\$VMName\Virtual Hard Disks\$VMName" + "_data.vhdx"
#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1809\win10_v1809.iso" 
#$ISOPath = "C:\Users\putrt\Downloads\MS_Win10_v1909\Win10_v1909.iso"
$ISOPath = "C:\Users\putrt\Downloads\MS_Svr2016\en_windows_server_2016_vl_x64_dvd_11636701.iso"

#######################################################
# See if a Switch named "Internal" already exists and assign True or False value to the Variable to track if it does or not
$InternalNetworkVirtualSwitchExists = ((Get-VMSwitch | where {$_.name -eq "Internal" -and $_.SwitchType -eq "Internal"}).count -ne 0)

# If statement to check if Private Switch already exists. If it does write a message to the host 
# saying so and if not create Private Virtual Switch
if ($InternalNetworkVirtualSwitchExists -eq "True")
{
write-host "< Internak Network >   ---- switch already Exists"
} 
else
{
New-VMSwitch -SwitchName "Internal"  -SwitchType Internal -Verbose
}

#########################################$$$$$$$$$$$$$$$$

# Create the BASE VM
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
  MemoryMaximumBytes =  1Gb
  ErrorAction =  'Stop'
  PassThru =  $True
  Verbose =  $True
  }

$VM = $VM | Set-VM @SetVMParam 
#---------------------------------

# Create a NEW 20GB VHD file this will be the E:\ drive
$NewVHDParam = @{
  Path = $VhdPath2
  Dynamic =  $True
  SizeBytes =  20GB
  ErrorAction =  'Stop'
  Verbose =  $True
  }

  $VHD = New-VHD @NewVHDParam
 #---------------------------------

  # Add the VHD file to the VM
  $AddVMHDDParam = @{
  Path = $VhdPath
  ControllerType =  'SCSI'
  ControllerLocation =  1
  }

  $VM | Add-VMHardDiskDrive @AddVMHDDParam
  #---------------------------------#>

  # Mount a ISO file to the DVD Drive
  $VMDVDParam = @{
  VMName =  $VMName
  Path = $ISOPath
  ErrorAction =  'Stop'
  Verbose =  $True
  }

Set-VMDvdDrive @VMDVDParam
#---------------------------------

# Set vlanID
Set-VMNetworkAdapterVlan $vm -VlanId 2
#---------------------------------

$NewIPAddress = @{
    InterfaceAlias  = "Internal" 
    AddressFamily = "IPv4"
	IPAddress  = "172.16.0.47"
 	PrefixLength  = 24 
    DefaultGateway  = "172.16.0.1"

}

New-NetIPAddress @NewIPAddress  -
#---------------------------------


$VM | Start-VM -Verbose


#####################################################
# MAKE IT SO ALL THE GUEsT AND PING EACH OTHER
# All VM on the same subnet
# Turn on VLANID
# Put all VM's on the  'INTERNAL' network only
# Set Default gateway and DNS to Domain Controller
# turn off firewall
# add computer to the domain

# Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False # turn off firewall
# add-computer –domainname adatum -Credential Adatum\administrator -restart –force
#####################################################
