# Commands for pushing DSC Resource Modules to Target Nodes.
# Resources you want to push must be available on this Authoring Machine.

#Required DSC resource modules
$moduleNames = "XWebAdministration", "PSDesiredStateConfiguration", "SchannelPolicyDsc", "NTFSPermission"
$files = Get-ChildItem -Path "\\lon-dc1\DSCResources\web\" -Recurse
#ServerList to push files to
$Servers = "DSC2016SPAPP" #, "DSCWeb16"

foreach ($server in $Servers)
{
    $Session = New-PSSession -ComputerName $server

    $getDSCResources = Invoke-Command -Session $Session -ScriptBlock {
        Get-DscResource
    }

    foreach ($module in $moduleNames)
    {
        # check to see if module already exist
        if ($getDSCResources.moduleName -notcontains $module){
            #3. Copy module to remote node.
            $Module_params = @{
                Path = (Get-Module $module -ListAvailable).ModuleBase
                Destination = "$env:SystemDrive\Program Files\WindowsPowerShell\Modules\$module"
                ToSession = $Session
                Force = $true
                Recurse = $true
                Verbose = $true
            } # end param

            Copy-Item @Module_params -Verbose
        } #end if
    } # end foreach $module

   Foreach($file in $files)
   {
        # Check to see if files already exit
        if(Test-Path $file){
            
            $Web_params = @{
            Path = $file.fullname
            Destination = "e$\inetpub\wwwroot\samplewebsite\"
            ToSession = $Session
            Force = $true
            Recurse = $true
            Verbose = $true
        }

        Copy-Item @Web_params -Verbose
        } # end if
   } # end foreach $file
    
    Remove-PSSession -Id $Session.Id
} # end for each $server