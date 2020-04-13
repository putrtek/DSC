# Base Server 2016 IIS 10 WebServer Configuration

Configuration IISWebServer

{
    param
    (
        
        [Parameter()]
        [String[]] $NodeName,
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $WebAppPoolName,
       
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $WebSiteName,
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $PhysicalPathWebSite,
		
       <# [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $WebApplicationName,
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $PhysicalPathWebApplication,
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $WebVirtualDirectoryName,
		
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $PhysicalPathVirtualDir,#>
	
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Port 
      
    )


    # Import the DSC Resource Modules that defines custom resources
    Import-DscResource -Module xWebAdministration # Configure IIS Webistes
    Import-DscResource -Module PSDesiredStateConfiguration # Generic DSC module required for MOST configurations
    Import-DscResource -Module SchannelPolicyDsc # Allows the Setting of SChannel Registry Keys
    Import-DscResource -Module AccessControlDsc # Allows setting of NTFS Permissions

    Node $NodeName
    {
        WindowsFeature IIS # Install IIS if it is not already installed
        {
            Ensure = "Present"
            Name = "Web-Server"
        }

        WindowsFeature ASP # Install .net4.5 if it is not already installed
        {
            Ensure = "Present"
            Name = "Web-ASP-Net45"
        }

        ###### Configure IIS Feature we need #####
        
        WindowsFeature WindowsAuthentication # Install WindowsAuthentication if it is not already installed
        {
            Ensure = "Present"
            Name = "Web-Windows-Auth"
        }

   

         WindowsFeature IISManagementConsole # Install IISManagementConsole if it is not already installed
        {
            Ensure = "Present"
            Name = "Web-Mgmt-Console"
        }

        ##### Disable IIS Featues that we DONT Need #####       

        WindowsFeature Web-ftp-server # Remove FTP Sever per IIST-SV-000118 and IIST-SV-000148
        {
          
            Ensure = "Absent"
            Name = "Web-ftp-server"
          
        }

        WindowsFeature Web-Mgmt-Compat # Remove IIS6 tools per IIST-SV-000118
        {
            Ensure = "Absent"
            Name = "Web-Mgmt-Compat"
            
        }

         WindowsFeature Web-Scripting-Tools # Remove Web scripting tools per IIST-SV-000118
        {
            Ensure = "Absent"
            Name = "Web-Scripting-Tools"
            
        }

         WindowsFeature Web-DAV-Publishing # Remove Web-DAV-Publishing per IIST-SV-000125 and IIST-SI-000217
        {
            Ensure = "Absent"
            Name = "Web-DAV-Publishing"
            
        }

        WindowsFeature IPP # Remove Internet Printing per  IIST-SV-000149
        {
            Ensure = "Absent"
            Name = "Print-Internet"
            
        }

        WindowsFeature Web-Mgmt-Service # Remove Web-Mgmt-Service per  IIST-SV-000142
        {
            Ensure = "Absent"
            Name = "Web-Mgmt-Service"
            
        }

         

       ##### Create a Web Application Pool #####
        xWebAppPool NewWebAppPool
        {
            Name   = $WebAppPoolName
            Ensure = "Present" # per IIST-SI-000251
            State  = "Started"
            autoStart    = $true
            managedPipelineMode   = 'Integrated'
            managedRuntimeVersion = 'v4.0'
            maxProcesses          = 1
            pingingEnabled        = $true # per IIST-SI-000257
            rapidFailProtection   = $true # per IIST-SI-000255 and IIST-SI-000258 
            restartMemoryLimit    = 3000000 # per IIST-SI-000254
            restartPrivateMemoryLimit = 3000000 # per IIST-SI-000254
            restartRequestsLimit      = 3000000 # per IIST-SI-000252
            rapidFailProtectionInterval    = (New-TimeSpan -Minutes 5).ToString() # per IIST-SI-000259
            rapidFailProtectionMaxCrashes  = 5
            idleTimeout                    = (New-TimeSpan -Minutes 20).ToString() # per IIST-SI-000235
            idleTimeoutAction              = 'Terminate' # per IIST-SI-000236
            DependsOn = "[WindowsFeature]IIS" 
        }

     
        #Create physical path for  websites e:\inetpub\wwwroot
        file NewWebsitePath
        {
            DestinationPath = $PhysicalPathWebSite
            Type            = "Directory"
            Ensure          = "Present"
            DependsOn       = "[xWebAppPool]NewWebAppPool"
        }

        
        file NewLogFileath  # Create physical path for  Log Files e:\weblogs
        {
            DestinationPath = "e:\weblogs"
            Type            = "Directory"
            Ensure          = "Present"
            
        }

         
        xWebSite NewWebSite  # Create a New Website with Port 443
        {
            Name         = $WebSiteName
            Ensure       = "Present"
            ApplicationPool = $WebSiteName
           
            BindingInfo  = MSFT_xWebBindingInformation
            {
                Protocol = "https" # per IIST-SI-000239
                Port     = $Port # per IIST-SI-000239
                IPAddress = '192.168.1.50' # per IIST-SI-000219
                HostName = $WebSiteName.ToLower() # per IIST-SI-000219
              #  CertificateThumbprint = ''
                CertificateSubject = $WebSiteName.ToLower()
                CertificateStoreName = 'My' # per IIST-SV-000129
                CertificateThumbprint = 'BB84DE3EC423DDDE90C08AB3C5A828692089493C' # per IIST-SI-000241
                SSLFlags              = '0' # secure connection be made using an IP/Port combination
            }


            AuthenticationInfo = MSFT_xWebAuthenticationInformation  #Anonymous fisabled per IIST-SI-000221
            {
                Anonymous = $false
                Basic =  $false
                Digest= $false
                Windows = $True
            }

            DefaultPage = 'index.html' # per IIST-SI-000232
            PhysicalPath = $PhysicalPathWebSite # per IIST-SI-000224
          #  State        = 'Stopped'
           DependsOn    = @("[xWebAppPool]NewWebAppPool", "[File]NewWebsitePath")
        }


        
        xWebSiteDefaults WebSiteSiteDefaults # Set Web site defaults
        {
            IsSingleInstance       = 'Yes'
            LogFormat              = 'W3C'
            LogDirectory           = "e:\weblogs\$WebSiteName"
            TraceLogDirectory      = "e:\weblogs\$WebSiteName\FailedReqLogFiles"
            DefaultApplicationPool = 'DefaultAppPool'
            DependsOn       = "[file]NewLogFileath"
        }

        xIISLogging ServerLogSettings
        {
            LogPath     = "e:\weblogs" # IIST-SV-000102 and IIST-SI-000238
            LogFormat   = "W3C" # per IIST-SI-000209
            LogTargetW3C = "File,ETW" # IIST-SV-000103 and IIST-SI-000206
            # IIST-SV-000109 and IIST-SV-000110 and IIST-SV-000111 ; IIST-SI-000208 ; IIST-SI-000210
            LogFlags = @('Date','Time','ClientIP','UserName','SiteName','ComputerName','ServerIP','Method','UriStem','UriQuery','HttpStatus','Win32Status' , 
'BytesSent','BytesRecv','TimeTaken','ServerPort','UserAgent','Cookie','Referer','ProtocolVersion','Host','HttpSubStatus')
            LogPeriod = "Daily"
            LoglocalTimeRollover = $true
            LogTruncateSize = "10485760" #IIST-SV-000145 10mb
            LogCustomFields = @(
                MSFT_xLogCustomField  # per IIST-SI-000209
                {
                    LogFieldName   = 'Connection'
                    SourceName     = 'Connection'
                    SourceType     = 'RequestHeader'
                };
                MSFT_xLogCustomField 
                {
                    LogFieldName   = 'Warning'
                    SourceName     = 'Warning'
                    SourceType     = 'RequestHeader'
                }
                ) # end LogCustomFields
         }

         
         # Configures the application pool defaults.
        xWebAppPoolDefaults PoolDefaults
        {
            IsSingleInstance      = 'Yes'
            ManagedRuntimeVersion = 'v4.0'
            IdentityType          = 'ApplicationPoolIdentity'
        }


        xSslSettings SiteSSLBindings # Set SSL Binding per IIST-SI-000244 ; IIST-SI-000246 ; IIST-SI-000203; IIST-SI-000220
        {
            Name     = $WebSiteName
            Bindings = @('Ssl', 'SslNegotiateCert', 'SslRequireCert')
            Ensure   = 'Present'
        }

          xWebConfigProperty SSLFlags # Set the "SSLFlags" to Ssl128 per IIST-SI-000242 ; IIST-SI-000204
        {          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/access'
            PropertyName = 'sslFlags'
            Value        = 'Ssl128'
            Ensure       = 'Present'
        }
        
        
        


         xWebConfigProperty FullTrust # Set the ".NET Trust Level" to Full per IIST-SI-000218
        {          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/trust'
            PropertyName = 'level'
            Value        = 'full'
            Ensure       = 'Present'
        }

        xWebConfigProperty DirectoryBrowsing # Disable 'directory browsing' per IIST-SV-000138 and IIST-SI-000231
        {
          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/directoryBrowse'
            PropertyName = 'enabled'
            Value        = 'false'
            Ensure       = 'Present'
        }
        
         xWebConfigProperty SessioStateMode # Ensure SessioState mode is set IProc  per IIST-SI-000201 and IIST-SI-000223

        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = 'Mode'
            Value        = 'InProc'
            Ensure       = 'Present'
         }

        xWebConfigProperty SessioStateTimeout # Ensure SessioStateTimeout <=20 per IIST-SI-000236 AND IIST-SV-000135
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = 'timeout'
            Value        = '00:20:00'
            Ensure       = 'Present'
         }


           xWebConfigProperty SessioStateCookie # Ensure SessioStateCookie is Enabled per IIST-SI-000134 AND IIST-SI-000202 
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = 'cookieless'
            Value        = 'UseCookies'
            Ensure       = 'Present'
         }

         xWebConfigProperty MachineKey # Set MachineKey to HMACSHA256 per IIST-SI-000137
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/machineKey'
            PropertyName = 'validation'
            Value        = 'HMACSHA256'
            Ensure       = 'Present'
         }

        xWebConfigProperty RequestFilterMaxURL # Set RequestFilterMaxURL to 4096 per IIST-SI-000225
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'MaxURL'
            Value        = '4096'
            Ensure       = 'Present'
         }

        xWebConfigProperty maxAllowedContentLength # Set RequestFilterMaxURL to 4096 per IIST-SI-000226
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'maxAllowedContentLength'
            Value        = '30000000'
            Ensure       = 'Present'
         }


        xWebConfigProperty MaxQueryString # Set RequestFilterMaxURL to 4096 per IIST-SI-000227
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'MaxQueryString'
            Value        = '2048'
            Ensure       = 'Present'
         }
      

        xWebConfigProperty allowHighBitCharacters # Set allowHighBitCharacters to false per IIST-SI-000228
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering'
            PropertyName = 'allowHighBitCharacters'
            Value        = 'False'
            Ensure       = 'Present'
         }
         

        xWebConfigProperty allowDoubleEscaping # Set allowDoubleEscaping to false per IIST-SI-000229
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering'
            PropertyName = 'allowDoubleEscaping'
            Value        = 'False'
            Ensure       = 'Present'
         }
        
        xWebConfigProperty allowUnlisted # Set allowUnlisted to true per IIST-SI-000230
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/fileExtensions'
            PropertyName = 'allowUnlisted'
            Value        = 'False'
            Ensure       = 'Present'
         }

          xWebConfigProperty SessionIdSecure # Set SessionIdSecure to true per IIST-SI-000152
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/asp/session'
            PropertyName = "keepSessionIdSecure"
            Value        = $True
            Ensure       = 'Present'
         }

    

           xWebConfigProperty httpErrors # Set httpErrors to true per IIST-SI-000140 and IIST-SI-000233
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/httpErrors'
            PropertyName = "errorMode"
            Value        = 'DetailedLocalOnly'
            Ensure       = 'Present'
         }
        

       # Disable the following Mime Types  .exe; .dll; .com ;.bat; .csh per IIST-SV-000124 and IIST-SI-000214
       xIisMimeTypeMapping exe
        {
            Ensure            = 'Absent' 
            Extension         = '.exe'
            MimeType          = 'application/octet-stream'
            ConfigurationPath = "IIS:\sites\"
            DependsOn         = '[WindowsFeature]IIS'
           
        }

         xIisMimeTypeMapping dll # per IIST-SV-000124 and IIST-SI-000214
        {
            Ensure            = 'Absent' 
            Extension         = '.exe'
            MimeType          = 'application/x-msdownload'
            ConfigurationPath = "IIS:\sites\"
            DependsOn         = '[WindowsFeature]IIS'
        }

        xIisMimeTypeMapping com # per IIST-SV-000124 and IIST-SI-000214
        {
            Ensure            = 'Absent' 
            Extension         = '.com'
            MimeType          = 'application/octet-stream'
            ConfigurationPath = "IIS:\sites\"
            DependsOn         = '[WindowsFeature]IIS'
        }

         xIisMimeTypeMapping bat # per IIST-SV-000124 and IIST-SI-000214
        {
            Ensure            = 'Absent'
            Extension         = '.bat'
            MimeType          = 'application/octet-stream'
            ConfigurationPath = "IIS:\sites\"
            DependsOn         = '[WindowsFeature]IIS'
        }

         xIisMimeTypeMapping csh # per IIST-SV-000124 and IIST-SI-000214
        {
            Ensure            = 'Absent'
            Extension         = '.csh'
            MimeType          = 'application/x-csh'
            ConfigurationPath = "IIS:\sites\"
            DependsOn         = '[WindowsFeature]IIS'
        }

       <#
                #https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
         Registry URIEnableCache # set URIEnableCache per above web iste and per IIST-SV-000151
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\URIEnableCache"
            ValueName   = "URIEnableCache"
            ValueData   = "00000001"
            ValueType   = "Dword"
            Force       =  $true
        
        }

          #https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
         Registry UriMaxUriBytes # set UriMaxUriBytes per above web iste and per IIST-SV-000151
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
            ValueName   = "UriMaxUriBytes"
            ValueData   = "262144"
            ValueType   = "Dword"
            Force       = $true
        }

        
          #https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
         Registry UriScavengerPeriod # set UriScavengerPeriod per above web iste and per IIST-SV-000151
        {
            Ensure      = "Present"  # You can also set Ensure to "Absent"
            Key         = "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\UriScavengerPeriod"
            ValueName   = "UriScavengerPeriod"
            ValueData   = '00:02:00' # two minutes oe 120 seconds
            ValueType   = "Dword" 
        }
        #>

           xWebConfigProperty errorMode # Set errors to Detailedlocalonly to true per IIST-SI-000152
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/httpErrors'
            PropertyName = 'errorMode'
            Value        = 'DetailedLocalOnly'
            Ensure       = 'Present'
         }



           Registry FileSystemObject # File System object Reg Key  must be Removed per IIST-SV-000157
        {
            Ensure      = "Absent"  # You can also set Ensure to "Absent"
            Key         = "HKEY_CLASSES_ROOT\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"
            ValueName   = ""
            Force       = $True
           
        }


        xWebConfigProperty isapiCgiRestriction # Set isapiCgiRestriction dsiabled per IIST-SI-000158
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/isapiCgiRestriction'
            PropertyName = 'notListedCgisAllowed'
            Value        = 'False'
            Ensure       = 'Present'
         }

          xWebConfigProperty CgiRestriction # Set isapiCgiRestriction dsiabled per IIST-SI-000158
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/isapiCgiRestriction'
            PropertyName = 'notListedisapisAllowed'
            Value        = 'False'
            Ensure       = 'Present'
         }

        
         xWebConfigProperty maxconnections # Set maxconnections > 0 per IIST-SI-000200
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.applicationHost/sites/siteDefaults/limits'
            PropertyName = 'maxconnections'
            Value        = '1000'
            Ensure       = 'Present'
         }

          xWebConfigProperty DisableDebugging # Disable Disable Debugging per IIST-SI-000234
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = ' system.webServer/asp'
            PropertyName = 'appAllowDebugging'
            Value        = $false
            Ensure       = 'Present'
         }

        Script delete-javavFiles # Run Powershell script to delete *.java and *.jpp files per IIST-SV-000130
        {
           
            TestScript = { 
                $java  =  Get-ChildItem -include '*.java', '*.jpp' -Recurse -ErrorAction silentlyContinue 
                if ($java -ne $Null) {return $True}
                 else {return $False}
             }
            SetScript  = { Get-ChildItem  -include '*.java', '*.jpp' -Recurse -ErrorAction silentlyContinue | foreach { Remove-Item -Path $_.FullName } }
            GetScript  = { @{ Result = ( Get-ChildItem -Filter '*.java', '*.jpp' -Recurse) } }
        }

             #
        NTFSAccessEntry NTFS-InetPub # Set NTFS permission on inetpub per IIST-SV-000144 and IIST-SI-000262
        {
            Path = "e:\inetpub"
            AccessControlList = @(
               
                NTFSAccessControlList
                {
                    Principal = "Users"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'ReadAndExecute'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
				 NTFSAccessControlList
                {
                    Principal = "TrustedInstaller"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
				 NTFSAccessControlList
                {
                    Principal = "Administrators"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
			
				 NTFSAccessControlList
                {
                    Principal = "SYSTEM"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
            )
        }
<#
 NTFSAccessEntry LogFolderPermissions  # per IIST-SI-000213 and IIST-SV-000115
          
            Path = "e:\weblogs"
            AccessControlList = @(
               NTFSAccessControlList
                {
                    Principal = "Auditors"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'Fullnconwe'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
				 NTFSAccessControlList
                {
                    Principal = "Web Admin"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
				 NTFSAccessControlList
                {
                    Principal = "Administrators"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
			
				 NTFSAccessControlList
                {
                    Principal = "SYSTEM"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder subfolders and files'
                            Ensure = 'Present'
                        }
                    )               
                }
				
            )
        }
#>
<#


NTFSAccessEntry LogFolderPermissions # per IIST-SI-000213 and IIST-SV-000115
{
	Path = "e:\weblogs"
	AccessControlList = @(
		NTFSAccessControlList
		{
			Principal = "Auditors"
			ForcePrincipal = $true
			AccessControlEntry = @(
		NTFSAccessControlEntry # Auditors  - Full Control
				{
					AccessControlType = 'Allow'
					FileSystemRights = 'FullControl'
					Inheritance = 'This folder subfolders and files'
					Ensure = 'Present'
				}
			)               
		}

       NTFSAccessControlList # System  - Full Control
		{
			Principal = "SYSTEM"
			ForcePrincipal = $true
			AccessControlEntry = @(
				NTFSAccessControlEntry
				{
					AccessControlType = 'Allow'
					FileSystemRights = 'FullControl'
					Inheritance = 'This folder subfolders and files'
					Ensure = 'Present'
				}
			)               
		}

        AccessControlList # Administrators - full Control
		{
			Principal = "Administrators"
			ForcePrincipal = $true
			AccessControlEntry = @(
				NTFSAccessControlEntry
				{
					AccessControlType = 'Allow'
					FileSystemRights = 'FullControl'
					Inheritance = 'This folder subfolders and files'
					Ensure = 'Present'
				}
			)               
		}

  AccessControlList # Web Admins  - Read
		{
			Principal = "Web Admin"
			ForcePrincipal = $true
			AccessControlEntry = @(
				NTFSAccessControlEntry
				{
					AccessControlType = 'Allow'
					FileSystemRights = 'Read'
					Inheritance = 'This folder subfolders and files'
					Ensure = 'Present'
				}
			)               
		}
		

	)
}
#>
 	
		
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154
Protocol "Disable TLS 1.0 Client" 
{
     Protocol = "TLS 1.0"
     Type = "Client"
     Ensure = "Absent"
}

Protocol "Disable TLS 1.0 Server" 
{
      Protocol = "TLS 1.0"
      Type = "Server"
       Ensure = "Absent"
}
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154
Protocol "Disable PCT 1.0 Client" 
{
     Protocol = "PCT 1.0"
     Type = "Client"
     Ensure = "Absent"
}

Protocol "Disable PCT 1.0 Server" 
{
      Protocol = "PCT 1.0"
      Type = "Server"
       Ensure = "Absent"
}
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154
Protocol "Disable SSL 2.0  Client" 
{
     Protocol = "SSL 2.0"
     Type = "Client"
     Ensure = "Absent"
}

Protocol "Disable SSL 2.0  Server" 
{
      Protocol = "SSL 2.0"
      Type = "Server"
       Ensure = "Absent"
}
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154
Protocol "Disable SSL 3.0  Client" 
{
     Protocol = "SSL 3.0"
     Type = "Client"
     Ensure = "Absent"
}

Protocol "Disable SSL 3.0  Server" 
{
      Protocol = "SSL 3.0"
      Type = "Server"
       Ensure = "Absent"
}
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154

Protocol "Disable TLS 1.1 Client" 
{
     Protocol = "TLS 1.1"
     Type = "Client"
     Ensure = "Present"
}

Protocol "Disable TLS 1.1 Server" 
{
      Protocol = "TLS 1.1"
      Type = "Server"
       Ensure = "Present"
}
################
# Set SChannel Registry Keys   per IIST-SV-000153 and IIST-SV-000154
Protocol "Disable TLS 1.2 Client" 
{
     Protocol = "TLS 1.2"
     Type = "Client"
     Ensure = "Present"
}

Protocol "Disable TLS 1.2 Server" 
{
      Protocol = "TLS 1.2"
      Type = "Server"
       Ensure = "Present"
}
################

    } #End Node
} #End Configuration


#### # This will create a MOF file
 IISWebServer -nodename DSC2016Web -WebAppPoolName SampleWebApp  -WebSiteName SampleWebSite -PhysicalPathWebSite E:\inetpub\wwwroot\ -Port 443 -OutputPath C:\Users\administrator.ADATUM\Downloads  -Verbose

 #This will apply the MOF file to the server 
 Start-DscConfiguration -Wait -verbose -Path C:\Users\administrator.ADATUM\Downloads\ -force