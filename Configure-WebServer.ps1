# Base Server 2016 IIS 10 WebServer Configuration
# This script covers/sets 34 of the 44 Server STIG items
# This script covers/sets 41  of the 48 Site STIG items
# Set-ExecutionPolicy bypass -Scope Process

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

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$SourcePath = "\\lon-dc1\DSCResources" ,
 
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$ModulePath = "$PSHOME\modules\PSDesiredStateConfiguration\PSProviders",
		
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
   # Import-DscResource -Module xWebAdministration # Configure IIS Webistes
   # Import-DscResource -Module SchannelPolicyDsc # Allows the Setting of SChannel Registry Keys
   # Import-DscResource -Module NTFSPermission # Allows setting of NTFS Permissions
    Import-DscResource –Module PSDesiredStateConfiguration
    # Import-DscResource -Module PSDscResources # Generic DSC module required for MOST configurations

    Node $NodeName
    {
         ### Ensure the follloing windows features are present 
        $WindowsFeaturesPresent = @("Web-Server","Web-ASP-Net45","WAS","WAS-Config-APIs","WAS-Process-Model","WAS-NET-Environment","Web-Windows-Auth", "Web-Mgmt-Console") 
        Foreach($feature in $WindowsFeaturesPresent)
        {
            WindowsFeature  $feature.tostring()   # Install The features we need
            {
                Ensure = "Present"
                Name = $feature.tostring()         
            } 
        
        }

        

      <##### Disable IIS Featues that we DONT Need per V-100121	and V-100129	   #####    

      $WindowsFeaturesAbsent = @("Web-ftp-server","Web-Mgmt-Compat", "Web-Scripting-Tools","Web-DAV-Publishing","Print-Internet", "Web-Mgmt-Service")

                       
        Foreach($feature in $WindowsFeaturesAbsent)
        {
            WindowsFeature  $feature.tostring()   # Remove The features we need
            {
                Ensure = "Absent"
                Name = $feature.tostring()         
            } 
        
        }

             
       

        #####################################
        # Start Required Services

        Service ServiceWAS
        {
            Name = 'WAS'
            Ensure = 'Present'
            StartupType = 'Automatic'
            State  = 'Running'
        }
        
                       
        file NewWebsitePath  # Create physical path for websites e:\inetpub\wwwroot per V-100225
        {
            DestinationPath = "$PhysicalPathWebSite\$WebSiteName" # e:\inetpb\wwwroot\samplewebsite
            Type            = "Directory"
            Ensure          = "Present"
            Checksum       = "modifiedDate"
           # DependsOn       = "[WindowsFeature]IIS"
        }
       
  
        
        file NewLogFilepath  # Create physical path for Log Files e:\weblogs
        {
            DestinationPath = "e:\weblogs"
            Type            = "Directory"
            Ensure          = "Present"
            Checksum       = "modifiedDate"
         #  DependsOn       = "[WindowsFeature]IIS"
            
        }

       <# File WebSiteFileshtml # Copy Web site files required to e:\ drive of Target Server
        {
            SourcePath = "$ModulePath\Web\index.html"
            DestinationPath = "$PhysicalPathWebSite\$WebSiteName\index.html" 
            Type            = "File"
            Ensure          = "Present"
            Recurse         = $true
            Checksum       = "modifiedDate" 
          DependsOn       = "[WindowsFeature]IIS"
         

        }
        #>
      <#  
        File WebSiteFilesconfig # Copy Web site files required to e:\ drive of Target Server
        {
            SourcePath = "$ModulePath\Web\web.config"
            DestinationPath = "$PhysicalPathWebSite\$WebSiteName\web.config" 
            Type            = "File"
            Ensure          = "Present"
            Recurse         = $true
            Checksum       = "modifiedDate" 
          DependsOn       = "[WindowsFeature]IIS"

        }
        #>
      
      <#
       ##### Create a Web Application Pool #####
        xWebAppPool NewWebAppPool
        {
            Name   = $WebAppPoolName # website must have a unique application pool. per V-100263
            Ensure = "Present" # website must have a unique application pool. per V-100263
            identityType = "ApplicationPoolIdentity"
            State  = "Started"
            autoStart    = $false
            managedPipelineMode   = 'Integrated'
            managedRuntimeVersion = 'v4.0'
            maxProcesses          = 1
            logEventOnRecycle     =  $rue  # Per V-100271
            pingingEnabled        = $true # ping enable to True  per V-100273
            rapidFailProtection   = $true # "Rapid Fail Protection" enabled per 100275
            restartMemoryLimit    = 3000000 # "Virtual Memory Limit" greater than "0".  per V-100267
            restartPrivateMemoryLimit = 3000000 # "tual Memory Limit" greater than "0".  per V-100269
            restartRequestsLimit      = 3000000 #  request limt > 0 V-100265
            rapidFailProtectionInterval    = (New-TimeSpan -Minutes 5).ToString() # per V-100277
            rapidFailProtectionMaxCrashes  = 5 # "Failure Interval" to "5" or less. per V-100277
            idleTimeout                    = (New-TimeSpan -Minutes 20).ToString() # per V-100245
            idleTimeoutAction              = 'Terminate'
           # DependsOn = "[WindowsFeature]IIS" 
        }

     
                
        xWebSite NewWebSite  # Create a New Website with Port 443
        {
            Name         = $WebSiteName
            Ensure       = "Present"
            PhysicalPath = "$PhysicalPathWebSite\$WebSiteName"
            ApplicationPool = $WebSiteName # website must have a unique application pool. per 100263
           
          #  BindingInfo  = MSFT_xWebBindingInformation
          # {
          #      Protocol  = "https" # per V-100253 and V-100255
          #      Port      = $Port # per V-100253 and v-100255
          #      IPAddress = '192.168.1.50' # per V-100217
          #      HostName  = $WebSiteName.ToLower() # per 100217
              #  CertificateThumbprint = '' # per V-100255
             #   CertificateSubject = $WebSiteName.ToLower()
             #   CertificateStoreName = 'My' # per 
             #   CertificateThumbprint = 'BB84DE3EC423DDDE90C08AB3C5A828692089493C' # per V-100135 and V-100255
           #     SSLFlags              = '0' # secure connection be made using an IP/Port combination
           # }


            AuthenticationInfo = MSFT_xWebAuthenticationInformation  # Anonymous disabled per V-100221
            {
                Anonymous = $false
                Basic =  $false
                Digest= $false
                Windows = $True
            }

            DefaultPage = "$PhysicFalPathWebSite\$WebSiteName\index.html"
            State        = 'Started'
            DependsOn    = @("[xWebAppPool]NewWebAppPool")
        }



        xWebSiteDefaults WebSiteSiteDefaults # Set Web site defaults
        {
            IsSingleInstance       = 'Yes'
            LogFormat              = 'W3C'
            LogDirectory           = "e:\weblogs\$WebSiteName"
            TraceLogDirectory      = "e:\weblogs\$WebSiteName\FailedReqLogFiles"
            DefaultApplicationPool = 'DefaultAppPool'
            DependsOn       = "[file]NewLogFilepath"
        }

        xIISLogging ServerLogSettings # Configure Logging settings
        {
            LogPath     = "e:\weblogs" 
            LogFormat   = "W3C" # per V-100105	and V-100203   
            LogTargetW3C = "File,ETW" # per V-100107  and V-100199
            # Set required log fields per V-100105 , V-100109, V-100201
            LogFlags = @('Date','Time','ClientIP','UserName','SiteName','ComputerName','ServerIP','Method','UriStem','UriQuery','HttpStatus','Win32Status' , 
'BytesSent','BytesRecv','TimeTaken','ServerPort','UserAgent','Cookie','Referer','ProtocolVersion','Host','HttpSubStatus')
            LogPeriod = "Daily" # per V-100165	  
            LoglocalTimeRollover = $true # per V-100251
            LogCustomFields = @(
                MSFT_xLogCustomField  #configure Custom fields connection per V-100111	and V-100205 
                {
                    LogFieldName   = 'Connection'
                    SourceName     = 'Connection'
                    SourceType     = 'RequestHeader'
                };
                
                MSFT_xLogCustomField  #configure Custom fields Warning per V-100111	and V-100205 
                {
                    LogFieldName   = 'Warning'
                    SourceName     = 'Warning'
                    SourceType     = 'RequestHeader'
                }

                MSFT_xLogCustomField  # #configure Custom fields Responseheader  per  V-100113		 
                {
                    LogFieldName   = 'ResponseHeader'
                    SourceName     = 'Content-Type'
                    SourceType     = 'ResponseHeader'
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
        

        xSslSettings SiteSSLBindings # Set SSL Binding per 100195 and V-100197 ; V-100219 ; V-100257
        {
           
            Name     = $WebSiteName
            #Bindings = @('Ssl', 'SslNegotiateCert', 'SslRequireCert')
            Bindings =  'SslRequireCert'             
          
        }

        xWebConfigProperty SSLFlags # Set the "SSLFlags" to Ssl128 per V-100257
        {          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/access'
            PropertyName = 'sslFlags'
            Value        = 'Ssl128'
            Ensure       = 'Present'
        }
        
        xWebConfigProperty FullTrust # Set the ".NET Trust Level" to Full per V-100215
        {          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/trust'
            PropertyName = 'level'
            Value        = 'full'
            Ensure       = 'Present'
        }
   
        
        xWebConfigProperty SessioStateMode # SessionState mode is set to InProc per v-100191 and V-100223
        {
        WebsitePath  = 'IIS:\Sites'
        Filter       = 'system.web/sessionState'
        PropertyName = 'Mode'
        Value        = 'InProc'
        Ensure       = 'Present'
        }

        xWebConfigProperty SessioStateTimeout # Ensure SessioStateTimeout <=20 per V-100145	and V-100247
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = 'timeout'
            Value        = '00:20:00'
            Ensure       = 'Present'
         }


        xWebConfigProperty SessioStateCookie # Ensure SessioStateCookie is Enabled per V-100143	and V-100193
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = 'cookieless'
            Value        = 'UseCookies'
            Ensure       = 'Present'
         }

        xWebConfigProperty MachineKey # Set MachineKey to HMACSHA256 per V-100149	
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/machineKey'
            PropertyName = 'validation'
            Value        = 'HMACSHA256'
            Ensure       = 'Present'
         }

        xWebConfigProperty RequestFilterMaxURL # Set RequestFilter MaxURL to 4096 per V-100227
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'MaxURL'
            Value        = '4096'
            Ensure       = 'Present'
        }

        xWebConfigProperty maxAllowedContentLength # Set RequestFilterMaxURL to 4096 per V-100229
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'maxAllowedContentLength'
            Value        = '30000000'
            Ensure       = 'Present'
         }


        xWebConfigProperty MaxQueryString # Set RequestFilterMaxURL to 4096 per V-100231
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/requestLimits'
            PropertyName = 'MaxQueryString'
            Value        = '2048'
            Ensure       = 'Present'
         }
      

        xWebConfigProperty allowHighBitCharacters # Set allowHighBitCharacters to false per V-100233
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering'
            PropertyName = 'allowHighBitCharacters'
            Value        = 'False'
            Ensure       = 'Present'
         }
         

        xWebConfigProperty allowDoubleEscaping # Set allowDoubleEscaping to false per v-100235
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering'
            PropertyName = 'allowDoubleEscaping'
            Value        = 'False'
            Ensure       = 'Present'
         }
        
        xWebConfigProperty allowUnlisted # Set allowUnlisted to False per V-100237
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/requestFiltering/fileExtensions'
            PropertyName = 'allowUnlisted'
            Value        = 'False'
            Ensure       = 'Present'
         }

        xWebConfigProperty DirectoryBrowsing # Disable 'directory browsing' per V-100151 and V-100239
        {
          
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/directoryBrowse'
            PropertyName = 'enabled'
            Value        = 'false'
            Ensure       = 'Present'
        }
      
        xWebConfigProperty httpErrors # Set httpErrors to Detailed per V-100241
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/httpErrors'
            PropertyName = "errorMode"
            Value        = 'DetailedLocalOnly'
            Ensure       = 'Present'
         }
         
        xWebConfigProperty DisableDebugging # Disable Disable Debugging per V-100243
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = ' system.webServer/asp'
            PropertyName = 'appAllowDebugging'
            Value        = $false
            Ensure       = 'Present'
         }
         

        xWebConfigProperty SessionIdSecure # Set SessionIdSecure to true per V-10017and V-100259
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/asp/session'
            PropertyName = "keepSessionIdSecure"
            Value        = $True
            Ensure       = 'Present'
         }

        xWebConfigProperty compressionEnabled # Set compressionEnabled to false per V-100261
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/sessionState'
            PropertyName = "compressionEnabled"
            Value        = $False
            Ensure       = 'Present'
         }

    
        $MimeTypes = @('.exe', '.dll', '.com' , '.bat', '.csh' )

        Foreach($mime in $MimeTypes)
        {
        
         # Disable the following Mime Types  .exe; .dll; .com ;.bat; .csh per V-100131 and V-100207	
            xIisMimeTypeMapping "MimeTypes_Disable_$($mime.toString())" # per  V-100131  and V-100207	
            {
                Ensure            = 'Absent' 
                Extension         =  $mime.toString()
                MimeType          = 'application/octet-stream'
                ConfigurationPath = "IIS:\sites\"
              #  DependsOn         = '[WindowsFeature]IIS'
           
            }
        }#end foreach

  
         # https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
         # If the HTTP service is already running, you must restart it for the changes to take effect.
        Registry URIEnableCache # set URIEnableCache per above web iste and perV-100173	
        {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Http\Parameters\URIEnableCache"
            ValueName   = "" #  Empty string sets Default value
            ValueData   = "1"
            ValueType   = "String"
            Force       =  $true
        
        }

        # #https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
         Registry UriMaxUriBytes # set UriMaxUriBytes per above web iste and per V-100173	
         {
            Ensure      = "Present" 
            Key         = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Http\Parameters\UriMaxUriBytes"
            ValueName   = "" #  Empty string sets Default value
            ValueData   = "262144"
            ValueType   = "String"
            Force       = $true
        }

        
          #https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/web-server/tuning-iis-10
        Registry UriScavengerPeriod # set UriScavengerPeriod per above web iste and per V-100173	
        {
            Ensure      = "Present"  
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Http\Parameters\UriScavengerPeriod"
            ValueName   = "" #  Empty string sets Default value
            ValueData   = '00:02:00' # two minutes or 120 seconds
            ValueType   = "String" 
            Force       = $true
        }
        
        
        xWebConfigProperty errorMode # Set errors to Detailedlocalonly to true per V-100155	
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/httpErrors'
            PropertyName = 'errorMode'
            Value        = 'DetailedLocalOnly'
            Ensure       = 'Present'
         }

       
        Registry Indexing # Indexing  Reg Key  must be Removed per v-100153
        {
            Ensure      = "Absent"  # You can also set Ensure to "Absent"
            Key         = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\."
            ValueName   = ""
            Force       = $True
           
        }


        xWebConfigProperty isapiCgiRestriction # Set isapiCgiRestriction dsiabled per V-100183
        {	
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/isapiCgiRestriction'
            PropertyName = 'notListedCgisAllowed'
            Value        = 'False'
            Ensure       = 'Present'
         }

        xWebConfigProperty CgiRestriction # Set isapiCgiRestriction dsiabled per V-100183	
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.webServer/security/isapiCgiRestriction'
            PropertyName = 'notListedisapisAllowed'
            Value        = 'False'
            Ensure       = 'Present'
         }

        
        xWebConfigProperty maxconnections # Set maxconnections > 0 per V-100187	
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.applicationHost/sites/siteDefaults/limits'
            PropertyName = 'maxconnections'
            Value        = '1000'
            Ensure       = 'Present'
         }
<#
        # tHIS SECTION IS CAUSING THE mof NOT TO bUILD COMMENT OUT FOR NOW UNTIL i FIGURE OUT WHY
        xWebConfigProperty AuthorizationAllows # Set Athorization to Admin only  per V-100185	
        {
            WebsitePath  = 'IIS:\Sites'
            Filter       = 'system.web/authorization'
            PropertyName = 'AtElement'
            Value        =  @{roles='Administrators'}
            Ensure       = 'Present'
         }
     #>   
     
        <# .bak, *.old, *.temp, *.tmp, *.backup, or “copy of...”. per # V-100283
        Script delete-javavFiles # Run Powershell script to delete *.java and *.jpp files  per V-100137	  
         
        {
           
            TestScript = { 
            $Ext = '.bak', '*.old', '*.temp', '*.tmp', '*.backup', 'copy of...','*.java', '*.jpp'
                $java  =  Get-ChildItem -include  $Ext -Recurse -ErrorAction silentlyContinue 
                if ($java -ne $Null) {return $True}
                 else {return $False}
             }
            SetScript  = { Get-ChildItem  -include '*.java', '*.jpp' -Recurse -ErrorAction silentlyContinue | foreach { Remove-Item -Path $_.FullName } }
            GetScript  = { @{ Result = ( Get-ChildItem -Filter '*.java', '*.jpp' -Recurse) } 
         }
         }

    Script enable-hsts # Run Powershell script to enable HSTS per V-100189
    {
 	    TestScript = { return $true }
	    SetScript  = { 
		Import-Module IISAdministration
		Reset-IISServerManager -Confirm:$false
		Start-IISCommitDelay

		$sitesCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
		$siteElement = Get-IISConfigCollectionElement -ConfigCollection $sitesCollection -ConfigAttribute @{"name"="SampleWebSite"}
		$hstsElement = Get-IISConfigElement -ConfigElement $siteElement -ChildElementName "hsts"
		Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "enabled" -AttributeValue $true
		Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "max-age" -AttributeValue 480
		Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "includeSubDomains" -AttributeValue $true
		Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName "redirectHttpToHttps" -AttributeValue $true

		Stop-IISCommitDelay
		Remove-Module IISAdministration
				    }
	    GetScript  = { } 
     }

     $fileExtensions = @('.config','.master','.cs', '.js','.asax' ,'.ascx','.aspx','.axd','.sitemap','.htm'
					,'.html','.csproj','.jpg','.gif', '.png','.css', '.pdb', '.dll', '.xml', '.pdf','.cache')

    Foreach($ext in $fileExtensions )
    {
       xWebConfigPropertyCollection  "RequestFiltering_Allow_$($ext.toString())" # Request Filtering White List  Allow $ext  per V-100209 and V-100211
         {
            WebsitePath       = 'MACHINE/WEBROOT/APPHOST'
            Filter            = 'system.webServer/security/requestFiltering'
            CollectionName    = 'fileExtensions '
            ItemName          = 'add'
            ItemKeyName       = 'fileExtension'
            ItemKeyValue      =  $ext.tostring()
            ItemPropertyName  = 'allowed'
            ItemPropertyValue = 'true'
            Ensure            = 'Present'
         }
    
    }#end foreach

    # 
    #Set NTFS permission on InetMgr per V-100167
    $ReadOnlyAccounts =  @("Users", "SYSTEM", "ALL APPLICATION PACKAGES", "ALL RESTRICTED APPLICATION PACKAGES")
   
    Foreach($account in $ReadOnlyAccounts)
    {
        NTFSPermission "Read_InetMgr_$($account.tostring())" # Users ReadAndExecute per V-100167	
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path = "c:\windows\system32\inetsrv"
            Rights  = "ReadAndExecute"
         } 
    }

     #Set NTFS permission on InetMgr per V-100167   
     $FullControlAccounts = @("TrustedInstaller",  "Administrators", "Web Admins")

     Foreach($account in $FullControlAccounts)
    {
        NTFSPermission "FullControl_InetMgr_$($account.tostring())" # Users ReadAndExecute per V-100167	
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path = "c:\windows\system32\inetsrv"
            Rights  = "ReadAndExecute"
         } 
    }

           
   #Set NTFS permission on web log directory per V-100115
   $FullControlAccounts = @("Auditors", "Administrators",  "SYSTEM")
   $ReadOnlyAccounts =  @("Web Admins")


    Foreach($account in $FullControlAccounts)
    {
        NTFSPermission "FullControl_Logs_$($account.tostring())" # log directory per V-100115
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path    = "e:\weblogs"
            Rights  = "ReadAndExecute"
         } 
    }

    Foreach($account in $ReadOnlyAccounts)
    {
        NTFSPermission "Read_Logs_$($account.tostring())" # log directory per V-100115
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path    = "e:\weblogs"
            Rights  = "ReadAndExecute"
         } 
    }

   
   
   #Set NTFS permission on inetpub per V-100163	and V-100279

   $FullControlAccounts = @("Auditors", "Administrators",  "SYSTEM")
   $ReadOnlyAccounts =  @("Users","ALL APPLICATION PACKAGES",  $($WebAppPoolName) )


    Foreach($account in $FullControlAccounts)
    {
        NTFSPermission "FullControl_InetPub_$($account.tostring())" #  inetpub per V-100163 and V-100279
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path    = "e:\inetpub"
            Rights  = "FullControl"
         } 
    }

    Foreach($account in $ReadOnlyAccounts)
    {
        NTFSPermission "Read_Inetpub_$($account.tostring())" #  inetpub per V-100163 and V-100279
        {
            Ensure  = "Present"
            Account = $account.tostring()
            Access  = "Allow"
            Path    = "e:\inetpub"
            Rights  = "ReadAndExecute"
         } 
    }

 

 $Presentprotocols = @("TLS 1.1",  "TLS 1.2") # Enable these Protocols

  foreach ($protocol in $Presentprotocols)
 {
   Protocol "Enable_$($protocol.tostring())_Client" # Set SChannel Registry Keys per V-100177
    {
     Protocol = $protocol.tostring()
     Type = "Client"
     Ensure = "Present"
    }

    Protocol "Enable_$($protocol.tostring())_Server" # Set SChannel Registry Keys per V-100177
    {
     Protocol = $protocol.tostring()
     Type = "Server"
     Ensure = "Present"
    }
     
 
 }
 #>
 
    } #End Node
} #End Configuration


#### # This will create a MOF file


 #This will apply the MOF file to the server 
 Start-DscConfiguration -ComputerName 'DSC2016SPAPP'  -Wait -verbose -Path C:\Users\administrator.ADATUM\Downloads\ -force 

<# 
Invoke-Command -ComputerName DSC2016SPAPP.adatum.com -ScriptBlock `
    {Get-WinEvent -LogName Microsoft-Windows-DSC/Operational -MaxEvents 10} 

    $cim = New-CimSession -ComputerName DSC2016SPAPP.adatum.com
    Get-DscConfiguration -CimSession $cim
    Get-DscConfigurationStatus -CimSession $cim

    Test-DscConfiguration -cimsession $cim #– true/false desired state
    Test-DscConfiguration -Detailed #– show resources in/out of state
    Get-DscConfiguration #– current state of configured resources
    Get-DscConfigurationStatus #– Date & time, success or failure, reboots
    Get-DscConfigurationStatus -All #– History of DSC events and status



    #>

 #$so = New-PsSessionOption –SkipCACheck
#Enter-PSSession -Computername dsc2016web -Credential (Get-Credential adatum\administrator) -UseSSL -SessionOption $so -verbose