Configuration DomainOps
    {

    $cred = Get-AutomationPSCredential -Name DomainAdmin

    Import-DscResource -ModuleName PSDesiredStateConfiguration,xNetworking,xComputerManagement

    Node $AllNodes.NodeName
        {

        LocalConfigurationManager
			{
				ConfigurationMode = 'ApplyAndAutoCorrect'
				RebootNodeIfNeeded = $true
				ActionAfterReboot = 'ContinueConfiguration'
				AllowModuleOverwrite = $true

			}
			
			WindowsFeature RSAT_AD_PowerShell 
				{
					Ensure = 'Present'
					Name   = 'RSAT-AD-PowerShell'
				}
			
			xDNSServerAddress DNS_Settings
            {
				Address = "10.7.0.4"
				InterfaceAlias = "Ethernet"
				AddressFamily = "IPv4"
			}        
	  
			xComputer Join_Domain
            {
                Name = $env:COMPUTERNAME
                Credential = $cred
                DomainName = "SCCM.LAB"
				DependsOn = "[xDNSServerAddress]DNS_Settings"
				
            }

        }

    }