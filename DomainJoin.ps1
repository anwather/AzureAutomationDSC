Configuration DomainOps
    {

    $cred = Get-AzureRmAutomationCredential -Name DomainAdmin

    Import-DscResource -ModuleName PSDesiredStateConfiguration,xNetworking,xComputerManagement

    Node JOIN
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
				Address = $cf.DnsServerAddress
				InterfaceAlias = $cf.InterfaceAlias
				AddressFamily = $cf.AddressFamily
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