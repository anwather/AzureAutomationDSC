Configuration NewDomainJoin
    {

    $DomainJoinCredential = Get-AutomationPSCredential -Name "DomainJoinCredential"

    Import-DscResource -ModuleName xNetworking,xComputerManagement
    
    Node SERVER
        {

        xDNSServerAddress DNS
            {
                Address = "10.8.0.4"
                InterfaceAlias = "Ethernet"
                AddressFamily = "IPv4" 
            }

        xComputer DomainJoin
            {
                Name = $Node.ComputerName
                DomainName = "MDT.LAB"
                Credential = $DomainJoinCredential
            }

        }

    }