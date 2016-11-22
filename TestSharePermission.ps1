Configuration TestSharePermission
{

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $Credential = Get-AutomationPSCredential -Name "SCCMAdminAccount"

    Node CMTrace
        {

        File TempFolder
            {
                Ensure = "Present"
				Type = "Directory"
				DestinationPath = "C:\Temp"
			}
        
        File CMTrace
            {
                SourcePath = "\\Sccm-cm01\c$\Program Files\Microsoft Configuration Manager\tools\CMTrace.exe"
                DestinationPath = "C:\Temp\"
                Credential = $Credential
            }

        }

}





