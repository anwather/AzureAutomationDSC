Configuration CredentialSample
{
   $Cred = Get-AutomationPSCredential -Name "DSCAdminAccount"

    Node $AllNodes.NodeName
    { 
        File ExampleFile
        { 
            SourcePath = "\\Server\share\path\file.ext" 
            DestinationPath = "C:\destinationPath" 
            Credential = $Cred 
        }
    }
}


