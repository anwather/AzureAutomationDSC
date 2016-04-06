$resourceGroupName = "SystemCenter"
$automationAccountName = "SystemCenter"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

$ConfigData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $True
         },
        @{
            NodeName = "Examplefile"
         }
    )
}

# Note you must put in the full path !!!!
Import-AzureRmAutomationDscConfiguration -SourcePath "CredentialSample.ps1" -Published -ResourceGroupName SystemCenter -AutomationAccountName SystemCenter -Force -Verbose

$automationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName CredentialSample -ConfigurationData $ConfigData -Verbose
