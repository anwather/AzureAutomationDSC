$resourceGroupName = "AA-Automation"
$automationAccountName = "AADSCFull"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

Import-AzureRmAutomationDscConfiguration -SourcePath "C:\Source\AzureAutomationDSC\SCCMPrerequisites.ps1" `
                                         -Published `
                                         -ResourceGroupName $resourceGroupName `
                                         -AutomationAccountName $automationAccountName `
                                         -Force `
                                         -Verbose

$automationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName CredentialSample -ConfigurationData $ConfigData -Verbose