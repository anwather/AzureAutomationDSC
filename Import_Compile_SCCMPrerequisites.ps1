$resourceGroupName = "AA-Automation"
$automationAccountName = "AADSC-Full"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

Import-AzureRmAutomationDscConfiguration -SourcePath "C:\Source\AzureAutomationDSC\SCCMPrerequisites.ps1" `
                                         -Published `
                                         -ResourceGroupName $resourceGroupName `
                                         -AutomationAccountName $automationAccountName `
                                         -Force `
                                         -Verbose

$automationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName SCCMPrerequisites -ConfigurationData $ConfigData -Verbose

$automationAccount | Get-AzureRmAutomationDscOnboardingMetaconfig -OutputFolder C:\Temp