$resourceGroupName = "AA-Automation"
$automationAccountName = "AADSC-Full"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

$ConfigData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $True
            PSDscAllowDomainUser = $True
         },
        @{
            NodeName = "CMTrace"
         }
    )
}

Import-AzureRmAutomationDscConfiguration -SourcePath "C:\Source\AzureAutomationDSC\TestSharePermission.ps1" `
                                         -Published `
                                         -ResourceGroupName $resourceGroupName `
                                         -AutomationAccountName $automationAccountName `
                                         -Force `
                                         -Verbose

$automationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName TestSharePermission -ConfigurationData $ConfigData -Verbose

#$automationAccount | Get-AzureRmAutomationDscOnboardingMetaconfig -OutputFolder C:\Temp