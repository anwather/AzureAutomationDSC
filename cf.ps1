

$cf = @{
	AllNodes = @(
       @{
            NodeName="*"
            RetryCount = 30
            RetryIntervalSec = 30
            PSDscAllowDomainUser = $true
			PSDscAllowPlainTextPassword = $true			
         },
         @{
            NodeName = "JOIN"
         }
	)
}

$resourceGroupName = "AA-Automation"
$automationAccountName = "AADSC-Full"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

Import-AzureRmAutomationDscConfiguration -SourcePath "C:\users\anwather\Documents\DomainOps.ps1" -Published -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Force -Verbose

$automationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName DomainOps -ConfigurationData $CF -Verbose


