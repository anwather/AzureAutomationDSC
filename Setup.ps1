$resourceGroupName = "SystemCenter"
$automationAccountName = "SystemCenter"
$automationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccountName

$cred = Get-Credential

$automationAccount | New-AzureRmAutomationCredential -Name DSCAdminAccount -Value $cred


