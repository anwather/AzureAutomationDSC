<#
.Synopsis
   Imports a configuration into Azure Automation DSC and optionally compiles it
.DESCRIPTION
   Imports a configuration into Azure Automation DSC and optionally compiles it. The script requires an Azure Automation account and a written configuration. 
   By default the monitoring job runs every 10 seconds however this can be configured by adjusting the function call.
.EXAMPLE
   Imports a configuration and uploads it, runs a compilation job and monitors it.
   
   .\Import_Compile_ADT_OSconfig.ps1 -ResourceGroupName <<Resource Group Name>>
                                     -AutomationAccountName <<Automation Account Name>>
                                     -ConfigurationPath <<full path to the configuration file - can not be a UNC path>>
                                     -Compile
.EXAMPLE
   Imports a configuration and uploads it. Does not run a compilation job
   
   .\Import_Compile_ADT_OSconfig.ps1 -ResourceGroupName <<Resource Group Name>>
                                     -AutomationAccountName <<Automation Account Name>>
                                     -ConfigurationPath <<full path to the configuration file - can not be a UNC path>>
                                     
#>

#TODO - Create a parameter for the Configuration Data hashtable.

Param(
    [Parameter(Mandatory=$true,HelpMessage="Provide a resource group name")]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true,HelpMessage="Provide an automation account name")]
    [string]$AutomationAccountName,

    [Parameter(Mandatory=$true,HelpMessage="Provide the full path to a configuration file")]
    [ValidateScript({$_ -match "^\w:"})] # Cannot be a UNC path
    [string]$ConfigurationPath,

    [switch]$Compile=$true
    )

Function Monitor-CompilationJob
    {
    Param([string]$JobID,[int]$Delay=5,$AutomationAccount)

    do
    {
    Write-Output "Checking status of job: $JobID"
    $job = $AutomationAccount | Get-AzureRmAutomationDscCompilationJob -Id $JobID
    Write-Output "Status: $($job.Status)" 
    Start-Sleep -Seconds $Delay   
    }
    while ($job.Status -notmatch "Completed|Suspended")
    

    }

try
    {
        $AutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction STOP
    }
catch
    {
        Write-Output $Error[0].Exception
        exit
    }


$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $True
            PSDscAllowDomainUser = $True
         },
        @{
            NodeName = "DomainJoin"
            ComputerName = "MDT-DJTEST01"
            
         }
    )
}

try
    {
        $AutomationAccount | Import-AzureRmAutomationDscConfiguration -SourcePath $ConfigurationPath `
                                                 -Published `
                                                 -ResourceGroupName $resourceGroupName `
                                                 -AutomationAccountName $automationAccountName `
                                                 -Force `
                                                 -Verbose `
                                                 -ErrorAction STOP
    }
catch
    {
       Write-Output $Error[0].Exception
       exit 
    }
                                         

if ($Compile)
    {
        $CompilationJob = $AutomationAccount | Start-AzureRmAutomationDscCompilationJob -ConfigurationName NetworkConfig -ConfigurationData $ConfigurationData -Verbose
        Monitor-CompilationJob -JobID $CompilationJob.Id -Delay 10 -AutomationAccount $AutomationAccount
    }