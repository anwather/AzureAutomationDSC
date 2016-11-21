﻿ Configuration SCCMPrerequisites
    {

    Import-DSCResource -ModuleName PSDesiredStateConfiguration

    Node PSS
        {
            WindowsFeature NetFx35_Install
			{
				Name = "Net-FrameWork-Features"
				Ensure = "Present"
                		#Source = "G:\Sources\SxS"
			}
            
            WindowsFeature RSAT_AD_PowerShell 
			{
				Ensure = 'Present'
				Name   = 'RSAT-AD-PowerShell'
			}

            WindowsFeature RDC
			{
				Name="RDC"
				Ensure="Present"
				DependsOn = "[WindowsFeature]RSAT_AD_PowerShell"
			}

			WindowsFeature BITS
			{
				Name="BITS"
				Ensure="Present"
				IncludeAllSubFeature = $true
				DependsOn = "[WindowsFeature]RDC"
			}

			WindowsFeature WebServer
			{
				Name="Web-Server"
				Ensure="Present"
				DependsOn = "[WindowsFeature]BITS"
			}

			WindowsFeature ISAPI
			{
				Name="Web-ISAPI-Ext"
				Ensure="Present"
				DependsOn="[WindowsFeature]WebServer"
			}

			WindowsFeature WindowsAuth
			{
				Name="Web-Windows-Auth"
				Ensure="Present"
				DependsOn="[WindowsFeature]WebServer"
			}

			WindowsFeature IISMetabase
			{
				Name="Web-Metabase"
				Ensure="Present"
				DependsOn="[WindowsFeature]WebServer"
			}

            File TempFolder
            {
                Ensure = "Present"
				Type = "Directory"
				DestinationPath = "C:\Temp"
				DependsOn = "[WindowsFeature]IISMetabase"
            }

			WindowsFeature IISWMI
			{
				Name="Web-WMI"
				Ensure="Present"
				DependsOn= "[WindowsFeature]WebServer"
			}
            


            

            WindowsFeature UpdateServices-UI
			{
				Ensure = "Present"
				Name = "UpdateServices-UI"
			}
        }
    }


