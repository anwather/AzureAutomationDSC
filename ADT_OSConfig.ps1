Configuration ADT_OSConfig
{

Param
(
    [PSCredential]
    $ShareCredential
)

Import-DscResource -ModuleName xComputerManagement, xExtendedEventLog #, @{ModuleName="PSDesiredStateConfiguration";ModuleVersion="1.1"}

    Node $AllNodes.NodeName
    {
        # enable DSC analytic & debug logs
        xDebugAnalyticLog Enable_DSCAnalyticLog
        {
            EventLogName = 'Microsoft-Windows-DSC'
            EventLogType = 'Analytic'
            Enabled = $true
        }

        xDebugAnalyticLog Enable_DSCDebugLog
        {
            EventLogName = 'Microsoft-Windows-DSC'
            EventLogType = 'Debug'
            Enabled = $true
        }

        # load NTUSER.DAT to modify default user registry settings
        Script Load_NTUSER_DAT 
        {
            GetScript = {@{}}
            TestScript = {
                if (-not (Get-PSDrive -Name HKU -Scope Global -Verbose -ErrorAction SilentlyContinue) )
                {
                    return $false
                } 
                else 
                {
                    return $true
                } 
            }

            SetScript = {
                if (-not (Get-PSDrive -Name HKU -Scope Global -Verbose -ErrorAction SilentlyContinue) )
                {
                    cmd /c 'Reg LOAD HKU\Temp C:\Users\Default\NTUSER.DAT'
                    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction SilentlyContinue
                }
            }
        }

        Script Map_HKCR 
        {
            GetScript = {@{}}
            TestScript = {
                if (-not (Get-PSDrive -Name HKCR -Scope Global -Verbose -ErrorAction SilentlyContinue) )
                {
                    return $false
                } 
                else 
                {
                    return $true
                } 
            }

            SetScript = {
                  New-PSDrive -Name HKCR -PSProvider Registry -Scope Global -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue
            }
        }

        #region HKEY_USERS : Default User Registry Settings

        # 
        Registry Task_Bar_No_Notification
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
           ValueName =  'TaskbarNoNotification'
           ValueData =  1
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # 
        Registry Hide_Desktop_Icons_1
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
           ValueName =  '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
           ValueData = 0
           ValueType = 'Dword'  
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # 
        Registry Hide_Desktop_Icons_2
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
           ValueName =  '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # 
        Registry Visual_Effects
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
           ValueName =  'VisualFXSetting'
           ValueData = 2
           ValueType = 'Dword'
           Ensure = 'Present'
           DependsOn = '[Script]Load_NTUSER_DAT'
           Force = $true
        }

        # Enable Always show icons never thumbnails
        Registry Always_Show_Icons
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'IconsOnly'
           ValueData = 1
           ValueType = 'Dword'  
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Enable Always show menus
        Registry Always_Show_Menus_HKU
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'AlwaysShowMenus'
           ValueData = 1
           ValueType = 'Dword'
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Display file icon on thumbnails
        Registry Disable_Display_File_Icon
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowTypeOverlay'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Display file size information in folder tips
        Registry Disable_Display_File_Size
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'FolderContentsInfoTip'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Enable Display the full path in the title bar
        Registry Display_Full_Path_In_Title_Bar
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
           ValueName =  'FullPath'
           ValueData = 1
           ValueType = 'Dword'
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Enable Show Hidden files, folders, and drives
        Registry Enable_Show_Hidden_Files_Drives
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'Hidden'
           ValueData = 1
           ValueType = 'Dword'  
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Hide empty drives in the Computer folder
        Registry Disable_Hide_Empty_Drives
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'HideDrivesWithNoMedia'
           ValueData = 0
           ValueType = 'Dword' 
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Hide extensions for known file types
        Registry Disable_Hide_Extensions_For_Known_File_Types
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'HideFileExt'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Enable Show Protected operating system files
        Registry Enable_Show_Protected_Operating_System_Files
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowSuperHidden'
           ValueData = 1
           ValueType = 'Dword'
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Show pop-up description for folders and desktop items
        Registry Disable_Show_Pop_up_Description
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowInfoTip'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Show preview handlers in preview pane
        Registry Disable_Show_Preview_Handlers
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowPreviewHandlers'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Use Sharing Wizard
        Registry Disable_Use_Sharing_Wizard_HKU
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'SharingWizardOn'
           ValueData = 0
           ValueType = 'Dword'  
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # 
        Registry Task_Bar_Size_Move
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'TaskbarSizeMove'
           ValueData = 0
           ValueType = 'Dword'  
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # Disable Setting Store and display recently opened items in Start menu and the taskbar
        Registry Disable_Display_MRU_Start_Menu
        {
           Key = 'HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'Start_TrackDocs'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        # 
        Registry Show_IE_Status_Bar
        {
           Key = 'HKU:\Temp\Software\Microsoft\Internet Explorer\MINIE'
           ValueName =  'ShowStatusBar'
           ValueData = 1
           ValueType = 'Dword'  
           Force = $true
           Ensure = 'Present'
           DependsOn = '[Script]Load_NTUSER_DAT'
        }

        #endregion 

        # unload NTUSER.DAT
        Script UnLoad_NTUSER_DAT 
        {
            GetScript = {@{}}
            TestScript = {
                if (Get-Item -Path HKU:\Temp -ErrorAction SilentlyContinue)
                {
                    return $false
                }
                else 
                {
                    return $true
                } 
            }

            SetScript = {
                # remove the drive
                Remove-PSDrive -Name HKU -Force -Confirm:$false -Verbose -ErrorAction SilentlyContinue

                # important! - release any handles bfore trying to unload the hive
                [GC]::Collect()

                # now unload the hive
                cmd /c 'Reg UNLOAD HKU\Temp' 
                }
            DependsOn = '[Script]Load_NTUSER_DAT'
        }
        
        #region HKEY_CURRENT_USER : Current User Registry Settings

        # Allows users to go to the desktop instead of the Start screen when they sign in.
        Registry Allows_Users_To_Desktop_On_Signin
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage'
           ValueName =  'OpenAtLogon'
           ValueData = 0
           ValueType = 'Dword'  
           Ensure = 'Present'
        }

        # 
        Registry New_Start_Panel_1
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
           ValueName =  '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # 
        Registry New_Start_Panel_2
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
           ValueName =  '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
        }

        # 
        Registry Visual_Effects_2
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
           ValueName =  'VisualFXSetting'
           ValueData = 2
           ValueType = 'Dword' 
           Ensure = 'Present'
        }

        # Enable Always show icons, never thumbnails
        Registry Icons_Only
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'IconsOnly'
           ValueData = 1
           ValueType = 'Dword' 
           Ensure = 'Present'
        }

        # Enable Always show menus
        Registry Always_Show_Menus_HKCU
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'AlwaysShowMenus'
           ValueData = 1
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # Disable Display file icon on thumbnails
        Registry Show_Type_Overlay
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowTypeOverlay'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # Disable Display file size information in folder tips
        Registry Folder_Contents_Info_Tip
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'FolderContentsInfoTip'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # Enable Display the full path in the title bar
        Registry Cabinet_State
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
           ValueName =  'FullPath'
           ValueData = 1
           ValueType = 'Dword'   
           Ensure = 'Present'
        }

        # Enable Show Hidden files, folders, and drives
        Registry Explorer_Hidden
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'Hidden'
           ValueData = 1
           ValueType = 'Dword'   
           Ensure = 'Present'
        }

        # Disable Hide empty drives in the Computer folder
        Registry Hide_Drives_With_No_Media
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'HideDrivesWithNoMedia'
           ValueData = 0
           ValueType = 'Dword'  
           Ensure = 'Present'
        }

        # Disable Hide extensions for known file types
        Registry Hide_File_Extensions
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'HideFileExt'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
        }

        # Enable Show Protected operating system files
        Registry Show_Protected_OS_Files
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowSuperHidden'
           ValueData = 1
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # Disable Show pop-up description for folders and desktop items
        Registry Show_Pop_Up_Description
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowInfoTip'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        # Disable Show preview handlers in preview pane
        Registry Disable_Show_Preview_Handlers_In_Preview_Pane
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'ShowPreviewHandlers'
           ValueData = 0
           ValueType = 'Dword' 
           Ensure = 'Present'
        }

        # Disable Use Sharing Wizard
        Registry Disable_Use_Sharing_Wizard_HKCU
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'SharingWizardOn'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        Registry Task_Bar_No_Notification_hkcu
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
           ValueName =  'TaskbarNoNotification'
           ValueData =  1
           ValueType = 'Dword'   
           Ensure = 'Present'
           Force = $true
        }

        # Disable Setting Store and display recently opened items in Start menu and the taskbar
        Registry DSC_Resource_Instance_Name
        {
           Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
           ValueName =  'Start_TrackDocs'
           ValueData = 0
           ValueType = 'Dword'   
           Ensure = 'Present'
        }

        # 
        Registry Show_Status_Bar
        {
           Key = 'HKCU:\Software\Microsoft\Internet Explorer\MINIE'
           ValueName =  'ShowStatusBar'
           ValueData = 1
           ValueType = 'Dword'  
           Ensure = 'Present'
        }

        #endregion

        #region HKEY_LOCAL_MACHINE : System Registry Configuration

        #Server Manager is not displayed automatically when a user logs onto the server.
        Registry Do_Not_Open_ServerManager_At_Logon
        {
           Key = 'HKLM:\Software\Microsoft\ServerManager'
           ValueName =  'DoNotOpenServerManagerAtLogon'
           ValueData = 1
           ValueType =  'Dword'
           Ensure = 'Present'
        }

        # 
        Registry Remove_Windows_Store
        {
           Key = 'HKLM:\Software\Policies\Microsoft\WindowsStore'
           ValueName =  'RemoveWindowsStore'
           ValueData = 1
           ValueType =  'Dword'
           Ensure = 'Present'
        }

        # Vulnerability in SSL 3.0 could allow information disclosure POODLE vulnerability https://technet.microsoft.com/en-us/library/security/3009008.aspx
        Registry Disable_SSL_3_0
        {
           Key = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
           ValueName =  'Enabled'
           ValueData = 0
           ValueType = 'Dword'
           Ensure = 'Present'
        }

        Registry Machine_Type
        {
           Key = 'HKLM:\Software\Image'
           ValueName =  'MachineType'
           ValueData = 'Virtual'
           ValueType = 'String' 
           Ensure = 'Present'
        }

        Registry Revision_Version
        {
           Key = 'HKLM:\Software\Image'
           ValueName =  'Revision'
           ValueData = '1.00' 
           ValueType = 'String'
           Ensure = 'Present'
        }

        # 
        Registry Revision_Date
        {
           Key = 'HKLM:\Software\Image'
           ValueName =  'RevisionDate'
           ValueData = '2014/04/01' 
           ValueType = 'String' 
           Ensure = 'Present'
        }

        Registry Explorer_Remove_Music_Folder_1
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        Registry Explorer_Remove_Music_Folder_2
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        Registry Explorer_Remove_Pictures_Folder_1
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        Registry Explorer_Remove_Pictures_Folder_2
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        Registry Explorer_Remove_Videos_Folder_1
        {
            Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        Registry Explorer_Remove_Videos_Folder_2
        {
            Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}'
            Ensure = 'Absent'
            ValueType = 'String'
            ValueName = ''
        }

        #endregion

        #region HKEY_CLASSES_ROOT : Class information

        # 
        Registry Desktop_Open_Command_Window_Here
        {
           Key = 'HKCR:\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\runas'
           ValueName =  ''
           ValueData = 'Open command window here (Administrator)'
           ValueType = 'String'  
           Ensure = 'Present'
        }

        # 
        Registry Desktop_HAS_LUA_Shield
        {
           Key = 'HKCR:\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\runas'
           ValueName =  'HasLUAShield'
           ValueData = ''
           ValueType = 'String'
           Ensure = 'Present'
        }

        # 
        Registry Desktop_Command
        {
           Key = 'HKCR:\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\runas\command'
           ValueName =  ''
           ValueData = 'cmd.exe'
           ValueType = 'String' 
           Ensure = 'Present'
        }

        # 
        Registry Explorer_Open_Command_Window_Here
        {
           Key = 'HKCR:\Directory\shell\runas'
           ValueName =  ''
           ValueData = 'Open command window here (Administrator)'
           ValueType = 'String'  
           Ensure = 'Present'
        }

        # 
        Registry Explorer_Has_LUA_Shield
        {
           Key = 'HKCR:\Directory\shell\runas'
           ValueName =  'HasLUAShield'
           ValueData = ''
           ValueType = 'String'
           Ensure = 'Present'
        }

        Registry Explorer_Open_Command_Window_Here_Command
        {
           Key = 'HKCR:\Directory\shell\runas\command'
           ValueName =  ''
           ValueData = 'cmd.exe /s /k pushd ""%V""'
           ValueType = 'String'
           Ensure = 'Present'
        }

        #endregion

        #region : Apply Other System Settings

        Script Disable_Indexing # Disable Drive Indexing
        {
            GetScript = {@{}}
            TestScript = {
                $DriveLetter = "C:"
                $Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$DriveLetter'"

                if($Volume.IndexingEnabled -eq $true)
                {
                    return $false
                } 
                else
                {
                    return $true
                }
            }

            SetScript = {
                $DriveLetter = "C:"
                $Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$DriveLetter'"
                $Volume | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
            }
        }

        Script Disable_LinkLayer_Topology_Discovery_Responder_Binding # Disable LLTDIO Binding
        {
            GetScript = {@{}}
            TestScript = {
                $Adapters = Get-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Mapper I/O Driver' | Where-Object {$_.Enabled -eq $true}
          
                if($Adapters)
                {
                    return $false
                } 
                else
                {
                    return $true
                }
            }

            SetScript = {
                Get-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Mapper I/O Driver' | 
                Where-Object {$_.Enabled -eq $true} |
                Set-NetAdapterBinding -Enabled $false
            }
        }

        Script Disable_LinkLayer_Topology_Discovery_Mapper_Driver_Binding # Disable LLTDIO Binding
        {
            GetScript = {@{}}
            TestScript = {
                $Adapters = Get-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Responder' | Where-Object {$_.Enabled -eq $true}

                if($Adapters)
                {
                    return $false
                } 
                else
                {
                    return $true
                }
            }

            SetScript = {
                Get-NetAdapterBinding -DisplayName 'Link-Layer Topology Discovery Responder' | 
                Where-Object {$_.Enabled -eq $true} |
                Set-NetAdapterBinding -Enabled $false
            }
        }

        Script Disable_IP_V6_Driver_Binding # Disable IPv6 Binding
        {
            GetScript = {@{}}
            TestScript = {
                $Adapters = Get-NetAdapterBinding -DisplayName 'Internet Protocol Version 6 (TCP/IPv6)' | Where-Object {$_.Enabled -eq $true}

                if($Adapters)
                {
                    return $false
                } 
                else
                {
                    return $true
                }
            }

            SetScript = {
                Get-NetAdapterBinding -DisplayName 'Internet Protocol Version 6 (TCP/IPv6)' | 
                Where-Object {$_.Enabled -eq $true} |
                Set-NetAdapterBinding -Enabled $false
            }
        }

        Script Disable_QoS_Packet_Scheduler # Disable Qos Packet Scheduler
        {
            GetScript = {@{}}
            TestScript = {
                $Adapters = Get-NetAdapterBinding -DisplayName 'QoS Packet Scheduler' | Where-Object {$_.Enabled -eq $true}

                if($Adapters)
                {
                    return $false
                } 
                else
                {
                    return $true
                }
            }

            SetScript = {
                Get-NetAdapterBinding -DisplayName 'QoS Packet Scheduler' | 
                Where-Object {$_.Enabled -eq $true} |
                Set-NetAdapterBinding -Enabled $false
            }
        }

        Script Disable_LMHosts # Disable LM Hosts
        {
            GetScript = {@{}}
            TestScript = {
                return $false
            }

            SetScript = {
                ([wmiclass]"Win32_NetworkAdapterConfiguration").EnableWINS($null,$false)
            }
        }

        Script Enable_NetBIOS # Enable NetBIOS for all adapters
        {
            GetScript = {@{}}
            TestScript = {
                return $false
            }

            SetScript = {
                Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
                Foreach-Object {$_.SetTcpipNetbios(1)}
            }
        }

        File Copy_layoutFile_locally
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath '\OSBuild\2012R2\StartMenu\AppsFolderLayout.Bin')
            DestinationPath = 'C:\Windows\System32\AppsFolderLayout.Bin'
            Type = 'File'
            Ensure = 'Present'
            Force = $true
            Credential = $ShareCredential
        }

        
        Script Change_Start_Screen_Layout # Change Start Screen Layout
        {
            GetScript = {@{}}
            TestScript = {
                return $false
            }

            SetScript = {
                Import-StartLayout -LayoutPath "AppsFolderLayout.Bin" -MountPath C:\ -ErrorAction SilentlyContinue
            }
            DependsOn = '[File]Copy_layoutFile_locally'
        }
        
        File Change_Admin_Start_Screen_Layout # Change Administrator Start Screen Layout
        {
            Ensure = 'Present'
            Type = 'File'
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\2012R2\StartMenu\appsFolder.itemdata-ms')
            DestinationPath = "$env:SystemDrive\Users\Administrator\AppData\Local\Microsoft\Windows" 
            Force = $true
            Attributes = 'ReadOnly'
            Credential = $ShareCredential
            DependsOn = '[Script]Change_Start_Screen_Layout'
        }       

        File Remove_Windows_Store_Shortcut
        {
            Ensure = 'Absent'
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Store.lnk"
            Force = $true
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_Administrative_Shortcut_Files_Network_Connections
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\Network Connections.lnk')
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Network Connections.lnk"
            Ensure = 'Present'
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_Administrative_Shortcut_Files_program_features
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\Programs and Features.lnk')
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Programs and Feature.lnk"
            Ensure = 'Present'
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_Administrative_Shortcut_Files_system
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\System.lnk')
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System.lnk"
            Ensure = 'Present'
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_Administrative_Shortcut_Files_device_manager
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\Device Manager.lnk')
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Device Manager.lnk"
            Ensure = 'Present'
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_Administrative_Shortcut_Files_disk_management
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\Disk Management.lnk')
            DestinationPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Disk Management.lnk"
            Ensure = 'Present'
            Type = 'File'
            Credential = $ShareCredential
        }

        File Copy_TempsDirs_Directory
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\2012R2\Dirs\temp')
            DestinationPath = "$env:SystemDrive\temp"
            Ensure = 'Present'
            Type = 'Directory'
            Recurse = $true
            Credential = $ShareCredential
        } 
        
        File Copy_BuildDirs_Directory
        {
            SourcePath = (Join-Path -Path $Node.InstallSharePath -ChildPath 'OSBuild\2012R2\Dirs\Build')
            DestinationPath = "$env:SystemDrive\Build"
            Ensure = 'Present'
            Type = 'Directory'
            Recurse = $true
            Credential = $ShareCredential
        } 
        #endregion

    #region Package install

        Package Install_SCOM_Package
        {
            Ensure = 'Present'
            Name = 'Microsoft Monitoring Agent'
            ProductId = '786970C5-E6F6-4A41-B238-AE25D4B91EEA'
            Path = "$($Node.InstallSharePath)OSBuild\SCOM 2012 R2 Agent 7.1.10184.0 QBEAU\MOMAgent.msi"
            Credential = $ShareCredential
            LogPath = "$($env:SystemDrive)\Windows\Temp\QBE_SCOMAgent_7.1.10184.0.log"
            Arguments = ' USE_SETTINGS_FROM_AD=0 MANAGEMENT_GROUP=QBEAO MANAGEMENT_SERVER_DNS=AUHBSSCMWP0001.au.qbe.pri ACTIONS_USE_COMPUTER_ACCOUNT=1 USE_MANUALLY_SPECIFIED_SETTINGS=1 AcceptEndUserLicenseAgreement=1 /qn'
        }

        Package Install_SCCM_Package
        {
            Ensure = 'Present'
            Name = 'Configuration Manager Client'
            ProductId = '343D4507-997F-4553-9F86-2BB81F19A05E'
            Path = "$($Node.InstallSharePath)OSBuild\SCCM 2012 R2 Agent 5.00.8239.1001\ccmsetup.exe"
            Credential = $ShareCredential
            LogPath = "$($env:SystemDrive)\Windows\Temp\ccmsetup.5.00.8239.1001"
            Arguments = ' /skipprereq:silverlight.exe SMSMP=AUHBSSCMWP0004.au.qbe.pri SMSSITECODE=P01 FSP=AUHBSSCMWP0005.au.qbe.pri RESETKEYINFORMATION=True CCMLOGMAXSIZE=500000 SMSCACHEFLAGS=COMPRESS;PERCENTDISKSPACE SMSCACHESIZE=10'
        }
        
        Package Install_SEP_Package
        {
            Ensure = 'Present'
            Name = 'Symantec Endpoint Protection'
            ProductId = 'F90EEB64-A4CB-484A-8666-812D9F92B37B'
            Path = "$($Node.InstallSharePath)OSBuild\Symantec Endpoint 12.1.6 MP5 VM\Sep64.msi"
            Credential = $ShareCredential
            LogPath = "$($env:SystemDrive)\Windows\Temp\QBE_SEP_12.1.6_MP5_VM.log"
            Arguments = 'REBOOT=ReallySuppress /qn'
        }

    #endregion        
    }
}