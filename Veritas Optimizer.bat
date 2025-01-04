@echo off

title Veritas Optimizer

shift /0
mode 110,30
SETLOCAL EnableDelayedExpansion
chcp 65001 >nul 2>&1
 color 8

cls

:HOME
title Veritas Optimizer
echo.
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m                                                    
echo.
Echo        [42m                                                                                                 [0m
echo.                                                                                              
Echo.                                                                                                           
Echo.                                           [1m[[0m  [32m1[0m  [1m][0m  [1mOtimização no PC[0m          
Echo.                                                                                                      
Echo.                                                                                                      
Echo.                                           [1m[[0m  [32m2[0m  [1m][0m  [1mOtimização de Rede[0m     
Echo.                                                                                                      
Echo.                                                                                                      
Echo.                                           [1m[[0m  [32m3[0m  [1m][0m  [1mOtimização de Games[0m             
Echo.         
Echo.
Echo.                                                  [1m[[0m [32mX[0m [1mINFO[0m [1m][0m   
Echo.      
Echo        [42m                                                                                                 [0m
Echo.        
Echo.         

SET CHOICES=
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO idI9ADI9SI9D090409akxkoaoptojestrat
IF /I '%INPUT%'=='2' GOTO pedalskiprogramik949520xujsduachujcipkaXd
IF /I '%INPUT%'=='3' GOTO zartowalemhehepomachajdomakerki9493
IF /I '%INPUT%'=='X' GOTO zrobilemtow6godzinchyba
cls

:idI9ADI9SI9D090409akxkoaoptojestrat

@shift /0
title Veritas Optimizer 1/3
color 6
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m
echo.
Echo          [42m                                                                                               [0m
echo.
Echo.
Echo.                                          [1m[[0m  [32mA[0m  [1m][0m  [32mTODOS OS AJUSTE 375+[0m
Echo.
Echo.     
Echo.         [1m[[0m  [32m1[0m  [1m][0m  [1mOtimização de CPU[0m        [1m[[0m  [32m2[0m  [1m][0m  [1mOtimização de GPU[0m        [1m[[0m  [32m3[0m  [1m][0m  [1mOtimização de RAM[0m
Echo.
Echo.
Echo.
Echo.         [1m[[0m  [32m4[0m  [1m][0m  [1mOtimização de bateria[0m      [1m[[0m  [32m5[0m  [1m][0m  [1mConfigurações do Regedit[0m       [1m[[0m  [32m6[0m  [1m][0m  [1mOtimização de Memoria[0m
Echo.
Echo.
Echo.
Echo.         [1m[[0m  [32m7[0m  [1m][0m  [1mReforço Rápido[0m           [1m[[0m  [32m8[0m  [1m][0m  [1mConfigurações do Jogo[0m           [1m[[0m  [32m9[0m  [1m][0m  [1mOtimização do Input Lag[0m                
Echo. 
echo                                         [32m[ B para voltar ][0m   [90m[ N para pagina 2 ][0m 
Echo.
Echo          [42m                                                                                                 [0m
Echo.
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO CPU
IF /I '%INPUT%'=='2' GOTO GPU
IF /I '%INPUT%'=='3' GOTO RAM 
IF /I '%INPUT%'=='4' GOTO POWER
IF /I '%INPUT%'=='5' GOTO REGEDIT 
IF /I '%INPUT%'=='6' GOTO MEMORY
IF /I '%INPUT%'=='7' GOTO BOOSTER
IF /I '%INPUT%'=='8' GOTO GAME
IF /I '%INPUT%'=='9' GOTO INPUT
IF /I '%INPUT%'=='B' GOTO X
IF /I '%INPUT%'=='A' GOTO ZEGNAJSIEZKOMPEMPOZDROKURWO
IF /I '%INPUT%'=='N' GOTO uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty
cls

:X

goto :HOME
cls

:CPU

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f

cls 
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:GPU

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:RAM

reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
reg add "HKEY_LOCAL_MACHINE\System\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1500" /f

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:POWER

@shift /0
color 6

@echo off
powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/736395149218676837/813644065455341599/AdamxPowerPlan.pow' -OutFile %HOMEPATH%\AppData\Local\Temp\AdamxPowerPlan.pow
powercfg -import "%HOMEPATH%\AppData\Local\Temp\AdamxPowerPlan.pow"
 
cls 
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:REGEDIT

@shift /0
color 6

bcdedit /set allowedinmemorysettings 0 
bcdedit /set useplatformclock No 
bcdedit /set useplatformtick No 
bcdedit /set hypervisorlaunchtype Off 
bcdedit /set tscsyncpolicy Enhanced 
bcdedit /set debug No 
bcdedit /set isolatedcontext No 
bcdedit /set pae ForceEnable 
bcdedit /set bootmenupolicy Legacy 
bcdedit /set usefirmwarepcisettings No 



Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0%Ã„Â½%" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f

del /s /f /q c:\windows\temp\*.*
rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q C:\WINDOWS\Prefetch
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\tempor~1
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\temp
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\tmp
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\ff*.tmp
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\history
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\cookies
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\recent
deltree %Ã‚Â°rÃ‹â€¡%c:\windows\spool\printers
del c:\WIN386.SWP

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:MEMORY

@shift /0
color 6
 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolSize" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionViewSize" /t REG_DWORD /d 192 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d 3072 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SessionPoolSize" /t REG_DWORD /d 192 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolSize" /t REG_DWORD /d 192 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PhysicalAddressExtension" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d 1048576 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d 96 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalCriticalWorkerThreads" /t REG_DWORD /d 00000020 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalDelayedWorkerThreads" /t REG_DWORD /d 00000020 /f

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:BOOSTER 

@Echo off
del C:\Windows\QuickBoostScript.bat
del C:\Windows\QuickBoostScript.bat
del C:\Windows\QuickBoostScript.bat
del C:\Windows\QuickBoostScript.bat
del C:\Windows\QuickBoostScript.bat
cls
color 6
echo.
echo.
echo.
Echo Installing Updated Script

echo.
powershell -c "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SanGraphic/QuickBoost/main/Script.bat' -OutFile QuickBoostScript.bat 
move /y QuickBoostScript.bat C:\Windows
call C:\Windows\QuickBoostScript.bat
pause
exit

:GAME

@shift /0
color 6

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d ffffffff /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:INPUT

color 6

bcdedit /deletevalue useplatformclock
bcdedit /set disabledynamictick yes
bcdedit /set useplatformtick yes
powercfg -h off

cls
goto :idI9ADI9SI9D090409akxkoaoptojestrat

:ZEGNAJSIEZKOMPEMPOZDROKURWO

@echo Off
                                                                                                                                                  
echo Veritas!                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                                                                                                                                                                    
Color 6                                                                                                                                                                                                

echo [-] Criando backup do registro
echo.
regedit.exe /e "C:\RegistryBackup.reg"
echo.
echo [+] Backup do registro criado com sucesso
echo.
echo [-] Desativando UAC
echo.
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
echo [+] UAC desativado
:PROMPT
SET /P AREYOUSURE= Press "Y" To confirm [Y]/[N]
IF /I "%AREYOUSURE%" NEQ "Y" GOTO END

echo.
echo [-] Começando a ajustar todas as configurações!
echo.

echo. 
echo [-] Ajustando algumas configurações do Windows
echo.
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
echo [+] Todas as configurações ajustadas
echo.
echo [-] Desativando transparência
echo.
echo [+] Transparência desativada
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
echo.
echo [-] Desativando DVR do jogo
echo.
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f


echo.
echo [-] Você deseja desativar o DVR do jogo? Pode causar telas pretas após a tabulação alternativa, mas causará muito menos atraso
echo.
ECHO 1.Sim
ECHO 2.Não

echo.
echo !SELECIONE SUA OPÇÃO DIGITANDO UM NÚMERO ENTRE 1-2!
echo.

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
)
IF %a%==2 (Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "1" /f
)
echo.
echo [+] Ajustes aplicados
echo.
pause
echo [-] Habilitando agendamento de GPU acelerado por hardware
echo.
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
echo [+] Agendamento de GPU acelerado por hardware habilitado
echo.
echo [-] Desativar taxa de atualização variável 
echo.
Reg.exe add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f
echo [+] Taxa de atualização variável desativada
echo.
echo [-] Desativando teclas aderentes, ajustando as configurações do teclado
echo.
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
echo [+] Teclas aderentes desativadas e algumas configurações do teclado ajustadas
echo.
echo [-] Ajustando as configurações de privacidade do Windows + ajustes extras
echo.
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
echo [+] Configurações de privacidade do Windows ajustadas + ajustes extras aplicados
echo.
echo [-] Deseja desativar os serviços de diagnóstico?
echo.
ECHO 1.Sim
ECHO 2.Não

echo.
echo !SELECIONE SUA OPÇÃO DIGITANDO UM NÚMERO ENTRE 1-2!
echo.

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f)

IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "2" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "3" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "3" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "2" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "3" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "3" /f
IF %a%==2 Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "3" /f

echo [+] Configurações de privacidade do Windows ajustadas + ajustes extras aplicados
PAUSE

echo.
echo [-] Desativando inicialização rápida
echo.
Powercfg -h off

echo.
echo [+] Inicialização rápida desativada
echo.
echo [-] Ajustando configurações adicionais do Windows
echo.
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MaxAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "196608" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f
echo.
echo [+] Configurações adicionais do Windows ajustadas

echo.
echo [-] Desativar estimativa de bateria
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f

echo.
echo [+] Estimativa de bateria desativada

echo.
echo [-] Ajustes na qualidade de vida
echo.
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "AllUpView" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView\AllUpView" /v "Remove TaskView" /t REG_DWORD /d "1" /f
echo.
echo [+] Adicionados alguns ajustes de QFA

echo.
echo [-] Alterando a separação de prioridade do Win32
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f

echo.
echo [+] Alterado a separação de prioridade Win32

echo.
echo [-] Ajustando configurações USB e prioridade de thread
echo.
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
echo.
echo [+] Configurações USB ajustadas e prioridade de thread

echo.
echo [-] Desativando dicas e aeroshake
echo.

Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
echo.
echo [+] Dicas e aeroshakes desativado
echo.

echo [-] Reduzindo o tempo de inicialização
echo.

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f
echo.
echo [+] Tempo de inicialização reduzido
echo.

echo [-] Configurações do ícone de cache
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "1750" /f
echo.
echo [+] Configurações ajustadas do ícone de cache
echo.
echo [-] Desativando notificações
echo.
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f
echo.
echo [+] Notificações desativadas
echo.
echo [-] Desativando a coleta de dados da Microsoft

Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
echo.
echo [+] Coleta de dados da Microsoft desativada 
echo.
echo [-] Otimizando jogos
echo.
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
echo.
echo [+] Jogos otimizados
echo.
echo [-] Ajustando TODOS os ajustes de CPU e energia
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCUR
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f

echo.
echo [+] Ajustou MUITOS ajustes de CPU e energia

echo.
echo [-] Ajustando TODAS as configurações de registro da GPU
echo.


Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f
echo.
echo [+] Ajustadas TODAS as configurações de registro do GPU

echo.
echo [-] Ajustando o menu para matar o tempo
echo.

Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
echo.
echo [+] Menu ajustado para matar o tempo

echo.
echo [-] Desativando a hibernação
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
echo.
echo [+] Hibernação desativada

echo.
echo [-] Prioridade de aplicação (áudio)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
echo.
echo [-] Prioridade de aplicação (captura)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
echo.
echo [-] Prioridade da Aplicação (Processamento de Pós-Produção)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
echo.
echo [-] Ajustes (Distribuição)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
echo.
echo [-] Prioridade da Aplicação (Baixa Latência)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
echo.
echo [-] Prioridade da Aplicação (Reprodução)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
echo.
echo [-] Prioridade da Aplicação (Áudio Profissional)
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "2" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "3" /f)
 
echo [+] Opção selecionada e ajustada
PAUSE

echo.
echo [-] Desativando serviços desnecessários
echo.
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f

echo.
echo [-] Desativando driver de energia GPU
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f

echo.
echo [-] Aplicativos em segundo plano desativados
echo.
echo [+] Desativou aplicativos de fundo desnecessários
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
echo.
echo [-] Diminuição do tempo de processo de paralisação
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f

echo [+] Diminuição do tempo de processo de paralisação
echo.
echo [-] Desativar a manutenção automática
echo.

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
echo [+] Manutenção Automática Desativada

echo.
echo [-] Aplicando Ajustes na Vram 
echo.

fsutil behavior query memoryusage
fsutil behavior set memoryusage 2
bcdedit /set increaseuserva 8000
echo [+] Ajustes Aplicados na Vram 
echo.
echo [-] Desativar a Compressão de Memória
echo.

PowerShell "Disable-MMAgent -MemoryCompression"
echo [+] Compressão de memória desativada
echo.
echo [-] Desativação de mitigações
echo.

PowerShell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"

echo.
echo [-] Desativar as Dicas Dinamicas 
echo.
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
echo [+] Ajustes aplicados com sucesso

echo.
echo [-] Scaling 
echo.
echo [-] JOGA EM 1920X1080? SELECCIONE NÃO SE NÃO QUISER!
echo.
ECHO 1.Sim
ECHO 2.Não

echo.
echo !SELECCIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-2!
echo.

set /p a=
IF %a%==1 (C:\Windows\AtlasModules\nsudo -U:T -P:E -UseCurrentConsole -Wait C:\Windows\AtlasModules\atlas-config.bat /displayscalingd)
IF %a%==2 (Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f)
echo [+] Opção Selecionada e Ajustada
PAUSE

echo.
echo [-] Reconstrução de Contadores de Desempenho
echo.
lodctr /r
echo [+] Contadores de Desempenho Reconstruídos 1
lodctr /r
echo [+] Contadores de Desempenho Reconstruídos 2

echo.
echo [-] Definições de eliminação de tarefas
echo.

taskkill -F -FI "IMAGENAME eq SystemSettings.exe"
echo [+] Ajustes de Eliminação de Tarefa Aplicada


echo. 
echo [-] Excluir o Cache do Windows Update e arquivos inúteis
echo.

net stop wuauserv
net stop UsoSvc
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
gpupdate /force
rd s q "C:\Windows\SoftwareDistribution"
md "C:\Windows\SoftwareDistribution"
net start wuauserv
net start UsoSvc

echo [-] Cache do Windows Update excluído e arquivos inúteis
echo.


PAUSE

echo.
echo [-] Aplicando a alta prioridade da CPU do Fortnite
echo.
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
echo [+] FN Aplicado de Alta Prioridade

echo.
echo [-] Desativar carimbos de ficheiro
echo.

FSUTIL beconjunto havior disablelastaccess 1
echo [+] Carimbos de Ficheiro Desativados


echo.
echo [-] Importar o melhor plano de bateria 
echo.

powershell -c "Invoke-WebRequest -Uri 'https://cdn.discordapp.com/attachments/736395149218676837/813644065455341599/AdamxPowerPlan.pow' -OutFile %HOMEPATH%\AppData\Local\Temp\AdamxPowerPlan.pow
powercfg -import "%HOMEPATH%\AppData\Local\Temp\AdamxPowerPlan.pow"
echo.
echo [-] Excluir Planos de Energia Inúteis
echo.
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
echo.
echo [-] Desfragmentar SSD
echo.

dfrgui

echo SVC split treshhold
echo.
echo [-] ENCONTRE O SEU TANTO DE RAM!
echo.
echo.

ECHO 1. 2GB
ECHO 2. 4GB
ECHO 3. 8GB
ECHO 4. 12GB
ECHO 5. 16GB
ECHO 6. 32GB
ECHO 7. 64GB
ECHO 8. Reverter
echo.

echo !SELECCIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-8!
echo.

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "34173266" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "68764420" /f)
IF %a%==3 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "137922056" /f)
IF %a%==4 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "307767570" /f)
IF %a%==5 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "376926742" /f)
IF %a%==6 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "861226034" /f)
IF %a%==7 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "1729136740" /f)
IF %a%==8 (Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "3670016" /f)


echo [-] SELECIONE QUAL É A SUA VERSÃO DO WINDOWS
echo.
ECHO 1. WINDOWS 10
ECHO 2. WINDOWS 11
echo.
echo !SELECIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO!

set /p a=
IF %a%==1 (Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f)
IF %a%==1 (Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f)
IF %a%==2 (Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f)
IF %a%==2 (Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f)

echo.
echo [-] ESCOLHA QUAL DOS DOIS É VOCÊ
echo.
ECHO 1. NOTEBOOK DE BAIXO CUSTO QUE SUPERAQUECE
ECHO 2. PC DESKTOP OU UM LAPTOP QUE NÃO SUPERAQUEÇA)
echo.
echo !SELECIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO!

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f)

Pause

echo [-] VOCÊ DESEJA DESATIVAR O SENSOR DE ARMAZENAMENTO (LIMPEZA AUTOMÁTICA) MEU LIMPADOR É MELHOR E NÃO FUNCIONA EM SEGUNDO PLANO!
echo.
ECHO 1. Sim
ECHO 2. Não
echo.
echo !SELECIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-2!

IF %a%==1 (Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f)
IF %a%==2 (Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "1" /f)

echo.
echo [-] Opções de Performance

%windir%\system32\SystemPropertiesPerformance.exe

Pause

echo.
echo [-] Definições de som e gravação
echo.

control mmsys.cpl sounds
echo.
echo [+] DIMINUIR OS PROCESSOS EM SEGUNDO PLANO

pause
echo.
echo [-] Remover aplicações de arranque

taskmgr

echo.
echo [-] Ajustes de serviço (adicionais)
echo.

sc config "XboxGipSvc" start=disabled
sc config "XblAuthManager" start=disabled
sc config "XblGameSave" start=disabled
sc config "XboxNetApiSvc" start=disabled
echo [-] Serviços Xbox desativados (novamente)

sc config "SteelSeriesUpdateService" start=disabled
sc config "LGHUBUpdaterService" start=disabled

echo [-] Indexação de Pesquisa Desativada

sc config "SensrSvc" start=disabled
echo [-] Serviço de Monitorização de Sensores Desativadoes Desativado

sc config "SensorService" start=disabled
echo [-] Disabled SensorService

sc config "WSearch" start=disabled
echo [-] Indexação de Pesquisa Desativada

sc config "RemoteAccess" start=disabled
echo [-] Roteamento e Acesso Remoto Desativados

sc config "ssh-agent" start=disabled
echo [-] Agen de Autenticação OpenSSH Desativado

sc config "AppVClient" start=disabled
echo [-] Cliente Microsoft App-V desativado

sc config "CertPropSvc" start=disabled
echo [-] Serviço de Certificado Desativado

sc config "tzautoupdate" start=disabled
echo [-] Atualizador Automático de Fuso Horário Desativado


echo.
echo [-] Ajustes de Animação
echo.

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
echo.
echo [-] Ajustes do Bios Legado
echo.
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
echo.
echo [-] Desativar serviços inúteis de uma unidade
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_402ac" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f

echo.
echo [-] Desativar HPET
bcdedit /deletevalue useplatformclock
echo.
echo [-] Desativar a marcação dinâmica (poupança de energia do notebook)
bcdedit /set disabledynamictick yes
echo.
echo [-] Desativar temporizadores sintéticos
bcdedit /set useplatformtick yes
echo.
echo [-] Tempo limite de arranque 0
bcdedit /timeout 0
echo.
echo [-] Desativar nx
bcdedit /set nx optout
echo.
echo [-] Disativa a animação da tela do boot 
bcdedit /set bootux disabled
echo.
echo [-] Acelere os tempos do boot
bcdedit /set bootmenupolicy standard
echo.
echo [-] Desativar hiper virtualização
bcdedit /set hypervisorlaunchtype off
echo.
echo [-] Disativa trusted platform module (TPM)
bcdedit /set tpmbootentropy ForceDisable
echo.
echo [-] Remover logótipo de início de sessão do Windows
bcdedit /set quietboot yes
echo.
echo [-] Desativar o logótipo do boot
cdedit /set {globalsettings} custom:16000067 true
echo.
echo [-] Desativar animação giratória
bcdedit /set {globalsettings} custom:16000069 true
echo.
echo [-] Desativar mensagens do boot
bcdedit /set {globalsettings} custom:16000068 true
echo.
echo [-] Ajustes de Teclado 
echo.
echo [-] Ajustar Propriedades do Teclado
echo.
main.cpl keyboard
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last BounceKey Setting" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Delay" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Repeat" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Wait" /t REG_DWORD /d "0" /f
echo.
echo [-] Tamanho da fila de dados do teclado
echo.
echo [-] ESCOLHA O SEU TIPO DE PC!
echo.
ECHO 1.PC OTIMO
ECHO 2.PC BOM
ECHO 3.PC MEDIO
ECHO 4.PC RUIM
ECHO 5.PC BATATA
ECHO 6.Alterar manualmente

echo.
echo !SELECCIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-6!
echo.

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "19" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f)
IF %a%==3 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "21" /f)
IF %a%==4 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "24" /f)
IF %a%==5 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "32" /f)
IF %a%==6 (REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /f)
IF %a%==6 (START regedit)
 
echo.
echo [+] Ajustes de teclado aplicados
echo.

PAUSE

echo.
echo [-] Ajustes do Mouse
echo.
echo [-] Ajustar as propriedades do Mouse
echo.
main.cpl mouse
pause
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d "40" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d "360" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "500" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f

echo.
echo [-] Tamanho da fila de dados do mouse
echo.
echo.
echo [-] ESCOLHA O SEU PC!
echo.
ECHO 1.PC OTIMO
ECHO 2.PC BOM
ECHO 3.PC MEDIO
ECHO 4.PC RUIM
ECHO 5.PC BATATA
ECHO 6.Alterar manualmente

echo.
echo !SELECCIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-6!

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "19" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f)
IF %a%==3 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "21" /f)
IF %a%==4 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "24" /f)
IF %a%==5 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "32" /f)
IF %a%==6 (REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters /f)
IF %a%==6 (START regedit)

echo.
echo [-] Aplicado Todos os Ajustes do Mouse!
echo.

PAUSE

echo.
echo [-] Ajustes USB
echo.

Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f

echo.
echo [+] Todos os ajustes aplicados com sucesso!
echo.




PAUSE


------------------------------------------------------------------------------------------------------------------------------------------



:pedalskiprogramik949520xujsduachujcipkaXd

@shift /0
title Veritas Otmização de Rede
color 6
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m  
echo.
Echo          [42m                                                                                                 [0m
echo. 
Echo.         
Echo.     
Echo.                        [1m[[0m  [32m1[0m  [1m][0m  [1mEmpulso[0m                        [1m[[0m  [32m2[0m  [1m][0m  [1mDetecção de Hit[0m
Echo.
Echo.
Echo.
Echo.                                             [1m[[0m  [32m3[0m  [1m][0m  [1mRegedit + Netsh[0m       
Echo.
Echo.
Echo.
Echo.                        [1m[[0m  [32m4[0m  [1m][0m  [1mOtimizar TCP[0m                     [1m[[0m  [32m5[0m  [1m][0m  [1mOtimizar Netsh[0m                
Echo. 
echo                                                  [32m[ B para voltar ][0m  
Echo.
Echo          [42m                                                                                                 [0m
Echo.
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO zmiejszonykutashehealeyikesXd
IF /I '%INPUT%'=='2' GOTO ophiciory2k20
IF /I '%INPUT%'=='3' GOTO toitaknicniedajejakcosXdDDDDDDD 
IF /I '%INPUT%'=='4' GOTO topodjebaneodinnejaplikacjiajkcoshehehacker
IF /I '%INPUT%'=='5' GOTO jaktoklikniesztobedzieszmialratapozdro
IF /I '%INPUT%'=='B' GOTO alebekemamzcbkgosciujaktymasz9lat

:alebekemamzcbkgosciujaktymasz9lat

goto :HOME

:zmiejszonykutashehealeyikesXd

@shift /0
color 6
echo.
echo Loading.
ping -n 3,5 localhost >nul
cls
echo.
echo Loading..
ping -n 3,5 localhost >nul
cls
echo.
echo Loading...
ping -n 3,5 localhost >nul

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat
powershell Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr
powershell Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_server
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient
powershell Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer
powershell Enable-NetAdapterQos -Name "*"
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent

powershell Set-NetTCPSetting -SettingName Internet -MinRto 300
netsh int ip set global multicastforwarding=disabled

netsh int ipv6 set dynamicportrange protocol=udp start=1025 num=64511
netsh int tcp set global rsc=en
POWERSHELL "Set-NetTCPSetting -SettingName InternetCustom -InitialCongestionWindow 10"
netsh int tcp set heuristics disabled

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "Start" /t REG_DWORD /d "1" /f
POWERSHELL Enable-NetAdapterBinding -Name * -ComponentID ms_pacer
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "1" /f
powershell Enable-NetAdapterBinding -Name * -ComponentID ms_tcpip6

reg add HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters /v DnsQueryTimeouts /d "1 1 2 2 4 0" /t REG_MULTI_SZ  /f


for /f %%r in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s^|Findstr HKEY_') do (
Reg add %%r /v "NonBestEffortLimit" /t Reg_DWORD /d "0" /f 
Reg add %%r /v "DeadGWDetectDefault" /t Reg_DWORD /d "1" /f 
Reg add %%r /v "PerformRouterDiscovery" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TCPNoDelay" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpInitialRTT" /t Reg_DWORD /d "2" /f
Reg add %%r /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f
Reg add %%r /v "MTU" /t Reg_DWORD /d "1500" /f
Reg add %%r /v "MSS" /t Reg_DWORD /d "1460" /f
Reg add %%r /v "UseZeroBroadcast" /t Reg_DWORD /d "0" /f
)

Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NTEContextList" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f

cls
goto :pedalskiprogramik949520xujsduachujcipkaXd

:ophiciory2k20

@shift /0
color 6 

netsh interface ipv4 set subinterface "Ethernet 2" mtu=1500 store=persistent
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
netsh int tcp set global autotuninglevel=exp
netsh int tcp set supplemental Internet congestionprovider=cubic
netsh int tcp set global ecn=en
netsh int tcp set heuristics disabled
netsh interface tcp set heuristics wsh=default

netsh int tcp set global dca=en
netsh int tcp set global netdma=disabled
PowerShell.exe Set-NetOffloadGlobalSetting -TaskOffload Disabled
netsh interface ip set interface Ethernet metric=
netsh interface ip set interface Ethernet ignoredefaultroutes=disabled store=persistent
netsh interface ip set interface Ethernet forwarding=disabled store=persistent
netsh interface ip set interface Ethernet otherstateful=disabled store=persistent
netsh interface ip set interface Ethernet weakhostsend=en store=persistent
netsh interface ip set interface Ethernet weakhostreceive=en store=persistent
netsh interface ip set interface Ethernet advertisedrouterlifetime=1800 store=persistent
netsh interface ip set interface Ethernet advertisedefaultroute=enabled store=persistent
netsh interface ip set interface Ethernet forcearpndwolpattern=disabled store=persistent
netsh interface ip set interface Ethernet enabledirectedmacwolpattern=disabled store=persistent

netsh interface tcp set heuristics disabled
netsh interface tcp set heuristics wsh=enabled
POWERSHELL Set-NetAdapterRSS -Name "*" -BaseProcessorNumber 2
netsh int udp set global uro=dis

Reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t Reg_DWORD /d "38" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f 
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" /V "DisableSecuritySettingsCheck" /T "REG_DWORD" /D "00000001" /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v SynAttackProtect /t REG_DWORD /d 0
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v ArpCacheLife /t REG_DWORD /d 86400
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v ArpCacheMinReferencedLife /t REG_DWORD /d 3600
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v ArpCacheSize /t REG_DWORD /d 200
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v TcpUseRFC1122UrgentPointer /t REG_DWORD /d 1
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters /f /v TcpMaxDupAcks /t REG_DWORD /d 2

powershell.exe "Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled"
netsh int tcp set g rsc=d
netsh int ipv4 set global defaultcurhoplimit=255

cls
goto :pedalskiprogramik949520xujsduachujcipkaXd

:toitaknicniedajejakcosXdDDDDDDD

@shift /0
color 6 

netsh interface ipv4 set interface "Ethernet" metric=70
netsh interface ipv4 set interface "Ethernet" mtu=1500
netsh int ipv4 set subinterface "Ethernet 2" mtu=1500 store=persistent
netsh int tcp set global netdma=dis
netsh int tcp set global initialRto=2000
netsh int ipv4 set glob defaultcurhoplimit=100
netsh int tcp set security mpp=disabled profiles=disabled
netsh int tcp set global timestamps=dis
netsh int ip set global icmpredirects=disabled
netsh int tcp set global hystart=en
netsh interface ip set interface Ethernet ignoredefaultroutes=disabled store=persistent
netsh interface ip set interface Ethernet forwarding=disabled store=persistent
netsh interface ip set interface Ethernet retransmittime=0 store=persistent
netsh interface ip set interface Ethernet basereachabletime=1 store=persistent
netsh interface ip set interface Ethernet managedaddress=enabled store=persistent
netsh interface ip set interface Ethernet otherstateful=disabled store=persistent
netsh interface ip set interface Ethernet advertisedrouterlifetime=1800 store=persistent
netsh interface ip set interface Ethernet advertisedefaultroute=enabled store=persistent
netsh interface ip set interface Ethernet forcearpndwolpattern=disabled store=persistent
netsh interface ip set interface Ethernet enabledirectedmacwolpattern=disabled store=persistent
netsh int tcp set supp internet congestionprovider=cubic
netsh int tcp set supp internet congestionprovider=ctcp
netsh int tcp set global ecn=e
netsh int tcp set heuristics disabled
netsh interface isatap set state disabled
netsh int tcp set global rsc=en
PowerShell.exe Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_pacer
netsh int ip set global taskoffload=disabled
PowerShell Disable-NetAdapterChecksumOffload -Name "*"
PowerShell Disable-NetAdapterLso -Name "*"
PowerShell Disable-NetAdapterRsc -Name "*"
PowerShell Disable-NetAdapterIPsecOffload -Name "*"
PowerShell Disable-NetAdapterPowerManagement -Name "*"
PowerShell Disable-NetAdapterQos -Name "*"

netsh int tcp set global ecn=d

REM ### Disable Netbios on NIC on local LAN
REM hklm\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces
REM NetbiosOptions 0 = auto
REM NetbiosOptions 1 = on
REM NetbiosOptions 2 = off
REM For /f %%k in ('Reg.exe Query hklm\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces /f "192.168." /d /s^|Findstr HKEY_') do (
For /f %%k in ('Reg.exe Query hklm\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces /f "NetbiosOptions" /v /s^|Findstr HKEY_') do (
	Reg.exe add %%k /v NetbiosOptions /t reg_dword /d 2 /f
	Reg.exe add %%k /v EnableNagling /t reg_dword /d 0 /f
)


for /f %%n in ('wmic path win32_networkadapter get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "02" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /t REG_DWORD /d "256" /f
)

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t REG_DWORD /d "1" /f 

for %%i in (csgo javaw FortniteClient-Win64-Shipping ModernWarfare r5apex) do (
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Application Name" /t Reg_SZ /d "%%i.exe" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Version" /t Reg_SZ /d "1.0" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Protocol" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local Port" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Local IP Prefix Length" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote Port" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Remote IP Prefix Length" /t Reg_SZ /d "*" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "DSCP Value" /t Reg_SZ /d "46" /f
    Reg add "HKLM\Software\Policies\Microsoft\Windows\QoS\%%i" /v "Throttle Rate" /t Reg_SZ /d "-1" /f
) >nul 2>nul

cls
goto :pedalskiprogramik949520xujsduachujcipkaXd

:jaktoklikniesztobedzieszmialratapozdro

@shift /0
color 6

netsh int ip set global taskoffload=enabled
netsh int tcp set global prr=dis
netsh int tcp set global hystart=dis
netsh int tcp set global ecn=en
netsh int tcp set global autotuninglevel=d
netsh int tcp set global nonsackrttresiliency=e
netsh int tcp set global rsc=en
netsh int tcp set supp internet congestionprovider=ctcp
powershell Restart-NetAdapter -name "*"
ipconfig /flushdns

cls
goto :pedalskiprogramik949520xujsduachujcipkaXd

:topodjebaneodinnejaplikacjiajkcoshehehacker

@shift /0
color 6 

reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{NIC-ID} /v TcpAckFrequency /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v Tcp1323Opts /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v GlobalMaxTcpWindowSize /t REG_DWORD /d 16777216 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DisableTimestamp /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v SackOpts /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{NIC-ID} /v TcpNoDelay /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v EnableTCPFastOpen /t REG_DWORD /d 1 /f

cls
goto :HOME

:zartowalemhehepomachajdomakerki9493

title Veritas Optimizer - Otimização de Games
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m  
echo.
Echo          [42m                                                                                                 [0m
echo.                                                                                              
Echo.                                                                                                           
Echo.                                              [1m[[0m  [32m1[0m  [1m][0m  [1mMinecraft[0m          
Echo.                                                                                                      
Echo.                                                                                                      
Echo.                                              [1m[[0m  [32m2[0m  [1m][0m  [1mFortnite[0m     
Echo.                                                                                                      
Echo.                                                                                                      
Echo.                                              [1m[[0m  [32m3[0m  [1m][0m  [1mCS:GO[0m             
Echo.         
Echo.
echo                                                   [32m[ B para voltar ][0m
echo.
ECHO          [42m                                                                                                 [0m
Echo.        
Echo.         

SET CHOICES=
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO Minecraft
IF /I '%INPUT%'=='2' GOTO Fortnite
IF /I '%INPUT%'=='3' GOTO CSGO 
IF /I '%INPUT%'=='B' GOTO dupacyckijawiemconajlepszehehe
cls

:Minecraft 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\javaw.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 00000003 /f

cls
goto :zartowalemhehepomachajdomakerki9493

:Fortnite 

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 00000003 /f

cls
goto :zartowalemhehepomachajdomakerki9493

:CSGO

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csgo.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 00000003 /f

cls
goto :zartowalemhehepomachajdomakerki9493

:dupacyckijawiemconajlepszehehe

goto :HOME

:zrobilemtow6godzinchyba

title Veritas Optimizer - INFO
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m  
echo.
Echo          [42m                                                                                                 [0m
echo.                                                                                               
Echo.                                                                                                         
Echo.                                                   dsc.gg/veritaz    
Echo.                                                                                         
Echo.                                                   creator ; tsvn__                                                                                               
Echo.                                                  
Echo.                                                
echo                                                   [32m[ B para voltar ][0m
echo.
ECHO          [42m                                                                                                 [0m
Echo.        
Echo.         

SET CHOICES=
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='B' GOTO superzabawabylapozdrawiamXd

:superzabawabylapozdrawiamXd

goto :HOME

:uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

@shift /0
title Veritas Optimizer 2/3
color 6
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m  
echo.
Echo          [42m                                                                                                 [0m
echo.
Echo.                                         
Echo.     
Echo.         [1m[[0m  [32m1[0m  [1m][0m  [1mOtimização de delay[0m      [1m[[0m  [32m2[0m  [1m][0m  [1mOtimização de ping [0m     [1m[[0m  [32m3[0m  [1m][0m  [1mDesative o Bluetooth[0m
Echo.
Echo.
Echo.
Echo.         [1m[[0m  [32m4[0m  [1m][0m  [1mOtimização de game[0m       [1m[[0m  [32m5[0m  [1m][0m  [1mWindows 32 Prioridade[0m      [1m[[0m  [32m6[0m  [1m][0m  [1mCleaner[0m
Echo.
Echo.
Echo.
Echo.         [1m[[0m  [32m7[0m  [1m][0m  [1mCorrija todos os erros do sistema[0m   [1m[[0m  [32m8[0m  [1m][0m  [1mDesativar descarregamento de tarefas[0m 
Echo.
Echo.
Echo.                                   [1m[[0m  [32m9[0m  [1m][0m  [1mDesative aplicativos em segundo plano[0m    
Echo.                                                                                                          
echo                      [90m[ X para pagina 1 ][0m   [32m[ B para voltar ao menu ][0m   [90m[ N para pagina 3 ][0m 
Echo.
Echo.
Echo          [42m                                                                                                 [0m
Echo.
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO mozektostoprzeczytaznudowtochcecipowiedziec
IF /I '%INPUT%'=='2' GOTO zetenprogramtobengerjebany
IF /I '%INPUT%'=='3' GOTO dalemtutajtakieopcjezewchujdajaczytopclubinternetu 
IF /I '%INPUT%'=='4' GOTO programniemazadnegorataanivirusa
IF /I '%INPUT%'=='5' GOTO jakchceszjakisprogramtopisznadcmvti0001 
IF /I '%INPUT%'=='6' GOTO tamdodajhasztagprzed0idodajpozdrowariacik
IF /I '%INPUT%'=='7' GOTO moglemdodachasztagalechujwieczywtedydzialawiecniechcemisie
IF /I '%INPUT%'=='8' GOTO pologbratkuwieszcojest5
IF /I '%INPUT%'=='9' GOTO blazingtooltogownololXd
IF /I '%INPUT%'=='B' GOTO zartowalemproszenieratujmniekacorvixonplsno
IF /I '%INPUT%'=='X' GOTO cipeczketomaszfajnaniepowiemzeniehehe
IF /I '%INPUT%'=='N' GOTO odmalolataczujewstreddopolicji

:mozektostoprzeczytaznudowtochcecipowiedziec

color 6

reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d ffffffff /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v Size /t REG_DWORD /d 00000003 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v EnableOplocks /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 00000020 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v SharingViolationDelay /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v SharingViolationRetries /t REG_DWORD /d 00000000 /f

cls
goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:zetenprogramtobengerjebany

color 6

reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "" /t REG_SZ /d "" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v Affinity /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v Priority /t REG_DWORD /d 00000003 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d 00002710 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d 00000008 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f

cls
goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:dalemtutajtakieopcjezewchujdajaczytopclubinternetu

color 6

reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d 00000004 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d 00000004 /f

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:programniemazadnegorataanivirusa

color 6

reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 00002710 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 00000008 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 00000006 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "BackgroundPriority" /t REG_DWORD /d 00000000 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:jakchceszjakisprogramtopisznadcmvti0001

color 6

reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v ConvertibleSlateMode /t REG_DWORD /d 0 /f
reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d 38 /f

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:tamdodajhasztagprzed0idodajpozdrowariacik

color 6

echo CLEANER

echo.
echo. [-] Limpeza de ficheiros de registo
echo.

cd/
@echo.
del *.log /a /s /q /f

echo [+] Ficheiros de Registo Limpos
echo.

echo [-] Limpeza de ficheiros Temp
echo.

RD /S /Q %temp%
MKDIR %temp%
takeown /f "%temp%" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q C:\Windows\Temp
MKDIR C:\Windows\Temp
takeown /f "C:\Windows\Temp" /r /d y
takeown /f %temp% /r /d y
echo [+] Ficheiros Temp limpos

echo.
echo [-] Liberando cache DNS
ipconfig /flushdns
echo. 
echo [-] Definições do Windows Update e Cache de Limpeza
echo.

net stop wuauserv
net stop UsoSvc
gpupdate /force
rd s q "C:\Windows\SoftwareDistribution"
md "C:\Windows\SoftwareDistribution"
net start wuauserv
net start UsoSvc

echo [+] Cache do Windows Update excluído e arquivos inúteis

echo.
echo [-] Limpa
echo.

cleanmgr



echo.
echo [+] Limpou todos os ficheiros
echo.

Pause

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:moglemdodachasztagalechujwieczywtedydzialawiecniechcemisie

echo off
echo Veritas
color 6

SFC /scannow

pause

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:pologbratkuwieszcojest5

color 6 

"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DisableTaskOffload" /t REG_DWORD /d 00000001 /f

cls
goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:blazingtooltogownololXd

color 6

reg.exe add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
reg.exe add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f

cls
goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty

:zartowalemproszenieratujmniekacorvixonplsno

goto :HOME

:cipeczketomaszfajnaniepowiemzeniehehe

goto :idI9ADI9SI9D090409akxkoaoptojestrat

:odmalolataczujewstreddopolicji

@shift /0
title Veritas Optimizer 3/3
color 6
echo.
echo.                                [32m██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗[0m
echo.                                [32m██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝[0m
echo.                                [32m██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗[0m
echo.                                [32m╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║[0m
echo.                                [32m ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║[0m
echo.                                [32m  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝[0m  
echo.
Echo          [42m                                                                                                 [0m
echo.
echo.
echo.
Echo.                                         [1m[[0m  [32m1[0m  [1m][0m  [1mAJUSTES DO TECLADO E MOUSE[0m   
Echo.
echo.            
Echo. 
echo                                    [90m[ X para pagina 2 ][0m   [32m[ B para voltar ao menu ][0m 
Echo. 
Echo.
Echo          [42m                                                                                                 [0m
Echo.
SET /P INPUT=[[32m%username%[0m[1m@Veritas][0m ~ 

cls

IF /I '%INPUT%'=='1' GOTO oddajetaopcjaeditywchodzajakwkurwejakasessa
IF /I '%INPUT%'=='B' GOTO mvtihackervixonpozdro216gildialubietocorobiepozdrohaha
IF /I '%INPUT%'=='X' GOTO dowloandtrojanvirusxd

:oddajetaopcjaeditywchodzajakwkurwejakasessa

@echo off
echo Veritas
color 6

echo.
echo [-] Ajustes de Keyobard
echo.
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f

Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last BounceKey Setting" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Delay" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Repeat" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Wait" /t REG_DWORD /d "0" /f
echo.
echo [+] Tamanho da fila de dados do teclado e mouse
echo.
echo [-] ESCOLHA O SEU PC!
echo.
ECHO 1.PC OTIMO
ECHO 2.PC BOM
ECHO 3.PC MEDIO
ECHO 4.PC RUIM
ECHO 5.PC BATATA
ECHO 6.Alterar manualmente
echo.
echo !SELECIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-6!
echo.

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "19" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f)
IF %a%==3 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "21" /f)
IF %a%==4 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "24" /f)
IF %a%==5 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "32" /f)
IF %a%==6 (REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /f)
IF %a%==6 (START regedit)
 
echo.
echo [-] Ajustes de teclado aplicados
echo.

PAUSE

echo.
echo [-] Ajustes do Mouse
echo.

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d "40" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d "360" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "500" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f
echo.
echo [-] Tamanho da fila de dados do mouse
echo.
echo.
echo [-] ESCOLHA O SEU PC!
echo.
ECHO 1.PC OTIMO
ECHO 2.PC BOM
ECHO 3.PC MEDIO
ECHO 4.PC RUIM
ECHO 5.PC BATATA
ECHO 6.Alterar manualmente

echo.
echo !SELECIONE A SUA OPÇÃO ESCREVENDO UM NÚMERO ENTRE 1-6!

set /p a=
IF %a%==1 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "19" /f)
IF %a%==2 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f)
IF %a%==3 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "21" /f)
IF %a%==4 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "24" /f)
IF %a%==5 (Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "32" /f)
IF %a%==6 (REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters /f)
IF %a%==6 (START regedit)

echo.
echo [+] Teclado e Mouse Ajustes Aplicados com Sucesso!
echo.

PAUSE
goto :odmalolataczujewstreddopolicji 

:mvtihackervixonpozdro216gildialubietocorobiepozdrohaha

goto :HOME

:dowloandtrojanvirusxd

goto :uwolnicbonusapozdrowieniadowiezienialecadlamojegotaty