function RequireAdmin {
    $CurrentWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentWindowsPrincipal = New-Object -TypeName System.Security.Principal.WindowsPrincipal `
        -ArgumentList $CurrentWindowsID
    $Admin = $CurrentWindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$Admin) {
        Start-Process -FilePath PowerShell.exe -ArgumentList `
            "-NoProfile -ExecutionPolicy RemoteSigned -File `"$PSCommandPath`" $PSBoundParameters" -Verb RunAs `
            -WindowStyle Normal
        [System.Environment]::Exit(0)
    }
}

function GetVertion {
    $ProductJsonPath = "$PSScriptRoot\product.json"

    if (!(Test-Path -Path $ProductJsonPath -PathType Leaf)) {
        Write-Warning -Message ("$ProductJsonPath 不存在")
        [System.Environment]::Exit(0)
    }

    $ProductInfo = $null
    try {
        $ProductInfo = Get-Content -Path $ProductJsonPath | ConvertFrom-Json
    }
    catch {
        Write-Warning -Message ("$ProductJsonPath 解析失败")
        [System.Environment]::Exit(0)
    }
    if (!$ProductInfo -or $ProductInfo -isNot [PSCustomObject]) {
        Write-Warning -Message ("$ProductJsonPath 解析失败")
        [System.Environment]::Exit(0)
    }

    $Version = $ProductInfo.'version'
    if (!$Version) {
        Write-Warning -Message ("$ProductJsonPath 不存在 version 信息")
        [System.Environment]::Exit(0)
    }

    return $Version
}

$Debug = $false
$DebugLog = "$PSScriptRoot\debug.log"

function ConfirmBefore {
    $Answer = Read-Host -Prompt '问题是否存在 (0: 否, 1: 是)'
    if ('1' -eq $Answer) {
        Add-Content -Path $script:DebugLog -Value '问题存在' -Force
    }
    else {
        Add-Content -Path $script:DebugLog -Value '问题不存在' -Force
    }
}

function ConfirmAfter {
    #Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
    $Answer = Read-Host -Prompt '问题是否解决 (0: 否, 1: 是)'
    if ('1' -eq $Answer) {
        Add-Content -Path $script:DebugLog -Value '问题已解决' -Force
    }
    else {
        Add-Content -Path $script:DebugLog -Value '问题未解决' -Force
    }
}

function RegWrite {
    param (
        $Desc,
        $Path,
        $Name,
        $Value,
        $Type,
        $Exclude
    )

    if ($Exclude -and $SystemInfo.Caption.Contains("$Exclude")) {
        return
    }

    if ($Desc) {
        Write-Host -Object ''
        Write-Host -Object $Desc
    }
    if ($script:Debug) {
        if ($Desc) {
            Add-Content -Path $script:DebugLog -Value '' -Force
            Add-Content -Path $script:DebugLog -Value "RegWrite Desc: $Desc" -Force
        }
        Add-Content -Path $script:DebugLog -Value "RegWrite Path: $Path" -Force
        Add-Content -Path $script:DebugLog -Value "RegWrite Name: $Name" -Force
        Add-Content -Path $script:DebugLog -Value "RegWrite Value: $Value" -Force
        Add-Content -Path $script:DebugLog -Value "RegWrite Type: $Type" -Force
        ConfirmBefore
    }

    if (!(Test-Path -Path $Path -PathType Container)) {
        Write-Warning -Message ("RegWrite: 不存在 Path=$Path, Name=$Name, Value=$Value, Type=$Type")
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegWrite 不存在 Path=$Path" -Force
        }
        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host -Object ("$Desc 失败, 无权创建 Path=$Path, Name=$Name, Value=$Value, Type=$Type") `
                -ForegroundColor Red
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegWrite 无权创建 Path=$Path" -Force
                ConfirmAfter
            }
            return
        }
    }
    else {
        if ($null -eq $Name -or '' -eq $Name) {
            Write-Warning -Message ("RegWrite: 已存在 Path=$Path, Name=$Name, Value=$Value, Type=$Type")
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegWrite 已存在 Path=$Path" -Force
                ConfirmAfter
            }
            return
        }
    }

    if (!(Test-Path -Path $Path -PathType Container)) {
        Write-Host -Object ("$Desc 失败, 不存在 Path=$Path, Name=$Name, Value=$Value, Type=$Type") -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegWrite 不存在 Path=$Path" -Force
            ConfirmAfter
        }
        return
    }

    if ($null -eq $Name -or '' -eq $Name) {
        if ($script:Debug) {
            ConfirmAfter
        }
        return
    }

    $Property = $null
    try {
        $Property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
    }

    if ($null -eq $Property -or '' -eq $Property) {
        if ('0' -eq "$Value") {
            Write-Warning -Message ("RegWrite: 不存在 Name=$Name, Path=$Path, Value=$Value, Type=$Type")
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegWrite 不存在 Name=$Name" -Force
            }
        }
    }
    else {
        $PropertyValue = $null
        try {
            $PropertyValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        }
        catch {
        }

        if ($null -eq $PropertyValue -or '' -eq $PropertyValue) {
            if ('0' -eq "$Value") {
                Write-Warning -Message ("RegWrite: 旧值不存在, Value=$Value, Path=$Path, Name=$Name, Type=$Type")
                if ($script:Debug) {
                    Add-Content -Path $script:DebugLog -Value "RegWrite 旧值不存在, Name=$Name" -Force
                }
            }
        }
        else {
            if ("$PropertyValue" -eq "$Value") {
                Write-Warning -Message ("RegWrite: 和旧值相等, Value=$Value, Path=$Path, Name=$Name, Type=$Type")
                if ($script:Debug) {
                    Add-Content -Path $script:DebugLog -Value "RegWrite 和旧值相等, Value=$Value, Name=$Name" -Force
                }
            }
        }
    }

    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Type $Type -ErrorAction Stop
    }
    catch {
        Write-Host -Object ("$Desc 失败, 无权修改 Name=$Name, Path=$Path, Value=$Value, Type=$Type") -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegWrite 无权修改 Name=$Name" -Force
        }
    }

    if ($script:Debug) {
        ConfirmAfter
    }
}

function RegDelete {
    param (
        $Desc,
        $Path,
        $Name,
        $Exclude
    )

    if ($Exclude -and $SystemInfo.Caption.Contains("$Exclude")) {
        return
    }

    if ($Desc) {
        Write-Host -Object ''
        Write-Host -Object $Desc
    }
    if ($script:Debug) {
        if ($Desc) {
            Add-Content -Path $script:DebugLog -Value '' -Force
            Add-Content -Path $script:DebugLog -Value "RegDelete Desc: $Desc" -Force
        }
        Add-Content -Path $script:DebugLog -Value "RegDelete Path: $Path" -Force
        Add-Content -Path $script:DebugLog -Value "RegDelete Name: $Name" -Force
        ConfirmBefore
    }

    if (!(Test-Path -Path $Path -PathType Container)) {
        Write-Warning -Message ("RegDelete: 不存在 Path=$Path, Name=$Name")
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegDelete 不存在 Path=$Path" -Force
            ConfirmAfter
        }
        return
    }

    if ($null -eq $Name -or '' -eq $Name) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object ("$Desc 失败, 无权删除 Path=$Path, Name=$Name") -ForegroundColor Red
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegDelete 无权删除 Path=$Path" -Force
            }
        }
        if ($script:Debug) {
            ConfirmAfter
        }
        return
    }

    $Property = $null
    try {
        $Property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
    }

    if ($null -eq $Property -or '' -eq $Property) {
        Write-Warning -Message ("RegDelete: 不存在 Name=$Name, Path=$Path")
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegDelete 不存在 Name=$Name" -Force
        }
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
        if ($script:Debug) {
            ConfirmAfter
        }
        return
    }

    $PropertyValue = $null
    try {
        $PropertyValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
    }

    if ($null -eq $PropertyValue -or '' -eq $PropertyValue) {
        Write-Warning -Message ("RegDelete: 旧值不存在, Path=$Path, Name=$Name")
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegDelete 旧值不存在, Name=$Name" -Force
        }
    }
    elseif ('0' -eq "$PropertyValue") {
        Write-Warning -Message ("RegDelete: 旧值为 0, Path=$Path, Name=$Name")
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegDelete 旧值为 0, Name=$Name" -Force
        }
    }

    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    }
    catch {
        Write-Host -Object ("$Desc 失败, 无权删除 Name=$Name, Path=$Path") -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegDelete 旧值为 0, 无权删除 Name=$Name" -Force
        }
    }

    if ($script:Debug) {
        ConfirmAfter
    }
}

function RegRename {
    param(
        $Desc,
        $Path,
        $Name,
        $NewName,
        $Exclude
    )

    if ($Exclude -and $SystemInfo.Caption.Contains("$Exclude")) {
        return
    }

    if ($Desc) {
        Write-Host -Object ''
        Write-Host -Object $Desc
    }
    if ($script:Debug) {
        if ($Desc) {
            Add-Content -Path $script:DebugLog -Value '' -Force
            Add-Content -Path $script:DebugLog -Value "RegRename Desc: $Desc" -Force
        }
        Add-Content -Path $script:DebugLog -Value "RegRename Path: $Path" -Force
        Add-Content -Path $script:DebugLog -Value "RegRename Name: $Name" -Force
        Add-Content -Path $script:DebugLog -Value "RegRename NewName: $NewName" -Force
        ConfirmBefore
    }

    if (!(Test-Path -Path $Path -PathType Container)) {
        Write-Host -Object ("$Desc 失败, 不存在 Path=$Path, Name=$Name, NewName=$NewName") `
            -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegRename 不存在 Path=$Path" -Force
            ConfirmAfter
        }
        return
    }

    $Property = $null
    try {
        $Property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
    }

    $NewProperty = $null
    try {
        $NewProperty = Get-ItemProperty -Path $Path -Name $NewName -ErrorAction Stop
    }
    catch {
    }

    if ($null -eq $Property -or '' -eq $Property) {

        if ($null -ne $NewProperty -and '' -ne $NewProperty) {
            Write-Warning -Message ("RegRename: 不存在 Name=$Name, 已存在 NewName=$NewName, Path=$Path")
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegRename 不存在 Name=$Name, 已存在 NewName=$NewName" -Force
                ConfirmAfter
            }
            return
        }

        Write-Host -Object ("$Desc 失败, 不存在 Name=$Name, Path=$Path, NewName=$NewName") `
            -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegRename 不存在 Name=$Name" -Force
            ConfirmAfter
        }
        return
    }

    if ($null -eq $NewProperty -or '' -eq $NewProperty) {
        try {
            Rename-ItemProperty -Path $Path -Name $Name -NewName $NewName -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object ("$Desc 失败, 无权重命名 Name=$Name, Path=$Path, NewName=$NewName") `
                -ForegroundColor Red
            if ($script:Debug) {
                Add-Content -Path $script:DebugLog -Value "RegRename 无权重命名 Name=$Name" -Force
            }
        }
        if ($script:Debug) {
            ConfirmAfter
        }
        return
    }

    Write-Warning -Message ("RegRename: 已存在 NewName=$NewName, Path=$Path, Name=$Name")
    if ($script:Debug) {
        Add-Content -Path $script:DebugLog -Value "RegRename 已存在 NewName=$NewName" -Force
    }
    try {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
    }
    catch {
        Write-Host -Object ("$Desc 失败, 无权删除 Name=$Name, Path=$Path, NewName=$NewName") `
            -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "RegRename 无权删除 Name=$Name" -Force
        }
    }

    if ($script:Debug) {
        ConfirmAfter
    }
}

function GetBlankIconPath {

    $BlankIconFile = [System.Environment]::ExpandEnvironmentVariables('%systemroot%\Blank.ico')
    if (Test-Path -Path $BlankIconFile -PathType Leaf) {
        return '%systemroot%\Blank.ico'
    }

    if (!(Test-Path -Path "$PSScriptRoot\Blank.ico" -PathType Leaf)) {
        Write-Warning -Message ('GetBlankIconPath: 不存在 Blank.ico 图标文件')
        return '%SystemRoot%\System32\imageres.dll,-1015'
    }

    try {
        Copy-Item -Path "$PSScriptRoot\Blank.ico" -Destination $BlankIconFile -Force -ErrorAction Stop
        return '%systemroot%\Blank.ico'
    }
    catch {
        Write-Warning -Message ("GetBlankIconPath: 复制 Blank.ico 图标文件到 $BlankIconFile 目录失败")
        return '%SystemRoot%\System32\imageres.dll,-1015'
    }
}

function UninstallApp {
    param (
        $Desc,
        $AppName
    )

    if ($Desc) {
        Write-Host -Object ''
        Write-Host -Object $Desc
    }
    if ($script:Debug) {
        if ($Desc) {
            Add-Content -Path $script:DebugLog -Value '' -Force
            Add-Content -Path $script:DebugLog -Value "UninstallApp Desc: $Desc" -Force
        }
        Add-Content -Path $script:DebugLog -Value "UninstallApp AppName: $AppName" -Force
        ConfirmBefore
    }

    $App = Get-AppxPackage -Name $AppName
    if (!$App) {
        Write-Warning -Message "UninstallApp: $AppName 不存在"
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "UninstallApp 不存在 AppName=$AppName" -Force
            ConfirmAfter
        }
        return
    }

    try {
        Remove-AppxPackage -Package $App
    }
    catch {
        Write-Host -Object ("$Desc 失败, 无权删除 AppName=$AppName") -ForegroundColor Red
        if ($script:Debug) {
            Add-Content -Path $script:DebugLog -Value "UninstallApp 无权删除 AppName=$AppName" -Force
        }
    }

    if ($script:Debug) {
        ConfirmAfter
    }
}

function UninstallOneDrive {

    Write-Host -Object ''
    Write-Host -Object '卸载 OneDrive'

    Stop-Process -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $OneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    if (!(Test-Path -Path $OneDrivePath -PathType Leaf)) {
        $OneDrivePath = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }

    if (Test-Path -Path $OneDrivePath -PathType Leaf) {
        Start-Process -FilePath $OneDrivePath -ArgumentList '/uninstall' -NoNewWindow -Wait
        Start-Sleep -Seconds 3
        Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    else {
        Write-Warning -Message "UninstallOneDrive: 不存在 OneDriveSetup.exe, OneDrivePath=$OneDrivePath"
    }

    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue

    RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
}

function UninstallXbox {

    Write-Host -Object ''
    Write-Host -Object '卸载 Xbox'

    UninstallApp -AppName 'Microsoft.XboxIdentityProvider'
    UninstallApp -AppName 'Microsoft.XboxSpeechToTextOverlay'
    UninstallApp -AppName 'Microsoft.XboxGamingOverlay'
    UninstallApp -AppName 'Microsoft.XboxGameOverlay'
    UninstallApp -AppName 'Microsoft.XboxApp'
    UninstallApp -AppName 'Microsoft.Xbox.TCUI'
    #UninstallApp -AppName 'Microsoft.GamingApp'

    RegWrite -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\GameBar' `
        -Name 'AutoGameModeEnabled' `
        -Value 0 `
        -Type DWord
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\System\GameConfigStore' `
        -Name 'GameDVR_Enabled' `
        -Value 0 `
        -Type DWord
    RegWrite -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR' `
        -Name 'AllowGameDVR' `
        -Value 0 `
        -Type DWord
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' `
        -Name 'AppCaptureEnabled' `
        -Value 0 `
        -Type DWord
}

function CommonOptim {

    RegWrite -Desc '隐藏任务栏中的搜索框' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' `
        -Name 'SearchboxTaskbarMode' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '隐藏任务视图按钮' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'ShowTaskViewButton' `
        -Value 0 `
        -Type DWord

    RegDelete -Desc '显示操作中心' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -Name 'DisableNotificationCenter' `
        -Exclude 11

    RegWrite -Desc '任务栏时钟精确到秒' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'ShowSecondsInSystemClock' `
        -Value 1 `
        -Type DWord `
        -Exclude 11

    RegWrite -Desc '显示开始菜单、任务栏、操作中心和标题栏的颜色' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' `
        -Name 'ColorPrevalence' `
        -Value 1 `
        -Type DWord
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\DWM' `
        -Name 'ColorPrevalence' `
        -Value 1 `
        -Type DWord

    #RegWrite -Desc '使开始菜单、任务栏、操作中心透明' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' `
    #    -Name 'EnableTransparency' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '不允许在开始菜单显示建议' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
    #    -Name 'SystemPaneSuggestionsEnabled' `
    #    -Value 0 `
    #    -Type DWord
    #RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
    #    -Name 'SubscribedContent-338388Enabled' `
    #    -Value 0 `
    #    -Type DWord
    #RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
    #    -Name 'SubscribedContent-338389Enabled' `
    #    -Value 0 `
    #    -Type DWord

    RegWrite -Desc '关闭在应用商店中查找处理未知扩展名的应用' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -Name 'NoUseStoreOpenWith' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '关闭商店应用推广' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'PreInstalledAppsEnabled' `
        -Value 0 `
        -Type DWord

    #RegWrite -Desc '关闭锁屏时的 Windows 聚焦推广' `
    #    -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
    #    -Name 'RotatingLockScreenEnable' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '关闭使用 Windows 时获取技巧和建议' `
    #    -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
    #    -Name 'SoftLandingEnabled' `
    #    -Value 0 `
    #    -Type DWord

    RegWrite -Desc '关闭突出显示新安装的程序' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'Start_NotifyNewApps' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '禁止自动安装推荐的应用程序' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        -Name 'SilentInstalledAppsEnabled' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '登录界面默认打开小键盘' `
        -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard' `
        -Name 'InitialKeyboardIndicators' `
        -Value '2' `
        -Type String

    RegWrite -Desc '关闭 Cortana' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'ShowCortanaButton' `
        -Value 0 `
        -Type DWord `
        -Exclude 11
    #RegWrite -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana' `
    #    -Name 'Value' `
    #    -Value 0 `
    #    -Type DWord
    #RegWrite -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
    #    -Name 'AllowCortana' `
    #    -Value 0 `
    #    -Type DWord

    RegWrite -Desc '打开资源管理器时显示此电脑' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'LaunchTo' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '显示所有文件扩展名' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'HideFileExt' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '显示隐藏文件' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'Hidden' `
        -Value 1 `
        -Type DWord
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'ShowSuperHidden' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '隐藏快捷方式小箭头' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons' `
        -Name '29' `
        -Value (GetBlankIconPath) `
        -Type String

    #RegWrite -Desc '隐藏可执行文件小盾牌' `
    #    -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons' `
    #    -Name '77' `
    #    -Value (GetBlankIconPath) `
    #    -Type String

    #RegWrite -Desc '隐藏 NTFS 蓝色双箭头压缩标识' `
    #    -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons' `
    #    -Name '179' `
    #    -Value (GetBlankIconPath) `
    #    -Type String

    RegRename -Desc 'Shift 右键显示在此处打开 PowerShell 窗口' `
        -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\Powershell' `
        -Name 'HideBasedOnVelocityId' `
        -NewName 'ShowBasedOnVelocityId' `
        -Exclude 11
    RegRename -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\Powershell' `
        -Name 'HideBasedOnVelocityId' `
        -NewName 'ShowBasedOnVelocityId' `
        -Exclude 11
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas' `
        -Name '(Default)' `
        -Value '在此处以管理员身份打开 PowerShell 窗口' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas' `
        -Name 'Extended' `
        -Value '' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command' `
        -Name '(Default)' `
        -Value "wt.exe new-tab PowerShell -noexit -command Set-Location -literalPath '%V'" `
        -Type String `
        -Exclude 10
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command' `
        -Name '(Default)' `
        -Value "PowerShell -noexit -command Set-Location -literalPath '%V'" `
        -Type String `
        -Exclude 11
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\runas' `
        -Name '(Default)' `
        -Value '在此处以管理员身份打开 PowerShell 窗口' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\runas' `
        -Name 'Extended' `
        -Value '' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\runas\command' `
        -Name '(Default)' `
        -Value "wt.exe new-tab PowerShell -noexit -command Set-Location -literalPath '%V'" `
        -Type String `
        -Exclude 10
    RegWrite -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shell\runas\command' `
        -Name '(Default)' `
        -Value "PowerShell -noexit -command Set-Location -literalPath '%V'" `
        -Type String `
        -Exclude 11

    RegWrite -Desc '创建快捷方式时不添快捷方式文字' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'Link' `
        -Value ([byte[]](0, 0, 0, 0)) `
        -Type Binary

    #RegDelete -Desc '隐藏音乐文件夹' `
    #    -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
    #        + '\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}')
    #RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
    #        + '\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}')
    RegWrite -Desc '隐藏音乐文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    #RegDelete -Desc '隐藏下载文件夹' `
    #    -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
    #        + '\{374DE290-123F-4565-9164-39C4925E467B}')
    #RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
    #        + '\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}')
    RegWrite -Desc '隐藏下载文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    #RegDelete -Desc '隐藏图片文件夹' `
    #    -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
    #        + '\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}')
    #RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
    #        + '\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}')
    RegWrite -Desc '隐藏图片文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    #RegDelete -Desc '隐藏视频文件夹' `
    #    -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
    #        + '\{A0953C92-50DC-43bf-BE83-3742FED03C9C}')
    #RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
    #        + '\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}')
    RegWrite -Desc '隐藏视频文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    #RegDelete -Desc '隐藏文档文件夹' `
    #    -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
    #        + '\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}')
    #RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
    #        + '\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}')
    RegWrite -Desc '隐藏文档文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    RegDelete -Desc '隐藏桌面文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace' `
            + '\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}')
    RegDelete -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer' `
            + '\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}')
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    RegWrite -Desc '隐藏 3D 对象文件夹' `
        -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' `
            + 'FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag') `
        -Name 'ThisPCPolicy' `
        -Value 'Hide' `
        -Type String `
        -Exclude 11
    #RegWrite -Path ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\' `
    #        + 'FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag') `
    #    -Name 'ThisPCPolicy' `
    #    -Value 'Hide' `
    #    -Type String

    #RegWrite -Desc '收起资源管理器功能区' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon' `
    #    -Name 'MinimizedStateTabletModeOff' `
    #    -Value 1 `
    #    -Type DWord

    RegWrite -Desc '快速访问不显示常用文件夹' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' `
        -Name 'ShowFrequent' `
        -Value 0 `
        -Type DWord

    #RegWrite -Desc '快速访问不显示最近使用的文件' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' `
    #    -Name 'ShowRecent' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '隐藏语言栏到任务栏' `
    #    -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\CTF\LangBar' `
    #    -Name 'ShowStatus' `
    #    -Value 4 `
    #    -Type DWord
    #RegWrite -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\CTF\LangBar' `
    #    -Name 'ExtraIconsOnMinimized' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '隐藏语言栏上的帮助按钮' `
    #    -Path ('Registry::HKEY_CURRENT_USER\Software\Microsoft\CTF\LangBar\ItemState' `
    #        + '\{ED9D5450-EBE6-4255-8289-F8A31E687228}') `
    #    -Name 'DemoteLevel' `
    #    -Value 3 `
    #    -Type DWord

    #RegWrite -Desc '禁用 Windows 11 加入的新右键菜单' `
    #    -Path ('Registry::HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' `
    #        + '\InprocServer32') `
    #    -Exclude 10

    RegWrite -Desc '在桌面显示我的电脑' `
        -Path ('Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' `
            + '\NewStartPanel') `
        -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' `
        -Value 0 `
        -Type DWord

    #RegWrite -Desc '在桌面显示回收站' `
    #    -Path ('Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' `
    #        + '\NewStartPanel') `
    #    -Name '{645FF040-5081-101B-9F08-00AA002F954E}' `
    #    -Value 0 `
    #    -Type DWord

    #RegDelete -Desc '禁用可执行文件的 "兼容性疑难解答" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\Compatibility'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Msi.Package\ShellEx\ContextMenuHandlers\Compatibility'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\lnkfile\shellex\ContextMenuHandlers\Compatibility'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\batfile\ShellEx\ContextMenuHandlers\Compatibility'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\cmdfile\ShellEx\ContextMenuHandlers\Compatibility'

    #RegDelete -Desc '禁用磁盘的 "启用 Bitlocker" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde'
    RegDelete -Desc '禁用磁盘的 "启用 Bitlocker" 右键菜单' `
        -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev'

    RegDelete -Desc '禁用磁盘的 "以便携式方式打开" 右键菜单' `
        -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{D6791A63-E7E2-4fee-BF52-5DED8E86E9B8}'

    #RegDelete -Desc '禁用磁盘的 "复制磁盘" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{59099400-57FF-11CE-BD94-0020AF85B590}'

    #RegDelete -Desc '禁用新建的 "联系人" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\.contact\ShellNew'

    #RegDelete -Desc '禁用新建、文件以及文件夹的 "公文包" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Briefcase\ShellNew'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers\BriefcaseMenu'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\BriefcaseMenu'

    #RegDelete -Desc '禁用新建 "ZIP/RAR文件" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\.rar\ShellNew'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\.zip\ShellNew'

    #RegDelete -Desc '禁用文件、磁盘以及属性的 "还原以前版本" 右键菜单' `
    #    -Path ('Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers' `
    #        + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\PropertySheetHandlers' `
    #        + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex' `
    #        + '\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex' `
    #        + '\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    RegDelete '禁用文件、磁盘以及属性的 "还原以前版本" 右键菜单' `
        -Path ('Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers' `
            + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Directory\shellex\PropertySheetHandlers' `
    #        + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers' `
            + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers' `
    #        + '\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex' `
    #        + '\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex' `
    #        + '\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}')

    #RegDelete -Desc '禁用桌面的 "小工具" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Gadgets'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\DesktopBackground\Shell\Gadgets'

    #RegDelete -Desc '禁用文件、文件夹、桌面以及所有对象的 "共享文件夹同步" 右键菜单' `
    #    -Path ('Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers' `
    #        + '\XXX Groove GFS Context Menu Handler XXX')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers' `
    #        + '\XXX Groove GFS Context Menu Handler XXX')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers' `
    #        + '\XXX Groove GFS Context Menu Handler XXX')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers' `
    #        + '\XXX Groove GFS Context Menu Handler XXX')
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers' `
    #        + '\XXX Groove GFS Context Menu Handler XXX')

    #RegDelete -Desc '禁用磁盘的 "刻录到光盘" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\{fbeb8a05-beee-4442-804e-409d6c4515e9}'

    RegDelete -Desc '禁用所有对象的 "共享" 右键菜单' `
        -Path 'Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers\ModernSharing'

    #RegDelete -Desc '禁用文件、目录、桌面、磁盘以及库的 "共享" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing'

    #RegDelete -Desc '禁用文件、目录、桌面、磁盘以及库的 "授予访问权限" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing'

    #RegDelete -Desc '禁用目录、文件夹、所有对象、的 "始终脱机可用" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Offline Files'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Offline Files'
    #RegDelete -Path ('Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers' `
    #        + '\{474C98EE-CF3D-41f5-80E3-4AAB0AB04301}')

    #RegDelete -Desc '禁用文件的 "OneDrive 文件同步" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\`*\shellex\ContextMenuHandlers\ FileSyncEx'

    #RegDelete -Desc '禁用文件的 "View 3D" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.bmp\Shell\T3D Print'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\T3D Print'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\T3D Print'

    #RegDelete -Desc '禁用文件的 "画图 3D" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.tiff\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.tif\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.png\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jpg\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jpeg\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jpe\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.jfif\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.gif\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.fbx\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.bmp\Shell\3D Edit'
    #RegDelete -Path 'Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\.3mf\Shell\3D Edit'

    #RegDelete -Desc '禁用文件夹的 "包含到库中" 右键菜单' `
    #    -Path 'Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location'

    RegDelete -Desc '禁用右键新建 BMP 图像' `
        -Path 'Registry::HKEY_CLASSES_ROOT\.bmp\ShellNew' `
        -Exclude 11

    RegDelete -Desc '禁用右键新建 RTF 文档' `
        -Path 'Registry::HKEY_CLASSES_ROOT\.rtf\ShellNew' `
        -Exclude 11

    RegWrite -Desc '禁用客户体验改善计划' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows' `
        -Name 'CEIPEnable' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '启用剪贴板历史记录' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Clipboard' `
        -Name 'EnableClipboardHistory' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '开始菜单隐藏最近添加的应用' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        -Name 'HideRecentlyAddedApps' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '开始菜单隐藏最常用的应用' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoStartMenuMFUprogramsList' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '在开始菜单、跳转列表和文件资源管理器中隐藏最近打开的项目' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoRecentDocsHistory' `
        -Value 1 `
        -Type DWord

    #RegWrite -Desc '拼音设置为全拼' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable Double Pinyin' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '启用自动拼音纠错' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable Auto Correction' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用超级简拼' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnableSuperAbbreviatedPinyin' `
    #    -Value 1 `
    #    -Type DWord

    RegWrite -Desc '输入法默认为中文' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
        -Name 'Default Mode' `
        -Value 0 `
        -Type DWord `
        -Exclude 11

    #RegWrite -Desc '字符集设为简体中文' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Output CharSet' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '使用半角输入模式' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'HalfWidthInputModeByDefault' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用智能模糊拼音' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnableSmartFuzzyPinyin' `
    #    -Value 1 `
    #    -Type DWord

    RegWrite -Desc '启用模糊拼音' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
        -Name 'Enable Fuzzy Input' `
        -Value 1 `
        -Type DWord

    RegWrite -Desc '中/英文模式切换按键设为 Shift 键' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
        -Name 'English Switch Key' `
        -Value 4 `
        -Type DWord

    RegWrite -Desc '全/半角切换按键设为无' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
        -Name 'EnableFullHalfWidthSwitchKey' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '逗号/句号、减号/等号、左/右方括号支持翻页' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\CandidateWindow\CHS\1' `
        -Name 'CustomizedPagingKey' `
        -Value 0 `
        -Type DWord

    RegWrite -Desc '禁用简体/繁体中文输入切换按键' `
        -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
        -Name 'EnableSimplifiedTraditionalOutputSwitch' `
        -Value 0 `
        -Type DWord

    #RegWrite -Desc '关闭输入法工具栏' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'ToolBarEnabled' `
    #    -Value 0 `
    #    -Type DWord

    #RegWrite -Desc '启用动态词频调整' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable Dynamic Candidate Ranking' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用自学习' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable self-learning' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用基于上下文的智能短语抽取' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnableSmartSelfLearning' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '使用用户定义的短语' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable EUDP' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用云建议' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'Enable Cloud Candidate' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用人名输入' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnablePeopleName' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用 U 模式输入' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnableUMode' `
    #    -Value 1 `
    #    -Type DWord

    #RegWrite -Desc '启用 V 模式输入' `
    #    -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod\Settings\CHS' `
    #    -Name 'EnableVMode' `
    #    -Value 1 `
    #    -Type DWord

    RegWrite -Desc '取消任务栏的固定图标' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' `
        -Name 'Favorites' `
        -Value ([byte[]](255)) `
        -Type Binary
    #RegDelete -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband' `
    #    -Name 'FavoritesResolve'

    RegWrite -Desc '关闭任务栏资讯和兴趣' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds' `
        -Name 'EnableFeeds' `
        -Value 0 `
        -Type DWord `
        -Exclude 11
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds' `
        -Name 'ShellFeedsTaskbarViewMode' `
        -Value 2 `
        -Type DWord `
        -Exclude 11

    RegWrite -Desc '一周的第一天设为周日' `
        -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'iFirstDayOfWeek' `
        -Value '6' `
        -Type String

    RegWrite -Desc '短日期格式设为 yyyy-MM-dd' `
        -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'sShortDate' `
        -Value 'yyyy-MM-dd' `
        -Type String

    RegWrite -Desc '长日期格式设为 yyyy年M月d日, dddd' `
        -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'sLongDate' `
        -Value "yyyy'年'M'月'd'日', dddd" `
        -Type String

    #RegWrite -Desc '短时间格式设为 tt h:mm' `
    #    -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
    #    -Name 'sShortTime' `
    #    -Value 'tt h:mm' `
    #    -Type String

    RegWrite -Desc '长时间格式设为 HH:mm:ss' `
        -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'sTimeFormat' `
        -Value 'HH:mm:ss' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'iTime' `
        -Value '1' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'iTimePrefix' `
        -Value '0' `
        -Type String
    RegWrite -Path 'Registry::HKEY_CURRENT_USER\Control Panel\International' `
        -Name 'iTLZero' `
        -Value '1' `
        -Type String

    RegWrite -Desc '禁用广告 ID' `
        -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' `
        -Name 'Enabled' `
        -Value 0 `
        -Type DWord

    Write-Host -Object ''
    Write-Host -Object '磁盘优化'
    Get-Volume | Optimize-Volume -NormalPriority -ErrorAction SilentlyContinue

    Write-Host -Object ''
    Write-Host -Object '删除系统还原点并禁用系统还原'
    vssadmin Delete Shadows /All /Quiet
    Get-Volume | ForEach-Object {
        if ($null -ne $_.DriveLetter) {
            $DriveLetter = $_.DriveLetter
            Disable-ComputerRestore ("${DriveLetter}:") -ErrorAction SilentlyContinue
        }
    }

    Write-Host -Object ''
    Write-Host -Object '优化电源设置'
    $Schemes = @(
        # 节能模式
        'a1841308-3541-4fab-bc81-f71556f20b4a',
        # 平衡模式
        '381b4222-f694-41f0-9685-ff5bb260df2e',
        # 高性能模式
        '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    )
    $Subs = @{
        # 无线适配器设置
        '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1' = @{
            # 节能模式: 最高性能
            '12bbebe6-58d6-4636-95bb-3217ef867c1a' = '0'
        }
        # 睡眠
        '238c9fa8-0aad-41ed-83f4-97be242c8f20' = @{
            # 在此时间后睡眠: 不进入睡眠
            '29f6c1db-86da-48c5-9fdb-f2b67b1f44da' = '0';
            # 在此时间后休眠: 不进入休眠
            '9d7815a6-7ee4-497e-8888-515a05f02364' = '0'
        };
        # 英特尔显卡设置
        '44f3beca-a7c0-460e-9df2-bb8b99e0cba6' = @{
            # 英特尔显卡电源计划: 最高性能
            '3619c3f2-afb2-4afc-b0e9-e7fef372de36' = '2'
        };
        # 多媒体设置
        '9596fb26-9850-41fd-ac3e-f7c3c00afd4b' = @{
            # 视频播放质量补偿: 视频播放性能补偿
            '10778347-1370-4ee0-8bbd-33bdacaade49' = '1'
            # 播放视频时: 优化视频质量
            '34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4' = '0'
        };
        # 电源按钮和盖子
        '4f971e89-eebd-4455-a8de-9e59040e7347' = @{
            # 合盖动作: 什么都不做
            '5ca83367-6e45-459f-a27b-476b1d01c936' = '0'
        }
    }
    foreach ($Scheme in $Schemes) {
        foreach ($Sub in $Subs.GetEnumerator()) {
            foreach ($Setting in $Sub.Value.GetEnumerator()) {
                POWERCFG /SETACVALUEINDEX $Scheme $Sub.Key $Setting.Key $Setting.Value
            }
        }
    }
    POWERCFG /SETACTIVE '381b4222-f694-41f0-9685-ff5bb260df2e'

    UninstallApp -Desc '卸载: Cortana' -AppName 'Microsoft.549981C3F5F10'
    UninstallApp -Desc '卸载: 获取帮助' -AppName 'Microsoft.GetHelp'
    UninstallApp -Desc '卸载: 使用技巧' -AppName 'Microsoft.Getstarted'
    UninstallApp -Desc '卸载: Office 中心' -AppName 'Microsoft.MicrosoftOfficeHub'
    UninstallApp -Desc '卸载: OneNote' -AppName 'Microsoft.Office.OneNote'
    UninstallApp -Desc '卸载: 纸牌游戏' -AppName 'Microsoft.MicrosoftSolitaireCollection'
    UninstallApp -Desc '卸载: 便签' -AppName 'Microsoft.MicrosoftStickyNotes'
    UninstallApp -Desc '卸载: 混合现实门户' -AppName 'Microsoft.MixedReality.Portal'
    UninstallApp -Desc '卸载: 画图 3D' -AppName 'Microsoft.MSPaint'
    UninstallApp -Desc '卸载: 画图 3D' -AppName 'Microsoft.Paint'
    #UninstallApp -Desc '卸载: 记事本' -AppName 'Microsoft.WindowsNotepad'
    UninstallApp -Desc '卸载: 3D 查看器' -AppName 'Microsoft.Microsoft3DViewer'
    UninstallApp -Desc '卸载: 人脉' -AppName 'Microsoft.People'
    UninstallApp -Desc '卸载: 截图和草图' -AppName 'Microsoft.ScreenSketch'
    UninstallApp -Desc '卸载: 钱包' -AppName 'Microsoft.Wallet'
    UninstallApp -Desc '卸载: 反馈中心' -AppName 'Microsoft.WindowsFeedbackHub'
    UninstallApp -Desc '卸载: 地图' -AppName 'Microsoft.WindowsMaps'
    UninstallApp -Desc '卸载: 录音机' -AppName 'Microsoft.WindowsSoundRecorder'
    UninstallApp -Desc '卸载: Grovve 音乐' -AppName 'Microsoft.ZuneMusic'
    UninstallApp -Desc '卸载: 电影和电视' -AppName 'Microsoft.ZuneVideo'
    UninstallApp -Desc '卸载: Skype' -AppName 'Microsoft.SkypeApp'
    UninstallApp -Desc '卸载: 闹钟和时钟' -AppName 'Microsoft.WindowsAlarms'
    UninstallApp -Desc '卸载: PowerAutomateDesktop' -AppName 'Microsoft.PowerAutomateDesktop'
    #UninstallApp -Desc '卸载: 照片' -AppName 'Microsoft.Windows.Photos'
    #UninstallApp -Desc '卸载: 手机' -AppName 'Microsoft.YourPhone'
    UninstallApp -Desc '卸载: Todo' -AppName 'Microsoft.Todos'
    UninstallApp -Desc '卸载: 邮件和日历' -AppName 'microsoft.windowscommunicationsapps'
    UninstallApp -Desc '卸载: 天气' -AppName 'Microsoft.BingWeather'
    UninstallApp -Desc '卸载: 咨询' -AppName 'Microsoft.BingNews'
    # 广告框架，microsoft.windowscommunicationsapps 和 Microsoft.BingWeather 依赖于该框架，需要先删除
    UninstallApp -Desc '卸载: 广告框架' -AppName 'Microsoft.Advertising.Xaml'

    UninstallXbox
    UninstallOneDrive

    Write-Host -Object ''
    Write-Host -Object '禁用零售演示服务'
    Set-Service -Name 'RetailDemo' -StartupType Disabled -Status Stopped


    # 会自动重启 explorer
    Stop-Process -Name 'explorer' -Force -ErrorAction SilentlyContinue
}

function GetEnabledUser {

    $AllUser = Get-LocalUser
    if ($null -eq $AllUser -or $AllUser.Count -le 0) {
        return $null
    }

    $CurrentUser = $null
    foreach ($User in $AllUser) {
        if ($User.Enabled) {
            $CurrentUser = $User
            break
        }
    }

    return $CurrentUser
}

function GetCurrentPower {

    $Result = POWERCFG /GETACTIVESCHEME
    if ($null -eq $Result -or '' -eq $Result) {
        return ''
    }

    if ($Result.Contains('a1841308-3541-4fab-bc81-f71556f20b4a')) {
        return '节能模式'
    }

    if ($Result.Contains('381b4222-f694-41f0-9685-ff5bb260df2e')) {
        return '平衡模式'
    }

    if ($Result.Contains('8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c')) {
        return '高性能模式'
    }

    return '未知模式'
}

function ChangePassword {
    param($User)

    if ($null -eq $User) {
        Write-Host -Object ''
        Write-Warning -Message '不存在本地账户'
        return
    }

    while ($true) {
        Write-Host -Object ''
        $Password = Read-Host ("请输入本地账户 $($User.Name) 的新密码，按回车键确认")
        if ($null -eq $Password -or '' -eq $Password) {
            Write-Host -Object ''
            Write-Warning -Message '密码为空，请重新输入'
            continue
        }

        try {
            Set-LocalUser -InputObject $User -Password (ConvertTo-SecureString -String $Password `
                    -AsPlainText -Force) -ErrorAction Stop
            Write-Host -Object ''
            Write-Host -Object ("本地账户 $($User.Name) 的密码已修改为 $Password")
        }
        catch {
            Write-Host -Object ''
            Write-Host -Object ("无权修改本地账户 $($User.Name) 的密码")
        }

        return
    }
}

function ChangePower {
    $CurrentPower = GetCurrentPower
    Write-Host -Object ''
    Write-Host -Object '===================='
    Write-Host -Object '选择电源模式，推荐 2'
    Write-Host -Object '===================='
    Write-Host -Object ''
    Write-Host -Object '1: 节能模式'
    Write-Host -Object ''
    Write-Host -Object '2: 平衡模式'
    Write-Host -Object ''
    Write-Host -Object '3: 高性能模式'

    while ($true) {
        Write-Host -Object ''
        $InputOption = Read-Host -Prompt ("请输入选择的序号(当前为$CurrentPower)，按回车键确认")
        if ($null -eq $InputOption -or '' -eq $InputOption) {
            Write-Host -Object ''
            Write-Warning -Message '选择无效，请重新输入'
            continue
        }
        if ('1' -eq $InputOption) {
            POWERCFG /SETACTIVE 'a1841308-3541-4fab-bc81-f71556f20b4a'
            Write-Host -Object ''
            Write-Host -Object '电源模式已设为节能模式'
            return
        }
        if ('2' -eq $InputOption) {
            POWERCFG /SETACTIVE '381b4222-f694-41f0-9685-ff5bb260df2e'
            Write-Host -Object ''
            Write-Host -Object '电源模式已设为平衡模式'
            return
        }
        if ('3' -eq $InputOption) {
            POWERCFG /SETACTIVE '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
            Write-Host -Object ''
            Write-Host -Object '电源模式已设为高性能模式'
            return
        }
        Write-Host -Object ''
        Write-Warning -Message '选择无效，请重新输入'
    }
}

function MainMenu {
    $CurrentUser = GetEnabledUser
    $CurrentPower = GetCurrentPower
    Clear-Host
    if ($script:Debug) {
        Write-Host -Object "=====> Windows 系统优化 v$VersionInfo 调试模式 <====="
    }
    else {
        Write-Host -Object "=====> Windows 系统优化 v$VersionInfo <====="
    }
    Write-Host -Object ''
    Write-Host -Object '================'
    Write-Host -Object '选择要进行的操作'
    Write-Host -Object '================'
    Write-Host -Object ''
    Write-Host -Object ("1: 修改本地帐户 $($CurrentUser.Name) 的密码")
    Write-Host -Object ''
    Write-Host -Object '2: 通用优化'
    Write-Host -Object ''
    Write-Host -Object ("3: 切换电源模式(当前为$CurrentPower)")
    Write-Host -Object ''
    Write-Host -Object '4: 磁盘优化'
    Write-Host -Object ''
    Write-Host -Object 'q: 退出'

    $InputOption = 'q'
    while ($true) {
        Write-Host -Object ''
        $InputOption = Read-Host -Prompt '请输入选择的序号，按回车键确认'
        if ($null -eq $InputOption -or '' -eq $InputOption) {
            Write-Host -Object ''
            Write-Warning -Message '选择无效，请重新输入'
            continue
        }
        if ('q' -eq $InputOption) {
            break
        }
        if ('1' -eq $InputOption) {
            break
        }
        if ('2' -eq $InputOption) {
            break
        }
        if ('3' -eq $InputOption) {
            break
        }
        if ('4' -eq $InputOption) {
            break
        }
        if ('Debug' -ieq $InputOption) {
            break
        }
        Write-Host -Object ''
        Write-Warning -Message '选择无效，请重新输入'
    }

    if ('q' -eq $InputOption) {
        [System.Environment]::Exit(0)
    }
    if ('1' -eq $InputOption) {
        ChangePassword -User $CurrentUser
        Write-Host -Object ''
        Read-Host -Prompt '按确认键返回主菜单'
        return MainMenu
    }
    if ('2' -eq $InputOption) {
        CommonOptim
        Write-Host -Object ''
        Read-Host -Prompt '按确认键返回主菜单'
        return MainMenu
    }
    if ('3' -eq $InputOption) {
        ChangePower
        Write-Host -Object ''
        Read-Host -Prompt '按确认键返回主菜单'
        return MainMenu
    }
    if ('4' -eq $InputOption) {
        Clear-Host
        Get-Volume | Optimize-Volume -NormalPriority -ErrorAction SilentlyContinue
        Write-Host -Object ''
        Read-Host -Prompt '按确认键返回主菜单'
        return MainMenu
    }
    if ('Debug' -ieq $InputOption) {
        $Script:Debug = $true
        Add-Content -Path $script:DebugLog -Value '' -Force
        Add-Content -Path $script:DebugLog -Value '' -Force
        Add-Content -Path $script:DebugLog -Value '' -Force
        $LogHead = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Add-Content -Path $script:DebugLog -Value "$LogHead" -Force
        return MainMenu
    }
}

$VersionInfo = GetVertion

if ($Version) {
    return $VersionInfo
}

RequireAdmin

Clear-Host
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$Host.UI.RawUI.WindowTitle = 'Windows 系统优化'
Set-Location -Path $PSScriptRoot

$SystemInfo = Get-CimInstance -ClassName Win32_OperatingSystem

if (!$SystemInfo.Caption.Contains('10') -and !$SystemInfo.Caption.Contains('11')) {
    Write-Warning -Message ('不支持 ' + $SystemInfo.Caption)
    [System.Environment]::Exit(0)
}

MainMenu

Write-Host -Object ''
Read-Host -Prompt '按回车键关闭此窗口'
