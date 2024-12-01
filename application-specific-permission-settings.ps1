# This script modifies registry key permissions to prevent errors or warning caused by the Microsoft-Windows-DistributedCOM.
# It is based on FixDCOMErrors.ps1 from https://cloud.gci.org/files/FixDCOMErrors.ps1 by https://github.com/bret-miller - see https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4?permalink_comment_id=2709788#gistcomment-2709788
# which in turn is based on finderrors.ps1 and fixerrors.ps1 from https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4 by https://github.com/kitmenke

# This script searches Event log for the errors such as the following and adjusts the permissions.

# A sample Event text is:
# The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID {2593F8B9-4EAF-457C-B68A-50F6B8EA6B54} and APPID {15C20B67-12E7-4BB6-92BB-7AFF07997402} to the user Computer\User SID (S-1-1-12-12345678-123456789-123456789-1234) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.


# Copyright (C) 2024 Maxim Masiutin. All rights reserved. email: maxim@masiutin.com. https://github.com/maximmasiutin/
# Copyright the contributors above mentioned: kitmenke, bret-miller.

# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

$EnableSeTakeOwnershipPrivilege = $false

# ************************* BEGIN enable-privilege
function enable-privilege {
    param(
        ## The privilege to adjust. This set is taken from
        ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )

    ## Taken from P/Invoke.NET with minor adjustments.
    $definition = @'
 using System;
 using System.Runtime.InteropServices;

 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@
    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}
# ************************* END enable-privilege

$dcomissues = @{}

$EVT_MSG1 = "The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID"

# Search for System event log ERROR(2) or WARNING(3) entries starting with the specified EVT_MSG
Get-WinEvent -FilterHashTable @{LogName = 'System'; Level = @(2, 3) } |
Where-Object { $_.Message -like "$EVT_MSG1*" } |
ForEach-Object {
    # Get CLSID and APPID from the event log entry
    $CLSID = $_.Properties[3].Value
    $APPID = $_.Properties[4].Value
    $dcomissues["$CLSID"] = "$APPID"
}

if ($dcomissues.Count -eq 0) {
    Write-Host "No System events with levels Error or Warning found that match the specified string ($EVT_MSG1)."
    exit 0
}

# Enable necessary privileges
$ResultTakeOwnershipPrivilege = enable-privilege SeTakeOwnershipPrivilege
$ResultRestorePrivilege = enable-privilege SeRestorePrivilege
Write-Host "Enabled privilege SeRestorePrivilege: $ResultRestorePrivilege"
if ($true -eq $ResultTakeOwnershipPrivilege) {
    Write-Host "Enabled privilege SeTakeOwnershipPrivilege: $ResultTakeOwnershipPrivilege"
}
if ($false -eq $ResultTakeOwnershipPrivilege) {


    # Enable the SeTakeOwnershipPrivilege
    function Enable-SeTakeOwnershipPrivilege {
        $Definition = @"
    using System;
    using System.Runtime.InteropServices;

    public class AdjPriv2 {
        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("kernel32.dll", ExactSpelling=true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES {
            public LUID Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        public const int TOKEN_ADJUST_PRIVILEGES = 0x20;
        public const int TOKEN_QUERY = 0x8;
        public const int SE_PRIVILEGE_ENABLED = 0x2;
        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public static bool Enable() {
            IntPtr hToken = IntPtr.Zero;
            TOKEN_PRIVILEGES tkp = new TOKEN_PRIVILEGES();
            tkp.Privileges = new LUID_AND_ATTRIBUTES();
            tkp.PrivilegeCount = 1;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken))
                return false;
            if (!LookupPrivilegeValue(null, SE_TAKE_OWNERSHIP_NAME, ref tkp.Privileges.Luid))
                return false;
            tkp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            return AdjustTokenPrivileges(hToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero);
        }
    }
"@

        Add-Type -TypeDefinition $Definition
        [AdjPriv2]::Enable() 
    }
    $EnableSeTakeOwnershipPrivilege = Enable-SeTakeOwnershipPrivilege
    Write-Host "Enabled privilege SeTakeOwnershipPrivilege: $EnableSeTakeOwnershipPrivilege"
}

# Print en empty line 
Write-Host

$Result = 0

# Function to fix registry permissions
function Fix-RegistryPermissions {
    param (
        [string]$KeyPath,
        [string]$KeyType
    )

    try {
        # Check if the registry key exists
        $keyExistsHandle = $null
        $keyExists = $false
        $errorCheckingExistance = $false
        try {
            $keyExistsHandle = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($KeyPath, 'ReadOnly')
            if ($null -eq $keyExistsHandle) {
                Write-Host "Registry key HKCR:\$KeyPath does not exist."
                $Result = 1
                return
            }
            else {
                $keyExistsHandle.Close()
                $keyExists = $true
            }
        }
        catch {
            Write-Host "Exception occurred while checking existence of registry key HKCR:\$KeyPath" -ForegroundColor Red
            Write-Host $_.Exception.Message
            $errorCheckingExistance = $true
        }

        if ($true -eq $errorCheckingExistance) {
            try {
                # Take ownership of the registry key
    
                Write-Host "Taking ownership of registry key Registry::HKEY_CLASSES_ROOT\"$KeyPath\"..." 
                $acl = Get-Acl -Path "Registry::HKEY_CLASSES_ROOT\$KeyPath"
                $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $acl.SetOwner($sid)
                try {
                    $securityObject = Set-Acl -Path "Registry::HKEY_CLASSES_ROOT\$KeyPath" -AclObject $acl -PassThru 
                    if ($securityObject) {
                        Write-Host "Successfully taken ownership of registry key: Registry::HKEY_CLASSES_ROOT\$KeyPath" -ForegroundColor Green
                        $keyExists = $true
                    }
                }
                catch {
                    Write-Host "Exception occurred while taking ownership"
                    Write-Host $_.Exception.Message
                }

            }
            catch {
                Write-Host "An error occurred while taking ownership of the registry key Registry::HKEY_CLASSES_ROOT\$KeyPath" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                $Result = 1
                return
            }

        }
       
        if ($true -eq $keyExists) {
            # Try to open the registry key with the specified permissions
            try {
                $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey(
                    $KeyPath,
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions
                )
                if ($null -eq $regKey) {
                    Write-Host "Unable to get registry key HKCR:\$KeyPath due to insufficient permissions."
                    $Result = 1
                    return
                }
                Write-Host "Opened registry key $($regKey.Name)"
            }
            catch {
                Write-Host "Exception occurred while opening registry key HKCR:\$KeyPath"
                Write-Host $_.Exception.Message
                $Result = 1
                return
            }

            # Define accounts to set permissions for
            $accounts = @(
                [System.Security.Principal.NTAccount]"Administrators",
                [System.Security.Principal.NTAccount]"SYSTEM",
                [System.Security.Principal.NTAccount]"NT SERVICE\TrustedInstaller",
                [System.Security.Principal.NTAccount][System.Security.Principal.WindowsIdentity]::GetCurrent().Name  # Current User
            )

            # Get the current ACL
            $acl = $regKey.GetAccessControl()

            # Set owner to Administrators
            $admin = [System.Security.Principal.NTAccount]"Administrators"
            Write-Host "Setting owner to $($admin.Value)..."
            $acl.SetOwner($admin)
            $regKey.SetAccessControl($acl)

            $fullControl = [System.Security.AccessControl.RegistryRights]::FullControl
            $allow = [System.Security.AccessControl.AccessControlType]::Allow
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $propagation = [System.Security.AccessControl.PropagationFlags]::None

            foreach ($account in $accounts) {
                Write-Host "Setting Full Control access for $($account.Value)..."
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $account, $fullControl, $inheritance, $propagation, $allow
                )
                $acl.SetAccessRule($rule)
            }

            # Apply the updated ACL to the registry key
            $regKey.SetAccessControl($acl)
            $regKey.Close()

            Write-Host "Successfully updated permissions for $KeyType key."
        }
    }
    catch {
        Write-Host "An error occurred while modifying the registry key:"
        Write-Host $_.Exception.Message
        $Result = 1
    }
}

foreach ($CLSID in $dcomissues.Keys) {
    $APPID = $dcomissues[$CLSID]
    Write-Host "Fixing: CLSID $CLSID, AppID $APPID..."

    # Fix CLSID key
    Fix-RegistryPermissions "CLSID\$CLSID" "CLSID"

    # Fix APPID key
    Fix-RegistryPermissions "AppID\$APPID" "APPID"

    # Print an empty line
    Write-Host
}

exit $Result
