# This script modifies registry key permissions to prevent errors or warning caused by the Microsoft-Windows-DistributedCOM.
# It is based on FixDCOMErrors.ps1 from https://cloud.gci.org/files/FixDCOMErrors.ps1 by https://github.com/bret-miller - see https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4?permalink_comment_id=2709788#gistcomment-2709788
# which in turn is based on finderrors.ps1 and fixerrors.ps1 from https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4 by https://github.com/kitmenke

# This script searches Event log for the errors such as the following and adjusts the permissions.

# A sample Event text is:
# The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID {2593F8B9-4EAF-457C-B68A-50F6B8EA6B54} and APPID {15C20B67-12E7-4BB6-92BB-7AFF07997402} to the user Computer\User SID (S-1-1-12-12345678-123456789-123456789-1234) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.
# or
# The machine-default permission settings do not grant Local Activation permission for the COM Server application with CLSID {C2F03A33-21F5-47FA-B4BB-156362A2F239} and APPID {316CDED5-E4AE-4B15-9113-7055D84DCC97} to the user NT AUTHORITY\LOCAL SERVICE SID (S-1-5-19) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.


# Copyright (C) 2024 Maxim Masiutin. All rights reserved. email: maxim@masiutin.com. https://github.com/maximmasiutin/
# Copyright the contributors above mentioned: kitmenke, bret-miller.

# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.





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
$EVT_MSG2 = "The machine-default permission settings do not grant Local Activation permission for the COM Server application with CLSID"

# Search for System event log ERROR(2) or WARNING(3) entries starting with the specified EVT_MSG
Get-WinEvent -FilterHashTable @{LogName = 'System'; Level = @(2, 3) } | Where-Object { $_.Message -like "$EVT_MSG1*" -or $_.Message -like "$EVT_MSG2*"} | ForEach-Object {
    # Get CLSID and APPID from the event log entry
    # which we'll use to look up keys in the registry
    $CLSID = $_.Properties[3].Value
    $APPID = $_.Properties[4].Value
    $dcomissues["$CLSID"] = "$APPID"
}

if ($dcomissues.Count -eq 0) {
    Write-Host "No System events with levels Error or Warning found that match the specified string (""$EVT_MSG1"" or ""$EVT_MSG2"")."
    exit 0;
}

# To check your priviledges:
# whoami /priv
$ResultTakeOwnershipPrivilege = enable-privilege SeTakeOwnershipPrivilege
$ResultRestorePrivilege = enable-privilege SeRestorePrivilege
# To change the owner you need SeRestorePrivilege
# http://stackoverflow.com/questions/6622124/why-does-set-acl-on-the-drive-root-try-to-set-ownership-of-the-object
Write-Host "Enabled privilege SeTakeOwnershipPrivilege: $ResultTakeOwnershipPrivilege"
Write-Host "Enabled privilege SeRestorePrivilege: $ResultRestorePrivilege"

$Result = 0

foreach ($CLSID in $dcomissues.keys) {
    $APPID = $dcomissues[$CLSID]
    Write-Host "Fixing: CLSID $CLSID, APPID $APPID..."
    try {
        $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("CLSID\$CLSID", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::takeownership)

        if ($null -eq $key) {
            Write-Host "Unable to get registry key HKCR:\CLSID\$CLSID"
            $Result = 1
        }
        else {
            Write-Host "Opened registry key $($key.Name)"
            $admin = [System.Security.Principal.NTAccount]"Administrators"
            Write-Host "Setting owner to $($admin.Value)..."
            $acl = $key.GetAccessControl()
            $acl.SetOwner($admin)
            $key.SetAccessControl($acl)


	    $fullControl = [System.Security.AccessControl.RegistryRights]::FullControl
            $allow = [System.Security.AccessControl.AccessControlType]::Allow
	    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $propagation = [System.Security.AccessControl.PropagationFlags]::None

            Write-Host "Setting Full Control access for $($admin.Value)..."
            $user = [System.Security.Principal.NTAccount]($admin.value)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($user,$fullControl,$inheritance,$propagation, $allow)
            $acl.SetAccessRule($rule)
            $key.SetAccessControl($acl)


            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-Host "Setting Full Control access for $me..."
            $user = [System.Security.Principal.NTAccount]($me)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($user,$fullControl,$inheritance,$propagation, $allow)
            $acl.SetAccessRule($rule)
            $key.SetAccessControl($acl)

            $key.Close()

            Write-Host "Success."
        }
    }
    catch {
        Write-Host $_.Exception | format-list
        $Result = 1
    }

}

exit $Result
