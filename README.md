# application-specific-permission-settings.ps1 

This script modifies registry key permissions to prevent errors or warning caused by the Microsoft-Windows-DistributedCOM.  
It is based on `FixDCOMErrors.ps1` from https://cloud.gci.org/files/FixDCOMErrors.ps1 by https://github.com/bret-miller - see https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4?permalink_comment_id=2709788#gistcomment-2709788  
which in turn is based on `finderrors.ps1` and `fixerrors.ps1` from https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4 by https://github.com/kitmenke  

Copyright &copy; 2024 Maxim Masiutin. All rights reserved. email: maxim@masiutin.com. https://github.com/maximmasiutin/  
Copyright &copy; the contributors above mentioned: kitmenke, bret-miller.

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.


This program searches Event log for the errors such as the following and adjusts the permissions.

A sample Event is:
```
The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID 
{2593F8B9-4EAF-457C-B68A-50F6B8EA6B54}
 and APPID 
{15C20B67-12E7-4BB6-92BB-7AFF07997402}
 to the user Computer\User SID (S-1-1-12-12345678-123456789-123456789-1234) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.
```

Another sample Event is:
```
The machine-default permission settings do not grant Local Activation permission for the COM Server application with CLSID 
{C2F03A33-21F5-47FA-B4BB-156362A2F239}
 and APPID 
{316CDED5-E4AE-4B15-9113-7055D84DCC97}
 to the user NT AUTHORITY\LOCAL SERVICE SID (S-1-5-19) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.
```

The XML View of the sample Event is:
```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-DistributedCOM" Guid="{1B562E86-B7AA-4131-BADC-B6F3A001407E}" EventSourceName="DCOM" /> 
  <EventID Qualifiers="0">10016</EventID> 
  <Version>0</Version> 
  <Level>3</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8080000000000000</Keywords> 
  <TimeCreated SystemTime="2024-11-12T11:11:28.7855692Z" /> 
  <EventRecordID>6593</EventRecordID> 
  <Correlation ActivityID="{982b49f4-349b-0006-79b6-2f989b34db01}" /> 
  <Execution ProcessID="1824" ThreadID="21844" /> 
  <Channel>System</Channel> 
  <Computer>Computer</Computer> 
  <Security UserID="S-1-1-12-12345678-123456789-123456789-1234" /> 
 </System>
 <EventData>
  <Data Name="param1">application-specific</Data> 
  <Data Name="param2">Local</Data> 
  <Data Name="param3">Activation</Data> 
  <Data Name="param4">{2593F8B9-4EAF-457C-B68A-50F6B8EA6B54}</Data> 
  <Data Name="param5">{15C20B67-12E7-4BB6-92BB-7AFF07997402}</Data> 
  <Data Name="param6">Computer</Data> 
  <Data Name="param7">User</Data> 
  <Data Name="param8">S-1-1-12-12345678-123456789-123456789-1234</Data> 
  <Data Name="param9">LocalHost (Using LRPC)</Data> 
  <Data Name="param10">Unavailable</Data> 
  <Data Name="param11">Unavailable</Data> 
 </EventData>
</Event>
```

Another example is:
```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-DistributedCOM" Guid="{1B562E86-B7AA-4131-BADC-B6F3A001407E}" EventSourceName="DCOM" /> 
  <EventID Qualifiers="0">10016</EventID> 
  <Version>0</Version> 
  <Level>3</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8080000000000000</Keywords> 
  <TimeCreated SystemTime="2024-11-13T00:27:52.1816258Z" /> 
  <EventRecordID>6773</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="1824" ThreadID="7292" /> 
  <Channel>System</Channel> 
  <Computer>Dell</Computer> 
  <Security UserID="S-1-5-19" /> 
  </System>
- <EventData>
  <Data Name="param1">machine-default</Data> 
  <Data Name="param2">Local</Data> 
  <Data Name="param3">Activation</Data> 
  <Data Name="param4">{C2F03A33-21F5-47FA-B4BB-156362A2F239}</Data> 
  <Data Name="param5">{316CDED5-E4AE-4B15-9113-7055D84DCC97}</Data> 
  <Data Name="param6">NT AUTHORITY</Data> 
  <Data Name="param7">LOCAL SERVICE</Data> 
  <Data Name="param8">S-1-5-19</Data> 
  <Data Name="param9">LocalHost (Using LRPC)</Data> 
  <Data Name="param10">Unavailable</Data> 
  <Data Name="param11">Unavailable</Data> 
  </EventData>
  </Event>
```