CFRS 772 - Final Project
Rachel B. Gully
rgully4@masonlive.gmu.edu

This program was written and tested in Python v2.7.12 and Volatility v2.6

Description:
  This module is a 3rd-party plugin for Volatility, which aims to help analysts detect
  malicious services installed on victim machines, and to provide them a lead on the malware's location. 
  When run, it will display the last five modified timestamps of the Services sub-keys from the Registry 
  (HKLM\SYSTEM\ControlSet001\Services).

  Users can also request to print N number of timestamps, or only print the top timestamps for a particular day.

Usage:
	1. Place the RecentSvcs.py module in the place you like to keep your
		3rd party modules. You can use it from your current directory too (i.e. ".\").

	2. Run volatility as such (NOTE: the runtime will depend on the size of your memory capture. the module can take a few minutes to run):
     > vol.py --plugins=<location\of\plugin> -f <mem_file>
       --profile=<target_profile> recentsvcs
     > vol.py --plugins=<location\of\plugin> -f <mem_file>
       --profile=<target_profile> recentsvcs -n <n timestamps> -s <m/d/Y>

Test for yourself:
	1. The sample memory dump of a Windows XP SP3 x86 machine, called "sample001.bin", has been provided for testing.
		- sample001.bin MD5:	24C9FF2F10E6BC8FC8EB13128079CF20

	2. Example runs against sameple001.bin:
		> vol.py --plugins=.\vol_plugins -f .\sample001.bin --profile=WinXPSP3x86 recentsvcs
		Volatility Foundation Volatility Framework 2.6
		--------------------------------- Discovered 5 timestamps ---------------------------------
		Last Write Time (UTC)  Service Name Service Dll                         Image Path
		---------------------- ------------ ----------------------              ----------------------
		 11/27/2012 01:27:03   Schedule     %SystemRoot%\system32\schedsvc.dll  %SystemRoot%\System32\svchost.exe -k netsvcs
		 11/26/2012 23:01:55   6to4         C:\WINDOWS\system32\6to4ex.dll      %SystemRoot%\System32\svchost.exe -k netsvcs
		 11/26/2012 22:03:27   Cdaudio      <None>                              <None>
		 11/26/2012 22:03:27   Flpydisk     <None>                              System32\DRIVERS\flpydisk.sys
		 11/26/2012 22:03:27   Parport      <None>                              System32\DRIVERS\parport.sys
		 11/26/2012 22:03:27   Processor    <None>                              System32\DRIVERS\processr.sys
		 11/26/2012 22:03:27   Sfloppy      <None>                              <None>
		 11/26/2012 22:03:27   Imapi        <None>                              System32\DRIVERS\imapi.sys
		 11/26/2012 22:03:26   mssmbios     <None>                              System32\DRIVERS\mssmbios.sys
		 11/26/2012 22:03:21   Disk         <None>                              System32\DRIVERS\disk.sys

		> vol.py --plugins=.\vol_plugins -f .\sample001.bin --profile=WinXPSP3x86 recentsvcs -s 11/22/2012 -n 4
		Volatility Foundation Volatility Framework 2.6
		--------------------------------- Discovered 4 timestamps on 11/23/2012 ---------------------------------
		Last Write Time (UTC)  Service Name Service Dll                         Image Path
		---------------------- ------------ ----------------------              ----------------------
		 11/23/2012 16:47:16   Eventlog     <None>                              %SystemRoot%\system32\services.exe
		 11/23/2012 16:36:56   Dot3svc      %SystemRoot%\System32\dot3svc.dll   %SystemRoot%\System32\svchost.exe -k dot3svc
		 11/23/2012 16:36:49   EapHost      %SystemRoot%\System32\eapsvc.dll    %SystemRoot%\System32\svchost.exe -k eapsvcs
		 11/23/2012 16:36:48   napagent     %SystemRoot%\System32\qagentrt.dll  %SystemRoot%\System32\svchost.exe -k netsvcs
		 11/23/2012 16:36:48   hkmsvc       %SystemRoot%\System32\kmsvc.dll     %SystemRoot%\System32\svchost.exe -k netsvcs

		> vol.py --plugins=.\vol_plugins -f .\sample001.bin --profile=WinXPSP3x86 recentsvcs -n 4
		Volatility Foundation Volatility Framework 2.6
		--------------------------------- Discovered 4 timestamps ---------------------------------
		Last Write Time (UTC)  Service Name Service Dll                         Image Path
		---------------------- ------------ ----------------------              ----------------------
		 11/27/2012 01:27:03   Schedule     %SystemRoot%\system32\schedsvc.dll  %SystemRoot%\System32\svchost.exe -k netsvcs
		 11/26/2012 23:01:55   6to4         C:\WINDOWS\system32\6to4ex.dll      %SystemRoot%\System32\svchost.exe -k netsvcs
		 11/26/2012 22:03:27   Cdaudio      <None>                              <None>
		 11/26/2012 22:03:27   Flpydisk     <None>                              System32\DRIVERS\flpydisk.sys
		 11/26/2012 22:03:27   Parport      <None>                              System32\DRIVERS\parport.sys
		 11/26/2012 22:03:27   Processor    <None>                              System32\DRIVERS\processr.sys
		 11/26/2012 22:03:27   Sfloppy      <None>                              <None>
		 11/26/2012 22:03:27   Imapi        <None>                              System32\DRIVERS\imapi.sys
		 11/26/2012 22:03:26   mssmbios     <None>                              System32\DRIVERS\mssmbios.sys

		> vol.py --plugins=.\vol_plugins -f .\sample001.bin --profile=WinXPSP3x86 recentsvcs -n 4 -s 11/22/2019
		Volatility Foundation Volatility Framework 2.6
		--------------------------------- Discovered 1 timestamps on 11/27/2012 ---------------------------------
		Last Write Time (UTC)  Service Name Service Dll                         Image Path
		---------------------- ------------ ----------------------              ----------------------
		 11/27/2012 01:27:03   Schedule     %SystemRoot%\system32\schedsvc.dll  %SystemRoot%\System32\svchost.exe -k netsvcs