# CFRS 772 - Final Project
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v2.7.12 and Volatility v2.6
#
# Description:
#   This module is an add on for Volatility. When run, it will display the
# 	last five modified timestamps of the Services sub-keys from the
# 	Registry (HKLM\SYSTEM\ControlSet001\Services).
#
# Usage:
# 	1. Place the RecentServices2.py module in the place you like to keep your
# 		3rd party modules. You can use it from your current directory too.
#   2. Run volatility as such:
#      > vol.py --plugins=<location\of\plugin> -f <mem_file>
#        --profile=<target_profile> recentservices2
#
# Resources:
#   1. Art of Memory Forensics, page 354 (978-1118825099)
# 	2. https://gist.github.com/bridgeythegeek/bf7284d4469b60b8b9b3c4bfd03d051e
# 	3. https://github.com/volatilityfoundation/volatility/blob/
# 		master/volatility/plugins/malware/svcscan.py
# 	4. https://github.com/volatilityfoundation/volatility/blob/
# 	   master/volatility/commands.py

"""
Example (RecentServices2.py is called from the current directory):

> vol.py --plugins=. -f ./sample001.bin --profile=WinXPSP3x86 recentservices2

Volatility Foundation Volatility Framework 2.6
Last Write Time (UTC)  Service Name ServiceDll
---------------------  ------------ ---------------------
 11/27/2012 01:27:03   Schedule     %SystemRoot%\system32\schedsvc.dll
 11/26/2012 23:01:55   6to4         C:\WINDOWS\system32\6to4ex.dll
 11/26/2012 22:03:27   Cdaudio		<None>
 11/26/2012 22:03:27   Flpydisk		<None>
 11/26/2012 22:03:27   Parport		<None>
 11/26/2012 22:03:27   Processor	<None>
 11/26/2012 22:03:27   Sfloppy		<None>
 11/26/2012 22:03:27   Imapi		<None>
 11/26/2012 22:03:26   mssmbios		<None>
 11/26/2012 22:03:21   Disk			<None>
"""

import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.malware.svcscan as svcscan
import time


class RecentServices2(common.AbstractWindowsCommand):
    """
    Volatility plugin used to
    pull the top 5 time stamps services were installed.
    TODO:
        1. Allow user to enter either a start time stamp, or a window of time
            to search. This involves taking arg input, and filtering results
            based on user based bounds.
    """

    # overriding the __init__ method to add in options
    """def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option(
            'START-TIME', short_option='s',
            help='Start time stamp to begin your search', type='string')
        config.add_option(
            'END-TIME', short_option='e',
            help='End time stamp to bound your search', type='string')
    """

    def calculate(self):
        """
        Use the volatility registry API to enumerate the
        Services registry key based on the last modified time stamp
        :return:
        """

        # Set up our registry api instance
        reg_api = registryapi.RegistryApi(self._config)
        key = "ControlSet001\\Services"

        # Pull the ControlSet001\Services registry sub-keys
        sub_keys = reg_api.reg_get_all_subkeys("system", key)
        services = dict((s.Name, int(s.LastWriteTime)) for s in sub_keys)

        # Sort them by their last modified timestamp, in descending order
        times = sorted(set(services.values()), reverse=True)

        # Pull the service info from the registry using SvcScanner
        svc_scanner = svcscan.SvcScan(self._config)
        service_info = svc_scanner.get_service_info(reg_api)

        # only return a subset of the Service last write times
        top_five = times[0:5]
        return [top_five, services, service_info]

    @staticmethod
    def render_text(outfd, data):
        # top_five are the timestamps
        # services will have the service names and other info
        top_five = data[0]
        services = data[1]
        service_info = data[2]

        # Set up the output table
        header1 = "{0:^22s} {1:^} {2:<30s} {3:<35s}\n".format(
            "Last Write Time (UTC)", "Service Name", "Service Dll",
            "Image Path")
        header2 = "{0:^22} {1:^} {2:<30s} {3:<35s}\n".format("-" * 22,
                                                             "-" * 12,
                                                             "-" * 22,
                                                             "-" * 22)
        outfd.write(header1)
        outfd.write(header2)

        # enumerate the services
        for epoch_time in top_five:
            for name, ts in services.items():
                if ts == epoch_time:
                    # Format the time stamp, and get the ServiceDll
                    actual_time = time.gmtime(epoch_time)
                    service_dll = service_info["{}".format(name)][0]
                    image_path = service_info["{}".format(name)][1]

                    if service_dll == "":
                        service_dll = "<None>"
                    if image_path == "":
                        image_path = "<None>"

                    # Print out the info
                    outfd.write("{0:^22} {1:<12} {2:<30s} {3:<35s}\n".format(
                        time.strftime('%m/%d/%Y %H:%M:%S', actual_time),
                        name, service_dll, image_path))
