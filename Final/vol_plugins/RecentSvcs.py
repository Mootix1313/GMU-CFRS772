# CFRS 772 - Final Project
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v2.7.12 and Volatility v2.6
#
# Description:
#   This module is an add on for Volatility. When run, it will display the
# 	last five modified timestamps of the Services sub-keys from the
# 	Registry (HKLM\SYSTEM\ControlSet001\Services). Please note this is only for
#   Windows based images.
#
# Usage:
# 	1. Place the RecentServices3.py module in the place you like to keep your
# 		3rd party modules. You can use it from your current directory too.
#   2. Run volatility as such:
#      > vol.py --plugins=<location\of\plugin> -f <mem_file>
#        --profile=<target_profile> recentsvcs
#      > vol.py --plugins=<location\of\plugin> -f <mem_file>
#        --profile=<target_profile> recentsvcs -n <n timestamps> -s <m/d/Y>
#
# Resources:
#   1. Art of Memory Forensics, page 354 (978-1118825099)
# 	2. https://gist.github.com/bridgeythegeek/bf7284d4469b60b8b9b3c4bfd03d051e
# 	3. https://github.com/volatilityfoundation/volatility/blob/
# 		master/volatility/plugins/malware/svcscan.py
# 	4. https://github.com/volatilityfoundation/volatility/blob/
# 	   master/volatility/commands.py

import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.malware.svcscan as svcscan
import time
import datetime
import sys


class RecentSvcs(common.AbstractWindowsCommand):
    """
    Pulls the five most recently modified services from the Registry.

    Examples:
        vol.py --plugins=. -f ./vmem.bin --profile=Win7SP1x86 recentsvcs

        vol.py --plugins=. -f ./vmem.bin --profile=Win7SP1x86 recentsvcs -n 4 -s 10/08/2011
    """

    # overriding the __init__ method to add in options
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        # Time stamps are expected to be in the format "%m/%d/%Y"
        config.add_option(
            'START-TIME', short_option='s',
            help='Start date to begin your search', type='string')
        config.add_option(
            'N-TIMES', short_option='n',
            help='Number of timestamps to print', type='int')

    def calculate(self):
        """
        Use the volatility registry API to enumerate the
        Services registry key based on the last modified time stamp
        :return [top_five, services, service_info]:
        """

        # Set up our registry api instance
        reg_api = registryapi.RegistryApi(self._config)
        key = "ControlSet001\\Services"

        # Pull the ControlSet001\Services registry sub-keys
        sub_keys = reg_api.reg_get_all_subkeys("system", key)

        # collect the name and the last write timestamp of the service
        services = dict((s.Name, int(s.LastWriteTime)) for s in sub_keys)

        # De-duped list of times from the Service registry sub keys
        times = sorted(set([ts for ts in services.values()]))

        # confirm that the start timestamp is within the timeline
        start = 0

        # Did the user provide a time window?
        if self._config.START_TIME:
            try:
                start = int(time.mktime(datetime.datetime.strptime(
                    self._config.START_TIME, "%m/%d/%Y").timetuple()))
            except ValueError:
                print("Please enter date in correct format:  mm/dd/YYYY")
                sys.exit(1)

            # Start time outside of the provided range?
            if start <= times[0]:
                start = times[0]
            elif start >= times[len(times)-1]:
                start = times[len(times)-1]

            # Get timestamps only on the provided day
            times = [t for t in times if time.gmtime(t)[7] ==
                     time.gmtime(start)[7]]

        # Pull the service info from the registry using SvcScanner
        svc_scanner = svcscan.SvcScan(self._config)
        service_info = svc_scanner.get_service_info(reg_api)

        # grab only the top five (or top n) timestamps from the services dict
        if self._config.N_TIMES:
            n = self._config.N_TIMES
            if n > len(times):
                n = len(times)
            top_five = sorted(times, reverse=True)[0:n]
        else:
            top_five = sorted(times, reverse=True)[0:5]

        return [top_five, services, service_info, start]

    @staticmethod
    def render_text(outfd, data):
        # top_five are the timestamps
        # services will have the service names and other info
        top_five = data[0]
        services = data[1]
        service_info = data[2]
        start = time.gmtime(data[3])

        # Print out the length of the results
        if start[0] != 1970:
            results = "{1} Discovered {0} timestamps on {2} {1}\n".format(
                len(top_five), "-" * 33, time.strftime('%m/%d/%Y', start))
        else:
            results = "{1} Discovered {0} timestamps {1}\n".format(
                len(top_five), "-" * 33, time.strftime('%m/%d/%Y', start))

        # Set up the output table
        header1 = "{0:^22s} {1:^} {2:<35s} {3:<35s}\n".format(
            "Last Write Time (UTC)", "Service Name", "Service Dll",
            "Image Path")
        header2 = "{0:^22} {1:^} {2:<35s} {3:<35s}\n".format("-" * 22,
                                                             "-" * 12,
                                                             "-" * 22,
                                                             "-" * 22)
        outfd.write(results)
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
                    outfd.write("{0:^22} {1:<12} {2:<35s} {3:<35s}\n".format(
                        time.strftime('%m/%d/%Y %H:%M:%S', actual_time),
                        name, service_dll, image_path))
