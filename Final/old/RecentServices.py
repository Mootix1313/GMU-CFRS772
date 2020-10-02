# CFRS 772 - Final Project
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module is an add on for Volatility. When run, it will display the
# 	last five modified timestamps of the in the Services sub-keys from the
# 	Registry (HKLM\SYSTEM\ControlSet001\Services).
#
# Usage:
# 	1. Place the RecentServices.py module in the place you like to keep your
# 		3rd party modules. You can use it from your current directory too.
#   2. Run volatility as such:
# 		- vol.py --plugins=<location\of\plugin> -f <mem_file>
# 			--profile=<target_profile> recentservices
# Resources:
#   1. Art of Memory Forensics, page 354 (978-1118825099)
# 	2. https://gist.github.com/bridgeythegeek/bf7284d4469b60b8b9b3c4bfd03d051e

import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import time


class RecentServices(common.AbstractWindowsCommand):
	"""
	Volatility plugin used to
	pull the top 5 time stamps services were installed.
	TODO:
		1. Print out ServiceDll next to the Service name
		2. Allow user to enter either a start time stamp, or a window of time
			to search.
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

		# only return a subset of the Services
		top_five = times[0:5]
		return [top_five, services]

	@staticmethod
	def render_text(outfd, data):
		# top_five are the timestamps
		# services will have the service names and other info
		top_five = data[0]
		services = data[1]

		# Set up the output table
		outfd.write("{0:^22s} {1:^}\n".format(
			"Last Write Time (UTC)", "Service Name"))
		outfd.write("{0:^22} {1:^}\n".format("-"*21, "-"*12))

		# enumerate the services
		for epoch_time in top_five:
			for name, ts in services.items():
				if ts == epoch_time:
					actual_time = time.gmtime(epoch_time)
					outfd.write("{0:^22} {1}\n".format(
						time.strftime('%m/%d/%Y %H:%M:%S', actual_time), name))

