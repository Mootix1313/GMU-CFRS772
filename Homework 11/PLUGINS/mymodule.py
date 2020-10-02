# CFRS 772 - Homework 11
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module is an example Volatility plugin. Code came from:
#   https://gist.github.com/bridgeythegeek/bf7284d4469b60b8b9b3c4bfd03d051e
#
# Usage (Tested this on my SIFT Workstation):
#  vol.py --plugins=.\PLUGINS -f vm.mem --profile

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
from volatility.renderers.basic import Hex


class MyPlugin(common.AbstractWindowsCommand):
    """My First Volatility Plugin"""

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def generator(self, data):
        for task in data:
            yield (0, [
                int(task.UniqueProcessId),
                str(task.CreateTime),
                str(task.ImageFileName)
            ])

    def unified_output(self, data):
        return TreeGrid([
            ("PID", int),
            ("Created", str),
            ("Image", str)],
            self.generator(data))