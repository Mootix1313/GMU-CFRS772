# CFRS 772 - Homework 11
# Rachel B. Gully
# rgully4@masonlive.gmu.edu
#
# This program was written and tested in Python v3.7.1
#
# Description:
#   This module is an example Autopsy plugin based on the tutorial from:
#   https://github.com/sleuthkit/autopsy/blob/develop/
#   pythonExamples/Aug2015DataSourceTutorial/FindContactsDb.py
#
#   All I did was clean up the code a bit to make it PEP8 compliant
#
# Usage:
#   1. Import this module into the Autopsy "Python
#   2. Run this ingest module against current case data
#
# References:
#   1. https://www.cfreds.nist.gov/
#   2. https://github.com/sleuthkit/autopsy/blob/develop/
#       pythonExamples/Aug2015DataSourceTutorial/

import jarray
import inspect
import os
import java.util.ArrayList as ArrayList
from java.lang import Class
from java.lang import System
from java.lang import ProcessBuilder
from java.io import File
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Image
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestJobContext
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModuleProcessTerminator
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.coreutils import ExecUtil


# Factory class of the "Run Exe" module
class RunExeIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "HW11 Run EXE Module"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that runs img_stat on each disk image."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return RunExeIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class RunExeIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(RunExeIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    def startUp(self, context):
        self.context = context
        
        # Get path to EXE based on where this script is run from.
        # Assumes EXE is in same folder as script
        # Verify it is there before any ingest starts
        exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "img_stat.exe")
        self.pathToEXE = File(exe_path)
        if not self.pathToEXE.exists():
            raise IngestModuleException("EXE was not found in module folder")

    # Where the analysis is done.
    def process(self, dataSource, progressBar):
        
        # Set the ogress bar to an Indeterminate state for now
        progressBar.switchToIndeterminate()

        # Return if we're not running on a windows sytem
        if not PlatformUtil.isWindowsOS(): 
            self.log(Level.INFO,
                     "Ignoring data source.  Not running on Windows")
            return IngestModule.ProcessResult.OK

        # Verify we have a disk image and not a folder of files
        if not isinstance(dataSource, Image):
            self.log(Level.INFO, "Ignoring data source.  Not an image")
            return IngestModule.ProcessResult.OK

        # Get disk image paths            
        imagePaths = dataSource.getPaths()
        
        # Save our output to a file in the reports folder
        #   named based on EXE and data source ID
        reportFile = File(Case.getCurrentCase().getCaseDirectory() +
                          "\\Reports" + "\\img_stat-" +
                          str(dataSource.getId()) + ".txt")

        # Run the EXE, saving output to the report
        # Check if the ingest is terminated and
        #   delete the incomplete report file
        self.log(Level.INFO, "Running program on data source")
        cmd = ArrayList()
        cmd.add(self.pathToEXE.toString())
        cmd.add(imagePaths[0])

        processBuilder = ProcessBuilder(cmd)
        processBuilder.redirectOutput(reportFile)
        ExecUtil.execute(processBuilder,
                         DataSourceIngestModuleProcessTerminator(self.context))
        
        # Add the report to the case, so it shows up in the tree
        if not self.context.dataSourceIngestIsCancelled():
            Case.getCurrentCase().addReport(reportFile.toString(),
                                            "Run EXE", "img_stat output")
        else:
            if reportFile.exists():
                if not reportFile.delete():
                    self.log(LEVEL.warning,
                             "Error deleting the incomplete report file")
            
        return IngestModule.ProcessResult.OK
