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
# Usage:
#   1. Import this module into the Autopsy "Python
#   2. Run this ingest module against current case data

import jarray
import inspect
import os
from java.lang import Class
from java.lang import System
from java.sql import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class HW11ContactsDbIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "HW11 Contacts DB Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Sample module that parses contacts.db."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return HW11ContactsDbIngestModule()


# Data Source-level ingest module.  One gets created per data source..
class HW11ContactsDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(HW11ContactsDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__,
                          inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of
    #   org.sleuthkit.autopsy.ingest.IngestJobContext.

    # See:
    # http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/classorg_1_1
    # sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException
        #   exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        self.context = context

    # Where the analysis is done.
    # The 'dataSource' object being passed in
    #   is of type org.sleuthkit.datamodel.Content.

    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/
    #   4.6.0/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html

    # 'progressBar' is of type
    #   org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress

    # See: http://sleuthkit.org/autopsy/docs/api-docs/
    #   4.6.0/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_
    #   ingest_module_progress.html
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # For our example, we want to find all files named “contacts.db”.
        # There is a findFiles() method that does that.
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "contacts.db")

        # keep track of progress
        num_files = len(files)
        progressBar.switchToIndeterminate(num_files)
        file_count = 0

        for f in files:
            # First check to see if the job was cancelled
            # If it was, return.
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # Begin processing the next file
            self.log(Level.INFO, "Processing file: " + f.getName())
            file_count += 1

            # The ContentUtils class provides a
            # utility to save file content to disk.
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(),
                                     str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))

            # Next, we need to open the SQLite database.
            try:
                Class.forName("org.sqlite.JDBC").newInstance()
                db_conn = DriverManager.getConnection(
                    "jdbc:sqlite:%s" % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO,
                         "Could not open database file (not SQLite) " +
                         f.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # We first start by querying for all rows in our simple table:
            try:
                stmt = db_conn.createStatement()
                result_set = stmt.executeQuery("SELECT * FROM contacts")
            except SQLException as e:
                self.log(Level.INFO,
                         "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # keep an artifact count
            artifact_count = 0

            # Process the DB
            while result_set.next():
                # Make an artifact on the blackboard and give it attributes
                art = f.newArtifact(
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT)

                # Name found in DB
                name = result_set.getString("name")
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME_PERSON
                    .getTypeID(),
                    ContactsDbIngestModuleFactory.moduleName, name))

                # Email found
                email = result_set.getString("email")
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL.getTypeID(),
                    ContactsDbIngestModuleFactory.moduleName, email))

                # Phone number found
                phone = result_set.getString("phone")
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER
                    .getTypeID()
                    , ContactsDbIngestModuleFactory.moduleName, phone))

                # Index the artifact for keyword searching
                try:
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE,
                             "Error indexing artifact " + art.getDisplayName())

            # Update the UI of the newly created artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(ContactsDbIngestModuleFactory.moduleName,
                                BlackboardArtifact.ARTIFACT_TYPE
                                .TSK_CONTACT,
                                None))

            # Clean up tasks for the current file
            stmt.close()
            db_conn.close()
            os.remove(lclDbPath)

        # After all db's are processed, post a message to the ingest inbox.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              "ContactsDb Analyzer",
                                              "Found %d files" % file_count)
        IngestServices.getInstance().postMessage(message)

        # return
        return IngestModule.ProcessResult.OK
