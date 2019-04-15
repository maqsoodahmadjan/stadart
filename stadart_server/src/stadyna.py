"""
MOI - methods of interest
"""

import sys, os, shutil
import json
import consts
import Queue
import utils
import time
from androguard.core import androconf
from messages import SecconMessageProducer
from device import Device
from optparse import OptionParser
from logconfig import logger
from stadyna_analyser import StadynaAnalyser

from androguard.core.bytecodes import apk

script_usage = "Usage: %prog apk_file_name [options]"

option_0 = {'name': ('-o', '--outdir'), 'dest': 'outputDir', 'help': 'directory with all files related to the analysis', 'type': 'string', 'nargs' : 1}
option_1 = {'name' : ('-i', '--inputApk'), 'dest': 'inputApk', 'help' : 'path to the file with results of processing', 'type': 'string', 'nargs' : 1}
options = [option_0, option_1]



def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')

    
def getDeviceForDynAnalysis():
    dev_list = Device.get_devices_list()
    
    devNum = len(dev_list)
    
    if devNum <= 0:
        logger.error("No device has been detected! Connect your device and restart the application!")
        return None
    
    if devNum == 1:
        return Device.get_device(dev_list[0])
    
    choice = None
    if devNum > 1:
        print "Select the device to use for analysis:\n"
        for i in xrange(0, devNum):
            print "%d. %s\n" % ((i + 1), dev_list[i])
        
        while not choice:
            try:
                choice = int(raw_input())
                if choice not in range(1, devNum+1):
                    choice = None
                    print 'Invalid choice! Choose right number!'
            except ValueError:
                print 'Invalid Number! Choose right number!'
        
        
    return Device.get_device(dev_list[choice - 1])


def checkInputFile(inputPath):
    logger.debug("Checking input path [%s]..." % inputPath)
    if not os.path.isfile(inputPath):
        logger.error("Input path [%s] does not point to a file!" % inputPath)
        return False
    logger.debug("The path [%s] point to the file!" % inputPath)
    
    ret_type = androconf.is_android(inputPath)
    if ret_type != "APK":
        logger.error("Input file [%s] is not APK file!" % inputPath)
        return False
    
    logger.debug("File [%s] is an APK file!" % inputPath)
    return True
    
def checkOutputPath(dst):
    if os.path.exists(dst):
        if not os.path.isdir(dst):
            logger.error("[%s] is not a directory!" % dst)
            return False
    else:
        logger.info("The path [%s] does not exist! Creating it!" % dst)
        os.makedirs(dst)
    
    return True

def copyFileToDir(src, dst):
    logger.debug("Coping file [%s] to output directory [%s]..." % (os.path.basename(src), dst))
        
    if not os.path.isfile(src):
        logger.debug("[%s] is not a file! Cannot be copied!" % src)
        return False
    try:
        shutil.copy2(src, dst)
    except Exception as e:
        logger.error(e)
        logger.error("Could not copy file [%s] to directory [%s]!" % (src, dst))
        return False
    
    logger.debug("File [%s] has been copied to directory [%s] successfully!" % (src, dst))
    return True


def analyseStadynaMsg(device, filesDir, stadynaAnalyser, stadynaMsg):
    logger.debug("Analysing obtained message...")
    operation = int(stadynaMsg.get(consts.JSON_OPERATION))
    if operation == consts.OP_CLASS_NEW_INSTANCE:
        logger.debug("Obtained message is OP_CLASS_NEW_INSTANCE!")
        processNewInstanceMsg(stadynaAnalyser, stadynaMsg)
        return
    if operation == consts.OP_METHOD_INVOKE:
        logger.debug("Obtained message is OP_METHOD_INVOKE!")
        processInvokeMsg(stadynaAnalyser, stadynaMsg)
        return
    if operation == consts.OP_DEX_LOAD:
        logger.debug("Obtained message is OP_DEX_LOAD!")
        processDexLoadMsg(device, filesDir, stadynaAnalyser, stadynaMsg)
        return
    logger.warning("Program does not contain routine to process message: [%d]!" % operation)


def processNewInstanceMsg(stadynaAnalyser, stadynaMsg):
    logger.debug("Processing OP_CLASS_NEW_INSTANCE message...")
    #call to str is required to omit 'u' symbol before the strings
    cls = str(stadynaMsg.get(consts.JSON_CLASS))
    method = str(stadynaMsg.get(consts.JSON_METHOD))
    prototype = str(stadynaMsg.get(consts.JSON_PROTO))
#     cls = stadynaMsg.get(consts.JSON_CLASS)
#     method = stadynaMsg.get(consts.JSON_METHOD)
#     prototype = stadynaMsg.get(consts.JSON_PROTO)
    stack = utils.transformStack(stadynaMsg.get(consts.JSON_STACK))
    stadynaAnalyser.processNewInstance(cls, method, prototype, stack)
    logger.debug("OP_CLASS_NEW_INSTANCE message processed!")


def processInvokeMsg(stadynaAnalyser, stadynaMsg):
    logger.debug("Processing OP_METHOD_INVOKE message...")
    #call to str is required to omit 'u' symbol before the strings
    cls = str(stadynaMsg.get(consts.JSON_CLASS))
    method = str(stadynaMsg.get(consts.JSON_METHOD))
    prototype = str(stadynaMsg.get(consts.JSON_PROTO))
#     cls = stadynaMsg.get(consts.JSON_CLASS)
#     method = stadynaMsg.get(consts.JSON_METHOD)
#     prototype = stadynaMsg.get(consts.JSON_PROTO)
    stack = utils.transformStack(stadynaMsg.get(consts.JSON_STACK))
    stadynaAnalyser.processInvoke(cls, method, prototype, stack)
    logger.debug("OP_METHOD_INVOKE message processed!")
    
    
def processDexLoadMsg(device, resultsDirPath, stadynaAnalyser, stadynaMsg):
    logger.debug("Processing OP_DEX_LOAD message...")
    #call to str is required to omit 'u' symbol before the strings
    source = str(stadynaMsg.get(consts.JSON_DEX_SOURCE))
    output = str(stadynaMsg.get(consts.JSON_DEX_OUTPUT))
#     source = stadynaMsg.get(consts.JSON_DEX_SOURCE)
#     output = stadynaMsg.get(consts.JSON_DEX_OUTPUT)
    stack = utils.transformStack(stadynaMsg.get(consts.JSON_STACK))
    
    if not device.get_file(source, resultsDirPath):
        logger.error("Could not get file [%s] from the device for analysis!" % source)
        return
    
    _, fileName = os.path.split(source)
    anFilePath = os.path.join(resultsDirPath, fileName)
    if not (os.path.exists(anFilePath)):
        logger.error("There is no local file [%s] to analyse!" % anFilePath)
        return
    
    stadynaAnalyser.processDexLoad(anFilePath, source, output, stack)
    logger.debug("OP_DEX_LOAD message processed!")
    

def checkExit(secconAnalyser, stopIfAllSuspiciousMethodsAreAnalysed=False):
    #logger.debug("Checking if we can exit...")
    if not secconAnalyser.containMethodsToAnalyse():
        logger.info("All suspicious methods are analysed! We can exit!")
        if stopIfAllSuspiciousMethodsAreAnalysed:
            logger.info("Generating KeyboardInterrupt to exit!")
            raise KeyboardInterrupt
        #else:
            #logger.warning("We cannot exit because it is not allowed by a user! Only a user can stop the analysis!")
    


def startMainActivity(device, package, mainActivity):
    fullMainActivityPath = None
    if mainActivity[0] == '.':
        fullMainActivityPath = package.join(mainActivity)
    else:
        fullMainActivityPath = mainActivity
    
    device.start_activity(package, fullMainActivityPath)
    


def perform_analysis(inputApkPath, resultsDirPath, sourceFilesDirPath):    
    logger.debug("Starting analysis of the application [%s]..." % inputApkPath)
    startTime = time.time()
    
    if not copyFileToDir(inputApkPath, sourceFilesDirPath):
        logger.error("Could not copy source file to directory! The analysis was not performed!")
        return
    
    apkFileNameExt = os.path.basename(inputApkPath)
    apkFileName, _ = os.path.splitext(apkFileNameExt)
    apkFilePath = os.path.join(sourceFilesDirPath, apkFileNameExt)
    
    stadynaAnalyser = StadynaAnalyser()
    stadynaAnalyser.makeInitialAnalysis(apkFilePath)
    
    initial_name = apkFileName + "_initial"
    stadynaAnalyser.saveGexf(resultsDirPath, initial_name)
    
    if not stadynaAnalyser.containMethodsToAnalyse():
        logger.info("Input apk file does not contain suspicious methods!")
        stadynaAnalyser.performInfoSave(resultsDirPath, apkFileName)
        logger.info("The analysis is finished!")
        return
    
    stadynaAnalyser.printMoiLists()
    
    dev = getDeviceForDynAnalysis()
    if not dev.is_alive():
        logger.warning("The selected device to perform dynamic analysis is not alive! Finishing!")
        stadynaAnalyser.performInfoSave(resultsDirPath, apkFileName)
        logger.info("The analysis is finished!")
        return
    
    #TODO: Check if it is possible racing conditions here
    #If we at first install application and then run Message analyser
    #everything is fine.
    #If we at first start Message analyser and then start the application
    #the first dex load is actual load when the application is installed. 
    
    androApk = apk.APK(inputApkPath)
    installed = dev.install_package(inputApkPath)
    if not installed:
        logger.error("An error occurred during the installation of the app [%s]! Cannot perform an analysis!" % inputApkPath)
        return
    
    package = androApk.get_package()
    mainActivity = androApk.get_main_activity() 
    uid = dev.get_package_uid(package)
    if uid == -1:
        logger.error("Cannot get the uid of the package [%s]! Cannot start an analysis!" % package)
        return
    
    #TODO: test section
    messages = Queue.Queue()
    seccon_producer = SecconMessageProducer(dev, messages)
    seccon_producer.setDaemon(False)
    seccon_producer.start()
    
    #sleeping 3sec before starting new activity 
    time.sleep(3)
    
    #Add here the invocation of the main activity
    startMainActivity(dev, package, mainActivity) 
    
    while 1:
        while not messages.empty():
            line = messages.get()
            #print 'Received line: ' + repr(line)
            decodedLine = json.loads(line)
            if int(decodedLine.get(consts.JSON_UID)) != uid:
                continue
            analyseStadynaMsg(dev, sourceFilesDirPath, stadynaAnalyser, decodedLine)
            stadynaAnalyser.printMoiLists()
        
        try:
            time.sleep(2)
            #The same method can be used for different calls. Thus, we comment this line now )
            #checkExit(stadynaAnalyser)  
        except KeyboardInterrupt:
            logger.debug("Exiting...")  
            break
    
    seccon_producer.stopThread()
    seccon_producer.join()
    
    endTime = time.time()
    
    stadynaAnalyser.performFinalInfoSave(resultsDirPath, apkFileName, (endTime-startTime))
    logger.info("The analysis is finished!")
    


def main(options, arguments):
    inputApkPath = None
    resultsDirPath = None
    sourceFilesDirPath = None
    
    if (options.inputApk == None):
        logger.error("The path to an input file is not specified! Exiting!")
        exit(1)
    else:
        inputApkPath = options.inputApk
    
    if (options.outputDir == None):
        logger.error("The path an output directory is not specified! Exiting!")
        exit(1)
    else:
        resultsDirPath = options.outputDir
    
    if not checkInputFile(inputApkPath):
        exit(1)
    
    if not checkOutputPath(resultsDirPath):
        exit(1)
    
    sourceFilesDirPath = os.path.join(resultsDirPath, "source_files/")
    if not checkOutputPath(sourceFilesDirPath):
        exit(1)
    
#     if not copyFileToDir(inputApkPath, sourceFilesDirPath):
#         exit(1)
    
#     apkFilename = os.path.basename(inputApkPath)
#     copiedApkPath = os.path.join(sourceFilesDirPath, apkFilename)
    
    #starting the analysis
    perform_analysis(inputApkPath, resultsDirPath, sourceFilesDirPath)



#################################################################
if __name__ == '__main__':
    parser = OptionParser(usage=script_usage)
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)
    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
     
    main(options, arguments)

####test
# if __name__ == '__main__':
#     main(None, None)
        