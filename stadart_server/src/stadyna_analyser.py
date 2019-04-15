import method_call_graph
import os, hashlib

from logconfig import logger
from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk, dvm
from method_call_graph import PERM_LEVEL_DANGEROUS, PERM_LEVEL_NORMAL,\
    PERM_LEVEL_SIGNATURE, PERM_LEVEL_SIGNATUREORSYSTEM

def getSha256(f, block_size=2**8):
    """
    Calculate SHA-256
    hash of a file
    """
    
    sha256 = hashlib.sha256()
    f = open(f, 'rb')
    while True:
        data = f.read(block_size)
        if not data:
            break
        sha256.update(data)
    return sha256.hexdigest()
  

class StadynaAnalyser:
    def __init__(self):
        
        self._stadynaMcg = method_call_graph.StadynaMcgAnalysis()
        #key = path, value = hash
        self._codeFiles = {} 
        #files loaded several times
        #key = hash; value = loaded_times_num
        self._loaded_files_count = {}
        
        #These are the MOI detected in application sources
        #src; dst
        self._sources_invoke = []
        self._sources_newInstance = []
        self._sources_dexload = []
        
        #These are MOI that have been not yet covered at least one time
        #src; dst
        self._uncovered_invoke = []
        self._uncovered_newInstance = []
        self._uncovered_dexload = []
        
        #MOI is not detected in the sources but method is called
        #This is for analysis
        #calling method (throughMethod); Dst; Stack
        self._suspicious_invoke = [] 
        self._suspicious_newInstance = []
        #file_name; stack - because sometimes we cannot infere the through method
        self._suspicious_dexload = []
        
        #These are all detected results
        #source method; through_method; dst_method
        self._covered_invoke = []
        self._covered_newInstance = []
        #source method; through; loaded file path
        self._covered_dexload = []
        
        
        self.initial_num_of_nodes = 0
        self.initial_num_of_edges = 0
        self.initial_num_of_real_nodes = 0
        self.initial_num_of_perm_normal_nodes = 0
        self.initial_num_of_perm_dangerous_nodes = 0
        self.initial_num_of_perm_signature_nodes = 0
        self.initial_num_of_perm_signatureOrSystem_nodes = 0
        self.initial_num_of_perm_protected_nodes = 0
        self.initial_num_of_refl_invoke_nodes = 0
        self.initial_num_of_refl_newInstance_nodes = 0
        self.initial_num_of_dexload_nodes = 0
        
        self.final_num_of_nodes = 0
        self.final_num_of_edges = 0
        self.final_num_of_real_nodes = 0
        self.final_num_of_perm_normal_nodes = 0
        self.final_num_of_perm_dangerous_nodes = 0
        self.final_num_of_perm_signature_nodes = 0
        self.final_num_of_perm_signatureOrSystem_nodes = 0
        self.final_num_of_perm_protected_nodes = 0
        self.final_num_of_refl_invoke_nodes = 0
        self.final_num_of_refl_newInstance_nodes = 0
        self.final_num_of_dexload_nodes = 0
        

    
    def _update_filename(self, f):
        file_hash = getSha256(f)
        file_load_count = self._loaded_files_count.setdefault(file_hash, 1) 
        
        # if a got file is not unique we rename it
        if file_load_count > 1:
            self._loaded_files_count[file_hash] = file_load_count + 1
            newFilePath = self._rename_source_file(f, file_hash, file_load_count + 1) 
            self._codeFiles[newFilePath] = hash
            return (False, newFilePath)
        else:
            self._codeFiles[f] = file_hash
            return (True, f)
    
    
    
    def makeFileAnalysis(self, file_path):
        logger.debug("Performing analysis of file [%s]..." % file_path)

        a = None
        d = None
        dx = None
        
        ret_type = androconf.is_android(file_path)
        if ret_type == "APK":
            a = apk.APK(file_path)
            d = dvm.DalvikVMFormat(a.get_dex())
        
        elif ret_type == "DEX" :
            try :
                d = dvm.DalvikVMFormat(open(file_path, "rb").read())
            except Exception as e :
                logger.error("[%s] is not valid dex file!" % file_path, e)
                return
                
                
        dx = analysis.VMAnalysis(d)
        
        invokeMethodPaths = analysis.seccon_get_invoke_method_paths(dx)
        newInstanceMethodPaths = analysis.seccon_get_newInstance_method_paths(dx)
        dynamicMethodPaths = analysis.seccon_get_dyncode_loading_paths(dx)
        
        if invokeMethodPaths:
            t = None
            for path in invokeMethodPaths:
                src = path.get_src(d.get_class_manager())
                dst = path.get_dst(d.get_class_manager())
                t = (src, dst)
                self._sources_invoke.append(t)
                self._uncovered_invoke.append(t)
        
        if newInstanceMethodPaths:
            t = None
            for path in newInstanceMethodPaths:
                src = path.get_src(d.get_class_manager())
                dst = path.get_dst(d.get_class_manager())
                t = (src, dst)
                self._sources_newInstance.append(t)
                self._uncovered_newInstance.append(t)
        
        if dynamicMethodPaths:
            t = None
            for path in dynamicMethodPaths:
                src = path.get_src(d.get_class_manager())
                dst = path.get_dst(d.get_class_manager())
                t = (src, dst)
                self._sources_dexload.append(t)
                self._uncovered_dexload.append(t)
        
        #building MFG for the file
        self._stadynaMcg.analyseFile(dx, a)
#         return file_path    

    
    def makeInitialAnalysis(self, f):
        fhash = getSha256(f)
        new_path = self._rename_source_file(f, fhash, 'main')
        self._loaded_files_count[fhash] = 1
        self._codeFiles[new_path] = fhash
        
        self.makeFileAnalysis(new_path)
        
        self.initial_num_of_nodes = self._stadynaMcg.get_current_node_count()
        self.initial_num_of_edges = self._stadynaMcg.get_current_edge_count()
        self.initial_num_of_real_nodes = self._stadynaMcg.get_current_real_node_count()
        
        self.initial_num_of_perm_normal_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_NORMAL)
        self.initial_num_of_perm_dangerous_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_DANGEROUS)
        self.initial_num_of_perm_signature_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_SIGNATURE)
        self.initial_num_of_perm_signatureOrSystem_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_SIGNATUREORSYSTEM)
        self.initial_num_of_perm_protected_nodes = self._stadynaMcg.get_current_protected_node_count()
        
        self.initial_num_of_refl_invoke_nodes = len(self._sources_invoke)
        self.initial_num_of_refl_newInstance_nodes = len(self._sources_newInstance)
        self.initial_num_of_dexload_nodes = len(self._sources_dexload)
        
        #TODO: add initial statistics
#         self._initial_num_of_real_nodes = self._stadynaMcg.get_current_real_node_count()
#         self._initial_num_of_real_edges = self._stadynaMcg.get_current_real_edge_count()
        
        
    
    def _rename_source_file(self, f, fhash, count_str):
        head, extention = os.path.splitext(f)
        new_filepath = "%s_%s-%s%s" % (head, fhash, count_str, extention)
        os.rename(f, new_filepath)
        return new_filepath 
    

    
    def containMethodsToAnalyse(self):
        #logger.debug("Checking if there are methods need to be analysed...")
        if not self._uncovered_invoke and not self._uncovered_newInstance and not self._uncovered_dexload:
            #logger.debug("All lists of analysed methods are empty!")
            return False
        #logger.debug("Not all methods are analysed!")
        return True
        
    

    def processDexLoad(self, fileName, source, output, stack):
        logger.debug("Processing dex load message...")
         
        file_hash = getSha256(fileName)
        file_load_count = self._loaded_files_count.setdefault(file_hash, 0) + 1
        newFilePath = self._rename_source_file(fileName, file_hash, str(file_load_count))
         
        self._loaded_files_count[file_hash] = file_load_count
        self._codeFiles[newFilePath] = file_hash
         
        dexloadPathFromStack = self._getDexLoadPathFromStack(stack)
         
        if dexloadPathFromStack:
            srcFromStack = dexloadPathFromStack[0]
            throughMethod = dexloadPathFromStack[1]
            if dexloadPathFromStack in self._uncovered_dexload:
                self._uncovered_dexload.remove(dexloadPathFromStack)
             
            self._addDexloadPathToMCG(srcFromStack, throughMethod, newFilePath) 
            #we do analyse files if appropriate dex load calls have found in sources of application
            #and if we have not analysed file yet 
            if file_load_count > 1:
                logger.info("File [%s] with hash [%s] is loaded for the [%d]th time! Skipping its analysis!" % (newFilePath, file_hash, file_load_count))
            else:
                self.makeFileAnalysis(newFilePath)
            return
        
        #if the stack does not contain a dexload method detected in the sources
        self._addSuspiciousDexload(newFilePath, stack) 
        logger.debug("Dex load message processed!")
         
    
     
    def _addSuspiciousDexload(self, filePath, stack):
        logger.info("No dexload method is found in the stack! Leaving the file [%s] for analysis! Adding it to suspicious dexload files!" % str(filePath))
        self._suspicious_dexload.append((filePath, stack))
     
 

    def _getDexLoadPathFromStack(self, stack):
        logger.debug("Processing dex load stack...")
        #test code
#         print "\n"
#         for stackEntry in stack:
#             print stackEntry
#         print "\n"
        #end of test code
         
        #we iterate over stack (not over entries in sources) 
        #because it is possible that there are several dexload entries
        #in the stack. Thus, we look for the most recent one.
        for stackEntryPos in xrange(1, len(stack)):
            stackEntry = stack[stackEntryPos]
            for dexloadPathFromSources in self._sources_dexload:
                dexloadSrcFromSources = dexloadPathFromSources[0]
                dexloadDstFromSources = dexloadPathFromSources[1]
                if stackEntry != dexloadSrcFromSources:
                    continue
                 
                prevStackEntry = stack[stackEntryPos - 1]
                if prevStackEntry == dexloadDstFromSources:
                    logger.debug("The method, which calls dexload, is found [%s%s%s]!" % dexloadSrcFromSources)
                    return dexloadPathFromSources
                             
        logger.debug("The called dexload method was not detected in sources!")            
        return None
     


    def _addDexloadPathToMCG(self, src, through, filename):
        logger.debug("Adding dexload method path to our graph...")
        tupl = (src, through, filename) 
        if tupl not in self._covered_dexload:
            self._covered_dexload.append(tupl)
            self._stadynaMcg.addDexloadPath(src, through, filename)
            logger.info("The path [%s] -- [%s] through [%s] for dexload is added to our graph!" % (str(src), str(filename), str(through)))
        else:
            logger.info("The path [%s] -- [%s] through [%s] for dexload is already in our graph!" % (str(src), str(filename), str(through)))
    


    def processInvoke(self, cls, method, prototype, stack):
        logger.debug("Processing method invoke: [%s %s %s]..."% (cls, method, prototype))
        #test code
#         print "\n"
#         for stackEntry in stack:
#             print stackEntry
#         print "\n"
        #end of test code
            
        invokeDstFromClient = (cls, method, prototype)
        invokePosInStack = self._findFirstInvokePos(stack)
        throughMethod = stack[invokePosInStack]
        invokeSrcFromStack = stack[invokePosInStack + 1]
        if invokePosInStack == -1:
            logger.info("Cannot find the first occurrence of invoke method in the stack! Adding method to suspicious list!")
            self._addSuspiciousInvoke(throughMethod, invokeDstFromClient, stack)
            return
        

        for invokePathFromSources in self._sources_invoke:
            invokeSrcFromSources = invokePathFromSources[0]
            if invokeSrcFromSources != invokeSrcFromStack:
                continue
            
            self._addInvokePathToMCG(invokeSrcFromSources, throughMethod, invokeDstFromClient)
            
            if invokePathFromSources in self._uncovered_invoke:
                self._uncovered_invoke.remove(invokePathFromSources)
            return
        
        self._addSuspiciousInvoke(throughMethod, invokeDstFromClient, stack)
        


    def _addSuspiciousInvoke(self, throughMethod, dst, stack):
        #TODO: Write logic later to filter out unsuspicious methods
        logger.info("The destination for invoke method [%s] was not found in the list of uncovered methods! Adding it to the list of suspicious methods!" % str(dst))
        self._suspicious_invoke.append((throughMethod, dst, stack))

    
    def _findFirstInvokePos(self, tmpList):
        logger.debug("Finding the first occurrence of invoke method in the stack...")
        position = -1
        for entry in tmpList:
            position += 1
            if entry[0] == "Ljava/lang/reflect/Method;" and entry[1] == "invoke" and entry[2] == "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;":
                logger.debug("The position of the first occurrence of invoke method is [%d]!" % position)
                return position
        
        logger.debug("We have not found invoke method in the stack!")
        return position
    
    
    def _addInvokePathToMCG(self, src, through, dst):
        logger.debug("Adding invoke method path to our graph...")
        tupl = (src, through, dst)
        if tupl not in self._covered_invoke:
            self._covered_invoke.append(tupl)
            self._stadynaMcg.addInvokePath(src, through, dst)
            logger.debug("The path [%s] -- [%s] through [%s] for invoke method is added to our graph!" % (str(src), str(dst), str(through)))
        else:
            logger.debug("The path [%s] -- [%s] through [%s] for invoke method is already in our graph!" % (str(src), str(dst), str(through)))
            
    
    def processNewInstance(self, cls, method, prototype, stack):
        logger.debug("Processing new instance. DST: [%s%s%s]..." % (cls, method, prototype))
        #test code
#         print "\n"
#         for stackEntry in stack:
#             print stackEntry
#         print "\n"
        #end of test code
        newInstanceDstFromClient = (cls, method, prototype)
        newInstancePosInStack = self._findFirstNewInstancePos(stack)
        throughMethod = stack[newInstancePosInStack]
        newInstanceSrcFromStack = stack[newInstancePosInStack + 1]
        if newInstancePosInStack == -1:
            self._addSuspiciousNewInstance(throughMethod, newInstanceDstFromClient, stack)
            return
        
        for newInstancePathFromSources in self._sources_newInstance:
            newInstanceSrcFromSources = newInstancePathFromSources[0]
            if newInstanceSrcFromSources != newInstanceSrcFromStack:
                continue
            
            self._addNewInstancePathToMCG(newInstanceSrcFromSources, throughMethod, newInstanceDstFromClient)
            
            if newInstancePathFromSources in self._uncovered_newInstance:
                self._uncovered_newInstance.remove(newInstancePathFromSources)
            return
        
        self._addSuspiciousNewInstance(throughMethod, newInstanceDstFromClient, stack)
        
    
    def _findFirstNewInstancePos(self, tmpList):
        logger.debug("Finding the first occurrence of new instance method in the stack...")
        position = -1
        for entry in tmpList:
            position += 1
            #print entry
            cls = entry[0]
            if cls != "Ljava/lang/Class;" and cls != "Ljava/lang/reflect/Constructor;":
                continue
            method = entry[1]
            if method != "newInstance":
                continue
            logger.debug("The position of the first occurrence of new instance method is [%d]!" % position)
            return position
        
        logger.debug("We have not found new instance method in the stack!")
        return position
    
    
    def _addNewInstancePathToMCG(self, src, through, dst):
        logger.debug("Adding newInstance method path to our graph...")
        tupl = (src, through, dst)
        if tupl not in self._covered_newInstance:
            self._covered_newInstance.append(tupl)
            self._stadynaMcg.addNewInstancePath(src, through, dst)
            logger.info("The path [%s] -- [%s] through [%s] for newInstance method is added to our graph!" % (str(src), str(dst), str(through)))
        else:
            logger.info("The path [%s] -- [%s] through [%s] for newInstance method is already in our graph!" % (str(src), str(dst), str(through)))
    
    
    def _addSuspiciousNewInstance(self, throughMethod, dst, stack):
        logger.info("The destination for newInstance method [%s] was not found in the list of uncovered methods! Adding it to the list of suspicious methods!" % str(dst))
        self._suspicious_newInstance.append((throughMethod, dst, stack))
        
    
    def printMoiLists(self, toLogger=True):
        printStr = None
        
        if self._uncovered_invoke or self._uncovered_newInstance or self._uncovered_dexload:
            printStr = "Printing still uncovered methods of interest:\n\n"
            if self._uncovered_invoke:
                printStr +="REFLECTION INVOKE:\n"
                for (src, dst) in self._uncovered_invoke:
                    printStr += "SRC: [%s %s %s]\n" % src
                    printStr += "DST: [%s %s %s]\n" % dst
                          
            if self._uncovered_newInstance:
                printStr += "REFLECTION NEW_INSTANCE:\n"
                for (src, dst) in self._uncovered_newInstance:
                    printStr += "SRC: [%s %s %s]\n" % src
                    printStr += "DST: [%s %s %s]\n" % dst
                          
            if self._uncovered_dexload:
                printStr += "DYNAMIC LOAD:\n"
                for (src, dst) in self._uncovered_dexload:
                    printStr += "SRC: [%s %s %s]\n" % src
                    printStr += "DST: [%s %s %s]\n" % dst
        else:
            printStr = "All methods of interest are covered at least one time!!!\n"
        
        if toLogger:
            logger.debug("%s" % printStr)
        else:
            print printStr
            
    
    def calculateFinalNumbers(self):
        self.final_num_of_nodes = self._stadynaMcg.get_current_node_count()
        self.final_num_of_edges = self._stadynaMcg.get_current_edge_count()
        self.final_num_of_real_nodes = self._stadynaMcg.get_current_real_node_count()
        
        self.final_num_of_perm_normal_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_NORMAL)
        self.final_num_of_perm_dangerous_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_DANGEROUS)
        self.final_num_of_perm_signature_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_SIGNATURE)
        self.final_num_of_perm_signatureOrSystem_nodes = self._stadynaMcg.get_current_permission_level_node_count(PERM_LEVEL_SIGNATUREORSYSTEM)
        
        self.final_num_of_perm_protected_nodes = self._stadynaMcg.get_current_protected_node_count()
        self.final_num_of_refl_invoke_nodes = len(self._sources_invoke)
        self.final_num_of_refl_newInstance_nodes = len(self._sources_newInstance)
        self.final_num_of_dexload_nodes = len(self._sources_dexload)
    
    

    
    
    def performFinalInfoSave(self, where, resultsFileName, executionTime = -1):
        logger.debug("Saving information...")
        self.calculateFinalNumbers()
        #saving gexf
        finalGexfFileName = "%s%s" % (resultsFileName, "_final")
        self.saveGexf(where, finalGexfFileName)

        
        #saving log file
        logFileName = '%s%s' % (resultsFileName, '_log.txt')
        logSavePath = os.path.join(where, logFileName)
        self._save_log_file(logSavePath, executionTime)
        
        logger.debug("Final results are saved!")
    
    def saveGexf(self, where, resultsFileName):
        gexfFileName = '%s%s' % (resultsFileName, '.gexf')
        gexfSavePath = os.path.join(where, gexfFileName)
        b = self._stadynaMcg.export_to_gexf()
        androconf.save_to_disk(b, gexfSavePath)
    
    
    def _save_log_file(self, logSavePath, executionTime):
        suspiciousInvNum = len(self._suspicious_invoke)
        suspiciousNewInstanceNum = len(self._suspicious_newInstance)
        suspiciousDexloadNum = len(self._suspicious_dexload)
        
        numOfUncoveredInvMethods = len(self._uncovered_invoke)
        numOfUncoveredNewInstanceMethods = len(self._uncovered_newInstance)
        numOfUncoveredDexloadMethods = len(self._uncovered_dexload)
        
        numOfCoveredInvMethods = len(self._sources_invoke) - numOfUncoveredInvMethods
        numOfCoveredNewInstMethods = len(self._sources_newInstance) - numOfUncoveredNewInstanceMethods
        numOfCoveredDexloadMethods = len(self._sources_dexload) - numOfUncoveredDexloadMethods
        
        numOfDetectedInvPaths = len(self._covered_invoke)
        numOfDetectedNewInstancePaths = len(self._covered_newInstance)
        numOfDetectedDexloadPaths = len(self._covered_dexload)
        
        
        buff = ""
        
        buff += "=============================================\n"
        buff += "Initial number of nodes in the graph: \t%d\n" % self.initial_num_of_nodes
        buff += "Initial number of real nodes in the graph: \t%d\n" % self.initial_num_of_real_nodes
        buff += "Initial number of edges in the graph: \t%d\n" % self.initial_num_of_edges
        buff += "Initial number of nodes protected with permissions of normal level: \t%d\n" % self.initial_num_of_perm_normal_nodes
        buff += "Initial number of nodes protected with permissions of dangerous level: \t%d\n" % self.initial_num_of_perm_dangerous_nodes
        buff += "Initial number of nodes protected with permissions of signature level: \t%d\n" % self.initial_num_of_perm_signature_nodes
        buff += "Initial number of nodes protected with permissions of signatureOrSystem level: \t%d\n" % self.initial_num_of_perm_signatureOrSystem_nodes
        buff += "Initial number of all nodes protected with permissions: \t%d\n" % self.initial_num_of_perm_protected_nodes
        buff += "Initial number of reflection invoke nodes: \t%d\n" % self.initial_num_of_refl_invoke_nodes
        buff += "Initial number of reflection new instance nodes: \t%d\n" % self.initial_num_of_refl_newInstance_nodes
        buff += "Initial number of dexload nodes: \t%d\n" % self.initial_num_of_dexload_nodes
        buff += "\n"
        buff += "Final number of nodes in the graph: \t%d\n" % self.final_num_of_nodes
        buff += "Final number of real nodes in the graph: \t%d\n" % self.final_num_of_real_nodes
        buff += "Final number of edges in the graph: \t%d\n" % self.final_num_of_edges
        buff += "Final number of nodes protected permissions of normal level: \t%d\n" % self.final_num_of_perm_normal_nodes
        buff += "Final number of nodes protected permissions of dangerous level: \t%d\n" % self.final_num_of_perm_dangerous_nodes
        buff += "Final number of nodes protected permissions of signature level: \t%d\n" % self.final_num_of_perm_signature_nodes
        buff += "Final number of nodes protected permissions of signatureOrSystem level: \t%d\n" % self.final_num_of_perm_signatureOrSystem_nodes
        buff += "Final number of all nodes protected with permissions: \t%d\n" % self.final_num_of_perm_protected_nodes
        buff += "Final number of reflection invoke nodes: \t%d\n" % self.final_num_of_refl_invoke_nodes
        buff += "Final number of reflection new instance nodes: \t%d\n" % self.final_num_of_refl_newInstance_nodes
        buff += "Final number of dexload nodes: \t%d\n" % self.final_num_of_dexload_nodes
        buff += "=============================================\n\n"
        
        buff += "=============================================\n"
        buff += "Number of covered reflection invoke methods: \t%d\n" % numOfCoveredInvMethods
        buff += "Number of covered reflection new instance methods: \t%d\n" % numOfCoveredNewInstMethods
        buff += "Number of covered dexload methods: \t%d\n" % numOfCoveredDexloadMethods
        buff += "\n"
        
        if self.final_num_of_refl_invoke_nodes > 0:
            buff += "Percentage of covered reflection invoke methods: \t%4.2f\n" % (100.0 * numOfCoveredInvMethods / self.final_num_of_refl_invoke_nodes)
        else: 
            buff += "Percentage of covered reflection invoke methods: ------\n" 
        
        if self.final_num_of_refl_newInstance_nodes > 0: 
            buff += "Percentage of covered reflection new instance methods: \t%4.2f\n" % (100.0 * numOfCoveredNewInstMethods / self.final_num_of_refl_newInstance_nodes)
        else:
            buff += "Percentage of covered reflection new instance methods: -----\n"
            
        if self.final_num_of_dexload_nodes > 0:
            buff += "Percentage of covered dexload methods: \t%4.2f\n" % (100.0 * numOfCoveredDexloadMethods / self.final_num_of_dexload_nodes)
        else:
            buff += "Percentage of covered dexload methods: -----\n"
            
        buff += "\n"
        buff += "Number of detected reflection invoke unique paths: \t%d\n" % numOfDetectedInvPaths
        buff += "Number of detected reflection new instance unique paths: \t%d\n" % numOfDetectedNewInstancePaths
        buff += "Number of detected dexload unique paths: \t%d\n" % numOfDetectedDexloadPaths
        buff += "=============================================\n\n"
        
        buff += "=============================================\n"
        buff += "Number of suspicious reflection invoke methods: \t%d\n" % suspiciousInvNum
        buff += "Number of suspicious reflection new instance methods: \t%d\n" % suspiciousNewInstanceNum
        buff += "Number of suspicious dexload methods: \t%d\n" % suspiciousDexloadNum
        buff += "=============================================\n\n"
        
        
        buff += "\n\n"    
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"
        buff += "DETECTED PATHS:\n"
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"
        
        if numOfDetectedInvPaths > 0:
            buff += "=============================================\n"
            buff += "DETECTED REFLECTION INVOKE PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfDetectedInvPaths):
                buff += "SRC MOI: \t%s\n" % str(self._covered_invoke[i][0])
                buff += "THROUGH: \t%s\n" % str(self._covered_invoke[i][1])
                buff += "DST: \t%s\n" % str(self._covered_invoke[i][2])
                buff += "\n"
            buff += "=============================================\n\n"
            
        if numOfDetectedNewInstancePaths > 0:
            buff += "=============================================\n"
            buff += "DETECTED REFLECTION NEW INSTANCE PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfDetectedNewInstancePaths):
                buff += "SRC MOI: \t %s \n" % str(self._covered_newInstance[i][0])
                buff += "THROUGH: \t %s \n" % str(self._covered_newInstance[i][1])
                buff += "DST: \t %s \n" % str(self._covered_newInstance[i][2])
                buff += "\n"
            buff += "=============================================\n\n"
              
        if numOfDetectedDexloadPaths > 0:
            buff += "=============================================\n"
            buff += "DETECTED DEXLOAD PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfDetectedDexloadPaths):
                buff += "SRC MOI: \t %s \n" % str(self._covered_dexload[i][0])
                buff += "THROUGH: \t %s \n" % str(self._covered_dexload[i][1])
                buff += "FILENAME: \t %s \n" % str(self._covered_dexload[i][2])
                buff += "\n"
            buff += "=============================================\n\n"
          
        buff += "\n\n"    
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"
        buff += "UNCOVERED PATHS:\n"
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n"
          
        if numOfUncoveredInvMethods > 0:
            buff += "=============================================\n"
            buff += "UNCOVERED REFLECTION INVOKE PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfUncoveredInvMethods):
                buff += "SRC MOI: \t%s\n" % str(self._uncovered_invoke[i][0])
                buff += "REFL CALL: \t%s\n" % str(self._uncovered_invoke[i][1])
                buff += "\n"
            buff += "=============================================\n\n"
              
        if numOfUncoveredNewInstanceMethods > 0:
            buff += "=============================================\n"
            buff += "UNCOVERED REFLECTION INVOKE PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfUncoveredNewInstanceMethods):
                buff += "SRC MOI: \t%s\n" % str(self._uncovered_newInstance[i][0])
                buff += "REFL CALL: \t%s\n" % str(self._uncovered_newInstance[i][1])
                buff += "\n"
            buff += "=============================================\n\n"
              
        if numOfUncoveredDexloadMethods > 0:
            buff += "=============================================\n"
            buff += "UNCOVERED DEXLOAD PATHS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, numOfUncoveredDexloadMethods):
                buff += "SRC MOI: \t%s\n" % str(self._uncovered_dexload[i][0])
                buff += "DEXLOAD CALL: \t%s\n" % str(self._uncovered_dexload[i][1])
                buff += "\n"
            buff += "=============================================\n\n"
          
          
        buff += "\n\n"    
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"
        buff += "SUSPICIOUS CALLS:\n"
        buff += "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"
          
        if suspiciousInvNum > 0:
            buff += "=============================================\n"
            buff += "SUSPICIOUS REFLECTION INVOKE CALLS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, suspiciousInvNum):
                buff += "REFL CALL: \t%s\n" % str(self._suspicious_invoke[i][0])
                buff += "DST: \t%s\n" % str(self._suspicious_invoke[i][1])
                buff += "STACK:\n%s\n" % str(self._suspicious_invoke[i][2])
                buff += "\n"
            buff += "=============================================\n\n"
              
        if suspiciousNewInstanceNum > 0:
            buff += "=============================================\n"
            buff += "SUSPICIOUS REFLECTION NEW INSTANCE CALLS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, suspiciousNewInstanceNum):
                buff += "REFL CALL: \t%s\n" % str(self._suspicious_newInstance[i][0])
                buff += "DST: \t%s\n" % str(self._suspicious_newInstance[i][1])
                buff += "STACK:\n%s\n" % str(self._suspicious_newInstance[i][2])
                buff += "\n"
            buff += "=============================================\n\n"
              
        if suspiciousDexloadNum > 0:
            buff += "=============================================\n"
            buff += "SUSPICIOUS DEXLOAD CALLS:\n"
            buff += "*********************************************\n"
            for i in xrange(0, suspiciousDexloadNum):
                buff += "FILENAME: \t%s\n" % str(self._suspicious_dexload[i][0])
                buff += "STACK:\n%s\n" % str(self._suspicious_dexload[i][1])
                buff += "\n"
            buff += "=============================================\n\n"
        
        
        with open(logSavePath, 'wb') as log:
            log.write(buff)
        

def main():
    pass
if __name__ == '__main__':
    main()
