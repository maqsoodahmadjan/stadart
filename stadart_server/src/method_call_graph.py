from xml.sax.saxutils import escape

from logconfig import logger
from androguard.core import bytecode
from androguard.core.analysis import analysis
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS, MANIFEST_PERMISSIONS
from androguard.core.bytecodes.api_permissions import DVM_PERMISSIONS_BY_ELEMENT,\
    DVM_PERMISSIONS_BY_API_CALLS
from androguard.core.analysis.analysis import PathVar


from networkx.classes.digraph import DiGraph

#TODO: add attribute the name of the file ? (problem with invocation of methods through reflection)

# DEFAULT_NODE_TYPE = "normal"
# DEFAULT_NODE_PERM = 0
# DEFAULT_NODE_PERM_LEVEL = -1

POSTFIX_DEXLOAD          = "DEXLOAD"
POSTFIX_REFL_INVOKE      = "REFL_INVOKE"
POSTFIX_REFL_NEWINSTANCE = "REFL_NEWINSTANCE"

POSTFIX_ACTIVITY  = "ACTIVITY"
POSTFIX_SERVICE   = "SERVICE"
POSTFIX_RECEIVER  = "RECEIVER"
POSTFIX_PERM      = "PERMISSION"

LABEL_REFL_INVOKE      = "REFLECTION INVOKE"
LABEL_REFL_NEWINSTANCE = "REFLECTION NEW INSTANCE"
LABEL_DEXLOAD          = "DYNAMIC CODE LOADING"
LABEL_ACTIVITY         = "ACTIVITY"
LABEL_SERVICE          = "SERVICE"
LABEL_RECEIVER         = "RECEIVER"

NODE_METHOD                =  "method"
NODE_CONSTRUCTOR           =  "constructor"  
NODE_STATIC_INIT           =  "static_initializer"
NODE_REFL_INVOKE           =  "refl_invoke"
NODE_REFL_NEWINSTANCE      =  "refl_newinstance"
NODE_FAKE_CLASS            =  "fake_class"
NODE_FAKE_DEXLOAD          =  "fake_dexload"
NODE_FAKE_DEXLOAD_FILE     =  "fake_dexload_filename"
NODE_FAKE_ACTIVITY         =  "fake_activity"
NODE_FAKE_SERVICE          =  "fake_service"
NODE_FAKE_RECEIVER         =  "fake_receiver"
NODE_FAKE_PERMISSION       =  "fake_permission"


NODE_COLORS = {
     NODE_METHOD                : (100, 100, 100), #method node                --- dark grey
     NODE_CONSTRUCTOR           : (150, 150, 150), #constuctor node            --- grey
     NODE_STATIC_INIT           : (200, 200, 200), #static initialization node --- light grey
     NODE_REFL_INVOKE           : (0, 255, 0),     #reflection invoke          --- lime
     NODE_REFL_NEWINSTANCE      : (0, 128, 0),     #reflection new instance    --- green
     NODE_FAKE_CLASS            : (0, 0, 0),       #class node                 --- black
     NODE_FAKE_DEXLOAD          : (255, 0, 0),     #dexload fact               --- red       
     NODE_FAKE_DEXLOAD_FILE     : (255, 0, 255),   #dexload file               --- magenta
     NODE_FAKE_ACTIVITY         : (255, 255, 0),   #entry point:activity       --- yellow
     NODE_FAKE_SERVICE          : (240, 230, 140), #entry point:service        --- khaki
     NODE_FAKE_RECEIVER         : (255,165,0),     #entry point:receiver       --- orange
     NODE_FAKE_PERMISSION       : (0, 0, 255),     #permissions                --- blue
}

REAL_NODE       = "real_node"
FAKE_NODE       = "fake_node"


NODE_SHAPE = {
    REAL_NODE : "disc",
    FAKE_NODE : "diamond",
}

#The values for permission levels are taken from Android
PERM_LEVEL_NORMAL = "normal"
PERM_LEVEL_DANGEROUS = "dangerous"
PERM_LEVEL_SIGNATURE = "signature"
PERM_LEVEL_SIGNATUREORSYSTEM = "signatureOrSystem"

PERMISSIONS_LEVEL = { 
    PERM_LEVEL_NORMAL : 0,
    PERM_LEVEL_DANGEROUS : 1,
    PERM_LEVEL_SIGNATURE : 2,
    PERM_LEVEL_SIGNATUREORSYSTEM : 3,    
}

# COLOR_PERMISSIONS_LEVEL = {
#     "dangerous"                 : (255, 0, 0),
#     "signatureOrSystem"         : (255, 63, 63),
#     "signature"                 : (255, 132, 132),
#     "normal"                    : (255, 181, 181),
# }

ATTR_TYPE             = "type"
ATTR_CLASS_NAME       = "class_name"
ATTR_METHOD_NAME      = "method_name"
ATTR_DESCRIPTOR       = "descriptor"
ATTR_REAL             = "real"
ATTR_PERM_NAME        = "permission_name"
ATTR_PERM_LEVEL       = "permission_level"
ATTR_DEXLOAD_FILENAME = "dexload_filename"

ID_ATTRIBUTES = {
    ATTR_TYPE              :  0,
    ATTR_CLASS_NAME        :  1,
    ATTR_METHOD_NAME       :  2,
    ATTR_DESCRIPTOR        :  3,
    ATTR_REAL              :  4,
    ATTR_PERM_NAME         :  5,
    ATTR_PERM_LEVEL        :  6,
    ATTR_DEXLOAD_FILENAME  :  7,
}


# DEXCLASSLOADER_COLOR = (0, 0, 0)
# ACTIVITY_COLOR = (51, 255, 51)
# SERVICE_COLOR = (0, 204, 204)
# RECEIVER_COLOR = (204, 51, 204)



#TODO: Need to be refactored
#There should be only node features(id, key, label, shape, color) and its attributes, which are obtained externally (nType, real, internal...)
class NodeS:
#     def __init__(self, id, key, label, shape, color, attributes):
#         self.id = id
#         self.key = key
#         if isinstance(key, basestring):
#             self.key = key
#         elif isinstance(key, tuple):
#             self.key = "%s %s %s" % key
#         self.shape = shape
#         self.color = color
#         
#         
#         
#         if label == None:
#             self.label = key
#         else:
#             self.label = label
#         
#         self.attributes = attributes
        
    
    def __init__(self, id, nType, key, label=None, real=True):
        self.id = id
        self.key = key
#         if isinstance(key, basestring):
#             self.key = key
#         elif isinstance(key, tuple):
#             self.key = "%s %s %s" % key
        self.nType = nType
        self.color = NODE_COLORS [nType]
        if real:
            self.shape = NODE_SHAPE [REAL_NODE]
        else:
            self.shape = NODE_SHAPE [FAKE_NODE]
         
         
         
        if label == None:
            self.label = key
        else:
            self.label = label
         
         
        self.attributes = {
                           ATTR_TYPE             : self.nType,
                           ATTR_CLASS_NAME       : None,
                           ATTR_METHOD_NAME      : None,
                           ATTR_DESCRIPTOR       : None,
                           ATTR_REAL             : str(real),
                           ATTR_PERM_NAME        : None,
                           ATTR_PERM_LEVEL       : None,
                           ATTR_DEXLOAD_FILENAME : None,
                        }
        
    
    def get_attributes(self) :
        return self.attributes

    def get_attribute(self, name) :
        return self.attributes[name]
    
    def get_attributes_gexf(self):
        #TODO: It would be nice to get attributes according to the node type
        buff = ""
        
        buff += "<viz:color r=\"%d\" g=\"%d\" b=\"%d\"/>\n" % (self.color[0], self.color[1], self.color[2])
        buff += "<viz:shape value=\"%s\"/>\n" % self.shape
        
#         if self.attributes[ATTR_COLOR] != None : 
#             buff += "<viz:color r=\"%d\" g=\"%d\" b=\"%d\"/>\n" % (self.attributes[ATTR_COLOR][0], self.attributes[ATTR_COLOR][1], self.attributes[ATTR_COLOR][2])
        
        
        buff += "<attvalues>\n"
        
        for attr in self.attributes:
            if self.attributes[attr] != None:
                buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[attr], escape(self.attributes[attr]))
#         buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_TYPE], escape(self.attributes[ATTR_TYPE]))
#         
#         
#         if self.attributes[ATTR_CLASS_NAME] != None:
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_CLASS_NAME], escape(self.attributes[ATTR_CLASS_NAME]))
#         if self.attributes[ATTR_METHOD_NAME] != None:
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_METHOD_NAME], escape(self.attributes[ATTR_METHOD_NAME]))
#         if self.attributes[ATTR_DESCRIPTOR] != None:
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_DESCRIPTOR], escape(self.attributes[ATTR_DESCRIPTOR]))
#         
#         
#         if self.attributes[ATTR_PERM_NAME] != None :
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_PERM_NAME], escape(self.attributes[ATTR_PERM_NAME]))
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_PERM_LEVEL], escape(self.attributes[ATTR_PERM_LEVEL]))
#             
#         if self.attributes[ATTR_DEXLOAD_FILENAME] != None:
#             buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_DEXLOAD_FILENAME], escape(self.attributes[ATTR_DEXLOAD_FILENAME])) 
#         
#         buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_REAL], str(self.attributes[ATTR_REAL]))
#         buff += "<attvalue id=\"%d\" value=\"%s\"/>\n" % (ID_ATTRIBUTES[ATTR_INTERNAL], str(self.attributes[ATTR_INTERNAL]))
        
        buff += "</attvalues>\n"

        return buff
    
    
    def set_attribute(self, name, value):
        if name not in self.attributes.keys():
            logger.debug("There is no [%name] key in the Node attributes!" % name)
        
        self.attributes[name] = value

# TODO: Check if we need this 
#     def add_risk(self, risk) :
#         if risk not in self.risks :
#             self.risks.append( risk )
# 
#     def add_api(self, perm, api) :
#         if perm not in self.api :
#             self.api[ perm ] = []
# 
#         if api not in self.api[ perm ] :
#             self.api[ perm ].append( api )

   
#     def set_attributes(self, values):
#         for i in values :
#             if i == "permissions" :
#                 self.attributes[ "permissions" ] += values[i]
#             elif i == "permissions_level" :
#                 if values[i] > self.attributes[ "permissions_level" ] :
#                     self.attributes[ "permissions_level" ] = PERMISSIONS_LEVEL[ values[i] ]
#                     self.attributes[ "permissions_level_name" ] = values[i]
#                     self.attributes[ "color" ] = COLOR_PERMISSIONS_LEVEL[ values[i] ]
#             elif i == "permissions_details" :
#                 self.attributes[ i ].add( values[i] )
#             else :
#                 self.attributes[ i ] = values[i]
    




class StadynaMcgAnalysis:
    def __init__(self):
        self.androGuardObjects = []
        
        self.nodes = {}
        self.nodes_id = {}
        self.entry_nodes = []
        self.G = DiGraph()
        
#         self.internal_methods = []
        #self.GI = DiGraph()
        
        
    def analyseFile(self, vmx, apk):
        vm = vmx.get_vm()
        self.androGuardObjects.append((apk, vm, vmx))

#         self.internal_methods.extend(vm.get_methods())
        
        #creating real internal nodes
        internal_called_methods = vmx.get_tainted_packages().stadyna_get_internal_called_methods()
        for method in internal_called_methods:
            class_name, method_name, descriptor = method
            
            nodeType = None
            if method_name == "<clinit>":
                nodeType = NODE_STATIC_INIT
            elif method_name == "<init>":
                nodeType = NODE_CONSTRUCTOR
            else:
                nodeType = NODE_METHOD
            n = self._get_node(nodeType, (class_name, method_name, descriptor))
            n.set_attribute(ATTR_CLASS_NAME, class_name)
            n.set_attribute(ATTR_METHOD_NAME, method_name)
            n.set_attribute(ATTR_DESCRIPTOR, descriptor)
            self.G.add_node(n.id)
            
        
        
        
        #creating real edges (nodes are already there)
        #currently we are working only with internal packages.
        for j in vmx.get_tainted_packages().get_internal_packages():
            src_class_name, src_method_name, src_descriptor = j.get_src(vm.get_class_manager())
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst(vm.get_class_manager())
             
            n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#             n1.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n1.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n1.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
             
            n2 = self._get_existed_node((dst_class_name, dst_method_name, dst_descriptor))
#             n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#             n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#             n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
            self.G.add_edge(n1.id, n2.id)
        
        
        
        #adding fake class nodes    
        for method in internal_called_methods:
            src_class_name, src_method_name, src_descriptor = method
            if src_method_name == "<init>" or src_method_name == "<clinit>":
                n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
                n2 = self._get_node(NODE_FAKE_CLASS, src_class_name, None, False)
                n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
                if src_method_name == "<clinit>":
                    self.G.add_edge(n1.id, n2.id)
                elif src_method_name == "<init>":
                    self.G.add_edge(n2.id, n1.id)
                
        
        #real (external) reflection invoke nodes    
        reflection_invoke_paths = analysis.seccon_get_invoke_method_paths(vmx)
        for j in reflection_invoke_paths:
            src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
            
            n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
            if n1 == None:
                logger.warning("Cannot find the node [%s], where reflection invoke is called!" % (src_class_name, src_method_name, src_descriptor))
                continue
            
            key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_REFL_INVOKE)
            n2 = self._get_node(NODE_REFL_INVOKE, key, LABEL_REFL_INVOKE, True)
            n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
            n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
            n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
            
            self.G.add_edge( n1.id, n2.id )
            
        
        #real (external) reflection new instance nodes   
        reflection_newInstance_paths = analysis.seccon_get_newInstance_method_paths(vmx)
        for j in reflection_newInstance_paths:
            src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
            
            n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
            if n1 == None:
                logger.warning("Cannot find the node [%s], where reflection new instance is called!" % (src_class_name, src_method_name, src_descriptor))
                continue
            
            key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_REFL_NEWINSTANCE)
            n2 = self._get_node(NODE_REFL_NEWINSTANCE, key, LABEL_REFL_NEWINSTANCE, True)
            n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
            n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
            n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
            
            self.G.add_edge( n1.id, n2.id )
        
        
        #adding fake entry points
        if apk != None:
            for i in apk.get_activities() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_existed_node((j, "onCreate", "(Landroid/os/Bundle;)V"))
                if n1 != None: 
                    key = "%s %s %s %s" % (j, "onCreate", "(Landroid/os/Bundle;)V", POSTFIX_ACTIVITY)
                    n2 = self._get_node(NODE_FAKE_ACTIVITY, key, LABEL_ACTIVITY, False)
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
                    
            for i in apk.get_services() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_existed_node( (j, "onCreate", "()V") )
                if n1 != None : 
                    key = "%s %s %s %s" % (j, "onCreate", "()V", POSTFIX_SERVICE)
                    n2 = self._get_node(NODE_FAKE_SERVICE, key, LABEL_SERVICE, False)
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            
            for i in apk.get_receivers() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_existed_node( (j, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V") )
                if n1 != None : 
                    key = "%s %s %s %s" % (j, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V", POSTFIX_RECEIVER)
                    n2 = self._get_node(NODE_FAKE_SERVICE, key, LABEL_RECEIVER, False)
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )

        
        #fake permissions
        list_permissions = vmx.stadyna_get_permissions([])
        for x in list_permissions:
            for j in list_permissions[x]:
                if isinstance(j, PathVar):
                    continue

                src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
                dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
                
                n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
                if n1 == None:
                    logger.warning("Cannot find node [%s %s %s] for permission [%s]!" % (src_class_name, src_method_name, src_descriptor, x))
                    continue
                
                #SOURCE, DEST, POSTFIX, PERMISSION_NAME
                key = "%s %s %s %s %s %s %s %s" %  (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, x)
                n2 = self._get_node(NODE_FAKE_PERMISSION, key, x, False)
                n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
                n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
                n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
                n2.set_attribute(ATTR_PERM_NAME, x)
                n2.set_attribute(ATTR_PERM_LEVEL, MANIFEST_PERMISSIONS[ x ][0])
                
                self.G.add_edge(n1.id, n2.id)
                                

        #fake DexClassLoader nodes
        dyn_code_loading = analysis.seccon_get_dyncode_loading_paths(vmx)
        for j in dyn_code_loading:
            src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
            
            n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
            if n1 == None:
                logger.warning("Cannot find dexload node [%s]!" % (src_class_name, src_method_name, src_descriptor))
                continue
            
            key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_DEXLOAD)
            n2 = self._get_node(NODE_FAKE_DEXLOAD, key, LABEL_DEXLOAD, False)
            n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
            n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
            n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
            
            self.G.add_edge( n1.id, n2.id )
        
        
        
        # Specific Java/Android library
        for c in vm.get_classes():
            #if c.get_superclassname() == "Landroid/app/Service;" :
            #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
            #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )

            #    self.G.add_edge( n1.id, n2.id )
            if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
                for i in vm.get_method("run") :
                    if i.get_class_name() == c.get_name() :
                        n1 = self._get_node(NODE_METHOD, (i.get_class_name(), i.get_name(), i.get_descriptor()))
                        n2 = self._get_node(NODE_METHOD, (i.get_class_name(), "start", i.get_descriptor())) 
                       
                        # link from start to run
                        self.G.add_edge( n2.id, n1.id )
                        #n2.add_edge( n1, {} )

                        # link from init to start
                        for init in vm.get_method("<init>") :
                            if init.get_class_name() == c.get_name():
                                #TODO: Leaving _get_existed_node to check if all the nodes are included
                                #It is possible that internal_packages does not contain this node. Leaving _get_existed_node to check this
                                n3 = self._get_node(NODE_CONSTRUCTOR, (init.get_class_name(), "<init>", init.get_descriptor()))
                                self.G.add_edge( n3.id, n2.id )
                                #n3.add_edge( n2, {} )
        
                        
                        
    def addInvokePath(self, src, through, dst):
        src_class_name, src_method_name, src_descriptor = src
        dst_class_name, dst_method_name, dst_descriptor = dst
        through_class_name, through_method_name, through_descriptor = through
        key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, through_class_name, through_method_name, through_descriptor, POSTFIX_REFL_INVOKE)
        n1 = self._get_existed_node(key)
        if n1 == None:
            logger.warning("Something wrong has happened! Could not find invoke Node in Graph with key [%s]" % str(key))
            return
        
        n2 = self._get_node(NODE_METHOD, (dst_class_name, dst_method_name, dst_descriptor))
        n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
        n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
        n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
        
        self.G.add_edge(n1.id, n2.id)
        
        #check if called method calls protected feature
        data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
        if data in DVM_PERMISSIONS_BY_API_CALLS:
            logger.info("BINGOOOOOOO! The protected method is called through reflection!")
            perm = DVM_PERMISSIONS_BY_API_CALLS[ data ]
            key1 = "%s %s %s %s %s %s %s %s" %  (through_class_name, through_method_name, through_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, perm)
            n3 = self._get_node(NODE_FAKE_PERMISSION, key1, perm, False)
            n3.set_attribute(ATTR_CLASS_NAME, dst_class_name)
            n3.set_attribute(ATTR_METHOD_NAME, dst_method_name)
            n3.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
            n3.set_attribute(ATTR_PERM_NAME, perm)
            n3.set_attribute(ATTR_PERM_LEVEL, MANIFEST_PERMISSIONS[ perm ][0])
            self.G.add_edge(n2.id, n3.id)
            

        
            
    def addNewInstancePath(self, src, through, dst):
        src_class_name, src_method_name, src_descriptor = src
        dst_class_name, dst_method_name, dst_descriptor = dst
        through_class_name, through_method_name, through_descriptor = through
        key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, through_class_name, through_method_name, through_descriptor, POSTFIX_REFL_NEWINSTANCE)
        n1 = self._get_existed_node(key)
        if n1 == None:
            logger.error("Something wrong has happened! Could not find Node in Graph with key [%s]" % str(key))
            return
        
        n2 = self._get_node(NODE_CONSTRUCTOR, (dst_class_name, dst_method_name, dst_descriptor))
        n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
        n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
        n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor) 
        
        self.G.add_edge(n1.id, n2.id)
        
        #we also need to add link to the class node
        #TODO: Think in the future what to do with this
        n_class = self._get_node(NODE_FAKE_CLASS, dst_class_name, None, False)
        n_class.set_attribute(ATTR_CLASS_NAME, dst_class_name)
        self.G.add_edge(n_class.id, n2.id)
        
        #checking if we need to add additional permission nodes
        data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
        if data in DVM_PERMISSIONS_BY_API_CALLS:
            logger.info("BINGOOOOOOO! The protected method is called through reflection!")
            perm = DVM_PERMISSIONS_BY_API_CALLS[ data ]
            key1 = "%s %s %s %s %s %s %s %s" %  (through_class_name, through_method_name, through_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, perm)
            n3 = self._get_node(NODE_FAKE_PERMISSION, key1, perm, False)
            n3.set_attribute(ATTR_CLASS_NAME, dst_class_name)
            n3.set_attribute(ATTR_METHOD_NAME, dst_method_name)
            n3.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
            n3.set_attribute(ATTR_PERM_NAME, perm)
            n3.set_attribute(ATTR_PERM_LEVEL, MANIFEST_PERMISSIONS[ perm ][0])
            self.G.add_edge(n2.id, n3.id)
        
            
    def addDexloadPath(self, src, through, filename):
        src_class_name, src_method_name, src_descriptor = src
        through_class_name, through_method_name, through_descriptor = through
        key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor,  through_class_name, through_method_name, through_descriptor, POSTFIX_DEXLOAD)
        n1 = self._get_existed_node(key)
        if n1 == None:
            logger.error("Something wrong has happened! Could not find Node in Graph with key [%s]" % str(key))
            return
        
        n2 = self._get_node(NODE_FAKE_DEXLOAD_FILE, filename, filename, False)
        n2.set_attribute(ATTR_DEXLOAD_FILENAME, filename)
        
        self.G.add_edge(n1.id, n2.id)
        
    

    def _get_node(self, nType, key, label=None, real=True):
        node_key = None
        if isinstance(key, basestring):
            node_key = key
        elif isinstance(key, tuple):
            node_key = "%s %s %s" % key
        else:
            logger.error("Unknown instance type of key!!!")
        
        if node_key not in self.nodes.keys():
            new_node = NodeS(len(self.nodes), nType, node_key, label, real)
            self.nodes[node_key] = new_node
            self.nodes_id[new_node.id] = new_node
        
        return self.nodes[node_key]
    
    
    def _get_existed_node(self, key):
        node_key = None
        if isinstance(key, basestring):
            node_key = key
        elif isinstance(key, tuple):
            node_key = "%s %s %s" % key
        else:
            logger.error("Unknown instance type of key!!!")
        
        try:
            return self.nodes[node_key]
        except KeyError:
            logger.error("Could not find existed node [%s]!" % node_key)
            return None

    def export_to_gexf(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        buff += "<gexf xmlns=\"http://www.gephi.org/gexf\" xmlns:viz=\"http://www.gephi.org/gexf/viz\">\n"
        buff += "<graph type=\"static\">\n"

        buff += "<attributes class=\"node\" type=\"static\">\n"
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_TYPE,              ID_ATTRIBUTES[ ATTR_TYPE ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_CLASS_NAME,        ID_ATTRIBUTES[ ATTR_CLASS_NAME ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_METHOD_NAME,       ID_ATTRIBUTES[ ATTR_METHOD_NAME ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_DESCRIPTOR,        ID_ATTRIBUTES[ ATTR_DESCRIPTOR ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_REAL,              ID_ATTRIBUTES[ ATTR_REAL ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_PERM_NAME,         ID_ATTRIBUTES[ ATTR_PERM_NAME ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_PERM_LEVEL,        ID_ATTRIBUTES[ ATTR_PERM_LEVEL ])
        buff += "<attribute title=\"%s\" id=\"%d\" type=\"string\"/>\n" % (ATTR_DEXLOAD_FILENAME,  ID_ATTRIBUTES[ ATTR_DEXLOAD_FILENAME ])
        buff += "</attributes>\n"

#         buff += "<attributes class=\"node\" type=\"static\">\n" 
#         buff += "<attribute id=\"%d\" title=\"type\" type=\"string\" default=\"normal\"/>\n" % ID_ATTRIBUTES[ "type"]
#         buff += "<attribute id=\"%d\" title=\"class_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "class_name"]
#         buff += "<attribute id=\"%d\" title=\"method_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "method_name"]
#         buff += "<attribute id=\"%d\" title=\"descriptor\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "descriptor"]
# 
# 
#         buff += "<attribute id=\"%d\" title=\"permissions\" type=\"integer\" default=\"0\"/>\n" % ID_ATTRIBUTES[ "permissions"]
#         buff += "<attribute id=\"%d\" title=\"permissions_level\" type=\"string\" default=\"normal\"/>\n" % ID_ATTRIBUTES[ "permissions_level"]
#         
#         buff += "<attribute id=\"%d\" title=\"dynamic_code\" type=\"boolean\" default=\"false\"/>\n" % ID_ATTRIBUTES[ "dynamic_code"]
#         
#         buff += "</attributes>\n"   

        buff += "<nodes>\n"
        for node in self.G.nodes() :
            buff += "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label))
            buff += self.nodes_id[ node ].get_attributes_gexf()
            buff += "</node>\n"
        buff += "</nodes>\n"


        buff += "<edges>\n"
        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1
        buff += "</edges>\n"


        buff += "</graph>\n"
        buff += "</gexf>\n"

        return buff
  
    
    def get_current_real_node_count(self):
        count = 0
        for node in self.nodes_id.keys():
            if self.nodes_id[node].get_attribute(ATTR_REAL) == "True":
                count += 1
        return count

    def get_current_node_count(self):
        return len(self.G.nodes())
    
    def get_current_edge_count(self):
        return len(self.G.edges())
    
    def get_current_permission_level_node_count(self, permission_level):
        count = 0
        for node in self.nodes_id.keys():
            if self.nodes_id[node].get_attribute(ATTR_PERM_LEVEL) == permission_level:
                count += 1
        return count
    
    def get_current_protected_node_count(self):
        count = 0
        for node in self.nodes_id.keys():
            if self.nodes_id[node].get_attribute(ATTR_PERM_LEVEL) != None:
                count += 1
        return count
    
    
    
#     def analyseFile(self, vmx, apk):
#         vm = vmx.get_vm()
#         self.androGuardObjects.append((apk, vm, vmx))
# 
#         self.internal_methods.extend(vm.get_methods())
#         
#         #creating real internal nodes
#         internal_called_methods = vmx.get_tainted_packages().stadyna_get_internal_called_methods()
#         for method in internal_called_methods:
#             src_class_name, src_method_name, src_descriptor = method
#             
#             srcNodeType = None
#             if src_method_name == "<clinit>":
#                 srcNodeType = NODE_STATIC_INIT
#             elif src_method_name == "<init>":
#                 srcNodeType = NODE_CONSTRUCTOR
#             else:
#                 srcNodeType = NODE_METHOD
#             n = self._get_node(srcNodeType, (src_class_name, src_method_name, src_descriptor))
#             n.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#             self.G.add_node(n.id)
#             
#         
#         
#         
#         #creating real edges (nodes are already there)
#         #currently we are working only with internal packages.
#         for j in vmx.get_tainted_packages().get_internal_packages():
#             src_class_name, src_method_name, src_descriptor = j.get_src(vm.get_class_manager())
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst(vm.get_class_manager())
#              
#             n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#             n1.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n1.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n1.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#              
#             n2 = self._get_existed_node((dst_class_name, dst_method_name, dst_descriptor))
#             n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#             self.G.add_edge(n1.id, n2.id)
#         
#         
#         
#         #adding fake class nodes    
#         for method in internal_called_methods:
#             src_class_name, src_method_name, src_descriptor = method
#             if src_method_name == "<init>" or src_method_name == "<clinit>":
#                 n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#                 n2 = self._get_node(NODE_FAKE_CLASS, src_class_name, None, False)
#                 n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
#                 if src_method_name == "<clinit>":
#                     self.G.add_edge(n1.id, n2.id)
#                 elif src_method_name == "<init>":
#                     self.G.add_edge(n2.id, n1.id)
#                 
#         
#         
# #         #creating real nodes
# #         for j in vmx.get_tainted_packages().get_internal_packages():
# #             src_class_name, src_method_name, src_descriptor = j.get_src(vm.get_class_manager())
# #             dst_class_name, dst_method_name, dst_descriptor = j.get_dst(vm.get_class_manager())
# #             
# #             n1 = None
# #             n2 = None
# #             
# #             srcNodeType = None
# #             if src_method_name == "<clinit>":
# #                 srcNodeType = NODE_STATIC_INIT
# #             elif src_method_name == "<init>":
# #                 srcNodeType = NODE_CONSTRUCTOR
# #             else:
# #                 srcNodeType = NODE_METHOD
# #             n1 = self._get_node(srcNodeType, (src_class_name, src_method_name, src_descriptor))
# #             n1.set_attribute(ATTR_CLASS_NAME, src_class_name)
# #             n1.set_attribute(ATTR_METHOD_NAME, src_method_name)
# #             n1.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
# #             
# #             dstNodeType = None
# #             if dst_method_name == "<clinit>":
# #                 dstNodeType = NODE_STATIC_INIT
# #             elif dst_method_name == "<init>":
# #                 dstNodeType = NODE_CONSTRUCTOR
# #             else:
# #                 dstNodeType = NODE_METHOD    
# #             n2 = self._get_node(dstNodeType, (dst_class_name, dst_method_name, dst_descriptor))
# #             n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
# #             n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
# #             n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
# #             
# #             self.G.add_edge(n1.id, n2.id)
# #             #n1.add_edge(n2, j)
#         
#         
# #         #adding fake class nodes
# #         #the nodes are already exist thus we can just get existed nodes
# #         for j in vmx.get_tainted_packages().get_internal_packages():
# #             src_class_name, src_method_name, src_descriptor = j.get_src(vm.get_class_manager())
# #             dst_class_name, dst_method_name, dst_descriptor = j.get_dst(vm.get_class_manager())
# #             
# #             n1 = None
# #             n2 = None 
# #             
# #             if src_method_name == "<init>" or dst_method_name == "<init>":
# #                 if src_method_name == "<init>":
# #                     n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
# #                     n2 = self._get_node(NODE_FAKE_CLASS, src_class_name, None, False)
# #                     n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
# #                 else:
# #                     n1 = self._get_existed_node((dst_class_name, dst_method_name, dst_descriptor))
# #                     n2 = self._get_node(NODE_FAKE_CLASS, dst_class_name, None, False)
# #                     n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
# #                 
# #                 #we adding edge from the class node to constructor 
# #                 self.G.add_edge(n2.id, n1.id)
# #             elif src_method_name == "<clinit>" or dst_method_name == "<clinit>":
# #                 if src_method_name == "<clinit>":
# #                     n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
# #                     n2 = self._get_node(NODE_FAKE_CLASS, src_class_name, None, False)
# #                     n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
# #                 else:
# #                     n1 = self._get_existed_node((dst_class_name, dst_method_name, dst_descriptor))
# #                     n2 = self._get_node(NODE_FAKE_CLASS, dst_class_name, None, False)
# #                     n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
# #                 
# #                 #we adding edge from static initializer to the class node
# #                 self.G.add_edge(n1.id, n2.id)
#         
#         
#         #adding fake entry points
#         if apk != None:
#             for i in apk.get_activities() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_existed_node((j, "onCreate", "(Landroid/os/Bundle;)V"))
#                 if n1 != None: 
#                     key = "%s %s %s %s" % (j, "onCreate", "(Landroid/os/Bundle;)V", POSTFIX_ACTIVITY)
#                     n2 = self._get_node(NODE_FAKE_ACTIVITY, key, "ACTIVITY", False)
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
#                     
#             for i in apk.get_services() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_existed_node( (j, "onCreate", "()V") )
#                 if n1 != None : 
#                     key = "%s %s %s %s" % (j, "onCreate", "()V", POSTFIX_SERVICE)
#                     n2 = self._get_node(NODE_FAKE_SERVICE, key, "SERVICE", False)
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
#             
#             for i in apk.get_receivers() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_existed_node( (j, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V") )
#                 if n1 != None : 
#                     key = "%s %s %s %s" % (j, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V", POSTFIX_RECEIVER)
#                     n2 = self._get_node(NODE_FAKE_SERVICE, key, "RECEIVER", False)
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
# 
#         
#         #fake permissions
#         list_permissions = vmx.get_permissions([])
#         for x in list_permissions:
#             for j in list_permissions[x]:
#                 if isinstance(j, PathVar):
#                     continue
# 
#                 src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
#                 dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
#                 
#                 n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#                 if n1 == None:
#                     logger.warning("Cannot find node [%s %s %s] for permission [%s]!" % (src_class_name, src_method_name, src_descriptor, x))
#                     continue
#                 
#                 #SOURCE, DEST, POSTFIX, PERMISSION_NAME
#                 key = "%s %s %s %s %s %s %s %s" %  (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, x)
#                 n2 = self._get_node(NODE_FAKE_PERMISSION, key, x, False)
#                 n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#                 n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#                 n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
#                 n2.set_attribute(ATTR_PERM_NAME, x)
#                 n2.set_attribute(ATTR_PERM_LEVEL, DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ x ][0])
#                 
#                 self.G.add_edge(n1.id, n2.id)
#                                 
# 
#         #fake DexClassLoader nodes
#         dyn_code_loading = analysis.seccon_get_dyncode_loading_paths(vmx)
#         for j in dyn_code_loading:
#             src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
#             
#             n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#             if n1 == None:
#                 logger.warning("Cannot find dexload node [%s]!" % (src_class_name, src_method_name, src_descriptor))
#                 continue
#             
#             key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_DEXLOAD)
#             n2 = self._get_node(NODE_FAKE_DEXLOAD, key, "DYNAMIC CODE LOADING", False)
#             n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#             
#             self.G.add_edge( n1.id, n2.id )
#         
#         
#         #fake reflection invoke nodes    
#         reflection_invoke_paths = analysis.seccon_get_invoke_method_paths(vmx)
#         for j in reflection_invoke_paths:
#             src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
#             
#             n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#             if n1 == None:
#                 logger.warning("Cannot find reflection invoke node [%s]!" % (src_class_name, src_method_name, src_descriptor))
#                 continue
#             
#             key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_REFL_INVOKE)
#             n2 = self._get_node(NODE_REFL_INVOKE, key, "REFLECTION INVOKE", False)
#             n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#             
#             self.G.add_edge( n1.id, n2.id )
#             
#         
#         #fake reflection new instance nodes   
#         reflection_newInstance_paths = analysis.seccon_get_newInstance_method_paths(vmx)
#         for j in reflection_newInstance_paths:
#             src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
#             
#             n1 = self._get_existed_node((src_class_name, src_method_name, src_descriptor))
#             if n1 == None:
#                 logger.warning("Cannot find reflection new instance node [%s]!" % (src_class_name, src_method_name, src_descriptor))
#                 continue
#             
#             key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_REFL_NEWINSTANCE)
#             n2 = self._get_node(NODE_REFL_NEWINSTANCE, key, "REFLECTION NEW INSTANCE", False)
#             n2.set_attribute(ATTR_CLASS_NAME, src_class_name)
#             n2.set_attribute(ATTR_METHOD_NAME, src_method_name)
#             n2.set_attribute(ATTR_DESCRIPTOR, src_descriptor)
#             
#             self.G.add_edge( n1.id, n2.id )
#             
#         
#         
#         # Specific Java/Android library
#         for c in vm.get_classes():
#             #if c.get_superclassname() == "Landroid/app/Service;" :
#             #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
#             #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )
# 
#             #    self.G.add_edge( n1.id, n2.id )
#             if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
#                 for i in vm.get_method("run") :
#                     if i.get_class_name() == c.get_name() :
#                         n1 = self._get_node(NODE_METHOD, (i.get_class_name(), i.get_name(), i.get_descriptor()))
#                         n2 = self._get_node(NODE_METHOD, (i.get_class_name(), "start", i.get_descriptor())) 
#                        
#                         # link from start to run
#                         self.G.add_edge( n2.id, n1.id )
#                         #n2.add_edge( n1, {} )
# 
#                         # link from init to start
#                         for init in vm.get_method("<init>") :
#                             if init.get_class_name() == c.get_name():
#                                 #TODO: Leaving _get_existed_node to check if all the nodes are included
#                                 #It is possible that internal_packages does not contain this node. Leaving _get_existed_node to check this
#                                 n3 = self._get_node(NODE_CONSTRUCTOR, (init.get_class_name(), "<init>", init.get_descriptor()))
#                                 self.G.add_edge( n3.id, n2.id )
#                                 #n3.add_edge( n2, {} )
#         
#                         
#                         
#     def addInvokePath(self, src, through, dst):
#         src_class_name, src_method_name, src_descriptor = src
#         dst_class_name, dst_method_name, dst_descriptor = dst
#         through_class_name, through_method_name, through_descriptor = through
#         key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor,  through_class_name, through_method_name, through_descriptor, POSTFIX_REFL_INVOKE)
#         n1 = self._get_existed_node(key)
#         if n1 == None:
#             logger.warning("Something wrong has happened! Could not find invoke Node in Graph with key [%s]" % str(key))
#             return
#         n2 = self._get_node(NODE_METHOD, (dst_class_name, dst_method_name, dst_descriptor))
#         n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#         n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#         n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
#         
#         self.G.add_edge(n1.id, n2.id)
#         
#         #check if called method calls protected feature
#         data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
#         if data in DVM_PERMISSIONS_BY_ELEMENT:
#             logger.info("BINGOOOOOOO! The protected method is called through reflection!")
#             perm = DVM_PERMISSIONS_BY_ELEMENT[ data ]
#             key1 = "%s %s %s %s %s %s %s %s" %  (through_class_name, through_method_name, through_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, perm)
#             n3 = self._get_node(NODE_FAKE_PERMISSION, key1, perm, False)
#             n3.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#             n3.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#             n3.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
#             n3.set_attribute(ATTR_PERM_NAME, perm)
#             n3.set_attribute(ATTR_PERM_LEVEL, DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ perm ][0])
#             self.G.add_edge(n2.id, n3.id)
#             
# 
#         
#             
#     def addNewInstancePath(self, src, through, dst):
#         src_class_name, src_method_name, src_descriptor = src
#         dst_class_name, dst_method_name, dst_descriptor = dst
#         through_class_name, through_method_name, through_descriptor = through
#         key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor,  through_class_name, through_method_name, through_descriptor, POSTFIX_REFL_NEWINSTANCE)
#         n1 = self._get_existed_node(key)
#         if n1 == None:
#             logger.error("Something wrong has happened! Could not find Node in Graph with key [%s]" % str(key))
#             return
#         n2 = self._get_node(NODE_CONSTRUCTOR, (dst_class_name, dst_method_name, dst_descriptor))
#         n2.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#         n2.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#         n2.set_attribute(ATTR_DESCRIPTOR, dst_descriptor) 
#         
#         self.G.add_edge(n1.id, n2.id)
#         
#         #we also need to add link to the class node
#         n_class = self._get_node(NODE_FAKE_CLASS, dst_class_name, None, False)
#         n_class.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#         self.G.add_edge(n_class.id, n2.id)
#         
#         #checking if we need to add additional permission nodes
#         data = "%s-%s-%s" % (dst_class_name, dst_method_name, dst_descriptor)
#         if data in DVM_PERMISSIONS_BY_ELEMENT:
#             logger.info("BINGOOOOOOO! The protected method is called through reflection!")
#             perm = DVM_PERMISSIONS_BY_ELEMENT[ data ]
#             key1 = "%s %s %s %s %s %s %s %s" %  (through_class_name, through_method_name, through_descriptor, dst_class_name, dst_method_name, dst_descriptor, POSTFIX_PERM, perm)
#             n3 = self._get_node(NODE_FAKE_PERMISSION, key1, perm, False)
#             n3.set_attribute(ATTR_CLASS_NAME, dst_class_name)
#             n3.set_attribute(ATTR_METHOD_NAME, dst_method_name)
#             n3.set_attribute(ATTR_DESCRIPTOR, dst_descriptor)
#             n3.set_attribute(ATTR_PERM_NAME, perm)
#             n3.set_attribute(ATTR_PERM_LEVEL, DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ perm ][0])
#             self.G.add_edge(n2.id, n3.id)
#         
#             
#     def addDexloadPath(self, src, through, filename):
#         src_class_name, src_method_name, src_descriptor = src
#         through_class_name, through_method_name, through_descriptor = through
#         key = "%s %s %s %s %s %s %s" % (src_class_name, src_method_name, src_descriptor,  through_class_name, through_method_name, through_descriptor, POSTFIX_DEXLOAD)
#         n1 = self._get_existed_node(key)
#         if n1 == None:
#             logger.error("Something wrong has happened! Could not find Node in Graph with key [%s]" % str(key))
#             return
#         
#         n2 = self._get_node(NODE_FAKE_DEXLOAD_FILE, filename, filename, False)
#         n2.set_attribute(ATTR_DEXLOAD_FILENAME, filename)
#         
#         self.G.add_edge(n1.id, n2.id)
