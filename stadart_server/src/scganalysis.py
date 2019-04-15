from xml.sax.saxutils import escape

from androguard.core.analysis.ganalysis import DiGraph, NodeF
from androguard.core import bytecode
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS
from androguard.core.analysis.risk import PERMISSIONS_RISK, INTERNET_RISK, PRIVACY_RISK, PHONE_RISK, SMS_RISK, MONEY_RISK
from androguard.core.analysis.analysis import PathVar, TAINTED_PACKAGE_CREATE


DEFAULT_RISKS = {
    INTERNET_RISK : ( "INTERNET_RISK", (195, 255, 0) ),
    PRIVACY_RISK : ( "PRIVACY_RISK", (255, 255, 51) ),
    PHONE_RISK : ( "PHONE_RISK", ( 255, 216, 0 ) ),
    SMS_RISK : ( "SMS_RISK", ( 255, 93, 0 ) ),
    MONEY_RISK : ( "MONEY_RISK", ( 255, 0, 0 ) ),
}

DEXCLASSLOADER_COLOR = (0, 0, 0)
ACTIVITY_COLOR = (51, 255, 51)
SERVICE_COLOR = (0, 204, 204)
RECEIVER_COLOR = (204, 51, 204)

STADYNA_DEXCLASSLOADER_COLOR = (255, 0, 0)

ID_ATTRIBUTES = {
    "type" : 0,
    "class_name" : 1,
    "method_name" : 2,
    "descriptor" : 3,
    "permissions" : 4,
    "permissions_level" : 5,
    "dynamic_code" : 6,
}


class ScGVMAnalysis:
    def __init__(self):
        #initialization of the algorithm
        self.nodes = {}
        self.nodes_id = {}
        self.entry_nodes = []
        self.G = DiGraph()
        #self.GI = DiGraph()
        
        
    def analyseFile(self, vmx, apk):
        vm = vmx.get_vm()

        
        for j in vmx.get_tainted_packages().get_internal_packages():
            src_class_name, src_method_name, src_descriptor = j.get_src(vm.get_class_manager())
            dst_class_name, dst_method_name, dst_descriptor = j.get_dst(vm.get_class_manager())
 
            n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
            n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
 
            self.G.add_edge(n1.id, n2.id)
            n1.add_edge(n2, j)
        
        #begin SECCON
#        internal_packages = self.vmx.get_tainted_packages().get_internal_packages()
#        print "INTERNAL PACKAGES:"
#        for j in self.vmx.get_tainted_packages().get_internal_packages():
#            src_class_name, src_method_name, src_descriptor = j.get_src(self.vm.get_class_manager())
#            dst_class_name, dst_method_name, dst_descriptor = j.get_dst(self.vm.get_class_manager())
#            print "SRC: [%s   %s   %s]" % (src_class_name, src_method_name, src_descriptor)
#            print "DST: [%s   %s   %s]" % (dst_class_name, dst_method_name, dst_descriptor)
#        print "EXTERNAL PACKAGES:"
#         for j in self.vmx.get_tainted_packages().get_external_packages():
#             src_class_name, src_method_name, src_descriptor = j.get_src(self.vm.get_class_manager())
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst(self.vm.get_class_manager())
# #             print "SRC: [%s   %s   %s]" % (src_class_name, src_method_name, src_descriptor)
# #             print "DST: [%s   %s   %s]" % (dst_class_name, dst_method_name, dst_descriptor)
#              
#             n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
#             n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
#             self.G.add_edge(n1.id, n2.id)
#             n1.add_edge(n2, j)
            

            
#            if (j not in internal_packages) and (j not in LOADED_API):
#                n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
#                n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
#                self.G.add_edge(n1.id, n2.id)
#                n1.add_edge(n2, j)

            
        #end SECCON

        #new objects
        internal_new_packages = vmx.get_tainted_packages().get_internal_new_packages()
        for j in internal_new_packages:
            for path in internal_new_packages[j]:
                src_class_name, src_method_name, src_descriptor = path.get_src(vm.get_class_manager())

                n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
                n2 = self._get_node(j, "", "")
                #self.GI.add_edge(n2.id, n1.id)
                n1.add_edge(n2, path)

        if apk != None:
            for i in apk.get_activities() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "(Landroid/os/Bundle;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "activity" } )
                    n1.set_attributes( { "color" : ACTIVITY_COLOR } )
                    n2 = self._get_new_node_from( n1, "ACTIVITY" )
                    n2.set_attributes( { "color" : ACTIVITY_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_services() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onCreate", "()V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "service" } )
                    n1.set_attributes( { "color" : SERVICE_COLOR } )
                    n2 = self._get_new_node_from( n1, "SERVICE" )
                    n2.set_attributes( { "color" : SERVICE_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )
            for i in apk.get_receivers() :
                j = bytecode.FormatClassToJava(i)
                n1 = self._get_exist_node( j, "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V" )
                if n1 != None : 
                    n1.set_attributes( { "type" : "receiver" } )
                    n1.set_attributes( { "color" : RECEIVER_COLOR } )
                    n2 = self._get_new_node_from( n1, "RECEIVER" )
                    n2.set_attributes( { "color" : RECEIVER_COLOR } )
                    self.G.add_edge( n2.id, n1.id )
                    self.entry_nodes.append( n1.id )

        # Specific Java/Android library
        for c in vm.get_classes():
            #if c.get_superclassname() == "Landroid/app/Service;" :
            #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
            #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )

            #    self.G.add_edge( n1.id, n2.id )
            if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
                for i in vm.get_method("run") :
                    if i.get_class_name() == c.get_name() :
                        n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
                        n2 = self._get_node( i.get_class_name(), "start", i.get_descriptor() ) 
                       
                        # link from start to run
                        self.G.add_edge( n2.id, n1.id )
                        n2.add_edge( n1, {} )

                        # link from init to start
                        for init in vm.get_method("<init>") :
                            if init.get_class_name() == c.get_name() :
                                n3 = self._get_node( init.get_class_name(), "<init>", init.get_descriptor() )
                                #n3 = self._get_node( i.get_class_name(), "<init>", i.get_descriptor() )
                                self.G.add_edge( n3.id, n2.id )
                                n3.add_edge( n2, {} )

            #elif c.get_superclassname() == "Landroid/os/AsyncTask;" :
            #    for i in vm.get_method("doInBackground") :
            #        if i.get_class_name() == c.get_name() :
            #            n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
            #            n2 = self._get_exist_node( i.get_class_name(), "execute", i.get_descriptor() )
            #            print n1, n2, i.get_descriptor()
                        #for j in vm.get_method("doInBackground") :
                        #    n2 = self._get_exist_node( i.get_class_name(), j.get_name(), j.get_descriptor() )
                        #    print n1, n2
                        # n2 = self._get_node( i.get_class_name(), "
            #    raise("ooo")

        #for j in vmx.tainted_packages.get_internal_new_packages() :
        #    print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
        #                                            j.get_bb().start + j.get_idx(), \
        #                                            j.get_class_name(), j.get_name(), j.get_descriptor())

        list_permissions = vmx.get_permissions([])
        for x in list_permissions:
            for j in list_permissions[x]:
                if isinstance(j, PathVar):
                    continue

                src_class_name, src_method_name, src_descriptor = j.get_src( vm.get_class_manager() )
                dst_class_name, dst_method_name, dst_descriptor = j.get_dst( vm.get_class_manager() )
                n1 = self._get_exist_node( dst_class_name, dst_method_name, dst_descriptor )

                if n1 == None :
                    continue

                n1.set_attributes( { "permissions" : 1 } )
                n1.set_attributes( { "permissions_level" : DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ x ][0] } )
                n1.set_attributes( { "permissions_details" : x } )

                try :
                    for tmp_perm in PERMISSIONS_RISK[ x ] :
                        if tmp_perm in DEFAULT_RISKS :
                            n2 = self._get_new_node( dst_class_name,
                                                     dst_method_name,
                                                     dst_descriptor + " " + DEFAULT_RISKS[ tmp_perm ][0],
                                                     DEFAULT_RISKS[ tmp_perm ][0] )
                            n2.set_attributes( { "color" : DEFAULT_RISKS[ tmp_perm ][1] } )
                            self.G.add_edge( n2.id, n1.id )

                            n1.add_risk( DEFAULT_RISKS[ tmp_perm ][0] )
                            n1.add_api( x, src_class_name + "-" + src_method_name + "-" + src_descriptor )
                except KeyError :
                    pass

        # Tag DexClassLoader
        for m, _ in vmx.get_tainted_packages().get_packages() :
            if m.get_name() == "Ldalvik/system/DexClassLoader;" :
                for path in m.get_paths() :
                    if path.get_access_flag() == TAINTED_PACKAGE_CREATE :
                        src_class_name, src_method_name, src_descriptor = path.get_src(vm.get_class_manager())
                        n1 = self._get_exist_node( src_class_name, src_method_name, src_descriptor )
                        n2 = self._get_new_node( dst_class_name, dst_method_name, dst_descriptor + " " + "DEXCLASSLOADER",
                                                 "DEXCLASSLOADER" )

                        n1.set_attributes( { "dynamic_code" : "true" } )
                        n2.set_attributes( { "color" : DEXCLASSLOADER_COLOR } )
                        self.G.add_edge( n2.id, n1.id )

                        n1.add_risk( "DEXCLASSLOADER" )
    
#     def __init__(self, vmx, apk):
#         self.vmx = vmx
#         self.vm = self.vmx.get_vm()
# 
#         self.nodes = {}
#         self.nodes_id = {}
#         self.entry_nodes = []
#         self.G = DiGraph()
#         self.GI = DiGraph()
# 
#         
#         for j in self.vmx.get_tainted_packages().get_internal_packages():
#             src_class_name, src_method_name, src_descriptor = j.get_src(self.vm.get_class_manager())
#             dst_class_name, dst_method_name, dst_descriptor = j.get_dst(self.vm.get_class_manager())
# 
#             n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
#             n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
# 
#             self.G.add_edge(n1.id, n2.id)
#             n1.add_edge(n2, j)
#         
#         #begin SECCON
# #        internal_packages = self.vmx.get_tainted_packages().get_internal_packages()
# #        print "INTERNAL PACKAGES:"
# #        for j in self.vmx.get_tainted_packages().get_internal_packages():
# #            src_class_name, src_method_name, src_descriptor = j.get_src(self.vm.get_class_manager())
# #            dst_class_name, dst_method_name, dst_descriptor = j.get_dst(self.vm.get_class_manager())
# #            print "SRC: [%s   %s   %s]" % (src_class_name, src_method_name, src_descriptor)
# #            print "DST: [%s   %s   %s]" % (dst_class_name, dst_method_name, dst_descriptor)
# #        print "EXTERNAL PACKAGES:"
# #        for j in self.vmx.get_tainted_packages().get_external_packages():
# #            src_class_name, src_method_name, src_descriptor = j.get_src(self.vm.get_class_manager())
# #            dst_class_name, dst_method_name, dst_descriptor = j.get_dst(self.vm.get_class_manager())
# #            print "SRC: [%s   %s   %s]" % (src_class_name, src_method_name, src_descriptor)
# #            print "DST: [%s   %s   %s]" % (dst_class_name, dst_method_name, dst_descriptor)
#             
# #            n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
# #            n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
# #            self.G.add_edge(n1.id, n2.id)
# #            n1.add_edge(n2, j)
#             
# 
#             
# #            if (j not in internal_packages) and (j not in LOADED_API):
# #                n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
# #                n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
# #                self.G.add_edge(n1.id, n2.id)
# #                n1.add_edge(n2, j)
# 
#             
#         #end SECCON
# 
#         #this is something strange
#         internal_new_packages = self.vmx.get_tainted_packages().get_internal_new_packages()
#         for j in internal_new_packages:
#             for path in internal_new_packages[j]:
#                 src_class_name, src_method_name, src_descriptor = path.get_src(self.vm.get_class_manager())
# 
#                 n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
#                 n2 = self._get_node(j, "", "")
#                 self.GI.add_edge(n2.id, n1.id)
#                 n1.add_edge(n2, path)
# 
#         if apk != None:
#             for i in apk.get_activities() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_exist_node( j, "onCreate", "(Landroid/os/Bundle;)V" )
#                 if n1 != None : 
#                     n1.set_attributes( { "type" : "activity" } )
#                     n1.set_attributes( { "color" : ACTIVITY_COLOR } )
#                     n2 = self._get_new_node_from( n1, "ACTIVITY" )
#                     n2.set_attributes( { "color" : ACTIVITY_COLOR } )
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
#             for i in apk.get_services() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_exist_node( j, "onCreate", "()V" )
#                 if n1 != None : 
#                     n1.set_attributes( { "type" : "service" } )
#                     n1.set_attributes( { "color" : SERVICE_COLOR } )
#                     n2 = self._get_new_node_from( n1, "SERVICE" )
#                     n2.set_attributes( { "color" : SERVICE_COLOR } )
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
#             for i in apk.get_receivers() :
#                 j = bytecode.FormatClassToJava(i)
#                 n1 = self._get_exist_node( j, "onReceive", "(Landroid/content/Context; Landroid/content/Intent;)V" )
#                 if n1 != None : 
#                     n1.set_attributes( { "type" : "receiver" } )
#                     n1.set_attributes( { "color" : RECEIVER_COLOR } )
#                     n2 = self._get_new_node_from( n1, "RECEIVER" )
#                     n2.set_attributes( { "color" : RECEIVER_COLOR } )
#                     self.G.add_edge( n2.id, n1.id )
#                     self.entry_nodes.append( n1.id )
# 
#         # Specific Java/Android library
#         for c in self.vm.get_classes():
#             #if c.get_superclassname() == "Landroid/app/Service;" :
#             #    n1 = self._get_node( c.get_name(), "<init>", "()V" )
#             #    n2 = self._get_node( c.get_name(), "onCreate", "()V" )
# 
#             #    self.G.add_edge( n1.id, n2.id )
#             if c.get_superclassname() == "Ljava/lang/Thread;" or c.get_superclassname() == "Ljava/util/TimerTask;" :
#                 for i in self.vm.get_method("run") :
#                     if i.get_class_name() == c.get_name() :
#                         n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
#                         n2 = self._get_node( i.get_class_name(), "start", i.get_descriptor() ) 
#                        
#                         # link from start to run
#                         self.G.add_edge( n2.id, n1.id )
#                         n2.add_edge( n1, {} )
# 
#                         # link from init to start
#                         for init in self.vm.get_method("<init>") :
#                             if init.get_class_name() == c.get_name() :
#                                 n3 = self._get_node( init.get_class_name(), "<init>", init.get_descriptor() )
#                                 #n3 = self._get_node( i.get_class_name(), "<init>", i.get_descriptor() )
#                                 self.G.add_edge( n3.id, n2.id )
#                                 n3.add_edge( n2, {} )
# 
#             #elif c.get_superclassname() == "Landroid/os/AsyncTask;" :
#             #    for i in self.vm.get_method("doInBackground") :
#             #        if i.get_class_name() == c.get_name() :
#             #            n1 = self._get_node( i.get_class_name(), i.get_name(), i.get_descriptor() )
#             #            n2 = self._get_exist_node( i.get_class_name(), "execute", i.get_descriptor() )
#             #            print n1, n2, i.get_descriptor()
#                         #for j in self.vm.get_method("doInBackground") :
#                         #    n2 = self._get_exist_node( i.get_class_name(), j.get_name(), j.get_descriptor() )
#                         #    print n1, n2
#                         # n2 = self._get_node( i.get_class_name(), "
#             #    raise("ooo")
# 
#         #for j in self.vmx.tainted_packages.get_internal_new_packages() :
#         #    print "\t %s %s %s %x ---> %s %s %s" % (j.get_method().get_class_name(), j.get_method().get_name(), j.get_method().get_descriptor(), \
#         #                                            j.get_bb().start + j.get_idx(), \
#         #                                            j.get_class_name(), j.get_name(), j.get_descriptor())
# 
#         list_permissions = self.vmx.get_permissions([])
#         for x in list_permissions:
#             for j in list_permissions[x]:
#                 if isinstance(j, PathVar):
#                   continue
# 
#                 src_class_name, src_method_name, src_descriptor = j.get_src( self.vm.get_class_manager() )
#                 dst_class_name, dst_method_name, dst_descriptor = j.get_dst( self.vm.get_class_manager() )
#                 n1 = self._get_exist_node( dst_class_name, dst_method_name, dst_descriptor )
# 
#                 if n1 == None :
#                     continue
# 
#                 n1.set_attributes( { "permissions" : 1 } )
#                 n1.set_attributes( { "permissions_level" : DVM_PERMISSIONS[ "MANIFEST_PERMISSION" ][ x ][0] } )
#                 n1.set_attributes( { "permissions_details" : x } )
# 
#                 try :
#                     for tmp_perm in PERMISSIONS_RISK[ x ] :
#                         if tmp_perm in DEFAULT_RISKS :
#                             n2 = self._get_new_node( dst_class_name,
#                                                      dst_method_name,
#                                                      dst_descriptor + " " + DEFAULT_RISKS[ tmp_perm ][0],
#                                                      DEFAULT_RISKS[ tmp_perm ][0] )
#                             n2.set_attributes( { "color" : DEFAULT_RISKS[ tmp_perm ][1] } )
#                             self.G.add_edge( n2.id, n1.id )
# 
#                             n1.add_risk( DEFAULT_RISKS[ tmp_perm ][0] )
#                             n1.add_api( x, src_class_name + "-" + src_method_name + "-" + src_descriptor )
#                 except KeyError :
#                     pass
# 
#         # Tag DexClassLoader
#         for m, _ in self.vmx.get_tainted_packages().get_packages() :
#             if m.get_name() == "Ldalvik/system/DexClassLoader;" :
#                 for path in m.get_paths() :
#                     if path.get_access_flag() == TAINTED_PACKAGE_CREATE :
#                         src_class_name, src_method_name, src_descriptor = path.get_src( self.vm.get_class_manager() )
#                         n1 = self._get_exist_node( src_class_name, src_method_name, src_descriptor )
#                         n2 = self._get_new_node( dst_class_name, dst_method_name, dst_descriptor + " " + "DEXCLASSLOADER",
#                                                  "DEXCLASSLOADER" )
# 
#                         n1.set_attributes( { "dynamic_code" : "true" } )
#                         n2.set_attributes( { "color" : DEXCLASSLOADER_COLOR } )
#                         self.G.add_edge( n2.id, n1.id )
# 
#                         n1.add_risk( "DEXCLASSLOADER" )

    
    def addInvokePath(self, src, dst):
            src_class_name, src_method_name, src_descriptor = src
            dst_class_name, dst_method_name, dst_descriptor = dst
            n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
            n2 = self._get_node(dst_class_name, dst_method_name, dst_descriptor)
 
            self.G.add_edge(n1.id, n2.id)
            #TODO: what this path mean?
            #n1.add_edge(n2, j)
            
    def addNewInstancePath(self, src, dst):
            src_class_name, src_method_name, src_descriptor = src
            dst_class_name, dst_method_name, dst_descriptor = dst        
            
            #TODO: Think how to process
#             n1 = self._get_node(src_class_name, src_method_name, src_descriptor)
#             n2 = self._get_node(dst_class_name, "", "")
#             self.GI.add_edge(n2.id, n1.id)
            
    def addDexloadPath(self, src, filename):
        src_class_name, src_method_name, src_descriptor = src
        n1 = self._get_exist_node(src_class_name, src_method_name, src_descriptor)
        n2 = self._get_new_node(filename, "", "", "STADYNA_DEXCLASSLOADER: %s" % filename)
        n1.set_attributes( { "dynamic_code" : "true" } )
        n2.set_attributes( { "color" : STADYNA_DEXCLASSLOADER_COLOR } )
        
    
            
    def _get_exist_node(self, class_name, method_name, descriptor) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        try :
            return self.nodes[ key ]
        except KeyError :
            return None

    def _get_node(self, class_name, method_name, descriptor):
        if method_name == "" and descriptor == "":
            key = class_name
        else:
            key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes:
            self.nodes[key] = NodeF(len(self.nodes), class_name, method_name, descriptor)
            self.nodes_id[self.nodes[key].id] = self.nodes[key]

        return self.nodes[key]

    def _get_new_node_from(self, n, label) :
        return self._get_new_node( n.class_name, n.method_name, n.descriptor + label, label )

    def _get_new_node(self, class_name, method_name, descriptor, label) :
        key = "%s %s %s" % (class_name, method_name, descriptor)
        if key not in self.nodes :
            self.nodes[ key ] = NodeF( len(self.nodes), class_name, method_name, descriptor, label, False )
            self.nodes_id[ self.nodes[ key ].id ] = self.nodes[ key ]

        return self.nodes[ key ]

    def set_new_attributes(self, cm) :
        for i in self.G.nodes() :
            n1 = self.nodes_id[ i ]
            m1 = self.vm.get_method_descriptor( n1.class_name, n1.method_name, n1.descriptor )

            H = cm( self.vmx, m1 )

            n1.set_attributes( H )

    def export_to_gexf(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        buff += "<gexf xmlns=\"http://www.gephi.org/gexf\" xmlns:viz=\"http://www.gephi.org/gexf/viz\">\n"
        buff += "<graph type=\"static\">\n"

        buff += "<attributes class=\"node\" type=\"static\">\n" 
        buff += "<attribute id=\"%d\" title=\"type\" type=\"string\" default=\"normal\"/>\n" % ID_ATTRIBUTES[ "type"]
        buff += "<attribute id=\"%d\" title=\"class_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "class_name"]
        buff += "<attribute id=\"%d\" title=\"method_name\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "method_name"]
        buff += "<attribute id=\"%d\" title=\"descriptor\" type=\"string\"/>\n" % ID_ATTRIBUTES[ "descriptor"]


        buff += "<attribute id=\"%d\" title=\"permissions\" type=\"integer\" default=\"0\"/>\n" % ID_ATTRIBUTES[ "permissions"]
        buff += "<attribute id=\"%d\" title=\"permissions_level\" type=\"string\" default=\"normal\"/>\n" % ID_ATTRIBUTES[ "permissions_level"]
        
        buff += "<attribute id=\"%d\" title=\"dynamic_code\" type=\"boolean\" default=\"false\"/>\n" % ID_ATTRIBUTES[ "dynamic_code"]
        buff += "</attributes>\n"   

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

    def export_to_gml(self) :
        buff = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
        buff += "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:y=\"http://www.yworks.com/xml/graphml\" xmlns:yed=\"http://www.yworks.com/xml/yed/3\" xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://www.yworks.com/xml/schema/graphml/1.1/ygraphml.xsd\">\n"

        buff += "<key attr.name=\"description\" attr.type=\"string\" for=\"node\" id=\"d5\"/>\n"
        buff += "<key for=\"node\" id=\"d6\" yfiles.type=\"nodegraphics\"/>\n"

        buff += "<graph edgedefault=\"directed\" id=\"G\">\n"

        for node in self.G.nodes() :
            buff += "<node id=\"%d\">\n" % (node)
            #fd.write( "<node id=\"%d\" label=\"%s\">\n" % (node, escape(self.nodes_id[ node ].label)) )
            buff += self.nodes_id[ node ].get_attributes_gml()
            buff += "</node>\n"

        nb = 0
        for edge in self.G.edges() :
            buff += "<edge id=\"%d\" source=\"%d\" target=\"%d\"/>\n" % (nb, edge[0], edge[1])
            nb += 1

        buff += "</graph>\n"
        buff += "</graphml>\n"
        
        return buff
    
    
    def get_current_real_node_count(self):
        return len(self.nodes)

    def get_current_real_edge_count(self):
        return len(self.G.edges())
    

DEFAULT_NODE_TYPE = "normal"
DEFAULT_NODE_PERM = 0
DEFAULT_NODE_PERM_LEVEL = -1 

PERMISSIONS_LEVEL = {
    "dangerous" : 3,
    "signatureOrSystem" : 2,
    "signature" : 1,
    "normal" : 0,
}

COLOR_PERMISSIONS_LEVEL = {
    "dangerous"                 : (255, 0, 0),
    "signatureOrSystem"         : (255, 63, 63),
    "signature"                 : (255, 132, 132),
    "normal"                    : (255, 181, 181),
}