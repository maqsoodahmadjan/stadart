import subprocess
import optparse
import threading
import sys
#sys.path.insert(1, '/Users/vaioco/android_stuff/androguard-2.0')
import xml.dom.minidom
import os
from os.path import isfile, join
from os import listdir
import shutil
from androguard.core.bytecodes.apk import *
import sys,traceback
import launcher
from utils import *

_master = None

failed_dir = "failed"
master_main_dir = "results/stub"
failed_dir = "results/failed"
failed_log = "failedapps.log"

signKey = ""
keystore = "./keys/my-release-key.keystore"
keystore_pass = "test"
master_smali_dir = "smali/com/example/bladerunner/"
master_smali_file = "Utils.smali"
master_smali_MyApp = "MyApp.smali"
master_smali_MainActivity = "MainActivity.smali"
FNULL = open(os.devnull, 'w')

apk_dataset = Deck()


class MyAPK(object):
    def __init__(self,target, master=None):
        try:
            self.apk = APK(target)
        except Exception as e:
            print e
            self.apk = None
            self.path = target
            self.main_activity = None
            self.name = "NULL"
            #self.write_except()
            raise MyError(self, "androguard APK ERROR")
        self.path = target
        self.pkg = ''
        self.main_activity = ''
        self.sha1 = ""
        self.name = os.path.basename(target).replace(" ","")
        self.master = master
        self.set_main_act()
        self.set_pck()

    def set_main_act(self):
        self.main_activity = self.apk.get_main_activity()
        print self.apk
        print self.main_activity
        if self.main_activity is None or len(self.main_activity) <= 0:
            if self.master is not None:
                raise MyError(self, "cannot get main activity")
    def set_pck(self):
        self.pkg = self.apk.get_package()
        if self.pkg is None or len(self.pkg) <= 0:
            raise MyError(self, "cannot get package")
    def __repr__(self):
        if self is None: return "NULL"
        if self.apk is None:
            return "path: " + self.path +  "\n"
        return "path: " + self.path + " name: " + self.name + "\n"
    def __str__(self):
        if self is None: return "NULL"
        if self.apk is None:
            return "path: " + self.path  + "\n"
        return "path: " + self.path + " name:" + self.name + "\n"
    def write_except(self):
        print 'coping ' + self.path + " to " + failed_dir
        subprocess.call(["mkdir", "-p", "%s" % (failed_dir)], stdout=FNULL, stderr=subprocess.STDOUT)
        subprocess.call(["cp", "%s" % (self.path), "%s/" % (failed_dir)], stdout=FNULL, stderr=subprocess.STDOUT)

def raccogliAPK(mypath,filter=None):
    global _master
    onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f)) and ".apk" in f]
    l = []
    for f in onlyfiles:
        path = join(mypath,f)
        '''
        try:
            tmp = MyAPK(path, _master)
        except MyError as e:
            #print e
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print "*** format_tb:"
            print repr(traceback.format_tb(exc_traceback))
            failure(path)
            continue
        '''
        l.append(path)
    apk_dataset.init(l)
    return len(onlyfiles)

def print_help(parser):
    print "arguments error!!\n"
    parser.print_help()
    exit(-1)

def decompile(target, where):
    _dir = where % (target.name)
    subprocess.check_call(["mkdir", "-p", "%s" % (_dir)], stdout=FNULL, stderr=subprocess.STDOUT)
    #print 'decompiling: '  + str(_dir)
    subprocess.check_call(["apktool","d","-f", "-s","-o","%s" % (_dir),"%s" % (target.path)], stdout=FNULL, stderr=subprocess.STDOUT)

def decompileMaster(target, where):
    subprocess.check_call(["mkdir", "-p", "%s" % (where)], stdout=FNULL, stderr=subprocess.STDOUT)
    cmd = "apktool d -f -o %s %s" % (where, target.path)
    print 'decompiling master: '  + str(cmd)
    subprocess.check_call(cmd.split(), stdout=FNULL, stderr=subprocess.STDOUT)
    #subprocess.call(["apktool","d","-f","-o","%s" % (_dir),"%s" % (target.master.path)], stdout=FNULL, stderr=subprocess.STDOUT)

def signApp(target):
    cmd = "jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -storepass cambiami -keystore %s" % (keystore)\
          + " %s.apk" %(target) + " %s" % (keystore_pass)
    subprocess.check_call(cmd.split(), stdout=FNULL, stderr=subprocess.STDOUT)
    #os.system(cmd)

def failure(path, msg):
    print 'failed with ' + str(path)
    if not os.path.exists(failed_dir):
        subprocess.check_call(["mkdir", "-p", "%s" % (failed_dir)], stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.check_call(["cp", "%s" % (path), "%s/" % (failed_dir)], stdout=FNULL, stderr=subprocess.STDOUT)
    try:
        if os.path.exists("results/" + os.path.basename(path)):
            shutil.rmtree("results/" + os.path.basename(path))
        with open("results/%s" % (failed_log), 'a') as o:
            o.write(str(msg))
            o.write("\n")
    except Exception as e:
        print e

def addTag(sharedUid, oldstring, manifest_lines):
    newstring = oldstring + " " + sharedUid
    index = 0
    for line in manifest_lines:
        tmp = line.replace(oldstring, newstring)
        manifest_lines[index] = tmp
        index += 1

def writeNewManifest(where, what):
    #print 'writing new manifest in ' + where
    with open("%s/AndroidManifest.xml.new" % (where), "wt") as fout:
        for line in what:
            fout.write(line)

def cambiaManifest(oldmanifest, newmanifest, where):
    subprocess.call(["rm", "%s" % (oldmanifest)], stdout=FNULL, stderr=subprocess.STDOUT)
    subprocess.call(["mv", "%s" % (newmanifest), "%s/AndroidManifest.xml" % (where)], stdout=FNULL, stderr=subprocess.STDOUT)



def parseManifest(target):
    target_output_dir = "results/%s/outputTarget"
    master_output_dir = "results/%s/"
    _dir = target_output_dir % (target.name)
    f = open("%s/AndroidManifest.xml" % (_dir), 'rb')
    manifest_lines = f.readlines()
    f.seek(0)
    xml_obj = xml.dom.minidom.parseString(f.read())
    perms = xml_obj.getElementsByTagName('manifest')
    for i in perms:
        pck = i.getAttribute("package")
        test = i.getAttribute("android:sharedUserId")
    if len(test) > 0:
        #failure(target)
        raise MyError(target, "app " + target.pkg + " already has sharedUserID")
        #return 1;
    '''
    app_tag = xml_obj.getElementsByTagName('application')
    for elem in app_tag:
        label = elem.getAttribute("android:label")
        #proc = elem.getAttribute("android:process")
    if len(label) <= 0: #or len(proc) > 0:
        raise MyError(target, "app " + target.pkg + " already has android:process")
        #failure(target)
        #return 1
    '''
    #addTag("android:process=\"%s\"" % (pck), "android:label=\"%s\"" % (label), manifest_lines)
    try:
        addTag("android:sharedUserId=\"org.sid.unito.MAM\"" , "package=\"%s\"" % (pck), manifest_lines)
    except UnicodeDecodeError as e:
        raise MyError(target, "error add tag in manifest")
    writeNewManifest(_dir, manifest_lines)
    cambiaManifest("%s/AndroidManifest.xml" % (_dir), "%s/AndroidManifest.xml.new" % (_dir),
                   _dir)

#    <application android:icon="@drawable/icon" android:label="@string/app_name">

def parseMasterApk(utils_file_lines, old, new):
    index = 0
    #print 'replacing: ' + old + ' with: ' + new
    for line in utils_file_lines:
        tmp = line.replace(old, new)
        utils_file_lines[index] = tmp
        index += 1

def writeUtilsFile(what, where):
    with open("%s" % (where), "wt") as fout:
        for line in what:
            fout.write(line)

def addMasterProc(master_manifest,oldstring, newstring):
    index = 0
    for line in master_manifest:
        tmp = line.replace(oldstring, newstring)
        master_manifest[index] = tmp
        index += 1


#add target's info in master apk
def addTargetInfo(target):
    target_output_dir = "results/%s/outputTarget"
    master_output_dir = "results/%s/"
    print str(threading.current_thread())
    _dir = master_output_dir % (target.name)
    _dir += "stub"
    fd = open("%s/AndroidManifest.xml" % (_dir))
    master_manifest = fd.readlines()
    #print 'master manifest: '
    fd.close()
    root = os.getcwd()
    adir = "%s/%s/%s" % (root, _dir, master_smali_dir )
    print 'reading : ' + master_smali_file + " in : " + adir
    os.chdir(adir)
    fd = open(master_smali_file)
    utils_file_lines = fd.readlines()
    parseMasterApk(utils_file_lines,"PCK_TROVAMI",target.pkg)
    parseMasterApk(utils_file_lines,"ACTIVITY_TROVAMI",target.main_activity)
    writeUtilsFile(utils_file_lines, master_smali_file)
    fd.close()
    fd = open(master_smali_MyApp)
    myapp_file_lines = fd.readlines()
    parseMasterApk(myapp_file_lines,"PCK_TROVAMI",target.pkg)
    parseMasterApk(myapp_file_lines,"ACTIVITY_TROVAMI",target.main_activity)
    writeUtilsFile(myapp_file_lines, master_smali_MyApp)
    fd.close()
    fd = open(master_smali_MainActivity)
    mainactivity_file_lines = fd.readlines()
    parseMasterApk(mainactivity_file_lines,"PCK_TROVAMI",target.pkg)
    parseMasterApk(mainactivity_file_lines,"ACTIVITY_TROVAMI",target.main_activity)
    writeUtilsFile(mainactivity_file_lines, master_smali_MainActivity)
    os.chdir(root)
    fd.close()
    #print 'adding to master proc name: ' + target.pkg
    addMasterProc(master_manifest,"PROC_TROVAMI", target.pkg)
    writeNewManifest(_dir, master_manifest)
    cambiaManifest("%s/AndroidManifest.xml" % (_dir), "%s/AndroidManifest.xml.new" % (_dir),
                   _dir)

'''
def prepareMaster(opts):
    target = MyAPK(opts.target)
    decompileMaster(master)
    addTargetInfo(master,target)
    rebuild("%s" % (target.name+"_master"), master_output_dir)
'''
def rebuild(writeTo, target):
    #print 'rebuilding: '  + str(target)
    try:
        subprocess.check_call(["apktool","b","-o","%s.apk" % (writeTo),"%s" % (target)], stdout=FNULL, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise MyError(None, "error apktool during rebuild")
    signApp(writeTo)

def _clean(target):
    target_output_dir = "results/%s/outputTarget"
    master_output_dir = "results/%s/"
    _dir = target_output_dir % (target.name)
    _dir2 = master_output_dir % (target.name) + "stub/"
    try:
        if os.path.exists(_dir):
            shutil.rmtree(_dir)
        if os.path.exists(_dir2):
            shutil.rmtree(_dir2)
    except OSError as e:
        print e

def copytolocalstub(path,where):
    try:
        subprocess.check_call(["cp", "-r", "%s" % (path), "%s" % (where)], stdout=FNULL, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print e

def analysis(apkpath, master):
    target_output_dir = "results/%s/outputTarget"
    master_output_dir = "results/%s/"
    try:
        _myapk = MyAPK(apkpath, master)
    except MyError as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print "*** format_tb:"
        print repr(traceback.format_tb(exc_traceback))
        failure(apkpath, e)
        return
    #subprocess.check_call(["mkdir", "-p", "%s" % (master_output_dir % (_myapk.name))], stdout=FNULL, stderr=subprocess.STDOUT)
    print 'analysis on : ' + str(_myapk)
    #print 'master: ' + str(_myapk.master)
    try:
        decompile(_myapk,target_output_dir)
    except subprocess.CalledProcessError as c:
        failure(_myapk.path, "cannot decompile APK")
        return
    #decompileMaster(_myapk,master_output_dir)
    copytolocalstub(master_main_dir, master_output_dir % (_myapk.name) + "stub/")
    try:
        parseManifest(_myapk)
        addTargetInfo(_myapk)
        _dir = master_output_dir % (_myapk.name) + "stub/"
        where = "results/%s/%s" % (_myapk.name, _myapk.name + "_master")
        rebuild(where, _dir)
        _dir = target_output_dir % (_myapk.name)
        where = "results/%s/%s" % (_myapk.name, _myapk.name + "_MAM")
        rebuild(where, _dir)
        _clean(_myapk)
        print 'ENDing analysis on : ' + str(_myapk)
    except MyError as e:
        print e
        failure(_myapk.path, e)
        return
    except subprocess.CalledProcessError:
        failure(_myapk.path, "cannot rebuild APK")
        return
    except IOError as e1:
        print 'IOERROR: ' + str(e1)
        failure(_myapk.path, "IOERROR")
        return

def prepareTarget(opts):
    global _master
    if not opts.target and opts.apks:
        try:
            _master = MyAPK(opts.master)
            decompileMaster(_master, master_main_dir)
        except MyError as e:
            print e
            return
        '''
        max_apks = get_conf('apks')
        while(1):
            total, nums = raccogliAPK(opts.apks, int(max_apks))
            resto = total - nums
            print 'ne mancano '  + str(resto)
            threads = get_conf('threads')
            if(threads > nums):
                threads = nums
            launcher.start(int(threads) , apk_dataset)
            if(resto <= 0):
                break;
        '''
        nums = raccogliAPK(opts.apks)
        threads = int(get_conf('threads'))
        print 'threads: ' + str(threads) + ' apks: ' + str(nums)
        if(threads > nums):
            threads = nums
        launcher.start(threads, apk_dataset, _master)
        return
    else:
        return

if __name__ == "__main__":
    parser = optparse.OptionParser();
    parser.add_option('-m', '--master', action="store", help="master apk", dest="master",type="string")
    parser.add_option('-t','--apk', action="store", help="Target apk", dest="target",type="string")
    parser.add_option('-d','--apks-dir', action="store", help="Target apk", dest="apks",type="string")
    (opts, args) = parser.parse_args()
    if not opts.master:
        print_help(parser)
    if opts.target or opts.apks:
        init_parser("conf.ini")
        prepareTarget(opts)



'''
TODO:

- CHECK IF SHAREDUSERID IS ALREADY DEFINED
- CHECK IF ANDROID:PROCESS IS ALREADY DEFINED

'''