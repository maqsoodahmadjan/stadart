import os
import threading
import subprocess
import Queue
from logconfig import logger

class AsynchronousFileReader(threading.Thread):
    '''
    Helper class to implement asynchronous reading of a file
    in a separate thread. Pushes read lines on a queue to
    be consumed in another thread.
    '''
 
    def __init__(self, fd, queue):
        assert isinstance(queue, Queue.Queue)
        assert callable(fd.readline)
        threading.Thread.__init__(self)
        self._fd = fd
        self._queue = queue
 
    def run(self):
        '''The body of the tread: read lines and put them on the queue.'''
        for line in iter(self._fd.readline, ''):
            self._queue.put(line)
 
    def eof(self):
        '''Check whether there is no more content to expect.'''
        return not self.is_alive() and self._queue.empty()


class Device:
    LOG_LEVELS = ['V', 'I', 'D', 'W', 'E', 'WTF']
    
    def __init__(self, name):
        self.device_name = name
    
    
    @staticmethod
    def get_devices_list():
        logger.debug("Getting the list of running devices...")
        devices = []
        input_devices = None
        try:
            input_devices = subprocess.check_output(["adb", "devices"])
        except subprocess.CalledProcessError:
            logger.error("Could not find attached devices!")
            return devices
            
        lines = input_devices.splitlines()
        for i in range(0,len(lines)): #first line just announces the list of devices
            words = lines[i].split('\t')
            if len(words) == 2 and words[1].strip() == 'device':
                devices.append(words[0].strip())
        
        logger.debug("Device list:\n[%s]", '\n'.join(devices))
        return devices


    @staticmethod
    def get_device(name):
        logger.debug("Instantiating a device [%s]..." % name)
        instance = Device(name)
        return instance
    
    
    def is_alive(self):
        logger.debug("Checking if a device [%s] is alive..." % self.device_name)
        if not self.device_name:
            logger.error("The device object is not instantiated!")
            return False
        input_devices = None
        try:
            input_devices = subprocess.check_output(["adb", "devices"])
        except subprocess.CalledProcessError:
            logger.error("Could not find the attached device [%s]!" % self.device_name)
            return False
        
        lines = input_devices.splitlines()
        for i in range(1,len(lines)): #first line just announces the list of devices
            words = lines[i].split('\t')
            if len(words) == 2 and words[1].strip() == 'device':
                trimmed = words[0].strip()
                if trimmed == self.device_name:
                    logger.debug("Device [%s] is alive!" % self.device_name)
                    return True
        
        logger.debug("Device [%s] is not running!" % self.device_name)
        return False
    
    
    def get_file(self, what, to_dir):
        logger.debug("Coping file [%s] from device to directory [%s]..." % (what, to_dir))
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % self.device_name)
            return False
        
        if what == "":
            logger.warning("The name of the file to download is not specified!")
            return False
        
        try:
            with open(os.devnull, 'w') as f_null:
                subprocess.check_call(["adb", "-s", self.device_name, "pull", what, to_dir], stderr=f_null)
        except subprocess.CalledProcessError:
            logger.error("Could not download file [%s] from the device!" % what)
            return False
        
        logger.debug("File [%s] is downloaded!" % what)
        return True
    
    
    def install_package(self, apk_path):
        logger.debug("Installing application [%s]..." % apk_path)
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % str(self.device_name))
            return False
        
        if apk_path == "":
            logger.warning("The path to the application to install is not specified!")
            return False
        
        try:
            with open(os.devnull, 'w') as f_null:
                subprocess.check_call(["adb", "-s", self.device_name, "install", "-r", apk_path], stderr=f_null)
        except subprocess.CalledProcessError:
            logger.error("Could not install application [%s] on the device!" % apk_path)
            return False
        
        logger.debug("Application [%s] is installed!" % apk_path)
        return True
    
    
    def get_logcat(self, tag = None, level = None):
        logger.debug("Attaching to a logcat pipe...")
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % self.device_name)
            return None
        
        if tag == None: tag = '*'
        if level == None: level = 'V'
        if level.upper() not in Device.LOG_LEVELS:
            logger.error("The log level %s is not specified correctly!" % str(level))
        
        command = ['adb', '-s', self.device_name, 'logcat', '%s:%s' % (tag, level)]
        if tag != '*':
            command.append('*:S')
        
        return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=None)
    
    
    def clean_logcat(self):
        logger.debug("Cleaning logcat...")
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % self.device_name)
            return
        
        try:
            with open(os.devnull, 'w') as f_null:
                subprocess.check_call(['adb', '-s', self.device_name, 'logcat', '-c'], stderr=f_null)
        except subprocess.CalledProcessError:
            logger.error("Could not clean logcat!")
            return
        
        logger.debug("Logcat is cleaned!")
            
    
    def get_package_uid(self, package_name):
        logger.debug("Getting UID of the package [%s]..." % package_name)
        uid = -1
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % self.device_name)
            return uid
        if package_name == "":
            logger.warning("The name of the package is not specified!")
            return uid
        
        uid_lines = subprocess.check_output(['adb', '-s', self.device_name, 'shell', 'cat', '/data/system/packages.list'])
        lines = uid_lines.splitlines()
        for i in range(0,len(lines)): #first line just announces the list of devices
            words = lines[i].split(' ')
            if words[0].strip() == package_name:
                uid = int(words[1].strip())
                break
        
        logger.debug("The UID of the package [%s] is [%d]" % (package_name, uid))
        return uid
    
    
    def start_activity(self, package_name, activity_name):
        #adb shell am start -n com.package.name/com.package.name.ActivityName 
        logger.debug("Starting activity [%s] of the package [%s]..." % (package_name, activity_name))
        if not self.is_alive():
            logger.error("The device [%s] is not running!" % self.device_name)
            return
        
        if not package_name:
            logger.warning("The name of the package is not specified!")
            return
        
        if not activity_name:
            logger.warning("The name of the activity is not specified!")
            return
        
        run_string = package_name + '/' + activity_name
        
        try:
            with open(os.devnull, 'w') as f_null:
                subprocess.check_call(['adb', '-s', self.device_name, 'shell', 'am start', '-n', run_string], stderr=f_null)
        except subprocess.CalledProcessError:
            logger.error("Could not run activity!")
            return
        
    
def main():
    devices = Device.get_devices_list()
    # print devices
    
    #d = Device("303195BA0D4D00EC")
    #res=d.get_file("/sdcard/scriptlog.txt", "/home/yury/tmp/")
    print devices
    
    # res=d.get_file("/sdcard/scriptlog.txt", "/home/yury/tmp/")
    # print res            
#    process = d.get_logcat()
#    stdout_queue = Queue.Queue()
#    stdout_reader = AsynchronousFileReader(process.stdout, stdout_queue)
#    stdout_reader.start()
#    
#    # Check the queues if we received some output (until there is nothing more to get).
#    while not stdout_reader.eof():
#        # Show what we received from standard output.
#        while not stdout_queue.empty():
#            line = stdout_queue.get()
#            print repr(line)
#        
#        time.sleep(.1)
#        
#    # Let's be tidy and join the threads we've started.
#    stdout_reader.join()
#    process.stdout.close()
    #print d.get_package_uid("com.android.browser")

if __name__ == '__main__':
    main()
        
    
