import time
import consts
import Queue
import threading
import json
from device import Device
from logconfig import logger


# def decode(s, encodings=('ascii', 'utf8', 'latin1')):
#     for encoding in encodings:
#         try:
#             return s.decode(encoding)
#         except UnicodeDecodeError:
#             pass
#     return s.decode('ascii', 'ignore')


class SecconMessageProducer(threading.Thread):
    def __init__(self, device, messages):
        assert isinstance(messages, Queue.Queue)
        threading.Thread.__init__(self)
        self._device = device
        self._messages = messages
        self._stop = False
        self._partial_messages = {}

    
    def parseSecconMsg(self, line):
        if not line:
            return None
        #template: !SECCON!:id12:p3:{"uid":"10012"}
        tmp_list = line.split(consts.SECCON_MARKER, 1)
        if len(tmp_list) == 1:
            return None
        seccon_msg = tmp_list[1].strip()
        if seccon_msg[0] == "{":
            #print "Whole message..."
            return seccon_msg
        #seccon_msg[0:1] == "id"
        tmp_list = seccon_msg[2:].split(":", 1)
        id = int(tmp_list[0].strip())
        seccon_msg = tmp_list[1].strip()
        #seccon_msg[0] == "p" or "f"
        if seccon_msg[0] == "p":
            tmp_list = seccon_msg[1:].split(":", 1)
            part_num = int(tmp_list[0].strip())
            seccon_msg = tmp_list[1].strip()
            cur_list = self._partial_messages.setdefault(id, [])
            cur_list.append(seccon_msg)
            self._partial_messages[id] = cur_list
            return None
        if seccon_msg[0] == "f":
            tmp_list = seccon_msg[1:].split(":", 1)
            final_part_num = int(tmp_list[0].strip())
            seccon_msg = tmp_list[1].strip()
            cur_list = self._partial_messages.setdefault(id, [])
            cur_list.append(seccon_msg)
            final_msg = ''.join(cur_list)
            del self._partial_messages[id]
            return final_msg

    
    def stopThread(self):
        self._stop = True

    
    def run(self):
        if not self._device.is_alive():
            return
        self._device.clean_logcat()
        process = self._device.get_logcat()
        msg = None
        res = False
        for line in iter(process.stdout.readline, ''):
            res = self.parseSecconMsg(line)
            if res != None:
                self._messages.put(res)

            if self._stop:
                logger.info("Terminating thread that reads 'adb logcat' output.")
                process.terminate() #stops the child process
                break
            
        process.stdout.close()
            


class SecconMessageProcessor(threading.Thread):
    def __init__(self, messages):
        assert isinstance(messages, Queue.Queue)
        threading.Thread.__init__(self)
        self._messages = messages
        self._stop = False
    
    
    def stopThread(self):
        self._stop = True
       
        
    def run(self):
        while True:
            while not self._messages.empty():
                line = self._messages.get()
                print 'Received line: ' + repr(line)
                load = json.loads(line)
                print load
                
            time.sleep(.1)
            if self._stop:
                logger.info("Terminating Stadyna message processor thread.")
                break



def main():         
    dev = Device.get_device("303195BA0D4D00EC")
    
    messages = Queue.Queue()
    seccon_producer = SecconMessageProducer(messages, dev)
    seccon_consumer = SecconMessageProcessor(messages)
    seccon_producer.setDaemon(False)
    seccon_consumer.setDaemon(False)
    seccon_producer.start()
    seccon_consumer.start()
    
    time.sleep(60)
    print "Time is finished!!!"
    seccon_producer.stopThread()
    seccon_consumer.stopThread()
    seccon_producer.join()
    seccon_consumer.join()

###### entry point ######
if __name__ == '__main__':
    main()

