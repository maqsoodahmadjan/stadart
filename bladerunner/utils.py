from ConfigParser import SafeConfigParser
import logging

class Deck:
    def __init__(self):
        self.apks = []
    def init(self, targets):
        for t in targets:
            '''
            if t.apk is not None:
                print str(t)
            '''
            self.apks.append(t)
    def __iter__(self):
        return iter(self.apks)



class MyError(Exception):
    def __init__(self, t, msg):
        self.target = t
        self.msg = msg
    def __str__(self):
        return self.msg + " " + repr(self.target)


parser = None

def init_parser(conf):
    global parser
    parser = SafeConfigParser()
    parser.read(conf)

def get_conf(name):
    global parser
    ret = parser.get('woot', name)
    return ret