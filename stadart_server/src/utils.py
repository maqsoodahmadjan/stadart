from logconfig import logger

def clsToDalvikCls(className):
    logger.debug("Converting [%s] class name to Dalvik format class name..." % className)
    res = None
    if className:
        res = "L%s" % className
        res = res.replace('.', '/')
    logger.debug("Dalvik format of the class name [%s] is [%s]!" % (className, res))
    return res


def transformStack(stack):
    logger.debug("Transforming stack data into internal representation...")
    transformedStack = []
    for i in stack:
        t = tuple(str(v.strip()) for v in i.split(","))
#         t = tuple(v.strip() for v in i.split(","))
        transformedStack.append(t)
    logger.debug("Stack transformed successfully!")
    return transformedStack

def convertPathToSeccon((cls, method, proto)):
    protoNew = proto.replace(" ", "")
    return (cls, method, protoNew)
    