from collections import Counter
from collections.abc import Mapping
import logging
logger = logging.getLogger()


def keypaths(nested):
    """ return a list of nested dict key paths
        like: [u'_source', u'details', u'program']
    """
    for key, value in nested.items():
        if isinstance(value, Mapping):
            for subkey, subvalue in keypaths(value):
                yield [key] + subkey, subvalue
        else:
            yield [key], value


def dictpath(path):
    """ split a string representing a
        nested dictionary path key.subkey.subkey
    """
    for i in path.split("."):
        yield "{0}".format(i)


def getValueByPath(input_dict, path_string):
    """
        Gets data/value from a dictionary using a dotted accessor-string
        http://stackoverflow.com/a/7534478
        path_string can be key.subkey.subkey.subkey
    """
    return_data = input_dict
    for chunk in path_string.split("."):
        return_data = return_data.get(chunk, {})
    return return_data

def mostCommon(listofdicts, dictkeypath):
    """
        Given a list containing dictionaries,
        return the most common entries
        along a key path separated by .
        i.e. dictkey.subkey.subkey
        returned as a list of tuples
        [(value,count),(value,count)]
    """
    inspectlist = list()
    path = list(dictpath(dictkeypath))
    for i in listofdicts:
        for k in list(keypaths(i)):
            if not (set(k[0]).symmetric_difference(path)):
                inspectlist.append(k[1])

    return Counter(inspectlist).most_common()