import importlib
import pkgutil
import os
import sys
from operator import itemgetter
import logging
from utils.dict_helpers import enum_keys

logger = logging.getLogger()


def event_criteria_values(an_event):
    """set up the list of event values to use when comparing plugins
    to this event to see if they should fire
    target values are the .keys() of the dict and the values of the 'category' and 'tags' fields
    where category is a key/value and tags is a list of values.
    """
    criteria_values = [e for e in enum_keys(an_event)]
    if (
        "tags" in criteria_values
        and isinstance(an_event["tags"], list)
        and len(an_event["tags"]) > 0
    ):
        for tag in an_event["tags"]:
            criteria_values.append(tag)
    if "category" in criteria_values and isinstance(an_event["category"], str):
        criteria_values.append(an_event["category"])

    return criteria_values


def register_plugins(directory_name):
    """
    take a directory name, scan it for python modules
    and register them (module,registration criteria, priority)
    """
    pluginList = list()  # tuple of module,registration dict,priority
    if os.path.exists(directory_name):
        if directory_name not in sys.path:
            sys.path.insert(0, directory_name)

        # Use pkgutil and importlib instead of pynsive
        for finder, name, ispkg in pkgutil.iter_modules([directory_name]):
            try:
                module = importlib.import_module(name)
                if "message" in dir(module):
                    mclass = module.message()
                    mreg = mclass.registration
                    mpriority = getattr(mclass, "priority", 100)

                    if isinstance(mreg, list):
                        logger.info(
                            "[*] plugin {0} registered to receive messages with {1}".format(
                                name, mreg
                            )
                        )
                        pluginList.append((mclass, mreg, mpriority))
            except Exception as e:
                logger.error(f"Unable to load module {name}: {e}")
                raise ImportError(f"Unable to load module {name}") from e
    return pluginList


def send_event_to_plugins(anevent, metadata, pluginList):
    """compare the event to the plugin registrations.
    plugins register with a list of keys or values
    or values they want to match on
    this function compares that registration list
    to the current event and sends the event to plugins
    in order
    """
    if not isinstance(anevent, dict):
        raise TypeError("event is type {0}, should be a dict".format(type(anevent)))

    # expecting tuple of module,criteria,priority in pluginList
    # sort the plugin list by priority
    executed_plugins = []
    for plugin in sorted(pluginList, key=itemgetter(2), reverse=False):
        # assume we don't run this event through the plugin
        send = False
        if isinstance(plugin[1], list):
            try:
                plugin_matching_keys = set([item.lower() for item in plugin[1]])
                event_tokens = [e for e in event_criteria_values(anevent)]
                if "*" in plugin_matching_keys or plugin_matching_keys.intersection(
                    event_tokens
                ):
                    send = True
            except TypeError:
                logger.error(
                    "TypeError on set intersection for dict {0}".format(anevent)
                )
                return (anevent, metadata)
        if send:
            (anevent, metadata) = plugin[0].onMessage(anevent, metadata)
            if anevent is None:
                # plug-in is signalling to drop this message
                # early exit
                return (anevent, metadata)
            plugin_name = plugin[0].__module__.replace("plugins.", "")
            executed_plugins.append(plugin_name)
    # Tag all events with what plugins ran on it
    if "plugins" in anevent:
        anevent["plugins"] = anevent["plugins"] + executed_plugins
    else:
        anevent["plugins"] = executed_plugins

    return (anevent, metadata)
