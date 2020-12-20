import argparse
import boto3
import botocore
import json
import io
import pandas as pd
import time
import pymongo
import sys
import urllib.parse
import random
import calendar
import glob
from datetime import datetime
import yaml
import chevron
from copy import deepcopy
import logging, logging.config
from pathlib import Path
from utils.dotdict import DotDict
from utils.dates import get_date_parts
from utils.dates import toUTC, utcnow
from utils.athena import run_query, dataframe_from_athena_s3, default_bucket
from utils.dict_helpers import merge
from utils.mostcommon import mostCommon
from utils.helpers import first_matching_index_value

logger = logging.getLogger()


def generate_meteor_id():
    """
    Function to generate a mongo document ID that's friendly to meteor
    """
    return "%024x" % random.randrange(16 ** 24)


def remove_previously_alerted(db, events, alert_params):
    """
    Iterate a list of events and remove any event already in the alerts table
    """
    new_events = []
    for event in events:
        # todo, add and alert_name = x?
        # search threshold 'events' and sequence 'slots.events'
        # to see if we've already alerted on this event
        alerted = db["alerts"].count_documents(
            {
                "$or": [
                    {"events": {"$elemMatch": {"eventid": event["eventid"]}}},
                    {"slots.events": {"$elemMatch": {"eventid": event["eventid"]}}},
                ]
            }
        )
        if not alerted:
            new_events.append(event)
    return new_events


def remove_inflight_events(db, events, alert_params):
    """
    Iterate a list of events and remove any event we already know about
    in the inflight sequence alerts table.
    """
    new_events = []
    for event in events:
        # todo, add and alert_name = x
        alerted = db["inflight_alerts"].count_documents(
            {"slots.events": {"$elemMatch": {"eventid": event["eventid"]}}}
        )
        if not alerted:
            new_events.append(event)
    return new_events


def save_alert(db, new_alert):
    """
    Given a new alert, insert into Mongo
    """
    alerts = db["alerts"]
    # generate a meteor-compatible ID
    new_alert["_id"] = generate_meteor_id()
    # set the date back to a datetime from unicode, so mongo/meteor can properly sort, select.
    new_alert["utctimestamp"] = toUTC(new_alert["utctimestamp"])
    # also set an epoch time field so minimongo can sort
    new_alert["utcepoch"] = calendar.timegm(
        toUTC(new_alert["utctimestamp"]).utctimetuple()
    )
    alerts.insert_one(new_alert)


def save_inflight_alert(db, new_alert):
    """
    Given a sequence alert, save to Mongo
    """
    alerts = db["inflight_alerts"]
    # set the date back to a datetime from unicode, so mongo/meteor can properly sort, select.
    new_alert["utctimestamp"] = toUTC(new_alert["utctimestamp"])
    # also set an epoch time field so minimongo can sort
    new_alert["utcepoch"] = calendar.timegm(
        toUTC(new_alert["utctimestamp"]).utctimetuple()
    )

    # insert or update
    if "_id" in new_alert:
        alerts.replace_one({"_id": new_alert["_id"]}, new_alert, True)

    else:
        # generate a meteor-compatible ID
        new_alert["_id"] = generate_meteor_id()
        alerts.insert_one(new_alert)


def get_athena_query(criteria, config):
    """
    get the query template, plus this alerts criteria
    """
    (
        hour,
        month,
        day,
        year,
        last_hour_hour,
        last_hour_month,
        last_hour_day,
        last_hour_year,
    ) = get_date_parts()
    database = config.athenadatabase
    table = config.athenatable
    query = r"""
    SELECT
    *
    FROM "{}"."{}"
    where
    {}
    AND (
        (year='{}'
        AND month='{}'
        AND day='{}'
        AND hour='{}')
        OR
        (year='{}'
        AND month='{}'
        AND day='{}'
        AND hour='{}')
    )
    limit 1000
    """.format(
        database,
        table,
        criteria,
        year,
        month,
        day,
        hour,
        last_hour_year,
        last_hour_month,
        last_hour_day,
        last_hour_hour,
    )
    return query


def get_threshold_alert_shell(alert_params):
    """
    default dict for a threshold alert
    """
    alert = {
        "alert_name": alert_params.get("alert_name", "unnamed"),
        "alert_type": alert_params.get("alert_type", "threshold"),
        "utctimestamp": utcnow().isoformat(),
        "severity": alert_params.get("severity", "INFO"),
        "summary": alert_params.get("summary", "threshold alert!"),
        "event_snippet": alert_params.get("event_snippet", ""),
        "event_sample_count": alert_params.get("event_sample_count", 3),
        "category": alert_params.get("category", "general"),
        "tags": alert_params.get("tags", []),
        "threshold": alert_params.get("threshold", 1),
        "aggregation_key": alert_params.get("aggregation_key", ""),
        "criteria": alert_params.get("criteria", ""),
        "debug": alert_params.get("debug", True),
        "events": [],
    }
    return alert


def get_deadman_alert_shell(alert_params):
    """
    default dict for a deadman alert
    """
    alert = {
        "alert_name": alert_params.get("alert_name", "unnamed"),
        "alert_type": alert_params.get("alert_type", "deadman"),
        "utctimestamp": utcnow().isoformat(),
        "severity": alert_params.get("severity", "INFO"),
        "summary": alert_params.get("summary", "deadman alert!"),
        "event_snippet": alert_params.get("event_snippet", ""),
        "event_sample_count": alert_params.get("event_sample_count", 0),
        "category": alert_params.get("category", "deadman"),
        "tags": alert_params.get("tags", ["deadman"]),
        "threshold": alert_params.get("threshold", 0),
        "aggregation_key": alert_params.get("aggregation_key", "none"),
        "criteria": alert_params.get("criteria", ""),
        "debug": alert_params.get("debug", True),
        "events": [],
    }
    return merge(alert_params, alert)


def process_inflight_alerts(config, db, session, athena):
    # iterate the inflight sequence alerts
    # and see if any slots without events have matches now
    alerts = db.inflight_alerts.find({}).sort("utcepoch", pymongo.DESCENDING)
    for alert in alerts:
        process_sequence_alert(config, db, session, athena, alert)


def create_sequence_alerts(db):
    # iterate inflight sequence alerts
    # for any with all slots met
    # create an alert
    # remove the inflight entry
    inflight_alerts = db.inflight_alerts.find({}).sort("utcepoch", pymongo.DESCENDING)
    for alert in inflight_alerts:
        slots = len(alert["slots"])
        matches = 0
        for slot in alert["slots"]:
            if "events" in slot:
                matches = matches + 1
        if slots == matches:
            # all slots are filled, create alert
            logger.debug("creating a fullfilled sequence alert")
            inflight_id = alert["_id"]
            alert["summary"] = chevron.render(alert["summary"], alert)
            save_alert(db, alert)
            # remove the inflight alert
            db.inflight_alerts.delete_one({"_id": inflight_id})


def expire_sequence_alerts(db):
    # iterate inflight sequence alerts
    # for any that are past their expiration date
    # remove the inflight entry
    inflight_alerts = db["inflight_alerts"]
    alerts = db.inflight_alerts.find({}).sort("utcepoch", pymongo.DESCENDING)
    for alert in alerts:
        if toUTC(alert["expiration"]) < utcnow():
            inflight_alerts.delete_one({"_id": alert["_id"]})


def get_sequence_alert_shell(alert_params):
    """
    default dict for a sequence alert
    """
    alert = {
        "alert_name": alert_params.get("alert_name", "unnamed"),
        "alert_type": alert_params.get("alert_type", "sequence"),
        "utctimestamp": alert_params.get("utctimestamp", utcnow().isoformat()),
        "lifespan": alert_params.get("lifespan", "3 days"),
        "severity": alert_params.get("severity", "INFO"),
        "summary": alert_params.get("summary", "sequence alert!"),
        "debug": alert_params.get("debug", True),
        "slots": alert_params.get("slots", []),
    }
    # calculate expiration in date format
    offset = pd.Timedelta(alert["lifespan"]).to_pytimedelta()
    alert["expiration"] = alert_params.get(
        "expiration", (toUTC(alert["utctimestamp"]) + offset).isoformat()
    )

    return alert


def process_sequence_alert(config, db, session, athena, alert_params):
    # For this sequence alert
    # for the first unfilled slot, search for matching events

    # load default params that may be missing in the alert config
    alert_params = merge(alert_params, get_sequence_alert_shell(alert_params))
    # we change the value of the slot
    # so lets iterate on index instead of just "for slot in slots"
    # find the first slot without matching events
    index, slot = first_matching_index_value(
        alert_params["slots"], condition=lambda i: not "triggered" in i
    )
    if slot:
        events = None
        # Search for slot criteria
        try:
            # resolve the criteria in case it's a chevron templated string
            criteria = chevron.render(slot["criteria"], alert_params)
            events = get_athena_events(criteria, config, athena, session)
        except Exception as e:
            logger.exception("Received exception while querying athena: %r" % e)

        # if slot is a threshold, are events matching criteria found?
        if slot["alert_type"] == "threshold" and events:
            # check to see if event(s) are already captured in an inflight alert
            # TODO: need to check events and their slot? or just events
            events = remove_inflight_events(db, events, alert_params)
            events = remove_previously_alerted(db, events, alert_params)
            if events:
                # do these events trigger the threshold alert in this slot?
                for alert in determine_threshold_trigger(slot, events):
                    # threshold met, save or create an inflight alert
                    inflight = deepcopy(alert_params)
                    inflight["slots"][index] = alert
                    save_inflight_alert(db, inflight)
        # if slot is a deadman, are we lacking enough events?
        if slot["alert_type"] == "deadman":
            # does the count or lack of events trigger the deadman alert in this slot?
            for alert in determine_deadman_trigger(slot, events):
                # criteria met, save or create an inflight alert
                inflight = deepcopy(alert_params)
                inflight["slots"][index] = alert
                save_inflight_alert(db, inflight)
    return


def get_athena_events(criteria, config, athena, session):
    events = []

    # query and wait for response
    query_status = None
    athena_query = get_athena_query(criteria, config)
    logger.debug(athena_query)
    athena_response = run_query(
        athena, athena_query, config.athenadatabase, default_bucket(session)
    )
    while query_status == "QUEUED" or query_status == "RUNNING" or query_status is None:
        query_status = athena.get_query_execution(
            QueryExecutionId=athena_response["QueryExecutionId"]
        )["QueryExecution"]["Status"]["State"]
        logger.debug(query_status)
        if query_status == "FAILED" or query_status == "CANCELLED":
            raise Exception(
                'Athena query with the string "{}" failed or was cancelled'.format(
                    athena_query
                )
            )
        if query_status != "SUCCEEDED":
            time.sleep(2)
    logger.debug("Query finished: {}".format(query_status))

    if query_status == "SUCCEEDED":
        # get the csv data athena produces and turn it into pandas/json
        pd_data = dataframe_from_athena_s3(
            session, athena_response, default_bucket(session)
        )
        # recreate event with nested json
        for message in pd_data.to_dict("records"):
            message["details"] = json.loads(message["details"])
            events.append(message)

    return events


def determine_deadman_trigger(alert_params, events):
    """Given a deadman alert's params and a set of events (or lack thereof)
    determine if it should fire and resolve summary/snippets, etc

    Largely the same as a threshold alert, except this accounts
    for a lack of events (altogether missing, or below a count) as the trigger
    """
    counts = mostCommon(events, alert_params["aggregation_key"])
    if not events:
        # deadman alerts are built to notice
        # when expected events are missing
        # but it means we have no events to pass on
        # make a meta event for the fact that events are missing
        events = []
        meta_event = {
            "utctimestamp": utcnow().isoformat(),
            "severity": "INFO",
            "summary": "Expected event not found",
            "category": "deadman",
            "source": "deadman",
            "tags": ["deadman"],
            "plugins": [],
            "details": {},
        }
        events.append(meta_event)

    if not counts:
        # make up a metadata count
        counts = [(alert_params["aggregation_key"], 0)]

    for i in counts:
        # lack of events, or event count below the threshold is a trigger
        if i[1] <= alert_params["threshold"]:
            alert = alert_params
            alert["triggered"] = True
            # set the summary via chevron/mustache template
            # with the alert plus metadata
            metadata = {"metadata": {"value": i[0], "count": i[1]}}
            alert = merge(alert, metadata)
            # limit events to those matching the aggregation_key value
            # so the alert only gets events that match the count mostCommon results
            alert["events"] = []
            for event in events:
                dotted_event = DotDict(event)
                if i[0] == dotted_event.get(alert_params["aggregation_key"]):
                    alert["events"].append(dotted_event)
            alert["summary"] = chevron.render(alert["summary"], alert)
            # walk the alert events for any requested event snippets
            for event in alert["events"][: alert_params["event_sample_count"]]:
                alert["summary"] += " " + chevron.render(
                    alert_params["event_snippet"], event
                )
            yield alert


def process_deadman_alert(config, db, session, athena, alert_params):
    events = []
    # load any default params that may be missing in the file
    alert_params = get_deadman_alert_shell(alert_params)
    try:
        events = get_athena_events(alert_params["criteria"], config, athena, session)
    except Exception as e:
        logger.exception("Received exception while querying athena: %r" % e)

    # see if the count of or lack of events is enough to trigger a deadman alert
    for alert in determine_deadman_trigger(alert_params, events):
        # criteria met, save
        save_alert(db, alert)


def determine_threshold_trigger(alert_params, events):
    """Given a threshold alert's params, and a set of events
    determine if it should fire and if so, resolve
    it's summary, event snippets, etc.
    """
    # mostCommon the events by the dotted aggregation key
    counts = mostCommon(events, alert_params["aggregation_key"])
    # determine if these events trigger an alert
    # according to the parameters
    logger.debug(counts)
    for i in counts:
        if i[1] >= alert_params["threshold"]:
            alert = alert_params
            alert["triggered"] = True
            # set the summary via chevron/mustache template
            # with the alert plus metadata
            metadata = {"metadata": {"value": i[0], "count": i[1]}}
            alert = merge(alert, metadata)
            # limit events to those matching the aggregation_key value
            # so the alert only gets events that match the count mostCommon results
            alert["events"] = []
            for event in events:
                dotted_event = DotDict(event)
                if i[0] == dotted_event.get(alert_params["aggregation_key"]):
                    alert["events"].append(dotted_event)
            alert["summary"] = chevron.render(alert["summary"], alert)
            # walk the alert events for any requested event snippets
            for event in alert["events"][: alert_params["event_sample_count"]]:
                alert["summary"] += " " + chevron.render(
                    alert_params["event_snippet"], event
                )
            yield alert


def process_threshold_alert(config, db, session, athena, alert_params):
    events = []
    # load any default params that may be missing in the file
    alert_params = get_threshold_alert_shell(alert_params)
    try:
        events = get_athena_events(alert_params["criteria"], config, athena, session)
    except Exception as e:
        logger.exception("Received exception while querying athena: %r" % e)

    if events:
        # first, drop any events we've already alerted on
        events = remove_previously_alerted(db, events, alert_params)
        # see if the aggregation for remaining events
        # meets the threshold to create an alert
        for alert in determine_threshold_trigger(alert_params, events):
            # threshold met, save
            save_alert(db, alert)


def main(config):
    # connect to mongo, aws
    client = pymongo.MongoClient(
        "mongodb://{}:{}/".format(config.mongohost, config.mongoport)
    )
    db = client[config.mongodatabase]
    session = boto3.session.Session()
    athena = session.client("athena")

    # debug, test connection
    if config.debug:
        logger.debug(client.admin.command({"listDatabases": 1}))

    # iterate inflight sequence alerts in the DB
    process_inflight_alerts(config, db, session, athena)

    # iterate alert files on disk
    # of all types
    for alert_file in glob.glob(config.alerts_file_mask):
        alert_params = yaml.safe_load(open(alert_file))
        if alert_params["alert_type"] == "threshold":
            process_threshold_alert(config, db, session, athena, alert_params)
        if alert_params["alert_type"] == "deadman":
            process_deadman_alert(config, db, session, athena, alert_params)
        if alert_params["alert_type"] == "sequence":
            process_sequence_alert(config, db, session, athena, alert_params)

    # for all sequence alerts in the DB
    # if slots are all met, create alert and remove inflight record
    create_sequence_alerts(db)
    # for all sequence alerts in the DB
    # expire any un-met inflight alerts that have exceeded their window
    expire_sequence_alerts(db)

    sys.exit()


if __name__ == "__main__":
    # config options from alerts.yaml or -c <filename>
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    args = parser.parse_args()

    with open(args.config or "{}".format(sys.argv[0].replace(".py", ".yml"))) as fd:
        config = DotDict(yaml.safe_load(fd))

    logging_config_file_path = Path(__file__).parent.joinpath(config.logging_config)
    with open(logging_config_file_path, "r") as fd:
        logging_config = yaml.safe_load(fd)
        logging.config.dictConfig(logging_config)

    logger = logging.getLogger()

    logger.debug("Logging configured")
    logger.debug(f"Configurated as {config}")
    main(config)