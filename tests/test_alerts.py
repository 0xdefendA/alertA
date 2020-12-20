import unittest
from io import BytesIO
from subprocess import PIPE, Popen
from pkg_resources import parse_version
import pytest
import pandas as pd
import pymongo
import yaml
import json
import glob
import logging, logging.config
from pathlib import Path
from utils.dates import utcnow
from pytest_docker_tools import build, container, fetch
from alerta import generate_meteor_id
from alerta import (
    get_threshold_alert_shell,
    get_sequence_alert_shell,
    get_deadman_alert_shell,
)
from alerta import remove_previously_alerted, remove_inflight_events
from alerta import save_alert, save_inflight_alert
from alerta import determine_threshold_trigger
from alerta import expire_sequence_alerts, create_sequence_alerts

mongo_image = fetch(repository="mongo:latest")

mongo_session = container(
    image="{mongo_image.id}",
    scope="session",
    ports={
        "27017/tcp": 27017,
    },
)
print("setting up logging")
logging_config_file_path = Path(__file__).parent.joinpath("logging_config.yml")
with open(logging_config_file_path, "r") as fd:
    logging_config = yaml.safe_load(fd)
    logging.config.dictConfig(logging_config)
global logger
logger = logging.getLogger()
logger.info("logging established")


@pytest.fixture(scope="module")
def mongo_connection(mongo_session):
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    return client


class TestAlertSetup(object):
    def test_mongo_instance(self, mongo_connection, mongo_session):
        assert "Waiting for connections" in mongo_session.logs()
        # client = pymongo.MongoClient(f'mongodb://{mongo_ip}:27017/')
        print(mongo_connection)
        assert mongo_connection["connect"]

    def test_database(self, mongo_connection):
        # the database to be used
        db = mongo_connection.test_alerta
        # the collection to be used
        alerts = db["alerts"]
        # flush the collection
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0
        result = alerts.insert_one({"x": 1})
        # print(result.inserted_id)
        assert alerts.count_documents({}) == 1
        alerts.delete_one({"_id": result.inserted_id})
        assert alerts.count_documents({}) == 0


class TestAlertFunctions(object):
    def test_generate_meteor_id(self):
        id = generate_meteor_id()
        # print(id)
        assert len(id) == 24

    def test_get_threshold_alert_shell(self):
        default_shell = get_threshold_alert_shell({})
        assert default_shell["alert_name"] == "unnamed"
        assert default_shell["alert_type"] == "threshold"
        assert default_shell["severity"] == "INFO"
        # ensure it's not naive
        assert "+00:00" in default_shell["utctimestamp"]

        non_default_shell = default_shell
        non_default_shell["alert_name"] = "test"
        result_shell = get_threshold_alert_shell(non_default_shell)
        assert result_shell["alert_name"] == "test"

    def test_get_sequence_alert_shell(self):
        default_shell = get_sequence_alert_shell({})
        assert default_shell["alert_name"] == "unnamed"
        assert default_shell["alert_type"] == "sequence"
        assert default_shell["severity"] == "INFO"
        assert default_shell["lifespan"] == "3 days"
        # ensure it's not naive
        assert "+00:00" in default_shell["utctimestamp"]

    def test_save_alert(self, mongo_connection):
        db = mongo_connection.test_alerta
        alerts = db["alerts"]
        assert alerts.count_documents({}) == 0
        alert_shell = get_sequence_alert_shell({})
        alert_shell["alert_name"] == "test"
        save_alert(db, alert_shell)
        assert alerts.count_documents({}) == 1
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0

    def test_remove_previously_alerted(self, mongo_connection):
        db = mongo_connection.test_alerta
        alerts = db["alerts"]
        inflight_alerts = db["inflight_alerts"]
        assert alerts.count_documents({}) == 0
        assert inflight_alerts.count_documents({}) == 0
        events = []
        for file in glob.glob("./tests/samples/sample_cloudtrail_event.json"):
            events += json.load(open(file))
        assert len(events) > 0

        # threshold event
        alert_shell = get_threshold_alert_shell({})
        alert_shell["alert_name"] == "test"
        save_alert(db, alert_shell)
        # alert has no events, remove should be a no-op
        resulting_events = remove_previously_alerted(db, events, alert_shell)
        assert len(resulting_events) == len(events)
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0

        # add event(s) to alert and save
        alert_shell["events"] = events
        save_alert(db, alert_shell)
        # events we present should be a duplicate and removed
        resulting_events = remove_previously_alerted(db, events, alert_shell)
        assert len(resulting_events) == 0
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0

        # sequence alert with slots of events
        alert_shell = get_sequence_alert_shell({})
        alert_shell["alert_name"] == "test"
        # make a slot of events
        alert_shell["slots"] = []
        alert_slot = get_threshold_alert_shell({})
        alert_shell["slots"].append(alert_slot)

        save_inflight_alert(db, alert_shell)
        assert inflight_alerts.count_documents({}) == 1
        # alert has no events, remove should be a no-op
        resulting_events = remove_inflight_events(db, events, alert_shell)
        assert len(resulting_events) == len(events)
        inflight_alerts.delete_many({})
        assert inflight_alerts.count_documents({}) == 0

        # # add event(s) to alert and save
        alert_shell["slots"] = [{"events": []}, {"events": []}, {"events": []}]
        alert_shell["slots"][0]["events"] = events
        save_inflight_alert(db, alert_shell)
        assert inflight_alerts.count_documents({}) == 1

        # # events we present should be a duplicate and removed
        resulting_events = remove_inflight_events(db, events, alert_shell)
        assert len(resulting_events) == 0
        inflight_alerts.delete_many({})
        assert inflight_alerts.count_documents({}) == 0

        # check another slot
        alert_shell["slots"] = [{"events": []}, {"events": []}, {"events": []}]
        alert_shell["slots"][1]["events"] = events
        save_inflight_alert(db, alert_shell)
        assert inflight_alerts.count_documents({}) == 1
        # # events we present should be a duplicate and removed
        resulting_events = remove_inflight_events(db, events, alert_shell)
        assert len(resulting_events) == 0
        inflight_alerts.delete_many({})
        assert inflight_alerts.count_documents({}) == 0

    def test_expire_sequence_alerts(self, mongo_connection):
        # setup
        db = mongo_connection.test_alerta
        inflight_alerts = db["inflight_alerts"]
        inflight_alerts.delete_many({})
        assert inflight_alerts.count_documents({}) == 0
        # create an expired sequence alert, and see if the routine removes it
        offset = pd.Timedelta("7 days").to_pytimedelta()
        last_week = utcnow() - offset
        alert_shell = {"utctimestamp": last_week.isoformat(), "lifespan": "1 day"}
        alert_shell = get_sequence_alert_shell(alert_shell)
        # print(alert_shell)
        save_inflight_alert(db, alert_shell)
        assert inflight_alerts.count_documents({}) == 1
        expire_sequence_alerts(db)
        assert inflight_alerts.count_documents({}) == 0

        # tear down
        inflight_alerts.delete_many({})
        assert inflight_alerts.count_documents({}) == 0

    def test_save_resolved_threshold_alert(self, mongo_connection):
        # threshold alerts look for a count by an aggregation key
        # in events that meet a criteria
        # ex: >1 AWS console login without MFA
        # and trigger an alert with a summary field that pulls from
        # the events
        # setup
        db = mongo_connection.test_alerta
        alerts = db["alerts"]
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0

        alert_shell = get_threshold_alert_shell({"alert_name": "test_threshold"})
        # a summary that will get resolved by the events
        alert_shell[
            "summary"
        ] = "{{events.0.eventname}} by {{events.0.useridentity.type}} {{metadata.count}} mfa:{{events.0.additionaleventdata.mfaused}}"
        alert_shell[
            "event_snippet"
        ] = "{{eventname}}/{{responseelements.consolelogin}} mfa:{{additionaleventdata.mfaused}} from {{sourceipaddress}}"
        # set the aggregation key to count events by
        # >= "threshold" of the events by this key will trip the alert
        alert_shell["aggregation_key"] = "additionaleventdata.mfaused"

        # create some events that satisfy the sequence
        # root user with no mfa
        events = []
        for file in glob.glob("./tests/samples/sample_cloudtrail_login_no_mfa.json"):
            events += json.load(open(file))
        assert len(events) > 0
        for alert in determine_threshold_trigger(alert_shell, events):
            logger.info(f"summary + snippet: {alert['summary']}")
            assert "ConsoleLogin by Root" in alert["summary"]
            # test event snippet by picking data in the json file
            assert "from 6.9.9.93" in alert["summary"]

    def test_save_resolved_deadman_alert(self, mongo_connection):
        # deadman alerts look for a lack of expected events
        # either no events at all, or below the expected threshold

        # setup
        db = mongo_connection.test_alerta
        alerts = db["alerts"]
        alerts.delete_many({})
        assert alerts.count_documents({}) == 0

        alert_shell = get_deadman_alert_shell({"alert_name": "test_threshold"})
        # a summary that will let us know we are missing expected events
        alert_shell["summary"] = "Expected events are missing"
        # alert_shell["aggregation_key"] = "doesnt.matter"
        # create some events that should happen all the time
        # to make sure we don't fire when we have events
        # a one login logon event
        events = []
        for file in glob.glob("./tests/samples/sample_OneLogin_EventBridge_Raw.json"):
            events += json.load(open(file))
        assert len(events) > 0
        alerts = list(determine_threshold_trigger(alert_shell, events))
        assert len(alerts) == 0

    def test_save_resolved_sequence_alert(self, mongo_connection):
        # sequence alerts are just a series of alerts
        # which should all be resolved (in order) before the alert
        # is created
        # the alerts are carried in 'slots' in the
        # sequence alert, all slots full of events and the alert fires.

        # setup
        db = mongo_connection.test_alerta
        inflight_alerts = db["inflight_alerts"]
        alerts = db["alerts"]
        alerts.delete_many({})
        inflight_alerts.delete_many({})
        assert alerts.count_documents({}) == 0
        assert inflight_alerts.count_documents({}) == 0
        # create an fulfilled sequence alert, and see if
        # it triggers an alert creation
        alert_shell = {"utctimestamp": utcnow().isoformat(), "lifespan": "7 day"}
        alert_shell = get_sequence_alert_shell(alert_shell)
        # create some events that satisfy the sequence
        # root user with no mfa
        events = []
        for file in glob.glob("./tests/samples/sample_cloudtrail_login_no_mfa.json"):
            events += json.load(open(file))
        assert len(events) > 0
        # a summary that will get resolved by the events in the slots
        alert_shell[
            "summary"
        ] = "{{slots.0.events.0.eventname}} by {{slots.0.events.0.useridentity.type}} {{metadata.count}} mfa:{{slots.0.events.0.additionaleventdata.mfaused}}"

        alert_shell["slots"] = []
        # make a slot of threshold alert + events that trigger it
        alert_slot = get_threshold_alert_shell({})
        alert_slot[
            "event_snippet"
        ] = "{{eventname}}/{{responseelements.consolelogin}} mfa:{{additionaleventdata.mfaused}} from {{sourceipaddress}}"
        alert_slot["aggregation_key"] = "additionaleventdata.mfaused"
        alert_slot["events"] = events

        # since we are injecting alerts instead of querying athena
        # resolve the slot threshold alert manually
        for alert in determine_threshold_trigger(alert_slot, events):
            # did the snippet get resolved?
            assert "ConsoleLogin/Success" in alert["summary"]
            # did events get copied into the resulting alert?
            assert len(alert["events"]) > 0
            # add this resolved threshold alert as a slot in the sequence alert
            alert_shell["slots"].append(alert)
        # save this inflight sequence alert
        save_inflight_alert(db, alert_shell)
        assert inflight_alerts.count_documents({}) == 1
        # run the routine resolving sequence alerts: create_sequence_alerts
        create_sequence_alerts(db)
        # assert there is a new alert created
        assert alerts.count_documents({}) == 1
        for alert in alerts.find({}):
            logger.info(f"found db alert: {alert['summary']}")
            # ensure the summary description was
            # resolved correctly by chevron
            assert "ConsoleLogin by Root" in alert["summary"]
            # ensure event snippets are preseved
            assert "ConsoleLogin/Success" in alert["slots"][0]["summary"]
            logger.info(f"found slot in sequence: {alert['slots'][0]['summary']}")
        # assert the inflight alert is removed
        assert inflight_alerts.count_documents({}) == 0