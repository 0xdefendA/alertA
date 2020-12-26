# alertA
An alert engine for the [defendA data lake](https://github.com/0xdefendA/defenda-data-lake)

## Why?
The [defendA data lake](https://github.com/0xdefendA/defenda-data-lake) is meant to be the easiest way to store unstructured JSON security data in a serverless architecture resulting in an easy to query Athena/S3 data lake. On it's own the data lake doesn't present a method to author or execute security alerting.

This project adds an alerting engine to the data lake. You can define alerts using simple .yaml files and template the structure and output of alerts without writing any code.

### Alert types: threshold, deadman and sequence
This engine includes the usual threshold alert type where you can choose a threshold of events that have to occur over some period of time grouped by a common element. i.e. X failed logins by username.

The engine also offers the 'deadman' type alert to fire when an expected event (or batch of events) is missing. For example this can be used to let you know you aren't receiving events from a particular source (google/okta/etc) and there may be a problem in your pipeline.

Additionally this engine offers a capability not usually seen in other alerting engines: the sequence alert.

With a sequence alert you define a series of triggers that have to occur in sequence in order for the alert to be triggered. This helps cut down on the false positives associated with single trigger alerts.

For example you can define an alert that triggers on a combination of failed login, successful login and account creation over some period of time and with configurable thresholds. Triggering on the combination of these events allows you to avoid investigating every occurance of the underlying events.

You can combine threshold and deadman alerts in whatever way makes sense for the alert you are trying to craft. For example lets say we store our AWS root account password in our company password vault and we are concerned that someone external may possess or discover the credentials, or that internal people may use it without accessing the password vault (meaning they've incorrectly stored it).

The idea for the alert is then a combination of threshold and deadman:

 - threshold >= 1 of a login to the aws root account
 - deadman lack of access to the creds for the account password vault (via api like https://bitwarden.com/help/article/event-logs/ )

 This ability to combine threshold and deadman criteria in combnation sequences makes this engine a powerful ally.


### Alert structure
Here's what a simple sample threshold alert looks like:

```yaml
---
alert_name: "aws_console_login"
alert_type: "threshold"
category: "authentication"
criteria: "source='cloudtrail' AND json_extract_scalar(details,'$.eventname') = 'ConsoleLogin'"
severity: "INFO"
summary: "User {{metadata.value}} {{metadata.count}} console logins"
event_snippet: "{{details.useridentity.arn}} to account {{details.recipientaccountid}} from IP {{details.sourceipaddress}}"
event_sample_count: 5
threshold: 1
aggregation_key: "details.useridentity.arn"
debug: True
tags:
  - "login"
  - "aws"
```

This alert is looking for AWS console logins, triggering on any single login and including details from the last 5 that match in the alert text.

#### Alert definition fields
The 'criteria' field is the SQL sent to Athena to gather events to consider for triggering an alert. The expectation is that there will be many events retrieved, then inspected for count thresholds, etc. i.e. the SQL does not have to be precise enough to select a single record.

The 'summary' field is the text of the alert. You can include fields within the alert or events using {{fieldname.subfieldname}} formatting.

The 'event_snippet' field is a sample of events you'd like to include in the alert text to give context.

'event_sample_count' is the max number of triggering events to include as part of the alert json structure. These will be a full copy of the event(s) that triggered the alert stored in the 'events' json key as a list.

'threshold' is the number of events that would trigger an alert (>= triggers a threshold alert, <= triggers a deadman alert>).

'aggregation_key' is the field within an event to use when considering whether a series of events crosses the threshold for an alert.

'debug' is a debugging tag to signal verbose output.

'tags' is a series of tags you'd like to apply to any alerts generated via this criteria.

### Sequence Alerts
Sequence alerts are a set of alerts that have to all be satisfied in order for the sequence alert to be triggered.

Sequence alerts consist of some metadata and a series of alerts in 'slots'. Each slot can be any alert you can define. If all the slots trigger, the sequence alert triggers. If the slots do not trigger within the timeout period of the sequence alert, the alert does not trigger.

Each slot can reference data within other slots, so you can establish alerts that do things like watch for failed logins, followed by successful login followed by program installation for a single user.

#### Sample Sequence Alert
Lets look at a sample sequence alert looking for risky logins. We will be using authentication events from OneLogin as OneLogin has a concept of a risk score associated with a login. It uses this to drive MFA decisions, etc but it should be unusual for someone to have multiple risky logins within a period of time. So while a normal alerting system would force you to trigger an alert on a single 'risky login', alertA can allow you to trigger only on multiple risky logins over a length of time.

Here's the alert definition:
```yaml
---
alert_name: "multiple_risky_logins"
alert_type: "sequence"
lifespan: "7 days"
severity: "INFO"
summary: "Multiple {{metadata.count}} risky logins by {{slots.0.events.0.details.user_name}}"
debug: True
category: "authentication"
tags:
    - "login"
    - "onelogin"
slots:
    -
        alert_name: "risky_login_1"
        alert_type: "threshold"
        severity: "INFO"
        criteria: "source='onelogin' AND CAST(json_extract_scalar(details,'$.risk_score') as INTEGER)>80"
        summary: "risky login by {{events.0.details.user_name}} risk score: {{events.0.details.risk_score}}"
        event_snippet: "{{details.user_name}} risk score {{details.risk_score}} from IP {{details.sourceipaddress}}"
        aggregation_key: "details.user_name"
        threshold: 1
        event_sample_count: 5
    -
        alert_name: "risky_login_2"
        alert_type: "threshold"
        severity: "INFO"
        criteria: "source='onelogin' AND CAST(json_extract_scalar(details,'$.risk_score') as INTEGER)>80 AND json_extract_scalar(details,'$.user_name')='{{slots.0.events.0.details.user_name}}'"
        summary: "risky login by {{events.0.details.user_name}} risk score: {{events.0.details.risk_score}}"
        event_snippet: "{{details.user_name}} risk score {{details.risk_score}} from IP {{details.sourceipaddress}}"
        aggregation_key: "details.user_name"
        threshold: 1
        event_sample_count: 5

```

The alert is looking for a series of two logins from the same user with a risk score greater than 80 over a period of 7 days. The alerts are in 'slots' and use aws Athena SQL as the language wich allows for access to the nested json particular to an event from OneLogin. For more on the SQL/structure please see the [datalake project](https://github.com/0xdefendA/defenda-data-lake).

#### Structure
To unpack the metadata, alert_name is simply the name we decide to give it. The alert_type is 'sequence' since we are looking for more than one thing to happen in order to trigger. The lifespan is the length of time this alert will live while it looks for all slots to satisfy. So if slot 0 is triggered, an 'in flight' alert is created looking for slot 1 to be triggered. If that happens within 7 days, the sequence alert fires. If 7 days pass without slot 1 triggering the alert is torn down and the cycle begins again.

The severity, etc fields are self-evident. The summary field is the text of the alert that will be created and can use templating to incorporate fields from within the alert structure. As you can see, you can incorporate data from any of the sub events that trigger a slot with template notation like `{{slots.0.events.0.details.user_name}}` which refers to the alert in slot 0, the first event that triggered that alert, the details substructure and the user_name field within. With this templating you can format the text to be practically anything you'd like.

This templating extends to the 'slots' for alerts as well. You can see an example in the critera for the 2nd slot:

```yaml
criteria: "source='onelogin' AND CAST(json_extract_scalar(details,'$.risk_score') as INTEGER)>80 AND position('Defaulted' IN json_extract_scalar(details,'$.risk_reasons'))=0 AND json_extract_scalar(details,'$.user_name')='{{slots.0.events.0.details.user_name}}'"
```
`{{slots.0.events.0.details.user_name}}` is a reference to the previous slot, first event, details.user_name field within that slot. This is how this sequence alert manages to trigger only when a particular user has more than X risky logins within a period of time, but you can also use this to tie slots together in whatever manner makes sense for your use case.

'In flight' sequence alerts are stored in the mongo collection called `inflight_alerts`. You can inspect this collection to get a sense of how your alerts are functioning, how many are being processed, etc.


## Docker
To get up and running quickly simply:

```bash
docker-compose -f docker-compose.yml -p alerta up
```
and you will end up with 2 containers (python and mongoDB) running the alertA code in this repo with a sample alert looking for a console login to aws.

This will get you up and running, for a production deployment you'll want a permanent data storage for the mongo database to preserve your alerts.

