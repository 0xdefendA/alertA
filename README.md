# alertA
An alert engine for the defendA data lake

## Why?
The [defendA data lake](https://github.com/0xdefendA/defenda-data-lake) is meant to be the easiest way to store unstructured JSON security data in a serverless architecture resulting in an easy to query Athena/S3 data lake. On it's own the data lake doesn't present a method to author or execute security alerting.

This project adds an alerting engine to the data lake. You can define alerts using simple .yaml files and template the structure and output of alerts without writing any code.

### Sequence alerts
Additionally this engine offers the capability of serveral types of alerts not usually seen in other alerting engines. Most notably is the 'sequence' alert.

With a sequence alert you define a series of triggers that have to occur in sequence in order for the alert to be triggered. This helps cut down on the false positives associated with single trigger alerts.

For example you can define an alert that triggers on a combination of failed login, successful login and account creation over some period of time and with configurable thresholds. Triggering on the combination of these events allows you to avoid investigating every occurance of the underlying events.


### Alert structure
Here's what a sample alert looks like:

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
The 'criteria' field is the SQL sent to Athena to gather events to consider for triggering an alert. The expectation is that there will be many events retrieved, then inspected for count thresholds, etc. i.e. the SQL does not have to be specific.

The 'summary' field is the text of the alert. You can include fields within the alert or events using {{fieldname}} formatting

The 'event_snippet' field is a sample of events you'd like to include in the alert text to give context.

'event_sample_count' is the max number of triggering events to include as part of the alert json structure

'threshold' is the number of events that would trigger an alert

'aggregation_key' is the field within an event to use when considering whether a series of events crosses the threshold for an alert.

'debug' is a debugging tag to signal verbose output

'tags' is a series of tags you'd like to apply to any alerts generated via this criteria.
