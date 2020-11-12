# alertA
An alert engine for the defendA data lake

## Why?
The defendA data lake is meant to be the easiest way to store unstructured JSON security data in a serverless architecture resulting in an easy to query Athena/S3 data lake. On it's own the data lake doesn't present a method to author or execute security alerting.

This project adds an alerting engine to the data lake. You can define alerts using simple .yaml files and template the structure and output of alerts without writing any code.

### Sequence alerts
Additionally this engine offers the capability of serveral types of alerts not usually seen in other alerting engines. Most notably is the 'sequence' alert.

With a sequence alert you define a series of triggers that have to occur in sequence in order for the alert to be triggered. This helps cut down on the false positives associated with single trigger alerts.

For example you can define an alert that triggers on a combination of failed login, successful login and account creation over some period of time and with configurable thresholds. Triggering on the combination of these events allows you to avoid investigating every occurance of the underlying events.
