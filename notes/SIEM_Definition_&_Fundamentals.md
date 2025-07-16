# SIEM Definition & Fundamentals

Security Information and Event Management (SIEM) encompasses the utilization of software offerings and solutions that merge the management of security data with the supervision of security events. 

SIEM tools possess an extensive range of core functionalities, such as the collection and administration of log events, the capacity to examine log events and supplementary data from various sources, as well as operational features like incident handling, visual summaries, and documentation.

SIEM systems generate a vast number of alerts owing to the substantial volume of events produced for each monitored platform. It is not unusual for an hourly log of events to range from hundreds to thousands. As a result, fine-tuning the SIEM for detecting and alerting on high-risk events is crucial.

### SIEM Business Requirements & Use Cases

#### Log Aggregation & normalization

Log consolidation entails gathering terabytes of security information from vital firewalls, confidential databases, and essential applications.

By centralizing and correlating information from various sources, SIEM delivers a holistic strategy for threat detection and handling.

#### Threat Alerting

Advanced analytics and threat intelligence are employed by SIEM solutions to recognize potential threats and generate real-time alerts. When a threat is detected, the system forwards alerts to the IT security team, equipping them with the necessary details to effectively investigate and mitigate the risk. 

#### Contextualization & Response

It is important to understand that merely generating alerts is not enough. If a SIEM solution sends alerts for every possible security event, the IT security team will soon be overwhelmed by the sheer volume of alerts, and false positives may become a frequent issue, particularly in older solutions.

#### Compliance

SIEM solutions play a significant role in compliance by assisting organizations in meeting regulatory requirements through a comprehensive approach to threat detection and management.

Regulations like PCI DSS, HIPAA, and GDPR mandate organizations to implement robust security measures, including real-time monitoring and analysis of network traffic. SIEM solutions can help organizations fulfill these requirements, enabling SOC teams to detect and respond to security incidents promptly.

Automated reporting and auditing capabilities are also provided by SIEM solutions, which are essential for compliance. These features allow organizations to produce compliance reports swiftly and accurately, ensuring that they satisfy regulatory requirements and can demonstrate compliance to auditors and regulators.

### SIEM benefits as a solution

In the absence of a SIEM, IT personnel would not have a centralized perspective on all logs and events, which could result in overlooking crucial events and accumulating a large number of events awaiting investigation. Conversely, a properly calibrated SIEM bolsters the incident response process, improving efficiency and offering a centralized dashboard for notifications based on predetermined categories and event thresholds.

For instance, if a firewall records five successive incorrect login attempts, resulting in the admin account being locked, a centralized logging system that correlates all logs is necessary for monitoring the situation. Similarly, a web filtering software that logs a computer connecting to a malicious website 100 times in an hour can be viewed and acted upon within a single interface using a SIEM.

## Eastic Stack Introduction

![Eastic 2](./elastic1.webp)

`Elasticsearch` is a distributed and JSON-based search engine, designed with RESTful APIs. As the core component of the Elastic stack, it handles indexing, storing, and querying. Elasticsearch empowers users to conduct sophisticated queries and perform analytics operations on the log file records processed by Logstash.

`Logstash` is responsible for collecting, transforming, and transporting log file records. Its strength lies in its ability to consolidate data from various sources and normalize them. It can [Process Inputs](https://www.elastic.co/guide/en/logstash/current/input-plugins.html), [modify a log record's format and content](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html), [send logs to Elasticsearch](https://www.elastic.co/guide/en/logstash/current/output-plugins.html).

`Kibana` serves as the visualization tool for Elasticsearch documents. Users can view the data stored in Elasticsearch and execute queries through Kibana.

`Beats` is an additional component of the Elastic stack that simplifies collecting data from various sources.

### Elastic Stask as a SIEM solution

To implement the Elastic stack as a SIEM solution, security-related data from various sources such as firewalls, IDS/IPS, and endpoints should be ingested into the Elastic stack using Logstash. Elasticsearch should be configured to store and index the security data, and Kibana should be used to create custom dashboards and visualizations to provide insights into security-related events.

![dahsboard](./Elastic_dashboard.png)

Kibana Query Language (KQL) is a powerful and user-friendly query language designed specifically for searching and analyzing data in Kibana.

`Basic structure`: field:value, eg. `event.code:4625` for [Windows event code 4625](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625) aka a failed login attempt on windows machine. Useful for brute force attacks, password guessing etc. ...

`Free Text Search`: search for a specific term across multiple fields, eg. `svc-sql1`.

`Logical Operators`: KQL supports logical operators AND, OR, NOT and parentheses, eg. `event.code:4625 AND winlog.event_data.SubStatus:0xC0000072` to fiter data for events that have the Windows event code 4625 (login failure) and the SubStatus vaue 0xC0000072 (reason for a login failure, 0xC0000072 indicates account is currently disabed). This would require further investigation.

`Comparison Operators`: :, :>, :>=, :<, :<=, and :! . Eg. `event.code:4625 AND winlog.event_data.SubStatus:0xC0000072 AND @timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"` aka identify failed login attempts against disabled accounts that took place between March 3rd 2023 and March 6th 2023.

`Wildcards and Regular Expressions`: eg. `event.code:4625 AND user.name: admin*` aka failed login attempt for usernames that start with admin.

### How to Identify the Available Data

Using the [Discover feature](https://www.elastic.co/guide/en/kibana/current/discover.html) we can explore and sift through the avaiable data, as well as gain insight into the architecture of the available fields, before we start constructing KQL queries.

Enter any fields like "4625", "0xC0000072"...

Good documentations on fields to search up:
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)
- [Elastic Common Schema (ECS) event fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [Winlogbeat fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html)
- [Winlogbeat ECS fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html)
- [Winlogbeat security module fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-security.html)
- [Filebeat fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields.html)
- [Filebeat ECS fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html)



