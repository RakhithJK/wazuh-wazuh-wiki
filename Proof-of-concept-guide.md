## <a name="version"></a>Guide version
This guide is compatible with Wazuh 4.2.0 and later. [Click here for older versions.](https://github.com/wazuh/wazuh/wiki/Proof-of-concept-guide/b3681f865eb671a0b0d13a1b1012477fd0d932ba)

## Index

- [Guide version](#version)

- [Auditing commands run by user](#audit)

- [Amazon AWS infrastructure monitoring](#aws)

- [Detecting a brute-force attack](#brute_force)

- [Monitoring Docker](#docker)

- [File integrity monitoring](#fim)

- [Blocking a malicious actor - IP Reputation](#ip_reputation)

- [Detecting unauthorized processes - Netcat](#netcat)

- [Osquery integration](#osquery)

- [Network IDS integration - Suricata](#suricata)

- [Detecting a web attack - Shellshock](#shellshock)

- [Detecting a web attack - SQL Injection](#sql_injection)

- [Slack integration](#slack)

- [Detecting suspicious binaries - Trojan](#trojan)

- [Detecting and removing malware - VirusTotal integration](#virustotal)

- [Vulnerability Detector](#vulnerability_detector)

- [Detecting malware - Yara](#yara)

## Introduction

The following document explains how to set up the Wazuh environment to test the different product capabilities.  It assumes that these components are already installed:

- Elasticsearch + Kibana + Wazuh Kibana plugin
- Wazuh manager + Filebeat (for integration with Elasticsearch)
- Wazuh agent (RHEL 7)
- Wazuh agent (Windows)

A good guide on how to install these components can be found at [our installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

The sections below explain the required configurations to set up different use cases.

## <a name="audit"></a>Auditing commands run by user

On the Linux monitored endpoint (RHEL), configure Audit logging to capture execve system calls (necessary to audit commands run by users). More info on [Audit Configuration Guide](https://documentation.wazuh.com/current/learning-wazuh/audit-commands.html).

RHEL also has good documentation about Audit kernel subsystem, check  [RHEL Audit documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing) for more information about this.

#### Configuration

- Install audit

- In order to monitor your user actions, get your current EUID ('root' user monitoring is not recommended for the test, as it can be quite noisy).

```
echo $EUID
```

- Configure `/etc/audit/rules.d/audit.rules`:

```
-a exit,always -F euid=${replace_by_your_user_euid} -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=${replace_by_your_user_euid} -F arch=b64 -S execve -k audit-wazuh-c
```

- Delete old rules (optional)

```
auditctl -D
```

- Update rules

```
auditctl -R /etc/audit/rules.d/audit.rules
```

#### Steps to generate the alerts

- Log in the RHEL Agent as the monitored user
- Execute a ping to `www.google.com`

#### Alerts

Related alerts can be found with:

- `data.audit.exe: "/usr/bin/ping"`

#### Affected endpoint

- RHEL 7 Agent


## <a name="aws"></a>Amazon AWS infrastructure monitoring

Wazuh module for AWS (aws-s3) enables log data gathering from different AWS sources. You can find a detailed guide on how to Monitor AWS resources in Wazuh [AWS Monitoring guide](https://documentation.wazuh.com/4.0/amazon/index.html)

#### Configuration

- Enable `aws-s3` wodle in `/var/ossec/etc/ossec.conf` in the Wazuh manager configuration file:

```xml
<wodle name="aws-s3">
    <disabled>no</disabled>
    <remove_from_bucket>no</remove_from_bucket>
    <interval>30m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>no</skip_on_error>
    <bucket type="cloudtrail">
      <name>wazuh-cloudtrail</name>
      <access_key>${replace_by_your_AwsAccessKey}</access_key>
      <secret_key>${replace_by_your_AwsSecretKey}</secret_key>
      <only_logs_after>2020-MAR-24</only_logs_after>
    </bucket>
    <bucket type="guardduty">
      <name>wazuh-aws-wodle</name>
      <path>guardduty</path>
      <access_key>${replace_by_your_AwsAccessKey}</access_key>
      <secret_key>${replace_by_your_AwsSecretKey}</secret_key>
      <only_logs_after>2020-MAR-24</only_logs_after>
    </bucket>
    <bucket type="custom">
      <name>wazuh-aws-wodle</name>
      <path>macie</path>
      <access_key>${replace_by_your_AwsAccessKey}</access_key>
      <secret_key>${replace_by_your_AwsSecretKey}</secret_key>
      <only_logs_after>2020-MAR-24</only_logs_after>
    </bucket>
    <bucket type="vpcflow">
      <name>wazuh-aws-wodle</name>
      <path>vpc</path>
      <access_key>${replace_by_your_AwsAccessKey}</access_key>
      <secret_key>${replace_by_your_AwsSecretKey}</secret_key>
      <only_logs_after>2020-MAR-24</only_logs_after>
    </bucket>
    <service type="inspector">
      <access_key>${replace_by_your_AwsAccessKey}</access_key>
      <secret_key>${replace_by_your_AwsSecretKey}</secret_key>
    </service>
</wodle>
```

#### Steps to generate the alerts

- Alerts are automatically generated from AWS logs (when using out-of-the-box rules). They will appear as soon as they are fetched from the AWS S3 bucket.

#### Alerts

Related alerts can be found with:

- `rule.groups: "amazon"`

#### Affected endpoint

- Wazuh manager


## <a name="brute_force"></a>Detecting a brute-force attack

Brute forcing SSH (on Linux) or RDP (on Windows) are common attack vectors. Wazuh provides out of the box rules capable of identifying brute-force attacks, by correlating multiple authentication failure events.

#### Configuration

- Ensure you have SSH installed and enabled.

- If you want to execute automated RDP connections you can use `hydra`:

```
yum install -y hydra
```

#### Steps to Generate the alerts

Run multiple failed authentication failure attempts against the monitored endpoints:

- Linux example :

```
for i in `seq 1 10`; do sshpass -p 'wrong_password' ssh -o StrictHostKeyChecking=no <rhel-agent-endpoint>; done
```

- Windows example:

```
hydra -l Administrator -p wrong_password <win-agent-endpoint> rdp
```

#### Alerts

- Linux: `rule.id:(5710 OR 5712)` (other related rules are 5711, 5716, 5720, 5503, 5504)
- Windows: `rule.id:(60122 OR 60137)`

#### Affected endpoints

- Linux RHEL
- Windows


## <a name="docker"></a>Monitoring Docker

The Wazuh module for Docker can be used to identify security incidents across containers, alerting in real-time. It acts as a subscriber to the Docker Engine API.

Check [Docker Wodle](https://documentation.wazuh.com/4.0/docker-monitor/monitoring_containers_activity.html) for detailed info

#### Configuration

- On the monitored system (the Docker host), install required Wazuh module dependency `pip install docker`

- Configure the Docker listener in the RHEL Agent

```xml
<ossec_config>
    <wodle name="docker-listener">
    <interval>10m</interval>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <disabled>no</disabled>
    </wodle>
</ossec_config>
```

#### Steps to generate the alerts

- Perform any usual Docker action like pulling an image, starting a container, running a command or deleting the container.

```
docker stop `docker ps -a -q` && docker rm `docker ps -a -q`
docker pull nginx
docker run -d -P --name nginx_container nginx
docker exec -ti nginx_container cat /etc/passwd
docker exec -ti nginx_container /bin/bash
docker stop nginx_container
docker rm nginx_container
```

#### Alerts

Related alerts can be found with:

- `rule.groups: "docker"`
- It's interesting to check for `data.docker.Action` field which states which action was performed

#### Affected endpoint

- Linux RHEL

## <a name="fim"></a>File integrity monitoring

#### Configuration

- Enable whodata on the monitored endpoint (RHEL and Windows) ossec.conf file. Optionally, this can also be done through centralized configuration groups:

```xml
<directories check_all="yes" whodata="yes">/usr/bin,/usr/sbin</directories>
<directories check_all="yes" whodata="yes">/bin,/sbin,/boot</directories>
<directories check_all="yes" report_changes="yes" whodata="yes" tags="cron">/etc/cron*</directories>
<directories check_all="yes" report_changes="yes" whodata="yes" recursion_level="2">/home,/root</directories>
```

- Add directories to be monitored on the Windows endpoint:

```xml
<scan_on_start>yes</scan_on_start>
<directories check_all="yes" report_changes="yes" whodata="yes">C:\\Users\\Administrator\\Desktop</directories>
<directories check_all="yes" report_changes="yes" whodata="yes">C:\\Wazuh</directories>
```

#### Steps to generate the alerts

- Create, remove, or modify a file in the monitored directories.

#### Alerts

Related alerts can be found with:

- `syscheck.path: "{path_to_the_modified_file}"`

#### Affected endpoints

- Linux RHEL
- Windows


## <a name="ip_reputation"></a>Blocking a malicious actor - IP Reputation

#### Prerequesites

- Apache server running on the monitored system (Linux RHEL)

- Wazuh agent configured to monitor the Apache access logs:

```xml
    <localfile>
       <log_format>apache</log_format>
       <location>/var/log/httpd/access_log</location>
    </localfile>
```

#### Configuration

On Wazuh manager (the server):

- Download Alienvault IP reputation database

```
wget https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
```

- Download script to convert from ipset format to cdblist format

```
wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
```

- Add an additional IP (the attacker) to the list. For the test, we will use the Windows endpoint.

```
echo "${replace_by_your_windows_ip_address}" >> /var/ossec/etc/lists/alienvault_reputation.ipset
```

- Convert the `.ipset` to `.cdb` using the previously downloaded script

```
python /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault
```

- Remove the `.ipset` file and the Python script

```
rm -rf /var/ossec/etc/lists/alienvault_reputation.ipset
rm -rf /var/ossec/etc/lists/iplist-to-cdblist.py
```

- Assign the right permissions and owner to the generated file:

```
chown ossec:ossec /var/ossec/etc/lists/blacklist-alienvault
chmod 660 /var/ossec/etc/lists/blacklist-alienvault
```

- Execute ossec binary to generate `.cdb` file

```
/var/ossec/bin/ossec-makelists
```

- Add a custom rule to trigger the active response. This can be done at `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="attack,">
  <rule id="100100" level="10">
    <if_group>web|attack|attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
```

- Add configuration to trigger the active response. Modify the `ruleset` block in the `/var/ossec/etc/ossec.conf` file:

```xml
<ossec_config>
    <ruleset>
        <!-- Default ruleset -->
        <decoder_dir>ruleset/decoders</decoder_dir>
        <rule_dir>ruleset/rules</rule_dir>
        <rule_exclude>0215-policy_rules.xml</rule_exclude>
        <list>etc/lists/audit-keys</list>
        <list>etc/lists/blacklist-alienvault</list>
        <!-- User-defined ruleset -->
        <decoder_dir>etc/decoders</decoder_dir>
        <rule_dir>etc/rules</rule_dir>
    </ruleset>

    <command>
        <name>firewall-drop</name>
        <executable>firewall-drop</executable>
        <timeout_allowed>yes</timeout_allowed>
    </command>

    <active-response>
        <command>firewall-drop</command>
        <location>local</location>
        <rules_id>100100</rules_id>
        <timeout>60</timeout>
    </active-response>
</ossec_config>
```

- Restart the Wazuh Manager
```
/var/ossec/bin/ossec-control restart
```

#### Steps to generate the alerts

- Log in the attacker system (the Windows box) and connect to the victim (Linux RHEL) Apache server from a web browser.
- A Linux firewall rule will temporarily block any connection from the attacker system for 60 seconds (using IPtables).

#### Alerts

Related alerts can be found with:

- ```rule.id:(601 OR 100100)```

#### Affected endpoint

- Linux RHEL


## <a name="netcat"></a>Detecting unauthorized processes - Netcat

Wazuh is capable of detecting if Netcat is running on a monitored host.

#### Configuration

On the monitored endpoint (Linux RHEL):

- Add `<localfile>` configuration block to periodically get a list of running processes. This can be done in the `ossec.conf` file.

```xml
<ossec_config>
    <localfile>
        <log_format>full_command</log_format>
        <alias>process list</alias>
        <command>ps -e -o pid,uname,command</command>
        <frequency>30</frequency>
    </localfile>
</ossec_config>
```

- Restart the Wazuh agent to apply changes

```
systemctl restart wazuh-agent
```

- Install Netcat and required dependencies

```xml
yum install nmap-ncat
```

On Wazuh Manager:

- Add following rules to  `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="ossec,">
    <rule id="100050" level="0">
        <if_sid>530</if_sid>
        <match>^ossec: output: 'process list'</match>
        <description>List of running processes.</description>
        <group>process_monitor,</group>
    </rule>
    <rule id="100051" level="7" ignore="900">
        <if_sid>100050</if_sid>
        <match>nc -l</match>
        <description>Netcat listening for incoming connections.</description>
        <group>process_monitor,</group>
    </rule>
</group>
```

#### Steps to Generate alerts

- Log in to the RHEL system and run `nc -l -p 8000` (keep it running for 30 seconds)

#### Alerts

- ```rule.id:(601 OR 100100)```

#### Affected endpoint

- Linux RHEL


## <a name="osquery"></a>Osquery integration

Wazuh agent can be integrated with Osquery, making it easy to capture additional information from the endpoint. This can be useful for telemetry and threat hinging. More info at [Wazuh Osquery documentation](https://documentation.wazuh.com/4.0/user-manual/capabilities/osquery.html)

#### Configuration

On the monitored endpoint (RHEL Linux):

- Install Osquery

```
yum install -y https://pkg.osquery.io/rpm/osquery-4.5.1-1.linux.x86_64.rpm
```

- Set the content of the Osquery configuration file  `/etc/osquery/osquery.conf` to:

```yaml
{
"options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "utc": "true"
},

"schedule": {
    "system_info": {
        "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
        "interval": 3600
    },
    "high_load_average": {
        "query": "SELECT period, average, '70%' AS 'threshold' FROM load_average WHERE period = '15m' AND average > '0.7';",
        "interval": 900,
        "description": "Report if load charge is over 70 percent."
    },
    "low_free_memory": {
        "query": "SELECT memory_total, memory_free, CAST(memory_free AS real) / memory_total AS memory_free_perc, '10%' AS threshold FROM memory_info WHERE memory_free_perc < 0.1;",
        "interval": 1800,
        "description": "Free RAM is under 10%."
    }
},

"packs": {
    "osquery-monitoring": "/usr/share/osquery/packs/osquery-monitoring.conf",
    "incident-response": "/usr/share/osquery/packs/incident-response.conf",
    "it-compliance": "/usr/share/osquery/packs/it-compliance.conf",
    "vuln-management": "/usr/share/osquery/packs/vuln-management.conf",
    "hardware-monitoring": "/usr/share/osquery/packs/hardware-monitoring.conf",
    "ossec-rootkit": "/usr/share/osquery/packs/ossec-rootkit.conf"
    }
}
```

- Edit `/var/ossec/etc/ossec.conf` to enable the Osquery wodle. The Wazuh module will take care of running Osquery when needed (no need to start Osqueryd):

```xml
<ossec_config>
    <wodle name="osquery">
        <disabled>no</disabled>
        <run_daemon>yes</run_daemon>
        <bin_path>/usr/bin</bin_path>
        <log_path>/var/log/osquery/osqueryd.results.log</log_path>
        <config_path>/etc/osquery/osquery.conf</config_path>
        <add_labels>no</add_labels>
    </wodle>
</ossec_config>
```

- Restart Wazuh-agent to apply changes

```
systemctl restart wazuh-agent
```

#### Steps to generate the alerts

- Wazuh automatically reads the `/var/log/osquery/osqueryd.results.log` and generates alerts based on the obtained information

#### Affected endpoint

- Linux RHEL


## <a name="suricata"></a>Network IDS integration - Suricata

Suricata is a NIDS solution that can detect threats by monitoring the network traffic. An example use case can be found at the following document: [Catch suspicious network traffic](https://documentation.wazuh.com/4.0/learning-wazuh/suricata.html).

### Configuration

On Linux RHEL monitored endpoint:

- Install Suricata (tested with version 5.0.4). It requires EPEL repository (be aware that this repository depends on your operating system version):

```
yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
yum -y install suricata-5.0.4
```

- Download and extract Emerging rules:

```
cd /tmp/
curl -LO https://rules.emergingthreats.net/open/suricata-5.0.4/emerging.rules.tar.gz
tar -xvzf emerging.rules.tar.gz && mv rules/*.rules /etc/suricata/rules/
chown suricata:suricata /etc/suricata/rules/*.rules
chmod 640 /etc/suricata/rules/*.rules
```

- Modify Suricata settings at  `/etc/suricata/suricata.yaml`

```yaml
EXTERNAL_NET: "any"
```

```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - "*.rules"
```

- Start Suricata

```
systemctl enable suricata
systemctl daemon-reload
systemctl start suricata
```

- Configure the Wazuh agent to read Suricata alerts file. The following settings need to be added to  `/var/ossec/etc/ossec.conf` file:

```
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/suricata/eve.json</location>
</localfile>
```

- Apply changes to Wazuh agent

```
systemctl restart wazuh-agent
```

#### Steps to generate the alerts

- Wazuh will automatically parse data from `/var/log/suricata/eve.json` and generate related alerts

#### Alerts

- `rule.groups:*suricata*`

#### Affected endpoint

- Linux RHEL


## <a name="shellshock"></a>Detecting a web attack - Shellshock

This example shows how Wazuh can detect a Shellshock attack by analyzing web server logs collected from a monitored endpoint. Please check [Wazuh Shellshock Attack documentation](https://documentation.wazuh.com/current/learning-wazuh/shellshock.html)

In addition, for further detection, the attack can also be detected at a network level when Suricata integration is configured.

#### Prerequesites

- Apache server running on the monitored system (Linux RHEL)

- Wazuh agent configured to monitor the Apache access logs:

```xml
    <localfile>
       <log_format>apache</log_format>
       <location>/var/log/httpd/access_log</location>
    </localfile>
```

- Suricata use case configured and monitoring the endpoint traffic (to make it easy, for the test, Suricata can run in the monitored system)

#### Configuration

This use case requires no additional configuration.

#### Steps to generate the alerts

- From an external host (the attacker), execute the following command:

```
curl -H "User-Agent: () { :; }; /bin/cat /etc/passwd" ${replace_by_your_web_server_address}
```

#### Alerts

- For alert based on web server log analysis: ```rule.description:*shellshock*```
- For alert based on network traffic analysis (Suricata NIDS): ```rule.description:*CVE-2014-6271*```

#### Affected endpoint

- Linux RHEL

## <a name="sql_injection"></a>Detecting a web attack - SQL Injection

This use case aims to show that Wazuh is able to detect a SQL Injection attack (https://portswigger.net/web-security/sql-injection). Wazuh can detect it by monitoring Apache logs and detect some patterns on it, like some common SQL attacks: `select`, `union`, etc...

#### Prerequesites

- Apache server running on the monitored system (Linux RHEL)

- Wazuh agent configured to monitor the Apache access logs:

```xml
    <localfile>
       <log_format>apache</log_format>
       <location>/var/log/httpd/access_log</location>
    </localfile>
```

- Suricata use case configured and monitoring the endpoint traffic (to make it easy, for the test, Suricata can run in the monitored system)

#### Configuration

This use case requires no additional configuration.

#### Steps to generate the alerts

- From an external host (the attacker), execute curl from a terminal:

```
curl -XGET "http://${replace_by_your_web_server_address}/?id=SELECT+*+FROM+users";
```

####  Alerts

- For alert based on web server log analysis: ```rule.id:31103```
- For alert based on network traffic analysis (Suricata NIDS): ```data.alert.signature_id:2006445```

#### Affected endpoint

- Linux RHEL

## <a name="slack"></a>Slack integration

Wazuh can report alerts to Slack by using the [ossec-integratord](https://documentation.wazuh.com/current/user-manual/reference/daemons/ossec-integratord.html) daemon. Please check our [Integration with external APIs](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html) for detailed information about this.

#### Configuration

On Wazuh manager:

- A Slack webhook must be configured before setting up this scenario.

- Configure Slack integration in `/var/ossec/etc/ossec.conf`:

```xml
<integration>
    <name>slack</name>
    <hook_url>${replace_by_SlackHook}</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
</integration>
```

#### Alerts

- Wazuh will automatically forward alerts level 10 or higher to the provided Slack hook (the Slack channel you associated with your Slack hook will show the alerts in real time).

#### Affected endpoints

- Wazuh manager

## <a name="trojan"></a>Trojan Detection

Wazuh can detect trojaned system binaries by using signatures in `/var/ossec/etc/shared/rootkit_trojans.txt` file. 

#### Configuration

- On the Linux monitored endpoint, we will use out-of-the box configuration for trojans detection in `/var/ossec/etc/ossec.conf` file:

```xml
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    
    <!-- Line for trojans detection -->
    <check_trojans>yes</check_trojans>
    
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    
    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>
```

#### Steps to generate the alerts

- Create a copy of the trojaned file

```
cp -p /usr/bin/w /usr/bin/w.copy
```

- Then modify the original system binary so it runs a shell script instead. In this case we modify  `/usr/bin/w`:

```bash
#!/bin/bash
echo "`date` this is evil"   > /tmp/trojan_created_file
echo 'test for /usr/bin/w trojaned file' >> /tmp/trojan_created_file
#Now running original binary
/usr/bin/w.copy
```

#### Alerts

Wait for the next rootcheck scan to be completed (frequency can be adjusted), and look for the resulting trojan alert running the following query:

- `location:rootcheck AND rule.id:510 AND data.title:Trojan*`

#### Affected endpoints

- Linux RHEL

## <a name="virustotal"></a>Detecting and removing malware - VirusTotal integration

Wazuh has the ability to integrate with VirusTotal API, running a query when a file change is detected. For this integration we use the `ossec-integratord` component that runs on the Wazuh manager. 

Please, check our [VirusTotal documentation](https://documentation.wazuh.com/current/user-manual/capabilities/virustotal-scan/index.html) for more information about this particular use case.

#### Prerequisites

- A VirusTotal API key (https://www.virustotal.com)
- Python installed on the Wazuh manager (`yum -y install python2`)
- Custom rules and decoders in the Wazuh manager
- Custom active response script in the monitored endpoint (Linux RHEL)

#### Configuring VirusTotal integration

- Enable Virustotal integration on the Wazuh manager, in the file `/var/ossec/etc/ossec.conf`

```xml
<ossec_config>
    <integration>
    <name>virustotal</name>
    <api_key>${your_virustotal_api_key}</api_key>
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
    </integration>
</ossec_config>
```

- Add these rules to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
    </rule>
        <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
    </rule>
</group>
```

The above rules are created to limit the times VirusTotal integration is triggered due to limitations in queries per minute (when using a free VirusTotal API key). This way we limit the integration to files being created or modified only in `/root` directory:

#### Configuring active response to remove malicious files

Additionally, once VirusTotal detects a file as a threat (positive match with antivirus engines), Wazuh will trigger an active response to remove the file from the system. The following changes are done on the Wazuh manager system: 

- Edit  `/var/ossec/etc/decoders/local_decoder.xml` and add the following decoder:

```xml
<decoder name="ar_log_fields">
    <parent>ar_log</parent>
    <regex offset="after_parent">^(\S+) Removed threat located at (\S+)</regex>
    <order>script_name, path</order>
</decoder>
```

- Add the auto-remove rule to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="virustotal,">
    <rule id="100092" level="12">
    <if_sid>607</if_sid>
    <match>Removed threat located at</match>
    <description>$(script_name) Removed threat located at $(path)</description>
    </rule>
</group>
```

- Append the following blocks to the Wazuh manager  `/var/ossec/etc/ossec.conf` file:

```xml
<ossec_config>
    <command>
        <name>remove-threat</name>
        <executable>remove-threat.sh</executable>
        <timeout_allowed>no</timeout_allowed>
    </command>

    <active-response>
        <disabled>no</disabled>
        <command>remove-threat</command>
        <location>local</location>
        <rules_id>87105</rules_id>
    </active-response>

</ossec_config>
```

- Restart Wazuh manager to apply configuration changes

```
systemctl restart wazuh-manager
```

#### Configuring the Wazuh agent side

Change the file integrity monitoring settings to monitor `/root`  in real-time. This change can be done in `/var/ossec/etc/ossec.conf` 

```xml
  <syscheck>
    <directories whodata="yes">/root</directories>
  </syscheck>
```
- On the monitored endpoint (Linux RHEL running the Wazuh agent),  add the following active response script at `/var/ossec/active-response/bin/remove-threat.sh`. 

```bash
#!/bin/bash
# Wazuh - Remove threat active response
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)

# Removing file
rm -f $FILENAME 
if [ $? -eq 0 ]; then
    echo "`date` $0 Removed positive threat located in $FILENAME" >> logs/active-responses.log
else
    echo "`date` $0 Error removing positive threat located in $FILENAME" >> logs/active-responses.log
fi

exit 0;
```

- Change `/var/ossec/active-response/bin/remove-threat.sh` owner and permissions:

```
chmod 750 /var/ossec/active-response/bin/remove-threat.sh
chown root:ossec /var/ossec/active-response/bin/remove-threat.sh
```

- Restart the Wazuh agent, on the monitored endpoint, to apply configuration changes

```
systemctl restart wazuh-agent
```

#### Steps to generate the alerts

When a file is modified under the monitored directory `/root`, it will trigger a VirusTotal scan and generate an alert if detected as malicious. 

Additionally, the active response has also be configured to remove the threat automatically.

```
cd /root
curl -LO http://www.eicar.org/download/eicar.com && ls -lah eicar.com
ls -lah eicar.com
```

#### Alerts

- `*eicar.com*`

#### Affected endpoints

- Linux RHEL


## <a name="vulnerability_detector"></a>Vulnerability detection

Wazuh can detect if installed applications do have an unpatched CVE in the monitored system. Check [Vulnerability Detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) documentation for further information about this.

#### Configuration on the Wazuh manager

- Enable vulnerability detector wodle in `/var/ossec/etc/ossec.conf`

```xml
<ossec_config>
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>

    <!-- Ubuntu OS vulnerabilities -->
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Debian OS vulnerabilities -->
    <provider name="debian">
      <enabled>yes</enabled>
      <os>stretch</os>
      <os>buster</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- RedHat OS vulnerabilities -->
    <provider name="redhat">
      <enabled>yes</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Windows OS vulnerabilities -->
    <provider name="msu">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Aggregate vulnerabilities -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>

  </vulnerability-detector>
</ossec_config>
```

#### Configuration on a Windows endpoint

In order to detect vulnerabilities on Windows endpoints, enable `hotfixes`  and `packages` collection in the `syscollector` component. This can be done in the Wazuh agent configuration file `/var/ossec/etc/ossec.conf`:

```xml
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <hotfixes>yes</hotfixes>
  <ports all="no">yes</ports>
  <processes>yes</processes>
</wodle>
```

#### Configuration on a Linux endpoint

In order to detect vulnerabilities on Linux endpoints, enable the collection of software `packages` in the `syscollector` component. This can be done in the Wazuh agent configuration file `/var/ossec/etc/ossec.conf`:

```xml
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
</wodle> 
```

#### Steps to generate the alerts

A global vulnerability database, with the list of all `CVEs` check is created on the Wazuh manager at `/var/ossec/queue/vulnerabilities/cve.db`.

Scans will be performed periodically, going through the list of applications collected for each monitored endpoint and looking for known vulnerabilities. 

#### Alerts

- `rule.groups:vulnerability-detector`

#### Affected endpoints

- Linux RHEL
- Windows


## <a name="yara"></a>Malware detection - Yara integration

Yara is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware artifacts. By integrating it with Wazuh we can scan files that have been added/modified and check if they contain malware.

#### Configuration on the Wazuh manager

Create local rules and decoders that will trigger on added/modified files in the `/tmp` directory, and also the rules that will check the results.

- Rules at `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="syscheck,">
    <rule id="100300" level="7">
        <if_sid>550</if_sid>
        <field name="file">/tmp</field>
        <description>File modified in /tmp directory.</description>
    </rule>
    <rule id="100301" level="7">
        <if_sid>554</if_sid>
        <field name="file">/tmp</field>
        <description>File added to /tmpdirectory.</description>
    </rule>
</group>

<group name="yara,">
    <rule id="108000" level="0">
        <decoded_as>yara_decoder</decoded_as>
        <description>Yara grouping rule</description>
    </rule>
    <rule id="108001" level="12">
        <if_sid>108000</if_sid>
        <match>wazuh-yara: INFO - Scan result: </match>
        <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
    </rule>
</group>
```

- Decoders at `/var/ossec/etc/decoders/local_decoders.xml`:

```xml
<decoder name="yara_decoder">
    <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
    <parent>yara_decoder</parent>
    <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
    <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
```

- Add this configuration to the Wazuh manager at `/var/ossec/etc/ossec.conf`the :

```xml
<ossec_config>
    <command>
        <name>yara</name>
        <executable>yara.sh</executable>
        <extra_args>-yara_path /usr/local/bin -yara_rules /home/wazuh/yara/rules/yara_rules.yar</extra_args>
        <timeout_allowed>no</timeout_allowed>
    </command>
    <active-response>
        <command>yara</command>
        <location>local</location>
        <rules_id>100300,100301</rules_id>
    </active-response>
</ossec_config>
```

- Restart Wazuh manager to apply configuration changes

```
systemctl restart wazuh-manager
```

#### Configuration on the monitored Linux system

- Compile and install Yara

```
yum -y install make gcc autoconf libtool openssl-devel && \
curl -LO https://github.com/VirusTotal/yara/archive/v4.0.2.tar.gz && \
tar -xvzf v4.0.2.tar.gz && \
cd yara-4.0.2 &&
./bootstrap.sh && ./configure && make && sudo make install && make check
```

- Download Yara rules

```
cd /tmp/
curl 'https://valhalla.nextron-systems.com/api/v1/get' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
-H 'Accept-Language: en-US,en;q=0.5' \
--compressed \
-H 'Referer: https://valhalla.nextron-systems.com/' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
--data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
-o yara_rules.yar
```

- Download a malware sample (this is a real malware artifact) and run a Yara scan

```
curl -LO https://wazuh-demo.s3-us-west-1.amazonaws.com/mirai -o /tmp/mirai
/usr/local/bin/yara /tmp/yara_rules.yar /tmp/mirai
```

- Create a `yara.sh` script in `/var/ossec/active-response/bin/`. Ensure owner and group must be `root:ossec` and permissions `0750`:

```bash
#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"


#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
fi

exit 0;

```

- Change `/var/ossec/active-response/bin/yara.sh` file owner and permissions:

```
chmod 750 /var/ossec/active-response/bin/yara.sh
chown root:ossec /var/ossec/active-response/bin/yara.sh
```

- Change the file integrity monitoring settings to monitor `/tmp` in real-time. This change can be done in `/var/ossec/etc/ossec.conf` 

```xml
  <syscheck>
    <directories whodata="yes">/tmp</directories>
  </syscheck>
```

- Restart Wazuh manager to apply configuration changes

```
systemctl restart wazuh-agent
```

#### Steps to generate the alerts

- Create the script `/tmp/malware_downloader.sh` to automatically download malware samples:

```bash
#!/bin/bash
# Wazuh - Malware Downloader for test purposes
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function fetch_sample(){

  curl -s -XGET "$1" -o "$2"

}

echo "WARNING: Downloading Malware samples, please use this script with  caution."
read -p "  Do you want to continue? (y/n)" -n 1 -r ANSWER
echo

if [[ $ANSWER =~ ^[Yy]$ ]]
then
  echo
  # Mirai
  echo "# Mirai: https://en.wikipedia.org/wiki/Mirai_(malware)"
  echo "Downloading malware sample..."
  fetch_sample "https://wazuh-demo.s3-us-west-1.amazonaws.com/mirai" "/tmp/mirai" && echo "Done!" || echo "Error while downloading."
  echo

  # Xbash
  echo "# Xbash: https://unit42.paloaltonetworks.com/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
  echo "Downloading malware sample..."
  fetch_sample "https://wazuh-demo.s3-us-west-1.amazonaws.com/xbash" "/tmp/xbash" && echo "Done!" || echo "Error while downloading."
  echo

  # VPNFilter
  echo "# VPNFilter: https://news.sophos.com/en-us/2018/05/24/vpnfilter-botnet-a-sophoslabs-analysis/"
  echo "Downloading malware sample..."
  fetch_sample "https://wazuh-demo.s3-us-west-1.amazonaws.com/vpn_filter" "/tmp/vpn_filter" && echo "Done!" || echo "Error while downloading."
  echo

  # Webshell
  echo "# WebShell: https://github.com/SecWiki/WebShell-2/blob/master/Php/Worse%20Linux%20Shell.php"
  echo "Downloading malware sample..."
  fetch_sample "https://wazuh-demo.s3-us-west-1.amazonaws.com/webshell" "/tmp/webshell" && echo "Done!" || echo "Error while downloading."
  echo
fi
```

- Download a malware sample to `/tmp` directory by running the script:

```
bash /tmp/malware_downloader.sh
```

- On the agent, the results of the Yara scan can be seen at `/var/ossec/logs/active-responses.log`

```bash
tail -f /var/ossec/logs/active-responses.log
wazuh-yara: INFO - Scan result: SUSP_XORed_Mozilla_RID2DB4 /tmp/mirai
wazuh-yara: INFO - Scan result: MAL_ELF_LNX_Mirai_Oct10_2_RID2F3A /tmp/mirai
wazuh-yara: INFO - Scan result: Mirai_Botnet_Malware_RID2EF6 /tmp/mirai
wazuh-yara: INFO - Scan result: MAL_ELF_VPNFilter_3_RID2D6C /tmp/vpn_filter
wazuh-yara: INFO - Scan result: Webshell_Worse_Linux_Shell_php_RID3323 /tmp/webshell
wazuh-yara: INFO - Scan result: Webshell_Worse_Linux_Shell_1_RID320C /tmp/webshell
```

#### Alerts

- `rule.groups:yara`

#### Affected endpoints

- Linux RHEL