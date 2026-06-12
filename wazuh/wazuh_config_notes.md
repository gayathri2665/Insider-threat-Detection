# Wazuh Integration Setup Guide for Database Security Monitoring

In a production environment, database activity monitoring is achieved by forwarding MySQL audit logs to the Wazuh Manager, which decodes and triggers security alerts.

## 1. Wazuh Agent Configuration

On the MySQL database server running the Wazuh Agent, edit `/var/ossec/etc/ossec.conf` to monitor the MySQL general/audit log file.

Add the following block:
```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/mysql/mysql_audit.log</location>
  </localfile>
</ossec_config>
```

Restart the agent:
```bash
systemctl restart wazuh-agent
```

---

## 2. Wazuh Manager Decoders

On the Wazuh Manager, create a custom decoder file at `/var/ossec/ruleset/decoders/0385-mysql-audit_decoders.xml` to parse JSON database logs.

```xml
<!-- Custom JSON Decoder for MySQL Activity Logs -->
<decoder name="mysql-audit-json">
  <prematch>^{"username":</prematch>
</decoder>

<decoder name="mysql-audit-json-fields">
  <parent>mysql-audit-json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

---

## 3. Wazuh Manager Rules

On the Wazuh Manager, create custom alert rules at `/var/ossec/ruleset/rules/0385-mysql-audit_rules.xml`. These rules trigger basic alerts, which are then analyzed by the Machine Learning engine for user behavior anomalies.

```xml
<group name="mysql_audit,database,">
  <!-- Parent Rule -->
  <rule id="100100" level="3">
    <decoded_as>mysql-audit-json</decoded_as>
    <description>Database activity detected</description>
  </rule>

  <!-- Failed Login Attempts -->
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="is_failed">^1$</field>
    <field name="query_type">^LOGIN$</field>
    <description>Database login failed for user $(username)</description>
    <group>authentication_failed,gpg13_7.1,</group>
  </rule>

  <!-- Bruteforce Login Attempts -->
  <rule id="100102" level="10" frequency="6" timeframe="30">
    <if_matched_sid>100101</if_matched_sid>
    <same_source_ip />
    <description>Database login brute force attack</description>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <!-- Privilege Modification Attempts -->
  <rule id="100103" level="8">
    <if_sid>100100</if_sid>
    <field name="query_type">^GRANT$|^REVOKE$|^ALTER$</field>
    <description>Database administrative/privilege query by $(username)</description>
    <group>privilege_escalation,pci_dss_10.2.2,</group>
  </rule>

  <!-- Failed Queries -->
  <rule id="100104" level="5">
    <if_sid>100100</if_sid>
    <field name="is_failed">^1$</field>
    <description>Database query failure for user $(username): $(error_message)</description>
  </rule>
</group>
```

Restart the Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

---

## 4. Active Response / API Forwarding

To route these alerts to our Deep Evidential Anomaly Detection Engine:
1. Configure an **Integrator** in Wazuh Manager (`/var/ossec/etc/ossec.conf`) to post alerts matching group `mysql_audit` to the python listener socket/HTTP endpoint:
```xml
<ossec_config>
  <integration>
    <name>custom-alert-shipper</name>
    <hook_url>http://localhost:5000/alert</hook_url>
    <rule_id>100100</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```
2. Or use our provided `wazuh_agent_simulator.py` to pipeline audit logs directly to the detection engine in real-time.
