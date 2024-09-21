# SOC-Automation-Lab
SOAR Lab made with the usage of Shuffle, TheHive and Wazuh.
# Cybersecurity Monitoring and Response System

## Project Introduction

This project demonstrates a comprehensive **cybersecurity monitoring and incident response system** built using open-source tools. The environment consists of multiple virtual machines configured to detect, analyze, and automatically respond to security threats in real-time. Core components include **Wazuh** for log monitoring and analysis, **TheHive** for incident management, and **Sysmon** for detailed system event logging. To automate responses such as blocking malicious IPs and sending alerts, I integrated **Shuffle**. This project showcases a highly automated approach to threat detection and response within a secure, virtualized lab environment.

## Skills Learned

- 🖥️ **Virtual Machine Setup and Management** (DigitalOcean)
- 🔒 **Firewall Configuration** (Securing VMs with custom rules)
- 📝 **Sysmon Configuration** (Windows system event logging)
- ⚙️ **Wazuh Installation and Configuration** (Custom rules, log monitoring)
- 📊 **Telemetry and Log Analysis** (Security incident detection)
- 🚨 **Incident Response Setup** (Using TheHive, Cortex, MISP for managing security alerts)
- 🤖 **Automation with Shuffle** (Triggering automatic responses like IP blocking)
- 🔗 **Security Tool Integration** (Wazuh, TheHive, Sysmon, Shuffle in a unified system)
- 🛡️ **Threat Simulation** (Using Mimikatz to simulate attacks and test security defenses)
- 📜 **Custom Rule Creation** (Writing rules in Wazuh for specific alerts)
- ✉️ **Email Notification Setup** (Automated alert emails for security incidents)

## Tools Used

- **[Wazuh](https://wazuh.com/)**: Security monitoring and log analysis platform.
- **[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)**: Windows system activity monitoring tool.
- **[TheHive](https://thehive-project.org/)**: Incident response and threat management platform.
- **[Cassandra](https://cassandra.apache.org/)**: Database for TheHive's back-end storage.
- **[ElasticSearch](https://www.elastic.co/)**: Log and event data search engine.
- **[Cortex](https://www.cortex-cert.org/)**: Automated enrichment of security events.
- **[MISP](https://www.misp-project.org/)**: Malware Information Sharing Platform for threat intelligence.
- **[Shuffle](https://shuffler.io/)**: Security orchestration and automation platform.
- **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**: Tool for simulating credential extraction attacks.
- **[DigitalOcean](https://www.digitalocean.com/)**: Cloud hosting platform for virtual machines.
- **Firewalls**: Securing VMs and controlling network traffic.

## Project Step-by-Step

### 1. Architecture Design
The first step of the project involved visualizing the overall lab architecture. This diagram serves as a blueprint for the setup, showing how each component like Wazuh, TheHive, and Sysmon would interact within the network.

![Lab Diagram](https://github.com/user-attachments/assets/253da700-7da9-44ef-9376-ae85c107b045)

Having a clear visual overview of the environment helped in understanding how data flows between the systems, including firewalls, monitoring agents, and the automation platform, Shuffle.

---

### 2. Installation of Sysmon on Windows 10
After setting up the lab environment, the next task was installing **Sysmon** on a Windows 10 virtual machine. Sysmon enhances the level of detail in the Windows logs, providing crucial telemetry about process creation, network connections, and other activities. You can see Sysmon integrated into the **Event Viewer** at the bottom here:

![Sysmon in Event Viewer](https://github.com/user-attachments/assets/cbdb1c97-5e70-45a0-b027-ead713b6fd4f)

This installation was a critical step to enable detailed logging, which was later consumed by **Wazuh** for real-time analysis.

---

### 3. Virtual Machines and Firewall Configuration
The lab’s core components were housed in **Virtual Machines** (VMs). First, I set up a VM to run **Wazuh**. This involved creating and configuring the virtual machine, preparing it to act as a **Security Information and Event Management (SIEM)** platform.

![Wazuh VM](https://github.com/user-attachments/assets/bf1800c6-0c49-4e79-a2dd-529b161bfd34)

Next, a **Firewall** was added to secure the network. Only trusted IP addresses, like my own, were allowed through the firewall to access the Wazuh dashboard. This prevents unauthorized access and adds an essential layer of security to the environment.

![Firewall with Whitelisted IP](https://github.com/user-attachments/assets/ba73946e-c969-4689-b5f3-5ab9421952df)

I immediately added Firewall to protect my **Wazuh** virtual machine:

![obraz](https://github.com/user-attachments/assets/5c0d8658-e8de-43a2-8997-a7bdef1838aa)


---

### 4. Wazuh Setup and Configuration
Firstly I connected to my **Wazuh** machine using Powershell:

![obraz](https://github.com/user-attachments/assets/21b0edb0-cf3c-49b4-959b-270c9a54618d)


With the firewall set up, I proceeded with **Wazuh** installation. Wazuh is a powerful open-source security monitoring tool that provides comprehensive threat detection and response capabilities.

![Wazuh Installed](https://github.com/user-attachments/assets/ea002735-0ea1-4f1c-bb73-c78cae5f960a)

After the installation, I was able to log into **Wazuh** dashboard:

![obraz](https://github.com/user-attachments/assets/82ac90f2-0d52-48ce-a57b-e296b4a1e3e5)

---

### 5. TheHive Installation and Setup
The next part of the project focused on installing and configuring **TheHive**, an incident response platform. This involved setting up a new VM.

![TheHive VM](https://github.com/user-attachments/assets/4ff9f178-5eb3-4c3d-8634-bdfa8f66b73d)

Same as I did with the **Wazuh** I added TheHive to my **Firewall**:

![obraz](https://github.com/user-attachments/assets/1919c327-a4b2-4971-ac53-8584ca577526)

Once the VM was in place, I installed four essential components: **Java**, **Cassandra**, **ElasticSearch**, and **TheHive** itself. These are foundational services that TheHive relies on to store and retrieve data, as well as process alerts.

![Everything Installed](https://github.com/user-attachments/assets/51f124fb-8188-4681-988e-ac383b11538a)

**Cassandra** was configured first, where I set the cluster name, listen address, and other critical parameters. **Cassandra** is an open source NoSQL distributed database trusted by thousands of companies for scalability and high availability without compromising performance.

![obraz](https://github.com/user-attachments/assets/6ff2411b-b420-4b64-a561-d2ca4ae01c4b)

Now **Cassandra** is up and running.

![obraz](https://github.com/user-attachments/assets/0d4fe741-f482-4780-85b9-2595b162a5e0)

Now I procedeed to setting up **ElasticSearch** and things like cluster name, node name, networkhost for oup thehive ip and httport. **Elasticsearch** is a distributed, RESTful search and analytics engine, scalable data store, and vector database capable of addressing a growing number of use cases.

![obraz](https://github.com/user-attachments/assets/1b0ac827-7e18-4511-9d68-99ca05056095)

**ElasticSearch** is up and running.

![obraz](https://github.com/user-attachments/assets/0642de24-84c1-45d2-a12a-1dff2f8f6181)

**TheHive** configuration. Firstly I needed to change owners of thehive lib so it can work:

![obraz](https://github.com/user-attachments/assets/f36e2b80-a69f-416b-8cbf-8e13c15e7f75)

After this, I configured **thehive**. Hostname and cluster-name:

![obraz](https://github.com/user-attachments/assets/fbbb6ff1-650f-4253-be75-7cd6db7d6bfe)

I changed baseurl for our **thehive** url:

![obraz](https://github.com/user-attachments/assets/5e2c791d-60be-40fd-b937-edbd506d8ff9)

And additional knowledge:

![obraz](https://github.com/user-attachments/assets/b2a8fda0-35c1-4f81-b8e9-8ce1d9295232)

**Cortex** is used for enrichment and **Misp** it used as CTI (Cyber Threat Intelligence).

**TheHive** is up and running:

![obraz](https://github.com/user-attachments/assets/fd51a156-c952-4587-8bd5-2a2f13d6cffe)

After this I was able to log into **TheHive** dashboard:

![obraz](https://github.com/user-attachments/assets/3f6c1d30-9f80-4c8d-a740-5c988a217c72)


---

### 6. Generating Telemetry and Setting Alerts
With Wazuh and TheHive in place, I began generating **Telemetry** data from the Windows 10 machine. I focused on capturing logs related to process creation, network events, and security anomalies. This was done by modifying **ossec.conf** on Wazuh to exclude unnecessary logs (like application logs) and focus on **Sysmon** logs for high-value telemetry.

![Telemetry Configuration](https://github.com/user-attachments/assets/d6d97cb1-562b-4d5b-ae89-6745fc438cb5)

Next, I used **Mimikatz**, a popular post-exploitation tool, to simulate an attack by extracting credentials from the machine. By doing this, I could test the detection capabilities of the entire setup, ensuring Wazuh would raise alerts when malicious activity occurred.

![Mimikatz Installed](https://github.com/user-attachments/assets/2501781e-69b1-49ef-b0dd-104682d6d3ad)

I configured **Filebeat** to handle the flow of logs, creating index patterns to organize and filter data, ensuring the right information was available for further analysis. As expected, Wazuh successfully detected the use of Mimikatz.

![Wazuh Detected Mimikatz](https://github.com/user-attachments/assets/12832ea0-c1aa-46b2-a92d-d8405c31c067)

Finally, I added custom rules to **Wazuh**'s `local_rules` to fine-tune the alerting mechanism. Custom rules allow for more granular control over the types of alerts generated and their severity levels, helping to focus on critical incidents.

---

### 7. Automation with Shuffle and Active Response
The final stage of the project involved integrating **Shuffle**, an automation platform. Shuffle connects Wazuh with other tools, enabling automated responses to security events. 

![Shuffle Workflow](https://github.com/user-attachments/assets/9acbfe66-356d-4759-8290-a37ed8545479)

By connecting Wazuh alerts to **TheHive** through Shuffle, I created workflows where detected threats would automatically trigger incident creation in TheHive. I further enriched these incidents by integrating **VirusTotal** lookups for hash values and automating responses like blocking IPs through firewall rules.

![Alert in Shuffle](https://github.com/user-attachments/assets/856f02e1-87f0-445d-85c2-5956659e517c)

Finally, I added an **active response** capability in Wazuh, allowing the system to block malicious IPs automatically. This functionality proved successful, as Wazuh issued commands to the firewall, which blocked traffic from unwanted sources.

![IP Blocked](https://github.com/user-attachments/assets/f5426e3a-729c-4df0-bff6-63a77bc7b21e)

With the email notification system set up, I received real-time alerts about the automation actions taking place, ensuring complete visibility into the automated defenses of the lab environment.
