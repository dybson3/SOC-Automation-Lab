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

I procedeed to the process of installing **Mimikatz**. To be able to use it I had to exclude Downloads folder from my Windows 10 firewall.

![obraz](https://github.com/user-attachments/assets/3f98785e-1f7f-4c81-875c-1eb7a94eb800)


Next, I used **Mimikatz**, a popular post-exploitation tool, to simulate an attack by extracting credentials from the machine. By doing this, I could test the detection capabilities of the entire setup, ensuring Wazuh would raise alerts when malicious activity occurred.

![Mimikatz Installed](https://github.com/user-attachments/assets/2501781e-69b1-49ef-b0dd-104682d6d3ad)

Launching **Mimikatz**:

![obraz](https://github.com/user-attachments/assets/8898f151-7fc9-4ba3-b657-8aefe674770c)

After that I changed the configuration of **filebeat** file to be able to receive alerts. I changed the "enabled" option from false to true.

![obraz](https://github.com/user-attachments/assets/c56f61f2-7d62-428a-a713-f00af051f52f)

Next in **Wazuh** dashboard I created index pattern to collect archived logs:

![obraz](https://github.com/user-attachments/assets/b56f0e21-4df9-426c-af4a-53b7f1e2f73e)

As we can see they have shown up (wazuh-archives):

![obraz](https://github.com/user-attachments/assets/843f906e-02b4-4dee-9afe-b79a328faa23)

With this setup all the logs were then collected in archives folder so I was able to search through them when I needed. As we can see in the archives folder I found logs with **Mimikatz** activity:

![obraz](https://github.com/user-attachments/assets/2280e9a9-169f-474d-a644-c0b89702f3f6)

Then I moved on to creating new rule especially for **Mimikatz**. 

![obraz](https://github.com/user-attachments/assets/fd1d8e6a-e996-4adc-952f-537f7088794d)

I modified the **local_rules** file to add my rule. Here's the rule I created:

![obraz](https://github.com/user-attachments/assets/649a227b-57e7-4bd4-b050-6600a901d1bc)

The **rule_id** for custom rules need to be at least 100 000. **Level 15** is the highest level for alerts.

As we can see the rule works and **Wazuh** used it properly:

![obraz](https://github.com/user-attachments/assets/95fc515e-d800-4970-bd93-aa07321f1dc7)

---

### 7. Automation with Shuffle 
This stage of the project involved integrating **Shuffle**, an automation platform. Shuffle connects Wazuh with other tools, enabling automated responses to security events. 

![Shuffle Workflow](https://github.com/user-attachments/assets/9acbfe66-356d-4759-8290-a37ed8545479)

Next thing to do was adding a note about shuffle in our **Wazuh** Manager in the **ossec.conf** file.

![obraz](https://github.com/user-attachments/assets/7dc9dbcf-7b1c-4554-bbd2-f7463fcd41b3)

As we can see now in our **Shuffle** workflow we can now see events from **Wazuh**.

![obraz](https://github.com/user-attachments/assets/add60b5f-bd56-4ba9-8806-b3cfad390b80)

After this I moved on to adding **Virus Total** to my environment. I created regex rules to send the hash to **Virus Total** so it can check the file.

![obraz](https://github.com/user-attachments/assets/a42beb7a-194c-4831-9737-78da9972a73a)

Then I added TheHive to my workflow.

![obraz](https://github.com/user-attachments/assets/7a0f8fcf-2775-419f-bb2c-7c08449afac2)

Configuring **TheHive** itself. I started with adding a new user that would be responsible for receiving alerts.

![obraz](https://github.com/user-attachments/assets/bb2575a8-c88b-43a2-bc49-8fc02364b0bc)

Then I had to allow **TheHive** in my firewall:

![obraz](https://github.com/user-attachments/assets/4ca06097-ca36-43b2-b1e9-0552e8d762ab)

Finally I was able to receive alerts in **TheHive**:

![obraz](https://github.com/user-attachments/assets/0e93da68-77df-4f95-ae99-bb68dc6735bb)

Another part was to get email notifications from **Shuffle** about potential threats. I added email app to my workflow.

![obraz](https://github.com/user-attachments/assets/e8ce558b-b301-4878-9e4f-e340e274b1b2)

Email was sent to me successfully!

![obraz](https://github.com/user-attachments/assets/3694622a-d2e5-4098-b66b-0b3af300756e)

### 7. Incident response
The final stage of my project was to create response action. The objective was to receive email and being able to block ip address that was not friendly for me.

I started with adding new Ubuntu machine to our virtual machines:

![obraz](https://github.com/user-attachments/assets/7bd21143-a7e1-4b80-b2ad-acd97c9ca60c)

I moved onto creating active response in the **ossec.conf** file:

![obraz](https://github.com/user-attachments/assets/750fb5d0-576b-4835-948c-55939a64ec37)

I added **firewall-drop0** argument to my **Wazuh** app on the **Shuffle**:

![obraz](https://github.com/user-attachments/assets/81eb87e9-da13-4071-844f-343a9d5e3b77)

For testing purposes in the command box I used google DNS which is 8.8.8.8.

![obraz](https://github.com/user-attachments/assets/d783f7d4-9516-4c21-a57d-8822966a109b)

Now the pings to 8.8.8.8 stopped which means my rules worked:

![obraz](https://github.com/user-attachments/assets/3a52ac94-2c83-4b71-b7d4-6a632a120113)

I was able to see the blockage in **iptables**:

![obraz](https://github.com/user-attachments/assets/b821a2d8-370c-428d-ac85-ab3a916a5e22)

This is how my shuffle workflow looked like at that time:

![obraz](https://github.com/user-attachments/assets/4ccb4dcd-7bd4-4d0f-ac40-203e874382f9)

Now the last activity was to add the feature of blocking unwanted IP's.

![obraz](https://github.com/user-attachments/assets/2c229f40-4451-4439-84cb-f92870f135ac)

I received an email from the **Shuffle**:

![obraz](https://github.com/user-attachments/assets/0ad58839-3aa8-41b8-8071-77f5022bb7f1)

As we can see our rule was added to **iptables** successfully!
