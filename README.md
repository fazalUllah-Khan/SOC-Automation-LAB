# SOC-Automation-LAB
Building a SOC Automation LAB using VMware, Wazuh, TheHive, and Shuffle (SOAR) for enhanced security monitoring and automated incident response.

I created a SOC Automation LAB using a Windows machine on VMware to simulate a realistic security environment. I integrated Wazuh for endpoint monitoring and threat detection, allowing for real-time security analysis. TheHive was used for efficient incident response management, enabling streamlined collaboration and rapid resolution of security incidents. To further automate the security process, I implemented Shuffle (SOAR), orchestrating security workflows and automating repetitive tasks. This lab setup provided hands-on experience in managing and automating security operations, improving overall response time and enhancing security posture.

# Architecture

<img width="452" alt="image" src="https://github.com/user-attachments/assets/21c53b7f-7478-4555-81b9-2a916cb74164" />

<img width="815" alt="image" src="https://github.com/user-attachments/assets/b99ef933-29df-4366-9ca2-20feab4ee32a" />

# Objective

* Install application and VM
* Use Windows 10 w/sysmon : As client PC 
* Wazuh Server : Ubuntu 22.04 on AWS Cloud 
* TheHive Server : Ubuntu 22.04 on AWS Cloud 

# Step 1: 
Installed VMware , setup windows 10 based on ISO 
# Step 2: 
Install sysmon & configured (sysmonconfig.xml) 
# Step 3:  Wazuh Setup
Launched AWS EC2 , with specific SG 

![image](https://github.com/user-attachments/assets/af114338-867e-468a-993f-1abcc68f09d7)

![image](https://github.com/user-attachments/assets/9e860f42-aa56-41db-9a70-d9e174940e63)

![image](https://github.com/user-attachments/assets/dbba4997-f9b5-41b5-a831-21fc58bf7091)

# Install Wazuh 
sudo apt-get update && sudo apt-get upgrade
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

![image](https://github.com/user-attachments/assets/c3a46f84-f2d5-489c-aaf5-2f8ec8e6137f)

P.s : Save User: admin and Password: EcEOGgX.2Bwx7WpVa0aukaXXXc

# Now we have create another EC2 for TheHive 
I used same Security group and specs for creating EC2 instance for theHive
P.s Make sure EC2 is t2.medium atleast

#  Installing TheHive
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
sudo systemctl status thehive
sudo systemctl start thehive
sudo systemctl enable thehive
sudo ufw status
sudo ufw allow 9000

# Important:

Check TheHive’s Listening Address:
sudo nano /etc/thehive/application.conf

Ensure that this line is set to listen on all interfaces:

application.baseUrl = "http://EC2 IP:9000"

Default Credentials on port 9000
credentials are 'admin@thehive' or “admin”with a password of 'secret'

# Troubleshooting
sudo -u thehive /opt/thehive/bin/thehive -Dconfig.file=/etc/thehive/application.conf -Dlogger.file=/etc/thehive/logback.xml
if application hang
sudo lsof -i :9000
sudo kill -9 <PID>
sudo systemctl restart thehive
Password /login issue 
sudo nano /etc/elasticsearch/jvm.options.d/jvm.options
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
ubuntu@ip-172-31-44-87:/opt/thehive/bin$ sudo systemctl restart elasticsearch

# Specific Configuration for Cassandra , ElasticSearch , Thehive
> sudo nano /etc/cassandra/cassandra.yaml
   update
    cluster_name='mysoc'
    listner_Address =<TheHivepubIP> or <localhost>
    rpc_address=<TheHivepubIP> or <localhost>
    Seed_provider=<TheHivepubIP> or <localhost>
> sudo systemctl stop cassandra.service
> rm -rf /var/lib/cassandra/*
> sudo systemctl start cassandra
> sudo systemctl status cassandra
Next ElasticSearch
> sudo nano /etc/elasticsearch/elasticsearch.yml
   update
   cluster_name=thehive
   node_name=node-1
   network_host= <TheHivepubIP> or <localhost>
   http.port=9200
   cluster.initial_master_node=['node-1']
>sudo systemctl restart elasticsearch
> sudo systemctl start/enable elasticsearch
> sudo systemctl status elasticsearch

Next Thehive specific configuratio

first we need to confirm thehive user access to certain path 
> ls -la /opt/thp    --> thehive user had no access only root had access
> sudo chown -R thehive:thehive /opt/thp

Perfect now we will move to update application.confi for thehive

> sudo nano /etc/thehive/application.conf
in database & index section update for cassanda and elasticsearch binding to hive
    hostname=["tehhive pub IP"] or "localhost"
    Cluster_name= mysoc
and in index
    hostname=["tehhive pub IP"] or "localhost"
    application.baseurl="http://<theHive_Pub_IP>:9000"

>sudo systemctl restart thehive
> sudo systemctl start/enable thehive
> sudo systemctl status thehive


Now move back to wazuh for configuration 
First thing to option the Wazuh
    User: admin
    Password: EcEOGgX.2Bwx7WpVa0XXXBoWUc

•	Ok now goto EC2 and copy it IP 
https://<EC2-IP>
•	Enter Admin username and password
•	In addition, we need to open ssh to wazuh and 

>ls                                           ///// {we should see file wazuh-install-files.tar
> sudo tar -xvf wazuh-install-files.tar      /// {in this extract wazuh-install-files/wazuh-passwords.txt if of our interest}
> cd wazuh-install-file 
> sudo cat wazuh-passwords.txt

We need 
# Admin user for the web user interface and Wazuh indexer. Use this user to log in to Wazuh dashboard
  indexer_username: 'admin'
  indexer_password: 'EcEOGgX.2Bwx7WpddddxoLBoWUc'

To perform responsive capabilities 
# Password for wazuh-wui API user
  api_username: 'wazuh-wui'
  api_password: 'sB3STGi0fzKsdrH4MA4q+u0pz?ma.*VL'

in wazuh we have no agent install 

 ![image](https://github.com/user-attachments/assets/b9c303d8-a98c-470a-955e-85ca27aa5bd1)

 Click add agent 

 ![image](https://github.com/user-attachments/assets/d36a918b-3fa1-4641-9606-6165cbfbb370)

 goto windows 10 pc 

 open windows shell as admin and Paste in windows
 
 ![image](https://github.com/user-attachments/assets/9458aa13-6838-4301-bf42-a0adee3d9523)

 One installation finish type to start wazuh service
>net start wazuhsvc

![image](https://github.com/user-attachments/assets/323d5a70-04a2-4776-84b2-dd77ddbb0b9a)

Type services in windows and check wazuh service is running

![image](https://github.com/user-attachments/assets/8119cb48-f290-4582-8aa3-650c0782eda2)

Notes: During connection with Wazuh I faced few issues that wazuh manager wasn’t detecting my windows machine. For that I needed to update EC2-SG to open port 1515 and 1514 also in my windows machine I goto Windows firewall -> inbound rule- add new rule -> TCP/1515 allow and save. 

![image](https://github.com/user-attachments/assets/d7f031b4-436a-4b56-a7e7-27b58a8c6a51)

![image](https://github.com/user-attachments/assets/251acdbb-fc68-4917-a0ca-e8ac20a6b96c)

![image](https://github.com/user-attachments/assets/4acb2311-703d-4fbd-8763-0a0cb7c755c7)

Next we are going to generate Telemetry & ingest into Wazuh using mimicat

Goto windows 10 machine 
C:\Program Files (x86)\ossec-agent\ossec.conf (ossec.conf is our file of interest) 
Make a copy of it before we make any changes in it/.

![image](https://github.com/user-attachments/assets/9ab8ba10-85c7-4ccc-879d-adcc63c94212)

Goto EventVeiw 
Click application and services  windows  Sysmon 

![image](https://github.com/user-attachments/assets/b731168c-77cf-4369-8bba-83f153eeb73f)

For simplicity we just want Sysmon logs so we removed app, sys and sec files to be reported

![image](https://github.com/user-attachments/assets/682c60c0-627b-438b-b2d1-d88c3568ba53)

So this means application, security and system will no long event in our windows system 
Ok save the modified file/.
p.s note it may give as you don’t have permission as admin. So just go search notepad open as admin copy the file we changed and go and replace ossec.conf it will be saved with updates like this
next open services and restart wazuh service as any time we make config changed we always need to restart wazuh. 

![image](https://github.com/user-attachments/assets/45ad342d-7bc4-4725-9c72-b1f8330a5a22)

Goto wazuh dashboard   events and search – sysmon
![image](https://github.com/user-attachments/assets/9232a42e-3d77-48b7-9036-6f4b35e9642b)

Next thing we need to install miniKatz. But before that ensure we disable windows defender or at least exclude download folder. 
![image](https://github.com/user-attachments/assets/fa4d2e82-1948-4462-b360-454b188107d9)

MimiKatz is that application software attackers use to exact credentials from your machine. 

1.	Download mimikatz.zip
![image](https://github.com/user-attachments/assets/0de9d01b-51b6-4bb0-ac9f-087b4233b196)

2. Extract it
![image](https://github.com/user-attachments/assets/d7d5bede-aa2b-485e-b0e3-c3cb376cfe87)

3.	Open window power shell as admin
Navigate to folder of mimikatz and run .exe
![image](https://github.com/user-attachments/assets/64234d67-68c2-400f-a2cc-c58d7df2efc9)

4.	Ok lets go back to wazuh to see if we find any events related to mimikatz
   ![image](https://github.com/user-attachments/assets/e812f2b8-5ac8-4482-b4af-a415f6c61640)

So this because we need to define rule to log everything 
So for this we need to do some modifications in wazuh ossec.config. first lets create a backup to be on safe side
![image](https://github.com/user-attachments/assets/45585c27-3a43-4dab-9690-f7e984b50d4c)

We found below set to no which will set to yes and save file

![image](https://github.com/user-attachments/assets/70930825-8c25-4ba3-978a-3fd8a61026ea)

And restart wazuh manager

![image](https://github.com/user-attachments/assets/5acd90f9-cdc7-4eed-9b37-6b66e667e9e8)

This make wazuh to share files in somewhere call archive
![image](https://github.com/user-attachments/assets/5a31c015-7f04-4ccf-9829-cc036dfddacf)

In order to wazuh injecting these logs we need to change we need to change our configuration in filebeat 
>sudo nano /etc/filebeat/filebeat.yml
Where found archive enable=false , I change it to =true
![image](https://github.com/user-attachments/assets/75726226-2638-4f7f-a306-6c13cbd00050)

	sudo systemctl restart filebeat.service
	sudo systemctl restart wazuh-manager.service
Let do some config in wazuh dashboard click
![image](https://github.com/user-attachments/assets/2c363eee-c97c-430d-82db-36cf6d5d09c8)
![image](https://github.com/user-attachments/assets/6d7e7cb0-bf3c-4ecb-8db3-53d63e95826b)
![image](https://github.com/user-attachments/assets/99e36c7f-7ad4-40dd-b750-2afc77406366)
![image](https://github.com/user-attachments/assets/87284489-0a7b-4ef5-aa17-561723dc35e6)
![image](https://github.com/user-attachments/assets/f85dc17f-3ce6-4ee7-bb15-b597ffe717c6)

Ok so now lets check if mimikatz event was really caught by wazuh. If below command give o/p yes it has otherwise we have to goto windows pc and re generate it
>sudo cat /var/ossec/logs/archives/archives.json | grep -i mimikatz
![image](https://github.com/user-attachments/assets/45186a67-4e26-49a0-90c1-9dadbf2e2ccc)

Generating mimitaz event

![image](https://github.com/user-attachments/assets/841015c7-174e-4543-8bda-251085ff87a4)

![image](https://github.com/user-attachments/assets/40bde111-15d8-4f3d-aa70-ad7d10fcf30e)

Let’s go and search again for mimikatz in wazuh we found 4 events 

![image](https://github.com/user-attachments/assets/68609ff0-d83f-44fa-8202-2a7e875949a6)

Ok upon expanding these events we can find details. Filename and image is important we shall check both so attacker don’t trick us. 

![image](https://github.com/user-attachments/assets/072f6675-b772-4a7a-9d25-ffaf53ba9042)

Ok lets create alert now
Buildin rule /var/ossec/rulesec/rules
But you can access them from wazuh GUI 

![image](https://github.com/user-attachments/assets/5b97b358-dab9-496b-a866-5835d0c9e1d1)
![image](https://github.com/user-attachments/assets/d7194dd0-0b9d-47e1-91ca-981ca0988749)
![image](https://github.com/user-attachments/assets/91dad71b-ecd2-497b-a158-7d7fc1631e40)
![image](https://github.com/user-attachments/assets/a66c95c8-cd8d-4200-b31e-67a6ee7971de)

And then we go back. Click on custom rule-> localrule.xml  modified it and paste the copied rule. Many things are updated/customize according to our needs. And save rule
![image](https://github.com/user-attachments/assets/6d3421e8-05e1-4445-86d6-b23bb7d83b07)

It will ask for restart manager and will do it confirm 
Before run mimikatz, just for fun I changed it name youareawsome.exe😊 
![image](https://github.com/user-attachments/assets/300b6a02-151b-459e-b892-844f9069ad08)

![image](https://github.com/user-attachments/assets/594c5c28-bdae-43eb-80f0-f28ec4a6a1c7)

Perfect! So now we run mimikatz .exe

![image](https://github.com/user-attachments/assets/c326f00b-f21c-4449-802f-b9db89be27e6)

And in Wazuh we see alert

![image](https://github.com/user-attachments/assets/a2412b0b-be1c-4b78-b502-450ecf4d0024)

Note: But if see the image name is changed as per attacker modification but we should check original file name which is mimikatz.exe and this is what we shall always concentrate 
![image](https://github.com/user-attachments/assets/b9b25865-6337-45e8-b0d7-bff474fea385)

So in next part we will be connecting shuffle (SOAR plateform). SOAR means security , orchestration , Automation and response . Which will then send an alert to TheHive and send to soc analyst via email. 
Ok as first step we have to create an account on shuffle by visiting  https://shuffler.io/register 
create workflows https://shuffler.io/workflows 
![image](https://github.com/user-attachments/assets/ef2ab37a-431a-4ca2-ac22-26a2e9c580fc)

And here is how to create 

![image](https://github.com/user-attachments/assets/a5789564-f5dd-4cf3-9cbc-9f782a2eef50)

![image](https://github.com/user-attachments/assets/c6f591f4-db4e-413b-bf33-b58809d2a2dc)

![image](https://github.com/user-attachments/assets/1aad7029-d2de-42c5-8606-59c4a6dfebf4)

![image](https://github.com/user-attachments/assets/924028db-cfbd-400b-aac2-cfa83f49f616)

https://shuffler.io/api/v1/hooks/webhook_8d7bad35-a118-411d-9271-94bc0f84944a
https://shuffler.io/api/v1/hooks/webhook_866776f5-5c2a-480f-88d4-38ca3edb52d5

![image](https://github.com/user-attachments/assets/3e7ccd65-eb8e-46ef-86fe-9e5f3ee81343)

Before that lets start wazuh and Thehive and confirm it is working. Since in my case last day I stopped my EC2 instances. Thus today when I started the Ips were changed. 
1-	I goto sudo nano /etc/thehive/application.conf
2-	And I changed hostname=”New Public IP”
3-	Saved and the restart/start elasticsearch, Cassandra and thehive service and check it status
Same goes for Wazuh
Goto windows agent(my PC) 
Make sure that the ossec.conf file on your Windows PC is correctly updated with the new Wazuh manager IP address (3.250.108.229). This file is usually located in C:\Program Files (x86)\ossec-agent\etc\ossec.conf.
Open ossec.conf and confirm the manager IP address is correct:
xml
Copy
<server>
  <address>3.250.108.229</address>
</server>

net stop WazuhSvc
net start WazuhSvc
 
So now have to tell wazuh that we are going to connect it to shuffle
For that open 
sudo nano /var/ossec/etc/ossec.conf 
<integration>
  <name>shuffle</name>
  <hook_url>http://YOUR_SHUFFLE_URL/api/v1/hooks/<HOOK_ID></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
![image](https://github.com/user-attachments/assets/5f59607d-c680-4625-80a5-70dfc1b7729c)

Once that is done restarted wazuh manger service
sudo systemctl restart wazuh-manager.service 
sudo systemctl status wazuh-manager.service
Ok now lets go and regenerate mimikatz telemetery on our windows machine
And goto shufftle

![image](https://github.com/user-attachments/assets/dee0605e-312a-4234-b712-7ac5d041012e)

![image](https://github.com/user-attachments/assets/a313434e-63b8-48c0-b5b0-fc30d6ac5bd3)

And how we see mimikatz detected 
![image](https://github.com/user-attachments/assets/00882a8a-ae62-4387-9f67-e98894f1c2e4)

Perfect! After testing our basic environment ready we will create our automated workflow

# WORKFLOW:
1.	Mimikatz Alert Sent to Shuffle 
2.	Shuffle Receives Mimikatz Alert (Extract SHA256 HASH From File)
3.	Check Reputation Score w/VirusTotal
4.	Send Details to TheHive to create Alert
5.	Send Email to SOC Analyst to begin investigation
Shuffle alert dissection
![image](https://github.com/user-attachments/assets/067d3100-13af-4aa2-b07e-1f8175e77a73)

Appended by hash type like sha1= <value>. So we need to parse we need to remove sha1 and use only <value>. That will be sent to virus total to check 
![image](https://github.com/user-attachments/assets/455ec05e-cb98-4b0f-aa62-7b9f90fc8f26)

To parse the SHA-256 value from the given string using regex, you can use the following regular expression:
regex
SHA256=([a-fA-F0-9]{64})
Explanation:
SHA256=: This part specifically matches the text "SHA256=" in the input string.
([a-fA-F0-9]{64}): This part captures the 64-character hexadecimal SHA-256 hash. It ensures the hash consists of exactly 64 characters, using only digits (0-9) and letters (a-f, A-F).
![image](https://github.com/user-attachments/assets/d7c828b0-74f7-4ba1-bc54-6697fe7a7e38)

Save it and click workflow and start, the click on man and then in details re run

![image](https://github.com/user-attachments/assets/fd55712f-8736-4fff-ac12-0deacffc9385)
Expand results
![image](https://github.com/user-attachments/assets/2e94feee-9dfa-413d-be04-1bf4d44a3cc5)

So we see it has successfully parse the sha256 .
Ok in next we will send this hash to virutotal and check score

![image](https://github.com/user-attachments/assets/4aaca003-09ef-4d03-8299-154234614aa3)

Ok to utilize virustotal we must have to create forst account with then 
Once account created and signin let generate API Key and copy to shuffle
![image](https://github.com/user-attachments/assets/74876c9a-44a4-4c30-9597-baf65bde0d18) ![image](https://github.com/user-attachments/assets/dec60a47-49b6-4860-a8ec-3581e25b2a5f)

1725aec2156a213e8ad44eb480efa2930ed888a0cdecf631b37d5c50dcb2c097

![image](https://github.com/user-attachments/assets/e4f21ff4-c7c0-4c99-81fd-4c77841c7039)
![image](https://github.com/user-attachments/assets/ae56f411-c34f-451d-b19c-4d35459d3253)

![image](https://github.com/user-attachments/assets/a67c8a13-9a62-4948-8d9c-03ce16a7c690)

 
And opps , it give error seems VT has some error to sync with our shuffle 


![image](https://github.com/user-attachments/assets/608a63e8-2f30-4a05-bbc2-5603177d2407)

For get report when we check in documentation 

![image](https://github.com/user-attachments/assets/33b6b519-f367-499d-8b31-b6aff5942ad3)

https://docs.virustotal.com/reference/file-info
here the last end of {id} but what we use in VT URL is /report? So seems this is the issue 
 ![image](https://github.com/user-attachments/assets/2be40386-d55e-4ebe-840a-28c4943ac981) ![image](https://github.com/user-attachments/assets/e6647215-401e-4151-ae34-13df27cdf37b) ![image](https://github.com/user-attachments/assets/c560bb9e-be9c-44f2-b74e-2e8e3cab9906)

 ![image](https://github.com/user-attachments/assets/4ca9bacc-becd-4bf7-b334-ddbee66d980f)

 After fixing and here is virus total 
 ![image](https://github.com/user-attachments/assets/5a98aa21-b1f6-4ac1-ab2a-a672a485c660)

 We can further expand to see analysis in section last malicious scan found 63 source identify this as malicious 
 ![image](https://github.com/user-attachments/assets/7f13469a-5fb8-41d5-9440-57cfc81422ad)

 Ok in next we will send details to thehive so it can create alert for case management 
Ok now lets search for Thehive in app tab
![image](https://github.com/user-attachments/assets/7bbeb41b-0938-42d9-aec7-152f4d10bf98)

So now lets go and login to Thehive website 

![image](https://github.com/user-attachments/assets/41da94c5-7ac5-4c9b-8284-2b2d6a98fce2)

![image](https://github.com/user-attachments/assets/46c0a975-f833-4c2a-a04f-66bc60d1f58a)

Set password. once you bring mouse to user  click preview  scroll down and set a password
![image](https://github.com/user-attachments/assets/6082acd3-a6f4-480a-9994-5189ff16b2a2)

For SOAR we created API key. This key we will need it. 
iWA92W+Yj9yeQrCporhBCDzem/xW77If
![image](https://github.com/user-attachments/assets/b1db8c3d-689c-4974-a808-85b3b6ce13f8)

So now Logout from admin and login as soc account. 
Ok now goto shuffle and let add thehive api key 
![image](https://github.com/user-attachments/assets/427e032c-aa97-458e-b453-e290877f9004)
Ok now we will configure Thehive in shuffle
![image](https://github.com/user-attachments/assets/f2d40d12-df5a-4b98-ab5d-a8e11df72764)

Title: "$exec.title"
Sourceref: Rule 100002
Status: New
Flag : false
Tags: ["T1003"]
Pap: 2
Severity : 2
Source : wazuh
Description: "Mimitakz Detected on host : " "$exec.text.win.system.computer"  ": from user : " "$exec.text.win.eventdata.user"
Summary: 
"Mimikatz Activity detected on: " "$exec.text.win.system.computer"  "and the process ID is: " "$exec.text.win.system.processID" "and the command line" "$exec.text.win.eventdata.commandLine"
Tlp: 2
Type: internal
Headers: Content-Type=application/json
Accept=application/json
ssl verify: False
to file : False 
![image](https://github.com/user-attachments/assets/9adedae7-b3e8-4667-aba3-12fa4c434d25)

Ok before we test we have to open port 9000 to received traffic from anywhere in EC2 Security group

![image](https://github.com/user-attachments/assets/cff0cc0a-4e0f-4e4f-a092-ab48d81af75e)

Now go and run shuffle 

Once it go through we will find alert in theHive mysoc@example.com account

![image](https://github.com/user-attachments/assets/f1309451-b7bb-44a6-b454-054477d9ba0d)

Next we have to configure an email to send a notification to SOC analysts
Again in App  Search email and drag it to workspace

 $exec.text.win.eventdata.utcTime 
Title : $exec$exec.title
Host: $exec.text.win.system.computer

![image](https://github.com/user-attachments/assets/9ecd6352-14b8-4b06-86ae-17d1545bb1f8)

And here we go after we save and run we an email is sent

![image](https://github.com/user-attachments/assets/1c3a035f-68ed-4948-ac20-c7c8c295edc1)

Here is email
![image](https://github.com/user-attachments/assets/5d3b30b1-ec06-4ba2-814b-13d3b8de8caf)












































































