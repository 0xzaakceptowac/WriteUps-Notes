# Topology
![[z.attachments/Pasted image 20250702225848.png]]

# Part I - Install and Configuration
* Victim and Attacker VM machines should lease IP addresses from DHCP server as previous Labs. Victim and Attacker should belong to same LAN
* Verify and setup Both machines

Pfsense Config
![[z.attachments/Pasted image 20250702234259.png]]

Linux Victim
![[z.attachments/Pasted image 20250702234623.png]]

Linux Attacker
![[z.attachments/Pasted image 20250702234651.png]]

## Installed Suricata

### Global Settings

Enabled Emerging Threats
![[z.attachments/Pasted image 20250703034326.png]]

Enabled GPLv2 Community rules
![[z.attachments/Pasted image 20250703034553.png]]

Run an update to apply
![[z.attachments/Pasted image 20250703034515.png]]

### Configure Interfaces

Uncheck these rules as per suricata documentation
![[z.attachments/Pasted image 20250703041007.png]]

Enable both WAN & LAN Interfaces
![[z.attachments/Pasted image 20250703042035.png]]

### Create an ICMP rule to test in LAN

* Home_Net for LAN

Highlighted the IP range covered for LAN
![[z.attachments/Pasted image 20250703042156.png]]

* External_net for LAN

Rules are opposite of the Home_net values (!)
![[z.attachments/Pasted image 20250703042406.png]]

* LAN Variables verify/explore pre-defined Servers -IP

Will be using default values for Servers
![[z.attachments/Pasted image 20250703042532.png]]

Will be using default values for Ports
![[z.attachments/Pasted image 20250703042705.png]]

* Custom ICMP rule
![[z.attachments/Pasted image 20250703142857.png]]

```
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"ping alert"; sid:1000001;)
```

* Alert shown based on rule configured
![[z.attachments/Pasted image 20250703142734.png]]

### Create an https rule to test in WAN

* Custom rule in WAN
![[z.attachments/Pasted image 20250703145212.png]]

```
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (msg:"https connection detected"; sid:1000002;)
```

* Alert shown based on rule configured
![[z.attachments/Pasted image 20250703145054.png]]

### Enable IPS

![[z.attachments/Pasted image 20250704122558.png]]

* Verification - blocking youtube when client wants to access it
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"User Accessed Youtube"; tls.sni; content:"youtube"; nocase; sid:1000006;)
```

* alert generated
![[z.attachments/Pasted image 20250704134427.png]]
* alert dropped
![[z.attachments/Pasted image 20250704134506.png]]
# Part II - Create custom rules

## Rule format
Action -> Header -> Options

* Perform one of the attacks ARP or DHCP spoofing as you did in Lab 3 and create a custom Snort rule to detect and prevent the attack.
##  DHCP spoofing without config

Victim IP address
![[z.attachments/Pasted image 20250703020440.png]]

Ettercap config
![[z.attachments/Pasted image 20250703021528.png]]

Victim ip catching the attack
![[z.attachments/Pasted image 20250703021804.png]]


## ARP  poisoning without config

router MacAddress
![[z.attachments/Pasted image 20250703023057.png]]

Victim arp (should match above)
![[z.attachments/Pasted image 20250703023219.png]]


Attacker send arp poisoning
![[z.attachments/Pasted image 20250703023242.png]]


Attacker Mac address
![[z.attachments/Pasted image 20250703023419.png]]

Victim arp (should match above)
![[z.attachments/Pasted image 20250703023511.png]]
## DHCP Spoofing IDS

* DHCP is on UDP port 68/67
![[z.attachments/Pasted image 20250703165820.png]]

* Test rule if it works
```
alert dhcp 192.168.70.1 67 -> any 68 (msg:"Potential DHCP spoofing- IP parameters are outside the trusted range!"; sid:1000003;)
```

* Tested a rule then it works, it captures the default dhcp process
![[z.attachments/Pasted image 20250703182145.png]]

* I just need to reverse it to capture traffic that are outside 192.168.70.1 which is our dhcp server

* added a ! mark for opposite logic
* no hits for this rule
```
alert dhcp !192.168.70.1 67 -> any 68 (msg:"Potential DHCP spoofing- IP parameters are outside the trusted range!"; sid:1000003;)
```

* First my spoofing attacks are not getting through as pfsense offer faster IP than ettercap
* I need to stop DHCP from pfsense to victim machine
![[z.attachments/Pasted image 20250703180433.png]]

* Temporarily blacklisted the victims machine to make the spoofing attack sucessful![[z.attachments/Pasted image 20250703223601.png]]

* DHCP spoofing sucessful
![[z.attachments/Pasted image 20250703223633.png]]

* Stretched the rule to detect any traffic that is occuring

```
alert dhcp any any -> any any (msg:"might be False positive - DHCP rule any any"; sid:1000004;)
```

* Ettercap seems to ping back to client machine using IPv6
* IDS did not capture the DHCP address that was set it ettercap because it is on different network?
* The only thing that was captured is:
	* the pingback of ipv6 from ettercap 
	* DHCP Request from client when host don't have IP address
![[z.attachments/Pasted image 20250703222924.png]]


## DHCP Spoofing (IPS)

* To tackle this rule creation, we must know how ettercap works
* based on the application behavior it scans via ipv6 and pings back for any devices in network
* Goal is to drop packets from ipv6 ping from outside network to our home network
* When this is achieved,
	* Suricata will block any ipv6 ping backs from ettercap
	* Suricata will block any DHCP offer that is outside it's gateway
* Implemented this rules
```
drop icmp any any -> any any (msg:"Blocking Device Discovery"; sid:1000008;) drop tcp any any -> any any (msg:"Rejecting Device Discovery"; sid:1000009;) 
drop udp !192.168.70.1 67 -> any 68 (msg:"Dropping DHCP offer"; sid:10000010;)
```
* List of activities that was blocked
![[z.attachments/Pasted image 20250704150238.png]]

* IP of victim machine
![[z.attachments/Pasted image 20250704150341.png]]

# Part III - Analyze predefined Snort rules
* WAN interface, under Global Settings > Enable Snort GPLv2 Community rules

* Hide Deprecated Rules Categories 
![[z.attachments/Pasted image 20250704151145.png]]
* Remove Blocked Hosts Interval one hour as recommended
![[z.attachments/Pasted image 20250704151204.png]]
* Under WAN categories make sure the GPLv2 is enabled and saved
![[z.attachments/Pasted image 20250704151220.png]]

Select one default enabled rule, click on SID to see the rule and explain it
* Alert that references to CVE 2014-0160 which is codename heartbleed bug which allows attackers to obtain sensitive information in process memory via buffer over-read
* uses tls protocol
* any source and destination IP
* any source and destination ports
* will only trigger if the connection was established
* object should match in database app-layer-event:"event"
* and other stuff for report categorization
```
alert tls any any -> any any (msg:"SURICATA TLS invalid encrypted heartbeat encountered, possible exploit attempt (heartbleed)"; flow:established; app-layer-event:tls.dataleak_heartbeat_mismatch; flowint:tls.anomaly.count,+,1; classtype:protocol-command-decode; reference:cve,2014-0160; sid:2230014; rev:1;)
```

Repeat previous steps to add from Global Settings: Emerging Threats Open (ETO) rules and explain one of the rules
* Alert that points out on an attempted service scan from NMAP
* uses tcp protocol
* fragbits:!M; dsize:0; flags:S,12; ack:0; window:2048 - packet related stuff
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sV"; fragbits:!M; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000545; rev:8; metadata:created_at 2010_07_30, confidence Low, signature_severity Informational, updated_at 2019_07_26;)

```


# PART IV - Port Knocking and IDS detection
## 1. Portknocking configuration

* Configure knockd in Victim's machine

reject port 22 connections using iptables
```
sudo iptables -A INPUT -p tcp --dport 22 -j REJECT 
```

save config
```
sudo netfilter-persistent save
```

start the service
```
sudo systemctl start netfilter-persistent
```


edit knockd.conf
```
sudo nano /etc/knockd.conf
```
![[z.attachments/Pasted image 20250703011705.png]]

edit knockd service
```
sudo nano /etc/default/knockd
```
![[z.attachments/Pasted image 20250703012031.png]]

start knockd service
```
sudo systemctl start knockd
```

verify the service
```
ssh tubetita@192.168.70.2 
```
![[z.attachments/Pasted image 20250703012633.png]]

Use port knocking to connect ssh
```
knock 192.168.70.2 9991 9992 9993 -d 500

ssh tubetita@192.168.70.2
```
![[z.attachments/Pasted image 20250703014508.png]]

## 2. Use IDS to detect ssh login attempts. 

```
alert tcp any any -> any 22 (msg:"SSH Connection detected"; sid:1000011;)
```
![[z.attachments/Pasted image 20250704163947.png]]
## 3. Bonus (challenge) detect port scanning

* Got this rule in Emerging threat scans
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN NMAP -f -sV"; fragbits:!M; dsize:0; flags:S,12; ack:0; window:2048; threshold: type both, track by_dst, count 1, seconds 60; classtype:attempted-recon; sid:2000545; rev:8; metadata:created_at 2010_07_30, confidence Low, signature_severity Informational, updated_at 2019_07_26;)

```

```
alert icmp any any -> any any (msg:"NMAP -sL"; sid:1000030;)
```

