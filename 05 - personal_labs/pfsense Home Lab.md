# Network Topology
## Part I & II

![](../z.attachments/Pasted%20image%2020250727162628.png)

## Part III

![](../z.attachments/Pasted%20image%2020250727162704.png)

# Part 1

1. [x] Configure the getaways on the Point-to-Point interfaces on Network 10.0.0.0/24 

Gateway Network C
![](../z.attachments/Pasted%20image%2020250727162729.png)Gateway Network A
![](../z.attachments/Pasted%20image%2020250727162908.png)

2. [x] Configure static routes. Wan interface on PF1 should point to OPT1 interface on PF2 and vice versa 
Static Route Network C
![](../z.attachments/Pasted%20image%2020250727162929.png)Static Route Network A
![](../z.attachments/Pasted%20image%2020250727162951.png)

3. [x] Verify default firewall setting by checking the logs 

4. [x] Verify and configure the firewall for each interface on PF1 and PF2 to allow traffic among the networks 

Network C - WAN, Firewall rules
![](../z.attachments/Pasted%20image%2020250727163012.png)Network C - LAN, Firewall rules
![](../z.attachments/Pasted%20image%2020250727163029.png)Network C - OPT, Firewall rules
![](../z.attachments/Pasted%20image%2020250727163053.png)

5. [x] Use ping to test the connectivity among networks. You should be able to ping from any device on network A any device on network C and have access to the internet.

Network C ping to Network A
![](../z.attachments/Pasted%20image%2020250727163116.png)Network C ping google.com
![](../z.attachments/Pasted%20image%2020250727163134.png)
Network A ping to Network C
![](../z.attachments/Pasted%20image%2020250727163157.png)
Network A ping to google.com
![](../z.attachments/Pasted%20image%2020250727163217.png)
6. [x] Use traceroute and netstat commands to verify the routing from source to destination network 
Network C netstat to Network A
![](../z.attachments/Pasted%20image%2020250727163238.png)
Network A traceroute to Network C
![](../z.attachments/Pasted%20image%2020250727163256.png)



# Part 2

- [x] On Windows VM configure Web Services by enabling IIS. Under control panel enable 
![](../z.attachments/Pasted%20image%2020250727163340.png)
- [x] Use IIS manager to verify Default Web Site status, port and path. Verify access to the web server by accessing web browser http://localhost You can create a different web page
![](../z.attachments/Pasted%20image%2020250727163403.png)
- [x] Now add OpenSSH server app under system> optional features> view and add OpenSSH Server. After installing the app under services make sure the service is enabled and running automatically 
![](../z.attachments/Pasted%20image%2020250727163423.png)

- [x] Use Windows Defender Firewall to create rules that allow access to the respective ports to access the web server remotely and establish SSH connection 
![](../z.attachments/Pasted%20image%2020250727163445.png)
- [x] Make Windows VM a client of Network C -LAN on PF2  
- [x] On PfSense PF2 create firewall rules that allow HTTP and SSH traffic
![](../z.attachments/Pasted%20image%2020250727163503.png)
- [x] On Network A have a Linux (kali) client machine connected (Untrusted) to the network 
![](../z.attachments/Pasted%20image%2020250727163520.png)
- [x] Use nmap or other tool to verify open ports on Network C (Windows)
![](../z.attachments/Pasted%20image%2020250727163539.png)
- [x] On PfSense PF1 under System> Advanced > admin Access enable Secure Shell and and Allow Agent Forwarding 
- [x] From VM on Network A (Linux) access web server on windows and establish a SSH connection. Use log traffic to analyze the results
SSH to gatway
![](../z.attachments/Pasted%20image%2020250727163601.png)

SSH to windows machine
![](../z.attachments/Pasted%20image%2020250727163625.png)
![](../z.attachments/Pasted%20image%2020250727163654.png)



- [x] On PF2 create firewall rules that blocks access to the web server and SSH
![](../z.attachments/Pasted%20image%2020250727163715.png)
- [x] Block access to internet (specific protocol) from Network C. Use log traffic to analyze the results

![](../z.attachments/Pasted%20image%2020250727163736.png)



# PART III Port Forwarding /10 

1. [x] Configure the following topology to implement Port forwarding 
2. [x] Before booting PF2 on Virtual box change ONLY NAT Interface into NAT Network. 
Considered as Nat Network
![](../z.attachments/Pasted%20image%2020250727163801.png)

PF2-Configuration
![](../z.attachments/Pasted%20image%2020250727163819.png)


3. [x] Configure one of the Linux machines with same Virtual Box interface NAT Network. This Linux machine represents the machine outside Network C and is connected to PF2 via NAT Network interface 
![](../z.attachments/Pasted%20image%2020250727163848.png)

Same network via NAT network
![](../z.attachments/Pasted%20image%2020250727163914.png)

3. [x] Verify IP addresses on PF2 and Linux machines you should be able to ping 10.0.2.0/24 network
PF2 ping to kali
![](../z.attachments/Pasted%20image%2020250727163932.png)

Kali to PF2
![](../z.attachments/Pasted%20image%2020250727163952.png)

3. [x] Boot the VM on Network C 192.168.0.0/24. You should be able to ping from VM the NAT Network on PF2 and have access to Internet

Windows (LAN-PFSENSE) ping to KALI (NAT-Network)
![](../z.attachments/Pasted%20image%2020250727164013.png)

5. [x] Start Apache2 (Web server) on VM located on Network C and Create a web page under /var/www directory and call it example.html 
![](../z.attachments/Pasted%20image%2020250727164048.png)

6. [x] Create firewall on PF2 to allow ICMP and TCP access in the 10.0.2.0/24 network 
![](../z.attachments/Pasted%20image%2020250727164105.png)

7. [x] Configure on PF2 Firewall NAT Port forwarding as follows: 

	- [x] a. Interface WAN 
	- [x] b. IPV4 family, TCP protocol 
	- [x] c. Destination WAN address 
	- [x] d. Destination port range HTTP
	- [x] e. Redirect target ip should be the IP of the host (VM on Network C) 192.168.0.0/24
	- [x] f. Redirect target port: HTTP 
	- [x] g. Input some description h. Enable NAT reflection as: Pure NAT 
	- [x] i. Filter rule association: Create new associated filter rule 

![](../z.attachments/Pasted%20image%2020250727164128.png)

6. [x] Check firewall rule for WAN interface. It should had added the new NAT rule 

![](../z.attachments/Pasted%20image%2020250727164155.png)

8. [x] Test port forwarding by accessing from outside http://10.0.2.15 (NAT Network) interface on PF2. The firewall will forward port HTTP 80 to VM on Network C. You should be able to access the web page you create on VM in network C

![](../z.attachments/Pasted%20image%2020250727164219.png)
