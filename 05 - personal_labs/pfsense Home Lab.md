# Network Topology
## Part I & II

![[../../z.Attachments/Pasted image 20250529192001.png]]

## Part III

![[../../z.Attachments/Pasted image 20250529192203.png]]
# Part 1

1. [x] Configure the getaways on the Point-to-Point interfaces on Network 10.0.0.0/24 

Gateway Network C
![[../../z.Attachments/Pasted image 20250529184710.png]]
Gateway Network A
![[../z.Attachments/Pasted image 20250529184927.png]]
2. [x] Configure static routes. Wan interface on PF1 should point to OPT1 interface on PF2 and vice versa 
Static Route Network C
![[../../z.Attachments/Pasted image 20250529184828.png]]
Static Route Network A
![[../../z.Attachments/Pasted image 20250529185012.png]]

3. [x] Verify default firewall setting by checking the logs 
4. [x] Verify and configure the firewall for each interface on PF1 and PF2 to allow traffic among the networks 

Network C - WAN, Firewall rules
![[../../z.Attachments/Pasted image 20250529191619.png]]
Network C - LAN, Firewall rules
![[../../z.Attachments/Pasted image 20250529194005.png]]
Network C - OPT, Firewall rules
![[../../z.Attachments/Pasted image 20250529193941.png]]




5. [x] Use ping to test the connectivity among networks. You should be able to ping from any device on network A any device on network C and have access to the internet.

Network C ping to Network A
![[../../z.Attachments/Pasted image 20250530095908.png]]
Network C ping google.com
![[../../z.Attachments/Pasted image 20250529211608.png]]

Network A ping to Network C
![[../../z.Attachments/Pasted image 20250529204105.png]]

Network A ping to google.com
![[../z.Attachments/Pasted image 20250529201056.png]]

6. [x] Use traceroute and netstat commands to verify the routing from source to destination network 
Network C netstat to Network A
![[../../z.Attachments/Pasted image 20250530100304.png]]

Network A traceroute to Network C
![[../../z.Attachments/Pasted image 20250529211924.png]]
6. [ ] Demo result to instructor




# Part 2

- [x] On Windows VM configure Web Services by enabling IIS. Under control panel enable 
![[../z.Attachments/Pasted image 20250529212225.png]]
- [x] Use IIS manager to verify Default Web Site status, port and path. Verify access to the web server by accessing web browser http://localhost You can create a different web page
![[../z.Attachments/Pasted image 20250529212320.png]]
- [x] Now add OpenSSH server app under system> optional features> view and add OpenSSH Server. After installing the app under services make sure the service is enabled and running automatically 
![[../z.Attachments/Pasted image 20250529212435.png]]

- [x] Use Windows Defender Firewall to create rules that allow access to the respective ports to access the web server remotely and establish SSH connection 
![[../z.Attachments/Pasted image 20250529212652.png]]
- [x] Make Windows VM a client of Network C -LAN on PF2  
- [x] On PfSense PF2 create firewall rules that allow HTTP and SSH traffic
![[../z.Attachments/Pasted image 20250602183149.png]]
- [x] On Network A have a Linux (kali) client machine connected (Untrusted) to the network 
![[../z.Attachments/Pasted image 20250602171020.png]]
- [ ] Use nmap or other tool to verify open ports on Network C (Windows)
![[../../z.Attachments/Pasted image 20250602171040.png]]
- [x] On PfSense PF1 under System> Advanced > admin Access enable Secure Shell and and Allow Agent Forwarding 
- [x] From VM on Network A (Linux) access web server on windows and establish a SSH connection. Use log traffic to analyze the results
SSH to gatway
![[../../z.Attachments/Pasted image 20250602174333.png]]

SSH to windows machine
![[../../z.Attachments/Pasted image 20250602180048.png]]
![[../../z.Attachments/Pasted image 20250602180325.png]]


- [x] On PF2 create firewall rules that blocks access to the web server and SSH
![[../../z.Attachments/Pasted image 20250602183058.png]]
- [x] Block access to internet (specific protocol) from Network C. Use log traffic to analyze the results

![[../../z.Attachments/Pasted image 20250602183001.png]]


- [x] Demo result to instructor


# PART III Port Forwarding /10 

1. [x] Configure the following topology to implement Port forwarding 
2. [ ] Before booting PF2 on Virtual box change ONLY NAT Interface into NAT Network. 
Considered as Nat Network
![[../../z.Attachments/Pasted image 20250602183342.png]]

PF2-Configuration
![[../../z.Attachments/Pasted image 20250602183437.png]]


3. [ ] Configure one of the Linux machines with same Virtual Box interface NAT Network. This Linux machine represents the machine outside Network C and is connected to PF2 via NAT Network interface 
![[../z.Attachments/Pasted image 20250602184742.png]]

Same network via NAT network
![[../../z.Attachments/Pasted image 20250602185053.png]]
![[../z.Attachments/Pasted image 20250602185129.png]]

3. [ ] Verify IP addresses on PF2 and Linux machines you should be able to ping 10.0.2.0/24 network
PF2 ping to kali
![[../../z.Attachments/Pasted image 20250602185359.png]]

Kali to PF2
![[../z.Attachments/Pasted image 20250602203657.png]]
3. [ ] Boot the VM on Network C 192.168.0.0/24. You should be able to ping from VM the NAT Network on PF2 and have access to Internet

Windows (LAN-PFSENSE) ping to KALI (NAT-Network)
![[../../z.Attachments/Pasted image 20250602185743.png]]


5. [x] Start Apache2 (Web server) on VM located on Network C and Create a web page under /var/www directory and call it example.html 
![[../../z.Attachments/Pasted image 20250602194833.png]]

6. [x] Create firewall on PF2 to allow ICMP and TCP access in the 10.0.2.0/24 network 
![[../../z.Attachments/Pasted image 20250602195254.png]]

7. [x] Configure on PF2 Firewall NAT Port forwarding as follows: 

	- [x] a. Interface WAN 
	- [x] b. IPV4 family, TCP protocol 
	- [x] c. Destination WAN address 
	- [x] d. Destination port range HTTP
	- [x] e. Redirect target ip should be the IP of the host (VM on Network C) 192.168.0.0/24
	- [x] f. Redirect target port: HTTP 
	- [x] g. Input some description h. Enable NAT reflection as: Pure NAT 
	- [x] i. Filter rule association: Create new associated filter rule 

![[../../z.Attachments/Pasted image 20250602202643.png]]

8. [ ] Check firewall rule for WAN interface. It should had added the new NAT rule 

![[../../z.Attachments/Pasted image 20250602202710.png]]
8. [ ] Test port forwarding by accessing from outside http://10.0.2.15 (NAT Network) interface on PF2. The firewall will forward port HTTP 80 to VM on Network C. You should be able to access the web page you create on VM in network C

![[../../z.Attachments/Pasted image 20250602204248.png]]
