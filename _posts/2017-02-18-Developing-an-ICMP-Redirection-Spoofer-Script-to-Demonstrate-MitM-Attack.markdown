---
title: Developing an ICMP Redirection Spoofer Script to Demonstrate MitM Attack
layout: post
---

Greetings,

I have translated my old Turkish blog post on CanYouPwn.Me.
You can find it directly here:
[https://canyoupwn.me/tr-icmp-redirect-saldirisi-kullanarak-mitm](https://canyoupwn.me/tr-icmp-redirect-saldirisi-kullanarak-mitm) (07.05.2016)

**Entry:**

With fake ICMP Redirection packets you can mitm a victim's network traffic and bypass some arp spoofing detection software because you can do this without creating a duplication in the Arp Table.

The method is mentioned in this article roughly, and a script that uses scapy library has been developed.


**About ICMP:**

ICMP (Internet Control Message Protocol) is protocol used for controlling purposes to provide feedback.

IP has no error correction or reporting feature. Therefore, ICMP is used for these purposes.

More information about Internet Protocol (IP) can be found [here](https://tools.ietf.org/html/rfc791#page-11).


ICMP is generally used to inform destroyed packages, error occurrences and when the path to the package will change.
"Ping" and "Traceroute" ("Tracert" on Windows), which are frequently used in command line tools, also work with ICMP Echo Request and Reply messages.

You can see what's happening when you ping a Host with Wireshark and similar programs.
 
If you give a command like:

ping www.google.com

at the command line, Wireshark will start catching ICMP packets.

When the frame is opened by double click, Type: 0 (Echo Reply) or Type: 8 (Echo Request) appears under the Internet Control Message Protocol tab.

This specifies the type of ICMP packets. 


*Echo request:*

![]({{ site.url }}/assets/icmp/Screenshot_1-1.png)


*Echo reply:*

![]({{ site.url }}/assets/icmp/Screenshot_2-1.png)


ICMP packets have different types of values and you can look at the [link](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)  for all of them. In this article only 3 of them are mentioned:


Type:8 (Echo Request)

Type:0 (Echo Reply)

Type:5 (Redirection Required)



**About ICMP Redirection Required:**

It is used to notify a better gateway. The host or router receiving the packet will add the new gateway to the routing table (if not configured for precaution purposes). There are 4 different codes: 0 (for network), 1 (for Host), 2 (for service and network), 3 (for service and host).

The visual can be useful [here](http://www.cs.technion.ac.il/Courses/Computer-Networks-Lab/projects/winter2000/dist_app/redirect_example.html) for understanding  better.

An ICMP Redirection Required frame structure looks like the following:

![]({{ site.url }}/assets/icmp/Screenshot_1.png)


The features mentioned in this article are indicated visually by numbers in red:1) Wireshark has identified "Redirect for host" for the end user.

2) ICMP appears because the protocol number is 1 in the header of the IP.

3) Redirect appears because ICMP is Type 5.

4) Redirect for host appears because of the code of Redirect is 1.


**About ICMP Redirection Spoofing Script:**

Some of the tools that can be used for ICMP Redirection attack are given below:

hping, ettercap, bettercap, zarp, scapy, icmp_redirect (Default on Kali Linux and BackTrack), icmpush, Sing .

In this article, I have developed a small script code that will attack ICMP redirection using the python scapy library.

The way to understand how to use ICMP is to look at the header information of the IP packet. If the protocol field is 1, it is understood that ICMP is used.

Scapy brings a lot of features in order not to deal with these details..

> **Note:** Kernel ip forward must be enabled on the attacker system, this command would be useful:

	
~~~~ 
echo “1”> /proc/sys/net/ipv4/ip_forward  	
~~~~

>or 

~~~~ 
sudo sysctl net.ipv4.ip_forward=1 	
~~~~

Scapy can be called from the terminal or added as a library while on a python interactive shell.

If the modules are imported like "import scapy", the methods must be used as scapy.metod().To use it as a method () instead module has to imported like this notation:

	
~~~~
“from scapy.all import * ” 
~~~~

Explanatory comments on the code added by Github to the author were seen enough.The commands that must be given for installation are as follows:

~~~~
wget https://raw.githubusercontent.com/cemonatk/My-Tools/master/cypm_icmpredirect.py
~~~~

then;
~~~~
python cypm_icmpredirect.py -a eth0 -k 'Victim IP' -g 'Gateway IP'
~~~~

To run the script in any directory through the terminal, a shortcut must be added under ~ bin / directory.

following commands would help while in the same directory;

~~~~
mv cypm_icmpredirect.py cypm_icmpredirect 

chmod +x cypm_icmpredirect

cd ~bin/

ln -s
~~~~

**Demonstration of Attack:**

The first state of the ARP table of the victim:
![]({{ site.url }}/assets/icmp/Screenshot_3.png)

After attack has started:
![]({{ site.url }}/assets/icmp/Screenshot_2-1 (1).png)


![]({{ site.url }}/assets/icmp/Screenshot_4.png)


The last state of the ARP table of the victim which is caused by "The Routing Table" has changed:


![wireshark]({{ site.url }}/assets/icmp/Screenshot_6.png)

When the victim wants to connect to canyoupwn.me, the DNS requests appear on the attacker machine's Wireshark:

![useful image]({{ site.url }}/assets/icmp/Screenshot_5.png)

**Some of the security measures against ICMP Redirection attacks:**

https://docs.oracle.com/cd/E36784_01/html/E36838/icmp-1.html
https://support.microsoft.com/en-us/kb/293626
http://www.itsyourip.com/Security/how-to-disable-icmp-redirects-in-linux-for-security-redhatdebianubuntususe-tested/comment-page-1/

For detailed information about "Full Duplex ICMP Redirection Attacks" this [link](https://blog.zimperium.com/doubledirect-zimperium-discovers-full-duplex-icmp-redirect-attacks-in-the-wild/) can be useful.
