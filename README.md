<img src="https://github.com/Karsten12/Great-Firewall/blob/master/Firewall.png" height="300">

# Great-Firewall

A network security project completed by myself and my good friend [Danny Deng-Winter](https://github.com/winnerwinter?tab=overview&from=2017-01-18) that investigates the on-path "Great Firewall of China"

#### 1. Proof ####
- Show via direct TCP connection to a server in China the existance of the Great firewall
- Telnet to 202.106.121.6 IPv4 address of the Chinese Ministry of Industry and Information
Technology www.miit.gov.cn.
- Do a google search on behalf of that server and show via pcap files that the firewall kills the connection via TCP RST packets (Google is banned in China)

#### 2. Ping function ####
- A utility that pings an inputed server ip from a random source port to check if it is alive, dead or blocked by the firewall
- TCP handshake

#### 3. Traceroute function #### 
- Traces the route our TCP connection travels through
- Accomplished by sending multiple packets of varying TTL (which die en-route) and thus traces the route the packets take

#### 4. Evasion ####
- A function that attempts to evade the Great firewalls censorship of Google in China by splitting up our Google search query into multiple data packets that do not trigger by individually seem to have nothing to do with Google
- Due to the Great Firewall's design, it uses pattern matching to search for keywords such as "google" or "facebook" that may indicate the need to send a reset pack. We thus send our packet in fragments such that the firewall does not piece them together such that these packets may go through and are then pieced together by the Chinese web-server. Additionally because we want the packet to arrive in the correct order we must pay attention, to the seq and ack numbers of the packets we send.


##### Logo designed by Karsten12 #####
