# Great-Firewall

A network security project that investigates the on-path "Great Firewall of China"

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
