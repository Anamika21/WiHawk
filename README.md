In a wireless network there are thousands of Wi-Fi routers which are configured with default user name and passwords, which make them vulnerable to security breaches. 
  
But so far we don’t have any tool which will prompt you before being victim of attack that your router is vulnerable to  either bypass authentication or its configured to default credentials.
WI-Hawk, It is an open source tool for auditing IP addresses to sniff out Wireless routers which are configured with default admin passwords and find out the routers which are vulnerable to bypass Authentication. 
The tool provides capability to scan network for such default configured routers by taking input in one of the following format: 
 
1.  Single IP
When user provides IP in xxx.xxx.x.x format, Wi-Hawk first checks whether router is vulnerable to bypass authentication or not, then it goes for auditing the password for the given IP 
 
2. Range of IP :
Wi-HAWK supports different format for range of IPs, User can provide IPs in XXX.XX.X.X-X or XXX.XX.X.X/X format. When provided a range of IP in above format, Wi-Hawk performs the same action as it does in scan for Single IP. For each IP in the given range, Wi-Hawk will first check if router is vulnerable to bypass authentication followed by auditing of each IP for default Username and Password. 
 
3. Shodan API: 
Shodan is a search engine that lets you find out specific types of computers (routers, servers, etc.) in the internet using a variety of filters like OS,Country,City,URL 
Wi-Hawk has been integrated to use SHODAN and its customized search engine to find out vulnerable IPs worldwide. The search filter which has been integrated to Wi-Hawk using Shodan
 
The tool can be used to identify following two types of security vulnerabilities in  provided IPs : 
 
1. Authentication Bypass 
2. Routers configured with default username/passwords
 
Authentication Bypass: Authentication plays a critical role in the security of web applications. When a user provides login credential to authenticate and prove his identity, user has assigned to certain privileges based on credential. It is often possible to bypass authentication by tampering with requests. Authentication bypass vulnerabilities, like buffer overflows, are generally caused by programmers when they assume that users will behave in a certain way, failing to foresee the consequences of users doing the unexpected. Penetration testing framework like Metasploit  includes a number of authentication bypass modules which use techniques such as exploiting buffer overflows in the authentication mechanism, but there are simpler methods that hackers can use as well. 
 
Wi-Hawk has been successfully able to identify routers for which authentication can be bypassed just by editing the http request URL to the IP. Wi-Hawk maintains such a list of URL which when appended to the http request can bypass authentication of the router by simply skipping the login page and directly calling an internal page that is supposed to be accessed only after authentication has been performed. In addition to this, it is often possible to bypass authentication measures by tampering with requests and tricking the application into thinking that the user is already authenticated. This can be accomplished either by modifying the given URL parameter or by manipulating the form or by counterfeiting sessions. 
Authentication bypass vulnerabilities, like buffer overflows, are generally caused by programmers when they assume that users will behave in a certain way, failing to foresee the consequences of users doing the unexpected. Penetration testing framework like Metasploit[2] includes a number of authentication bypass modules which use techniques such as exploiting buffer overflows in the authentication mechanism, but there are simpler methods that hackers can use as well. 
Wi-Hawk has been successfully able to identify routers for which authentication can be bypassed just by editing the http request URL to the IP. Wi-Hawk maintains such a list of URL which when appended to the http request can bypass authentication of the router. 
Identifying routers with default Username/Password 
The tool uses a database which contains a list of possible router’s default username/passwords. Based on type of input given it scans a single IP, or a range of IPs, or uses SHODAN search engine to scan the IPs returned by the search.


To use WiHawk, please follow below mentioned steps:
  1. Install IRONWASP(https://ironwasp.org/)
  2. Launch Ironwasp to open it.
  3. Goto Tools option available in menu.
  4. Select WiHawk to auidt your router and launch it.
  5. By launching WiHawk it gives you options to enter the value in 3 ways:
  
        (a) Audit SIngle IP: Provide valid IP as input to scan in following format
                  Ex: 192.168.1.1
                  
        (b) Audit Range of IPs or Network: Provide range of valid IPs in below mentioned format:
                  Ex: 192.168.1.1-25   or 192.168.1.1/25
                  
        (c) Audit Using Shodan API: To use Shodan API , you must have an API key to scan vulnerbale IPs in your Country, City and Geo Location.
        
              
          
