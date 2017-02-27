![Zenected](https://zenected.com/zenected_logo_h120.png)
##Zenected Threat Defense VPN

__Zenected__ is a cloud based security threat protection service. It’s delivered through a set of pre-configured services. Once a user connects to the __Zenected__, that user’s network traffic is filtered to keep the bad things out (e.g. phishing sites, malware). The only thing this a user has to configure on the endpoint device (be it a mobile device, a desktop or laptop or IoT device) is a VPN connection.

All services are updated every hour with a new set of threat indicators prepared by Perun Works.

__Zenected__ is easy to manage. It uses a web front-end for administrators to manage your instance. An administrator user can:
- manage __Zenected__ users including adding more admin users
- blacklist URLs or domain names that you don't want your users to access
- whitelist URLs or domain names, that were identified as malicious but you still want your users to be able to get to them
- review exception requests from users

If you are a __Zenected__ end-user what you will like about it, is:
- no need to install additional software on your mobile phone, tablet or laptop – __Zenected__ uses standard OS features build-in into all modern systems
- if you encounter a certain resource blocked by the system, you can request an exception. Each exception is then reviewed by an administrator.

For more info and resources visit: https://zenected.com

__Zenected__ code posted on GitHub is licensed under GNU General Public License (https://www.gnu.org/licenses/gpl-3.0.en.html). More code will be posted in due course so please visit this pages regularly.

##Requirements
1. Host running Ubuntu 14.04 LTS. You can use the mini install (https://help.ubuntu.com/community/Installation/MinimalCD)
2. If you plan to run it at home, please make sure you have a routable IP address. If you are not sure about it, please ask you ISP for help.
3. Make sure you open the following ports on your router:
   `tcp 80` (webserver),
   `tcp 443` (webserver - user admin and Zenected admin),
   `udp 500` (VPN),
   `udp 4500` (VPN)

##Installation
It's fairly simple, but requires a few steps.

1. Copy the **__zenected_install.sh__** into your future __Zenected__ server to __/opt__ folder.
2. Make the file executable by:
   `sudo chmod 750 /opt/zenected_install.sh`
3. Run it:
   `sudo /opt/zenected_install.sh`
4. Relax for a few minutes. Now it's a good time to grab a coffee. The install will take a few minutes depending on your system specs.
5. Once the script finishes, check if __Zenected__ got installed by:
   `dpkg -s zenected-aws`
6. If the __zenected__ package is not installed, you can install it by:
   `sudo apt-get install zenected-aws`
7. Once __zenected__ is installed on your system, please configure it by running:
   `sudo /opt/zenected/zenected_setup.zenx`
   
##Thanks!
__Zenected__ uses a lot of great free software. Here is a list:

- Ubuntu (http://www.ubuntu.com/)
- PHP (https://secure.php.net/)
- MySQL (http://www.mysql.com/)
- daloRADIUS (http://www.daloradius.com/)
- Dnsmasq (http://www.thekelleys.org.uk/dnsmasq/doc.html)
- Squid (http://www.squid-cache.org/)
- SquidGuard (http://www.squidguard.org/)

##News and updates
For news and updates please follow us on:

- Facebook: https://www.facebook.com/Zenected/
- Twitter: https://twitter.com/zenected

##Last but not least...
We are proud to be presented on BlackHat Asia 2017 Arsenal. 
[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2017.svg)](https://www.toolswatch.org/2017/02/the-black-hat-arsenal-asia-2017-great-line-up/)
