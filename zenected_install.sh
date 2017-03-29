#!/bin/bash
# Welcome message
echo -e "\n\nThanks for installing Zenected Threat Defense VPN. The whole process will take a few minutes depending on your system specs.\n"

##hiding output
#{
#} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# OS: update the system
echo -e "1. Updating the OS and installing initial dependencies"

#hiding output
{
/usr/bin/apt-get -qq update && /usr/bin/apt-get -qq -y upgrade > /dev/null

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# Depts: Install initial dependencies
echo -e "Installing dependencies"
/usr/bin/apt-get -qq -y install curl git mysql-client debconf sed sqlite3 > /dev/null

} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# For a start: Creating Zenected config file and relevant dirs
echo -e "2. Creating Zenected config file and relevant dirs"

#hiding output
{

mkdir /etc/zenected
echo -e "#Zenected config\n" > /etc/zenected/zenected.conf
 #getting host ip
 CURRENT_IP=`curl -k -s https://zenected.com/remote_ip.php`
 echo -e "ZEN_IP=\""$CURRENT_IP"\"" >> /etc/zenected/zenected.conf
mkdir -p /opt/zenected/downloads
mkdir /opt/zenected/dns
mkdir /opt/zenected/url
mkdir -p /var/www/zen/users
#this next one is for Google Cloud Platform
mkdir -p /etc/ipsec.d/examples 

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# OS: set up regular updates
echo -e "3. Configuring automated OS updates"

#hiding output
{

UPDATES_M=$[RANDOM % 38 ]
UPDATES_H=$[RANDOM % 23 ]
echo -e "\n0 3\t* * *\troot\t/usr/bin/apt-get update && /usr/bin/apt-get -y upgrade >> /var/log/apt/myupdates.log\n" >> /etc/crontab
#@echo -e "\n$UPDATES_H $UPDATES_M        * * *   root    /opt/zenected/zenected_update.zenx" >> /etc/crontab

} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# IPS: Suricata and Oinkmaster
echo -e "4. Installing and configuring IPS"

#hiding output
{

##as described here: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation

sudo apt-get -y install oinkmaster libpcre3 libpcre3-dbg libpcre3-dev \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config

sudo apt-get -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0

VER=3.1
wget "http://www.openinfosecfoundation.org/download/suricata-$VER.tar.gz"
tar -xvzf "suricata-$VER.tar.gz"
cd "suricata-$VER"

sudo apt-get -y install libnss3-dev libnspr4-dev

./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libnss-libraries=/usr/lib --with-libnss-includes=/usr/include/nss/ --with-libnspr-libraries=/usr/lib --with-libnspr-includes=/usr/include/nspr

make
sudo make install-full
sudo ldconfig

## ending Suricata install

#### /etc/suricata/suricata.yaml
cat > /etc/suricata/suricata.yaml << SURICATA
%YAML 1.1
---
host-mode: auto
default-log-dir: /var/log/suricata/
unix-command:
  enabled: no

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'

  # Extensible Event Format (nicknamed EVE) event log in JSON format
  - eve-log:
      enabled: yes
      type: file #file|syslog|unix_dgram|unix_stream
      filename: eve.json
      # the following are valid when type: syslog above
      #identity: "suricata"
      #facility: local5
      #level: Info ## possible levels: Emergency, Alert, Critical,
                   ## Error, Warning, Notice, Info, Debug
      types:
        - alert
        ##- http:
        ##    extended: yes     # enable this for extended logging information
            # custom allows additional http fields to be included in eve-log
            # the example below adds three additional fields when uncommented
            #custom: [Accept-Encoding, Accept-Language, Authorization]
        ##- dns
        ##- tls:
        ##    extended: yes     # enable this for extended logging information
        - files:
            force-magic: yes ##no   # force logging magic on all logged files
            force-md5: yes ##no     # force logging of md5 checksums
        #- drop
        ##- ssh
  - unified2-alert:
      enabled: no #yes
      filename: unified2.alert
      xff:
        enabled: no
        mode: extra-data
        header: X-Forwarded-For
  - http-log:
      enabled: yes
      filename: http.log
      append: yes
  - tls-log:
      enabled: no  # Log TLS connections.
      filename: tls.log # File to store TLS logs.
      append: yes
      certs-log-dir: certs # directory to store the certificates files
  - dns-log:
      enabled: no
      filename: dns.log
      append: yes
  - pcap-info:
      enabled: no
  - pcap-log:
      enabled:  no
      filename: log.pcap
      limit: 1000mb
      max-files: 2000
      mode: normal # normal or sguil.
      use-stream-depth: no #If set to "yes" packets seen after reaching stream inspection depth are ignored. "no" logs all packets
  - alert-debug:
      enabled: no
      filename: alert-debug.log
      append: yes
  - alert-prelude:
      enabled: no
      profile: suricata
      log-packet-content: no
      log-packet-header: yes
  - stats:
      enabled: yes
      filename: stats.log
      interval: 8
  - syslog:
      enabled: no
      facility: local5
  - drop:
      enabled: no
      filename: drop.log
      append: yes
  - file-store:
      enabled: no       # set to yes to enable
      log-dir: files    # directory to store the files
      force-magic: no   # force logging magic on all stored files
      force-md5: no     # force logging of md5 checksums
  - file-log:
      enabled: yes ##no
      filename: files-json.log
      append: yes
      force-magic: yes ##no   # force logging magic on all logged files
      force-md5: yes ##no     # force logging of md5 checksums
magic-file: /usr/share/file/magic
nfq:
#  mode: accept
#  repeat-mark: 1
#  repeat-mask: 1
#  route-queue: 2
#  batchcount: 20
#  fail-open: yes
nflog:
  - group: 2
    buffer-size: 18432
  - group: default
    qthreshold: 1
    qtimeout: 100
    max-size: 20000
af-packet:
  - interface: eth0
    threads: 1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
  - interface: eth1
    threads: 1
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
  - interface: default

legacy:
  uricontent: enabled

detect-engine:
  - profile: medium
  - custom-values:
      toclient-src-groups: 2
      toclient-dst-groups: 2
      toclient-sp-groups: 2
      toclient-dp-groups: 3
      toserver-src-groups: 2
      toserver-dst-groups: 4
      toserver-sp-groups: 2
      toserver-dp-groups: 25
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]  # include only these cpus in affinity settings
    - receive-cpu-set:
        cpu: [ 0 ]  # include only these cpus in affinity settings
    - decode-cpu-set:
        cpu: [ 0, 1 ]
        mode: "balanced"
    - stream-cpu-set:
        cpu: [ "0-1" ]
    - detect-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive" # run detect threads in these cpus
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"
    - verdict-cpu-set:
        cpu: [ 0 ]
        prio:
          default: "high"
    - reject-cpu-set:
        cpu: [ 0 ]
        prio:
          default: "low"
    - output-cpu-set:
        cpu: [ "all" ]
        prio:
           default: "medium"
  detect-thread-ratio: 1.5

cuda:
  mpm:
    data-buffer-size-min-limit: 0
    data-buffer-size-max-limit: 1500
    cudabuffer-buffer-size: 500mb
    gpu-transfer-size: 50mb
    batching-timeout: 2000
    device-id: 0
    cuda-streams: 2
mpm-algo: ac
pattern-matcher:
  - b2gc:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2gm:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b2g:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
  - b3g:
      search-algo: B3gSearchBNDMq
      hash-size: low
      bf-size: medium
  - wumanber:
      hash-size: low
      bf-size: medium

defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535 # number of defragmented flows to follow
  max-frags: 65535 # number of fragments to keep (higher than trackers)
  prealloc: yes
  timeout: 60
flow:
  memcap: 64mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30
vlan:
  use-for-tracking: true

flow-timeouts:

  default:
    new: 30
    established: 300
    closed: 0
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
  tcp:
    new: 60
    established: 3600
    closed: 120
    emergency-new: 10
    emergency-established: 300
    emergency-closed: 20
  udp:
    new: 30
    established: 300
    emergency-new: 10
    emergency-established: 100
  icmp:
    new: 30
    established: 300
    emergency-new: 10
    emergency-established: 100

stream:
  memcap: 32mb
  checksum-validation: yes      # reject wrong csums
  inline: auto                  # auto will use inline mode in IPS mode, yes or no set it statically
  reassembly:
    memcap: 128mb
    depth: 1mb                  # reassemble 1mb into a stream
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Host table:
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 16777216

logging:
  default-log-level: notice
  default-output-filter:
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: no
      filename: /var/log/suricata.log
  - syslog:
      enabled: no
      facility: local5
      format: "[%i] <%d> -- "

mpipe:
  load-balance: dynamic
  iqueue-packets: 2048
  inputs:
  - interface: xgbe2
  - interface: xgbe3
  - interface: xgbe4
  stack:
    size128: 0
    size256: 9
    size512: 0
    size1024: 0
    size1664: 7
    size4096: 0
    size10386: 0
    size16384: 0

pfring:
  - interface: eth0
    threads: 1
    cluster-id: 99
    cluster-type: cluster_flow
  - interface: default

pcap:
  - interface: eth0
  - interface: default

pcap-file:
  checksum-checks: auto

ipfw:
default-rule-path: /etc/suricata/rules
rule-files:
 - perun_hashes.rules
 - perun_rules.rules
 - perun_feodo.abusech.rules
 - perun_phishing.rules
 - perun_zeus.abusech.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

vars:

  address-groups:

    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "$HOME_NET"

    SMTP_SERVERS: "$HOME_NET"

    SQL_SERVERS: "$HOME_NET"

    DNS_SERVERS: "$HOME_NET"

    TELNET_SERVERS: "$HOME_NET"

    AIM_SERVERS: "$EXTERNAL_NET"

    DNP3_SERVER: "$HOME_NET"

    DNP3_CLIENT: "$HOME_NET"

    MODBUS_CLIENT: "$HOME_NET"

    MODBUS_SERVER: "$HOME_NET"

    ENIP_CLIENT: "$HOME_NET"

    ENIP_SERVER: "$HOME_NET"

  port-groups:

    HTTP_PORTS: "80"

    SHELLCODE_PORTS: "!80"

    ORACLE_PORTS: 1521

    SSH_PORTS: 22

    DNP3_PORTS: 20000

action-order:
  - pass
  - drop
  - reject
  - alert

host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: [10.0.0.0/8, 192.168.1.100, "8762:2352:6241:7245:E000:0000:0000:0000"]
  old-solaris: []
  solaris: ["::1"]
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []

asn1-max-frames: 256

engine-analysis:
  rules-fast-pattern: yes
  rules: yes

pcre:
  match-limit: 3500
  match-limit-recursion: 1500

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    imap:
      enabled: detection-only
    msn:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      libhtp:
         default-config:
           personality: IDS
           request-body-limit: 3072
           response-body-limit: 3072
           request-body-minimal-inspect-size: 32kb
           request-body-inspect-window: 4kb
           response-body-minimal-inspect-size: 32kb
           response-body-inspect-window: 4kb
           double-decode-path: no
           double-decode-query: no

         server-config:

profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks
    limit: 100
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes

coredump:
  max-dump: unlimited

napatech:
    hba: -1
    use-all-streams: yes
    streams: [1, 2, 3]

SURICATA
#### END: /etc/suricata/suricata.yaml


#### /etc/oinkmaster.conf
cat > /etc/oinkmaster.conf << OINKMASTER
# Oinkmaster config for PerunWorks
# Perun Rules
url = file:///opt/zenected/downloads/perun_rules.tar.gz
url = file:///opt/zenected/downloads/perun_hashes.tar.gz
url = file:///opt/zenected/downloads/perun_feodo_rules.tar.gz
url = file:///opt/zenected/downloads/perun_zeus_rules.tar.gz
url = file:///opt/zenected/downloads/perun_phishing_rules.tar.gz

skipfile local.rules
skipfile deleted.rules
skipfile snort.conf

OINKMASTER
#### END: /etc/oinkmaster.conf

#setting Suricata to run when server restarts
sed -i "s/RUN=no/RUN=yes/g" /etc/default/suricata


service suricata restart

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# WWW: Apache
echo -e "5. Installing and configuring the web server"

#hiding output
{
apt-get -qq -y install apache2 > /dev/null

#### /etc/apache2/mods-enabled/dir.conf
cat > /etc/apache2/mods-enabled/dir.conf << APACHEDIR
<IfModule mod_dir.c>
    DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm
</IfModule>
APACHEDIR
#### END: /etc/apache2/mods-enabled/dir.conf

#### /etc/apache2/sites-available/000-default.conf #404 error
cat > /etc/apache2/sites-available/000-default.conf << APACHE404
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorDocument 404 /index.php
</VirtualHost>

APACHE404

#### END: /etc/apache2/sites-available/000-default.conf

#### /etc/apache2/sites-available/zenusers-ssl.conf
cat > /etc/apache2/sites-available/zenusers-ssl.conf << WWWZENUSERS
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost

		DocumentRoot /var/www/zen/

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined
		SSLEngine on
		SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
		SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>

		BrowserMatch "MSIE [2-6]" \
				nokeepalive ssl-unclean-shutdown \
				downgrade-1.0 force-response-1.0
		BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
	</VirtualHost>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

WWWZENUSERS
#### END: /etc/apache2/sites-available/zenusers-ssl.conf

#### /var/www/zen/index.html
cat > /var/www/zen/index.html << INDEXZEN
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title></title>
  </head>
  <body>
  </body>
</html>

INDEXZEN
#### END: /var/www/zen/index.html

echo "ServerName localhost" >> /etc/apache2/apache2.conf
a2enmod ssl
a2ensite zenusers-ssl.conf
a2dismod autoindex
service apache2 reload
service apache2 restart

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# DB: MySQL
echo -e "6. Installing and configuring MySQL"

#hiding output
{
MYSQL_PASS=`date +%s | sha256sum | base64 | head -c 32; echo`
echo -e "ZEN_MYSQL=\""$MYSQL_PASS"\"" >> /etc/zenected/zenected.conf

debconf-set-selections <<< "mysql-server mysql-server/root_password password $MYSQL_PASS"
debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $MYSQL_PASS"

apt-get -qq -y install mysql-server php5-mysql > /dev/null
mysql_install_db > /dev/null 2>&1
 #securing MySQL installation
 #mysqladmin -u root -p$MYSQL_PASS #not relevant?
 mysql -u root -p$MYSQL_PASS -e "UPDATE mysql.user SET Password=PASSWORD('$MYSQL_PASS') WHERE User='root'"
 mysql -u root -p$MYSQL_PASS -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
 mysql -u root -p$MYSQL_PASS -e "DELETE FROM mysql.user WHERE User=''"
 mysql -u root -p$MYSQL_PASS -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
 mysql -u root -p$MYSQL_PASS -e "FLUSH PRIVILEGES"

} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# PHP
echo -e "7. Installing and configuring PHP"
#hiding output
{

apt-get -qq -y install php5 php-db php-pear libapache2-mod-php5 php5-mcrypt php5-gd php5-sqlite > /dev/null

} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# Proxy: Squid & squidGuard
echo -e "8. Installing and configuring Proxy"

#hiding output
{

apt-get -qq -y install squidGuard > /dev/null

#### /etc/squid3/squid.conf
cat > /etc/squid3/squid.conf << SQUIDCONF
#       WELCOME TO SQUID 3.3.8
acl localnet src 172.16.0.0/12	# RFC1918 possible internal network
acl localnet src 192.168.0.0/16
acl localnet src 10.0.0.0/8
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

http_port 3128 intercept
http_port 3127

coredump_dir /var/spool/squid3
url_rewrite_program /usr/bin/squidGuard -c /etc/squidguard/squidGuard.conf
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern (Release|Packages(.gz)*)$      0       20%     2880
refresh_pattern .		0	20%	4320

SQUIDCONF
#### END: /etc/squid3/squid.conf

#### /etc/squidguard/squidGuard.conf
cat > /etc/squidguard/squidGuard.conf << SQUIDGUARD
# CONFIG FILE FOR SQUIDGUARD
# Caution: do NOT use comments inside { }

dbhome /opt/zenected/url
logdir /var/log/squidguard

dest perun_malware {
    urllist     perun_malware.url
}

dest perun_phishing {
    urllist     perun_phishing.url
}

dest local_blacklist {
    urllist     local_blacklist.url
}

acl {
    default {
        pass !perun_malware !perun_phishing !local_blacklist all
        redirect http://127.0.0.1/?clienturl=%u&reason=%t
    }
}

SQUIDGUARD
#### END: /etc/squidguard/squidGuard.conf

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# User mngm: Radius
echo -e "9. Installing and configuring User management"

#hiding output
{

RADIUS_SHAREDPASS=`date +%s | sha256sum | base64 | head -c 32; echo`
echo -e "ZEN_RADIUS_SHARED=\""$RADIUS_SHAREDPASS"\"" >> /etc/zenected/zenected.conf
sleep 2

##the following lines are for Google CLoud Platform
##apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 40976EAF437D05B5
##apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32
##add-apt-repository "deb http://archive.ubuntu.com/ubuntu trusty universe multiverse"
##apt-get update
## END: Google Cloud Platform

apt-get -qq -y install radiusclient1 > /dev/null
apt-get -qq -o Dpkg::Options::=--force-confnew -y install freeradius > /dev/null
apt-get -qq -o Dpkg::Options::=--force-confnew -y install freeradius-mysql > /dev/null
apt-get -qq -y install libfreeradius2 > /dev/null


## Update /etc/hosts with this hosts name (otherwise freeradius has some issues)
THISHOST=`hostname -s`
sed -i "s/127.0.0.1.*/127.0.0.1 localhost $THISHOST/g" /etc/hosts

#### /var/lib/dpkg/info/freeradius-mysql.postinst
sed -i "s/invoke-rc.d freeradius force-reload/invoke-rc.d freeradius restart/g" /var/lib/dpkg/info/freeradius-mysql.postinst
sed -i "s/\/etc\/init.d\/freeradius force-reload/\/etc\/init.d\/freeradius restart/g" /var/lib/dpkg/info/freeradius-mysql.postinst
#### END: /var/lib/dpkg/info/freeradius-mysql.postinst
/var/lib/dpkg/info/freeradius-mysql.postinst

apt-get -qq -y -o Dpkg::Options::=--force-confnew install freeradius-utils > /dev/null
apt-get -qq -y -o Dpkg::Options::=--force-confnew install php-db > /dev/null

RADIUS_MYSQLPASS=`date +%s | sha256sum | base64 | head -c 32; echo`
echo -e "ZEN_RADIUS_MYSQL=\""$RADIUS_MYSQLPASS"\"" >> /etc/zenected/zenected.conf

mysql -u root -p$MYSQL_PASS -e "DROP DATABASE radius"
mysql -u root -p$MYSQL_PASS -e "CREATE DATABASE radius"
mysql -u root -p$MYSQL_PASS -e "GRANT ALL ON radius.* TO radius@localhost IDENTIFIED BY \"$RADIUS_MYSQLPASS\""
mysql -u root -p$MYSQL_PASS -e "FLUSH PRIVILEGES"
mysql -u radius -p$RADIUS_MYSQLPASS radius < /etc/freeradius/sql/mysql/schema.sql

#### /etc/freeradius/sites-available/inner-tunnel
cat > /etc/freeradius/sites-available/inner-tunnel << RADINNERTUNNEL
# -*- text -*-

server inner-tunnel {
listen {
       ipaddr = 127.0.0.1
       port = 18120
       type = auth
}
authorize {
        chap
        mschap
        suffix
        update control {
               Proxy-To-Realm := LOCAL
        }
        eap {
                ok = return
        }
        files
        sql
        expiration
        logintime
        pap
}

authenticate {
        Auth-Type PAP {
                pap
        }
        Auth-Type CHAP {
                chap
        }
        Auth-Type MS-CHAP {
                mschap
        }
        #  against /etc/passwd!  See the FAQ for details.
        #
        unix
        eap
}
session {
        radutmp
        sql
}

post-auth {
        Post-Auth-Type REJECT {
                # log failed authentications in SQL, too.
#               sql
                attr_filter.access_reject
        }
}

pre-proxy {
}

post-proxy {
        eap
}

} # inner-tunnel server block


RADINNERTUNNEL
#### END: /etc/freeradius/sites-available/inner-tunnel


#### /etc/freeradius/sql.conf
cat > /etc/freeradius/sql.conf << FREERADSQL
# -*- text -*-
##
## sql.conf -- SQL modules
##
##      $Id$

sql {
        database = "mysql"
        driver = "rlm_sql_\${database}"
        server = "localhost"
        #port = 3306
        login = "radius"
        password = "$RADIUS_MYSQLPASS"
        radius_db = "radius"
        acct_table1 = "radacct"
        acct_table2 = "radacct"
        postauth_table = "radpostauth"
        authcheck_table = "radcheck"
        authreply_table = "radreply"
        groupcheck_table = "radgroupcheck"
        groupreply_table = "radgroupreply"
        usergroup_table = "radusergroup"
        deletestalesessions = yes
        sqltrace = no
        sqltracefile = \${logdir}/sqltrace.sql
        num_sql_socks = 5
        connect_failure_retry_delay = 60
        lifetime = 0
        max_queries = 0
        nas_table = "nas"
        \$INCLUDE sql/\${database}/dialup.conf
}

FREERADSQL
#### END: /etc/freeradius/sql.conf

#### /etc/freeradius/radiusd.conf
cat > /etc/freeradius/radiusd.conf << FREERADUSD
# -*- text -*-
##
## radiusd.conf -- FreeRADIUS server configuration file.
##
##      http://www.freeradius.org/
##      $Id$

prefix = /usr
exec_prefix = /usr
sysconfdir = /etc
localstatedir = /var
sbindir = \${exec_prefix}/sbin
logdir = /var/log/freeradius
raddbdir = /etc/freeradius
radacctdir = \${logdir}/radacct

name = freeradius

confdir = \${raddbdir}
run_dir = \${localstatedir}/run/\${name}
db_dir = \${raddbdir}
libdir = /usr/lib/freeradius
pidfile = \${run_dir}/\${name}.pid
user = freerad
group = freerad
max_request_time = 30
cleanup_delay = 5
max_requests = 1024

listen {
        type = auth
        ipaddr = *
        port = 0
}

listen {
        ipaddr = *
        port = 0
        type = acct
}

hostname_lookups = no
allow_core_dumps = no
regular_expressions     = yes
extended_expressions    = yes

log {
        destination = files
        file = \${logdir}/radius.log
        syslog_facility = daemon
        stripped_names = no
        auth = no
        auth_badpass = no
        auth_goodpass = no
}

checkrad = \${sbindir}/checkrad

security {
        max_attributes = 200
        reject_delay = 1
        status_server = yes
}

proxy_requests  = yes
\$INCLUDE proxy.conf
\$INCLUDE clients.conf

thread pool {
        start_servers = 5
        max_servers = 32
        min_spare_servers = 3
        max_spare_servers = 10
        max_requests_per_server = 0
}

modules {
        \$INCLUDE \${confdir}/modules/
        \$INCLUDE eap.conf
        \$INCLUDE sql.conf
        \$INCLUDE sql/mysql/counter.conf
}

instantiate {
        exec
        expr
        expiration
        logintime
}

\$INCLUDE policy.conf
\$INCLUDE sites-enabled/


FREERADUSD
#### END: /etc/freeradius/radiusd.conf

#### /etc/freeradius/sites-available/default
cat > /etc/freeradius/sites-available/default << FREERADSITES
#       $Id$
authorize {
        preprocess
        chap
        mschap
        digest
        suffix
#       ntdomain
        eap {
                ok = return
        }
        files
        sql
        expiration
        logintime
        pap
}

authenticate {
        Auth-Type PAP {
                pap
        }

        Auth-Type CHAP {
                chap
        }

        Auth-Type MS-CHAP {
                mschap
        }

        digest
        unix
        eap
}

preacct {
        preprocess
        acct_unique
        suffix
        files
}

accounting {
        detail
        unix
        radutmp
        sql
#       sql_log
        exec
        attr_filter.accounting_response
}

session {
        radutmp
        sql
}

post-auth {
#       sql
#       sql_log
#       ldap
        exec
        Post-Auth-Type REJECT {
#               sql
                attr_filter.access_reject
        }
}

pre-proxy {
#       attr_rewrite
#       pre_proxy_log
}

post-proxy {
        eap
}

FREERADSITES
#### END: /etc/freeradius/sites-available/default

#### /etc/freeradius/clients.conf
cat > /etc/freeradius/clients.conf << FREERADIUSCLIENTS
# -*- text -*-
##      $Id$
#client localhost {
#        ipaddr = 127.0.0.1
#        secret          = $RADIUS_SHAREDPASS
#        require_message_authenticator = no
#        nastype     = other
#}

client 127.0.0.1 {
        secret  = $RADIUS_SHAREDPASS
        nastype = other
}

FREERADIUSCLIENTS
#### END: /etc/freeradius/clients.conf

#### /etc/radiusclient/radiusclient.conf
cat > /etc/radiusclient/radiusclient.conf << RADIUSCLIENTCONF
auth_order      radius,local
login_tries     4
login_timeout   60
nologin /etc/nologin
issue   /etc/radiusclient/issue
authserver      localhost:1812
acctserver      localhost:1813
servers         /etc/radiusclient/servers
dictionary      /etc/radiusclient/dictionary
login_radius    /usr/sbin/login.radius
seqfile         /var/run/radius.seq
mapfile         /etc/radiusclient/port-id-map
default_realm
radius_timeout  10
radius_retries  3
login_local     /bin/login

RADIUSCLIENTCONF
#### END: /etc/radiusclient/radiusclient.conf

#### /etc/radiusclient/servers
cat > /etc/radiusclient/servers << RADIUSCLIENTSERVERS
# Make sure that this file is mode 600 (readable only to owner)!
#
#Server Name or Client/Server pair              Key
#----------------                               ---------------
localhost                                       $RADIUS_SHAREDPASS

RADIUSCLIENTSERVERS
#### END: /etc/radiusclient/servers

#### /etc/radiusclient/dictionary.microsoft
cat > /etc/radiusclient/dictionary.microsoft << DICTIONARYMS
#
#       Microsoft's VSA's, from RFC 2548
#
#       $Id: poptop_ads_howto_8.htm,v 1.8 2008/10/02 08:11:48 wskwok Exp $
#
VENDOR          Microsoft       311     Microsoft
BEGIN VENDOR    Microsoft
ATTRIBUTE       MS-CHAP-Response        1       string  Microsoft
ATTRIBUTE       MS-CHAP-Error           2       string  Microsoft
ATTRIBUTE       MS-CHAP-CPW-1           3       string  Microsoft
ATTRIBUTE       MS-CHAP-CPW-2           4       string  Microsoft
ATTRIBUTE       MS-CHAP-LM-Enc-PW       5       string  Microsoft
ATTRIBUTE       MS-CHAP-NT-Enc-PW       6       string  Microsoft
ATTRIBUTE       MS-MPPE-Encryption-Policy 7     string  Microsoft
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
ATTRIBUTE       MS-MPPE-Encryption-Type 8       string  Microsoft
ATTRIBUTE       MS-MPPE-Encryption-Types  8     string  Microsoft
ATTRIBUTE       MS-RAS-Vendor           9       integer Microsoft
ATTRIBUTE       MS-CHAP-Domain          10      string  Microsoft
ATTRIBUTE       MS-CHAP-Challenge       11      string  Microsoft
ATTRIBUTE       MS-CHAP-MPPE-Keys       12      string  Microsoft encrypt=1
ATTRIBUTE       MS-BAP-Usage            13      integer Microsoft
ATTRIBUTE       MS-Link-Utilization-Threshold 14 integer        Microsoft
ATTRIBUTE       MS-Link-Drop-Time-Limit 15      integer Microsoft
ATTRIBUTE       MS-MPPE-Send-Key        16      string  Microsoft
ATTRIBUTE       MS-MPPE-Recv-Key        17      string  Microsoft
ATTRIBUTE       MS-RAS-Version          18      string  Microsoft
ATTRIBUTE       MS-Old-ARAP-Password    19      string  Microsoft
ATTRIBUTE       MS-New-ARAP-Password    20      string  Microsoft
ATTRIBUTE       MS-ARAP-PW-Change-Reason 21     integer Microsoft
ATTRIBUTE       MS-Filter               22      string  Microsoft
ATTRIBUTE       MS-Acct-Auth-Type       23      integer Microsoft
ATTRIBUTE       MS-Acct-EAP-Type        24      integer Microsoft
ATTRIBUTE       MS-CHAP2-Response       25      string  Microsoft
ATTRIBUTE       MS-CHAP2-Success        26      string  Microsoft
ATTRIBUTE       MS-CHAP2-CPW            27      string  Microsoft
ATTRIBUTE       MS-Primary-DNS-Server   28      ipaddr
ATTRIBUTE       MS-Secondary-DNS-Server 29      ipaddr
ATTRIBUTE       MS-Primary-NBNS-Server  30      ipaddr Microsoft
ATTRIBUTE       MS-Secondary-NBNS-Server 31     ipaddr Microsoft
#ATTRIBUTE      MS-ARAP-Challenge       33      string  Microsoft
#
#       Integer Translations
#
#       MS-BAP-Usage Values
VALUE           MS-BAP-Usage            Not-Allowed     0
VALUE           MS-BAP-Usage            Allowed         1
VALUE           MS-BAP-Usage            Required        2
#       MS-ARAP-Password-Change-Reason Values
VALUE   MS-ARAP-PW-Change-Reason        Just-Change-Password            1
VALUE   MS-ARAP-PW-Change-Reason        Expired-Password                2
VALUE   MS-ARAP-PW-Change-Reason        Admin-Requires-Password-Change  3
VALUE   MS-ARAP-PW-Change-Reason        Password-Too-Short              4
#       MS-Acct-Auth-Type Values
VALUE           MS-Acct-Auth-Type       PAP             1
VALUE           MS-Acct-Auth-Type       CHAP            2
VALUE           MS-Acct-Auth-Type       MS-CHAP-1       3
VALUE           MS-Acct-Auth-Type       MS-CHAP-2       4
VALUE           MS-Acct-Auth-Type       EAP             5
#       MS-Acct-EAP-Type Values
VALUE           MS-Acct-EAP-Type        MD5             4
VALUE           MS-Acct-EAP-Type        OTP             5
VALUE           MS-Acct-EAP-Type        Generic-Token-Card      6
VALUE           MS-Acct-EAP-Type        TLS             13
END-VENDOR Microsoft

DICTIONARYMS
#### END: /etc/radiusclient/dictionary.microsoft

#### /etc/radiusclient/dictionary
cat > /etc/radiusclient/dictionary << RADIUSDICTIONARY
#
# Updated 97/06/13 to livingston-radius-2.01 miquels@cistron.nl
#
#       Following are the proper new names. Use these.
#
ATTRIBUTE       User-Name               1       string
ATTRIBUTE       Password                2       string
ATTRIBUTE       CHAP-Password           3       string
ATTRIBUTE       NAS-IP-Address          4       ipaddr
ATTRIBUTE       NAS-Port-Id             5       integer
ATTRIBUTE       Service-Type            6       integer
ATTRIBUTE       Framed-Protocol         7       integer
ATTRIBUTE       Framed-IP-Address       8       ipaddr
ATTRIBUTE       Framed-IP-Netmask       9       ipaddr
ATTRIBUTE       Framed-Routing          10      integer
ATTRIBUTE       Filter-Id               11      string
ATTRIBUTE       Framed-MTU              12      integer
ATTRIBUTE       Framed-Compression      13      integer
ATTRIBUTE       Login-IP-Host           14      ipaddr
ATTRIBUTE       Login-Service           15      integer
ATTRIBUTE       Login-TCP-Port          16      integer
ATTRIBUTE       Reply-Message           18      string
ATTRIBUTE       Callback-Number         19      string
ATTRIBUTE       Callback-Id             20      string
ATTRIBUTE       Framed-Route            22      string
ATTRIBUTE       Framed-IPX-Network      23      ipaddr
ATTRIBUTE       State                   24      string
ATTRIBUTE       Session-Timeout         27      integer
ATTRIBUTE       Idle-Timeout            28      integer
ATTRIBUTE       Termination-Action      29      integer
ATTRIBUTE       Called-Station-Id       30      string
ATTRIBUTE       Calling-Station-Id      31      string
ATTRIBUTE       Acct-Status-Type        40      integer
ATTRIBUTE       Acct-Delay-Time         41      integer
ATTRIBUTE       Acct-Input-Octets       42      integer
ATTRIBUTE       Acct-Output-Octets      43      integer
ATTRIBUTE       Acct-Session-Id         44      string
ATTRIBUTE       Acct-Authentic          45      integer
ATTRIBUTE       Acct-Session-Time       46      integer
ATTRIBUTE       Acct-Input-Packets      47      integer
ATTRIBUTE       Acct-Output-Packets     48      integer
ATTRIBUTE       Acct-Terminate-Cause    49      integer
ATTRIBUTE       Chap-Challenge          60      string
ATTRIBUTE       NAS-Port-Type           61      integer
ATTRIBUTE       Port-Limit              62      integer
ATTRIBUTE       Connect-Info            77      string

#
#       Experimental Non Protocol Attributes used by Cistron-Radiusd
#
ATTRIBUTE       Huntgroup-Name          221     string
ATTRIBUTE       User-Category           1029    string
ATTRIBUTE       Group-Name              1030    string
ATTRIBUTE       Simultaneous-Use        1034    integer
ATTRIBUTE       Strip-User-Name         1035    integer
ATTRIBUTE       Fall-Through            1036    integer
ATTRIBUTE       Add-Port-To-IP-Address  1037    integer
ATTRIBUTE       Exec-Program            1038    string
ATTRIBUTE       Exec-Program-Wait       1039    string
ATTRIBUTE       Hint                    1040    string

#
#       Non-Protocol Attributes
#       These attributes are used internally by the server
#
ATTRIBUTE       Expiration                21    date
ATTRIBUTE       Auth-Type               1000    integer
ATTRIBUTE       Menu                    1001    string
ATTRIBUTE       Termination-Menu        1002    string
ATTRIBUTE       Prefix                  1003    string
ATTRIBUTE       Suffix                  1004    string
ATTRIBUTE       Group                   1005    string
ATTRIBUTE       Crypt-Password          1006    string
ATTRIBUTE       Connect-Rate            1007    integer

#
#       Integer Translations
#

#       User Types

VALUE           Service-Type            Login-User              1
VALUE           Service-Type            Framed-User             2
VALUE           Service-Type            Callback-Login-User     3
VALUE           Service-Type            Callback-Framed-User    4
VALUE           Service-Type            Outbound-User           5
VALUE           Service-Type            Administrative-User     6
VALUE           Service-Type            NAS-Prompt-User         7

#       Framed Protocols

VALUE           Framed-Protocol         PPP                     1
VALUE           Framed-Protocol         SLIP                    2

#       Framed Routing Values

VALUE           Framed-Routing          None                    0
VALUE           Framed-Routing          Broadcast               1
VALUE           Framed-Routing          Listen                  2
VALUE           Framed-Routing          Broadcast-Listen        3

#       Framed Compression Types

VALUE           Framed-Compression      None                    0
VALUE           Framed-Compression      Van-Jacobson-TCP-IP     1

#       Login Services

VALUE           Login-Service           Telnet                  0
VALUE           Login-Service           Rlogin                  1
VALUE           Login-Service           TCP-Clear               2
VALUE           Login-Service           PortMaster              3

#       Status Types

VALUE           Acct-Status-Type        Start                   1
VALUE           Acct-Status-Type        Stop                    2
VALUE           Acct-Status-Type        Accounting-On           7
VALUE           Acct-Status-Type        Accounting-Off          8

#       Authentication Types

VALUE           Acct-Authentic          RADIUS                  1
VALUE           Acct-Authentic          Local                   2
VALUE           Acct-Authentic          PowerLink128            100

#       Termination Options

VALUE           Termination-Action      Default                 0
VALUE           Termination-Action      RADIUS-Request          1

#       NAS Port Types, available in 3.3.1 and later

VALUE           NAS-Port-Type           Async                   0
VALUE           NAS-Port-Type           Sync                    1
VALUE           NAS-Port-Type           ISDN                    2
VALUE           NAS-Port-Type           ISDN-V120               3
VALUE           NAS-Port-Type           ISDN-V110               4

#       Acct Terminate Causes, available in 3.3.2 and later

VALUE           Acct-Terminate-Cause    User-Request            1
VALUE           Acct-Terminate-Cause    Lost-Carrier            2
VALUE           Acct-Terminate-Cause    Lost-Service            3
VALUE           Acct-Terminate-Cause    Idle-Timeout            4
VALUE           Acct-Terminate-Cause    Session-Timeout         5
VALUE           Acct-Terminate-Cause    Admin-Reset             6
VALUE           Acct-Terminate-Cause    Admin-Reboot            7
VALUE           Acct-Terminate-Cause    Port-Error              8
VALUE           Acct-Terminate-Cause    NAS-Error               9
VALUE           Acct-Terminate-Cause    NAS-Request             10
VALUE           Acct-Terminate-Cause    NAS-Reboot              11
VALUE           Acct-Terminate-Cause    Port-Unneeded           12
VALUE           Acct-Terminate-Cause    Port-Preempted          13
VALUE           Acct-Terminate-Cause    Port-Suspended          14
VALUE           Acct-Terminate-Cause    Service-Unavailable     15
VALUE           Acct-Terminate-Cause    Callback                16
VALUE           Acct-Terminate-Cause    User-Error              17
VALUE           Acct-Terminate-Cause    Host-Request            18

#
#       Non-Protocol Integer Translations
#

VALUE           Auth-Type               Local                   0
VALUE           Auth-Type               System                  1
VALUE           Auth-Type               SecurID                 2
VALUE           Auth-Type               Crypt-Local             3
VALUE           Auth-Type               Reject                  4

#
#       Cistron extensions
#
VALUE           Auth-Type               Pam                     253
VALUE           Auth-Type               None                    254

#
#       Experimental Non-Protocol Integer Translations for Cistron-Radiusd
#
VALUE           Fall-Through            No                      0
VALUE           Fall-Through            Yes                     1
VALUE           Add-Port-To-IP-Address  No                      0
VALUE           Add-Port-To-IP-Address  Yes                     1

#
#       Configuration Values
#       uncomment these two lines to turn account expiration on
#

#VALUE          Server-Config           Password-Expiration     30
#VALUE          Server-Config           Password-Warning        5

INCLUDE /etc/radiusclient/dictionary.merit
INCLUDE /etc/radiusclient/dictionary.microsoft

RADIUSDICTIONARY
#### END: /etc/radiusclient/dictionary

## Deloradius install
wget -O /opt/zenected/downloads/daloradius.tar.gz https://zenected.com/downloads/daloradius-0.9-9.tar.gz
tar zxf /opt/zenected/downloads/daloradius.tar.gz -C /opt/zenected/downloads/
rm /opt/zenected/downloads/daloradius.tar.gz

mysql -u radius -p$RADIUS_MYSQLPASS radius < /opt/zenected/downloads/daloradius-0.9-9/contrib/db/mysql-daloradius.sql

cp -r /opt/zenected/downloads/daloradius-0.9-9/* /var/www/zen/users
rm -r /opt/zenected/downloads/daloradius-0.9-9/

#### .../library/daloradius.conf.php {this will move to /var/www/zen/users/...}
sed -i "s/_USER'\] = 'root';/_USER'\] = 'radius';/g"  /var/www/zen/users/library/daloradius.conf.php
sed -i "s/_PASS'\] = '';/_PASS'\] = '$RADIUS_MYSQLPASS';/g"  /var/www/zen/users/library/daloradius.conf.php
sed -i "s/_RADIUSSECRET'\] = '';/_RADIUSSECRET'\] = '$RADIUS_SHAREDPASS';/g"  /var/www/zen/users/library/daloradius.conf.php
#### END: .../library/daloradius.conf.php

service freeradius restart

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# VPN: l2tp
echo -e "10. Installing and configuring VPN"

#hiding output
{

apt-get -qq -y install xl2tpd ppp lsof > /dev/null
# unattended Openswan install:
#DEBIAN_FRONTEND=noninteractive apt-get -qq install --yes --force-yes openswan
apt-get -y install nss iproute2 gawk cut > /dev/null
#@ apt-get install libreswan

#@@@@
apt-get -y install libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
        libcap-ng-dev libcap-ng-utils libselinux1-dev \
        libcurl4-nss-dev libgmp3-dev flex bison gcc make \
        libunbound-dev libnss3-tools libevent-dev
apt-get -y --no-install-recommends install xmlto

# Install Fail2Ban to protect SSH server
apt-get -y install fail2ban

# Compile and install Libreswan
SWAN_VER=3.17
SWAN_FILE="libreswan-${SWAN_VER}.tar.gz"
SWAN_URL="https://download.libreswan.org/${SWAN_FILE}"
wget -t 3 -T 30 -nv -O "$SWAN_FILE" "$SWAN_URL"
[ ! -f "$SWAN_FILE" ] && { echo "Cannot retrieve Libreswan source file. Aborting."; exit 1; }
/bin/rm -rf "/opt/src/libreswan-${SWAN_VER}"
tar xvzf "$SWAN_FILE" && rm -f "$SWAN_FILE"
cd "libreswan-${SWAN_VER}" || { echo "Failed to enter Libreswan source dir. Aborting."; exit 1; }
# Workaround for Libreswan compile issues
cat > Makefile.inc.local <<EOF
WERROR_CFLAGS =
EOF
make programs && make install

#@ from: https://github.com/hwdsl2/setup-ipsec-vpn/blob/master/vpnsetup.sh
#@@@@

###AWS
#PUBLIC_IP=$(wget --retry-connrefused --tries=3 --timeout 15 -qO- 'http://169.254.169.254/latest/meta-data/public-ipv4')
#PRIVATE_IP=$(wget --retry-connrefused --tries=3 --timeout 15 -qO- 'http://169.254.169.254/latest/meta-data/local-ipv4')
###END: AWS
PUBLIC_IP=`curl -k -s https://zenected.com/remote_ip.php`
DEFAULT_IF=$(ip route list | awk '/^default/ {print $5}')
PRIVATE_IP=`ifconfig $DEFAULT_IF | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'`
PRIVATE_IP_NETMASK=`ip -o -f inet addr show $DEFAULT_IF | grep -v '127.0.0.1' | awk '{print $4}'`


##This will be changed during Zenected setup
echo -e "ZEN_SHARED=\"Zenected" >> /etc/zenected/zenected.conf

#### /etc/ipsec.conf
cat > /etc/ipsec.conf << IPSECCONF
version 2.0
config setup
  dumpdir=/var/run/pluto/
  nat_traversal=yes
  virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!192.168.42.0/24
  oe=off
  protostack=netkey
  nhelpers=0
  interfaces=%defaultroute
conn vpnpsk
  connaddrfamily=ipv4
  auto=add
  left=$PRIVATE_IP
  leftid=$PUBLIC_IP
  leftsubnet=$PRIVATE_IP_NETMASK
  leftnexthop=%defaultroute
  leftprotoport=17/1701
  rightprotoport=17/%any
  right=%any
  rightsubnetwithin=0.0.0.0/0
  forceencaps=yes
  authby=secret
  pfs=no
  type=transport
  auth=esp
  ike=3des-sha1,aes-sha1
  phase2alg=3des-sha1,aes-sha1
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear

IPSECCONF
#### END: /etc/ipsec.conf

#### /etc/ipsec.secrets
cat > /etc/ipsec.secrets << IPSECSECRETS
include /var/lib/openswan/ipsec.secrets.inc
$CURRENT_IP     %any:   PSK     "$IPSEC_PASS"
IPSECSECRETS
#### END: /etc/ipsec.secrets

#### /etc/xl2tpd/xl2tpd.conf
cat > /etc/xl2tpd/xl2tpd.conf << XLTPDCONF
[global]
port = 1701
;debug avp = yes
;debug network = yes
;debug state = yes
;debug tunnel = yes
[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
;ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes

XLTPDCONF
#### END: /etc/xl2tpd/xl2tpd.conf

#### /etc/ppp/options.xl2tpd
cat > /etc/ppp/options.xl2tpd << OPTIONSXL2TPD
ipcp-accept-local
ipcp-accept-remote
#ms-dns 8.8.8.8
#ms-dns 8.8.4.4
ms-dns 192.168.42.1
noccp
auth
crtscts
idle 1800
mtu 1280
mru 1280
lock
lcp-echo-failure 10
lcp-echo-interval 60
connect-delay 5000

plugin radius.so
plugin radattr.so

OPTIONSXL2TPD
#### END: /etc/ppp/options.xl2tpd

### AWS iptables
/bin/cp -f /etc/sysctl.conf /etc/sysctl.conf.old-$(date +%Y-%m-%d-%H:%M:%S) 2>/dev/null
cat > /etc/sysctl.conf <<EOF
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
kernel.randomize_va_space = 1
net.core.wmem_max=12582912
net.core.rmem_max=12582912
net.ipv4.tcp_rmem= 10240 87380 12582912
net.ipv4.tcp_wmem= 10240 87380 12582912
EOF

/bin/cp -f /etc/iptables.rules /etc/iptables.rules.old-$(date +%Y-%m-%d-%H:%M:%S) 2>/dev/null
cat > /etc/iptables.rules <<EOF
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:ICMPALL - [0:0]
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp --icmp-type 255 -j ICMPALL
-A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p udp -m multiport --dports 500,4500 -j ACCEPT
-A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
-A INPUT -p udp --dport 1701 -j DROP
-A INPUT -j DROP
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A FORWARD -i eth+ -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp+ -o eth+ -j ACCEPT
-A FORWARD -j DROP
-A ICMPALL -p icmp -f -j DROP
-A ICMPALL -p icmp --icmp-type 0 -j ACCEPT
-A ICMPALL -p icmp --icmp-type 3 -j ACCEPT
-A ICMPALL -p icmp --icmp-type 4 -j ACCEPT
-A ICMPALL -p icmp --icmp-type 8 -j ACCEPT
-A ICMPALL -p icmp --icmp-type 11 -j ACCEPT
-A ICMPALL -p icmp -j DROP
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 192.168.42.0/24 -o eth+ -j SNAT --to-source ${PRIVATE_IP}
COMMIT
EOF

cat > /etc/network/if-pre-up.d/iptablesload <<EOF
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
exit 0
EOF
### END: AWS iptables

} &> /dev/null #un-hiding output


#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# DNS: dnamasq
echo -e "11. Installing and configuring DNS"

#hiding output
{

apt-get -qq -y install dnsmasq > /dev/null

#### /etc/dnsmasq.conf
cat > /etc/dnsmasq.conf << DNSMASQ
# Configuration file for dnsmasq.
no-resolv

##forward dns queries upstream
server=8.8.8.8
server=8.8.4.4

no-hosts

addn-hosts=/opt/zenected/dns/perun_ads.domains
addn-hosts=/opt/zenected/dns/perun_feodo.domains
addn-hosts=/opt/zenected/dns/perun_zeus.domains
addn-hosts=/opt/zenected/dns/perun_suspicious.domains
addn-hosts=/opt/zenected/dns/local_blacklist.domains

DNSMASQ

#### END: /etc/dnsmasq.conf

service dnsmasq restart

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#Zenected repo and service
echo -e "12. Installing and configuring Zenected"

#hiding output
{

apt-get -qq -y install software-properties-common
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EDEA5A7B
add-apt-repository "deb http://repository.perunworks.com/ trusty main"
apt-get update > /dev/null

apt-get -qq -y install zenected-aws > /dev/null

#### /etc/rc.local
cat > /etc/rc.local << RCLOCAL
#!/bin/sh -e
#
# rc.local
#

##Zenected
sudo /opt/zenected/zenected_restart.zenx

exit 0

RCLOCAL
#### END: /etc/rc.local

#### Create ZenRedir DB
ZENREDIR_MYSQLPASS=`date +%s | sha256sum | base64 | head -c 32; echo`
echo -e "ZEN_REDIR_MYSQL=\""$ZENREDIR_MYSQLPASS"\"" >> /etc/zenected/zenected.conf

mysql -u root -p$MYSQL_PASS -e "DROP DATABASE zenredir"
mysql -u root -p$MYSQL_PASS -e "CREATE DATABASE zenredir"
mysql -u root -p$MYSQL_PASS -e "GRANT ALL ON zenredir.* TO zenredir@localhost IDENTIFIED BY \"$ZENREDIR_MYSQLPASS\""
mysql -u root -p$MYSQL_PASS -e "FLUSH PRIVILEGES"
#mysql -u radius -pZENREDIR_MYSQLPASS radius < /etc/freeradius/sql/mysql/schema.sql

#### END: ZenRedir DB

#Randomize updates time
echo -e "ZEN_UPDATES_H=\""$UPDATES_H"\"" >> /etc/zenected/zenected.conf
echo -e "ZEN_UPDATES_M=\""$UPDATES_M"\"" >> /etc/zenected/zenected.conf

echo -e "<?php \$zenredir_db_pass=\"$ZENREDIR_MYSQLPASS\"; ?>" > /var/www/html/zenected.conf.php

} &> /dev/null #un-hiding output


echo -e "13. Updating Zenected"

#hiding output
{

/opt/zenected/zenected_update.zenx

} &> /dev/null #un-hiding output
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo -e "14. Restarting services"

#hiding output
{

# Restarting services
/usr/sbin/service ipsec restart
/usr/sbin/service xl2tpd restart
/usr/sbin/service freeradius restart

} &> /dev/null #un-hiding output

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
#THE END
echo -e "\n\nThanks for your patience. The Zenected install script has now finished.\nRemember to check Resources (manuals and tips) at https://zenected.com\n\nYou can now continue to configure Zenected.\n"
read -r -n 1 -s -p "Press any key to continue and run Zenected Setup..."
/opt/zenected/zenected_setup.zenx
