# macOS-Open-Source-Server
macOS Open Source Server: An Open Source Version of macOS Server Services

This [README.md](README.md) has notes on migrating macOS Server.app v. 5.7 High Sierra to Server.app v. 5.8 Mojave,
which has deprecated all server services except for **Profile Manager** and **Open Directory**. This roughly follows
the [macOS Server Service Migration Guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf),
but adds important details or omissions of that documentation. The outcome will be a macOS-based server that hosts open source
versions of services traditionally included in the old Server.app, but with a user-configurable and upgradable configuration.

The general approach here will be to migrate Server.app v. 5.7 configurations into either open source services, or native 
macOS services if such exist. I will use Server.app v. 5.8's Open Directory for authentication, but this is not necessary.

These notes use [MacPorts](https://www.macports.org). It is also easy to use [Homebrew](https://brew.sh), like this [repo](../../../../taniguti/Services_on_macOS).

Table of Contents
=================
  * [Hardware](#hardware)
  * [Server.app v. 5.7 Backup](#serverapp-v-57-backup)
  * [SSH](#ssh)
  * [Macports migration](#macports-migration)
  * [Logrotate](#logrotate)
  * [Server.app](#server-app)
  * [Domain Name](#domain-name)
      * [Domain Name Registration](#domain-name-registration)
      * [Domain Name DNS Configuration](#domain-name-dns-configuration)
          * [SPF](#spf)
          * [DKIM](#dkim)
  * [DNS](#dns)
  * [Network Configuration](#network-configuration)
  * [Web](#web)
      * [`apachectl`-based](#apachectl-based)
      * [Server.app-based](#server-app-based)
          * [`VirtualHost` Method](#virtualhost-method)
          * [`AliasMatch` Method](#aliasmatch-method)
      * [Apache2 log file rotatation](#apache2-log-file-rotatation)
  * [VPN (macOS `vpnd`, L2TP-IPSec-PSK)](#vpn-macos-vpnd-l2tp-ipsec-psk)
  * [OpenVPN](#openvpn)
  * [Mail](#mail)


## Hardware

This is done on a Mac Mini (2018) which, when configured with a 6-core i&, is small, quiet, and very, very performant.
I added 64 GB of memory purchased from OWC, which is a straighforward process so long as you take the time to keep the screws
organized from each of the disassembly stages. See these [instructional](https://eshop.macsales.com/installvideos/mac-mini-2018-memory/)
[videos](https://www.youtube.com/watch?v=gQq4hLKv1Cc).

These services will run well on any old Mac desktop configured with a suffient processor and memory, including my old
2012 Mac Mini server model.

Like those old Mac servers, I'll call the base hard drive in these notes `Server HD` (not `Macintosh HD`).


## Server.app v. 5.7 Backup

Save Server.app v. 5.7's service configurations in `/Library/Server` in `/Library/Server_v57` on the new server. Save all other Server.app-related files in `/Library/Server_v57/Server\ HD`, which correspond to `/` in the old server's file system.

Create these directions and make a copy of the entire Server.app:

New server:
```
sudo mkdir -p /Library/Server_v57/Server\ HD/Applications
sudo rsync -a -e 'ssh -l admin' admin@old-server:/Applications/Server.app /Library/Server_v57/Server\ HD/Applications/
```


## SSH

Lock down ssh with key logins only, only allow specific users and groups.

New server:
```
ssh-keygen -t ed25519 -a 256 -C admin@new-server
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
sudo vi /etc/ssh/sshd_config
diff /etc/ssh/sshd_config.orig /etc/ssh/sshd_config
```

```
57a58
> PasswordAuthentication no
61a63
> ChallengeResponseAuthentication no
119a122,127
> 
> # Allow ssh authentication for only these users; also set in
> # System Preferences>Sharing>Remote Login.
> # See Directory Utility or `sudo dscl /Local/Default -read /Groups/admin`
> AllowUsers admin
> AllowGroups admin
```

Copy `~/.ssh/id_ed25519.pub` to `~/.ssh/authorized_keys` on other hosts.


## Macports migration

Follow this [Macports migration procedure](https://trac.macports.org/wiki/Migration) to migrate Macports to the new server.

Avoid server rot by updating Macports binaries regularly:
```
sudo bash -c 'port selfupdate ; port -puN upgrade outdated ; port uninstall inactive'
```


## Logrotate

Use `logrotate` for services that don't have built-in log rotataion capabilities
```
sudo port install logrotate
sudo cp -p /opt/local/etc/logrotate.conf /opt/local/etc/logrotate.conf.orig
sudo vi /opt/local/etc/logrotate.conf
diff /opt/local/etc/logrotate.conf.orig /opt/local/etc/logrotate.conf
```

Use `bzip2` for compression:
```
> # use bzip2 for log file compression
> compresscmd /usr/bin/bzip2
> uncompresscmd /usr/bin/bunzip2
> compressoptions -9
> compressext .bz2
> 
```


## Server.app 

Install and turn on **Profile Manager** and **Open Directory**.


## Domain Name

### Domain Name Registration

Purchase a domain name from your favorite registrar. Personally, I really like [NameCheap](https://www.namecheap.com). These 
notes will configure this domain with a "split horizon," so that the domain is bound to an external IP address on the open 
internet by the DNS provider of your choice, and an internal LAN IP address by the [DNS service](#dns) on the server. That 
way, devices will connect with the server via rouer port forwarding while on the outside internet, and directly and securely 
over the LAN while at home or through a VPN tunnel.

### Domain Name DNS Configuration

Choose a DNS service, either from the Domain Name Registrar you used, or a separate provider. There are [security considerations](https://arstechnica.com/information-technology/2014/02/how-to-run-your-own-e-mail-server-with-your-own-domain-part-1/) for using the domain name registrar as the domain's DNS provider.  Personally, I like
[DNS Made Easy](https://dnsmadeeasy.com), and use their [Mail Server Forwarding Service](https://dnsmadeeasy.com/services/mailservices/) for a dynamic IP address. Later, configure `ddclient` to detect and 
automatically update server IP address changes with the DNS provider.

Check your domain for proper configuration (`A` records, `MX` records) and its appearance on any blacklists using tools like 
[MXToolbox](http://mxtoolbox.com/) for things like [blacklist lookup](http://mxtoolbox.com/blacklists.aspx),
[SPF lookup](https://mxtoolbox.com/spf.aspx), and [DKIM lookup](https://mxtoolbox.com/dkim.aspx), useful for checking the
[SPF record](#spf) and [DKIM record](#dkim) you're about to enter.

#### SPF

Add an SPF `TXT` record to your DNS configuration that tells email MTA's the valid domains that may send email from your domain. Personally, I use an ISP Mail Relay, so my SPF records look like:
```
dig @8.8.4.4 domainname.com any
```
> `v=spf1 a mx +include:comcast.net -all`

There is an SPF `TXT` record added for each email domain that has a DNS `A` and `MX` record.

#### DKIM


## DNS

### Copy the previous Server.app's DNS configuration

Follow krypted's [Export DNS Records from macOS Server](http://krypted.com/mac-os-x-server/export-dns-records-macos-server/) 
to export DNS records from the existing server.

Copy the previous Server.app's `named` configuration to the new server:
```
sudo mkdir /Library/Server_v57
sudo rsync -a -e 'ssh -l admin' --exclude rndc.key admin@old-server:/Library/Server/named /Library/Server_v57
```

Keep a copy of the old server's `serveradmin` DNS settings:

Old server:
```
sudo serveradmin -x set dns > serveradmin_v57_dns.plist
sudo chown admin:admin serveradmin_v57_dns.plist
rsync serveradmin_v57_dns.plist admin@new-server:~/Downloads
```

### Install `bind9` with the latest Python version

```
sudo port -pN install python37
sudo port select --set python3 python37
sudo port -pN install bind9 nmap
```

### Configure `named`

New server:
```
port notes bind9
sudo rsync -a /Library/Server_v57/named/ /opt/local/var/named
sudo mkdir /opt/local/var/log/named
sudo chown named:named /opt/local/var/named/* /opt/local/var/log/named
sudo rndc-confgen -A hmac-sha512 -a -c /opt/local/var/named/rndc.key -u named
sudo cp /Library/Server_v57/named/named.conf /opt/local/etc
```

```
sudo vi /opt/local/etc/named.conf
diff /Library/Server_v57/named/named.conf /opt/local/etc/named.conf
```

Edit in Macports-specific file locatons, use a secure hash for `controls` (not the deprecated `hmac-md5` algorithm used in 
Server.app v5.7), specify a `named` pid file, enable log file rotation, and restrict queries to the acl 
`com.apple.ServerAdmin.DNS.public` (acl names unchanged from Server.app).

```
1c1
< include "/Library/Server/named/rndc.key";
---
> include "/opt/local/var/named/rndc.key";
3c3
< 	directory "/Library/Server/named";
---
> 	directory "/opt/local/var/named";
6a7,9
> 	allow-query {
> 		com.apple.ServerAdmin.DNS.public;
> 	};
16a20
> 	pid-file "/opt/local/var/run/named/named.pid";
32c36
< 		file "/Library/Logs/named.log";
---
> 		file "/opt/local/var/log/named/named.log" versions 10 size 2m;
```

### Load and test `named`

```
sudo port load bind9
sudo ps -ef | grep named | grep -v grep
sudo lsof -i ':53'
nmap -p 53 new-server
nslookup github.com 127.0.0.1
host github.com 127.0.0.1
dig @new-server github.com
```

This provides a solid name server for the LAN. It can also be modified for fancier options like
[Hidden Master](https://www.c0ffee.net/blog/dns-hidden-master/) DNS with DNSSEC, and even a vanity
name server.


## Network Configuration

Assign `new-server` a fixed IP address on the LAN with a router DHCP reservation, e.g. `10.0.1.3`.
* System Preferences.app>Network>Interface>Advanced…>TCP/IP>Configure IPv4: `Manually`, IPv4 Address: `10.0.1.3`
* System Preferences.app>Network>Interface>Advanced…>DNS>DNS Servers: + `127.0.0.1`
* System Preferences.app>Network>Interface>Advanced…>DNS>Search Domains: + `new-server.tld` (assuming that your DNS has this zone)
* Ultimately, configure the router to use DNS server `10.0.1.3` so that any device on the LAN uses `new-server` as its DNS server.


Make sure that hostname lookups [FQDN] and reverse lookups for `new-server` point to each other:
```
host new-server.domainname.tld
host 10.0.1.3
```

Server.app on `new-server`:<br/>
Server.app>Open Directory> Toggle OD off & on and verify that the OD Master is running properly with the new localhost DNS server.

## Web

Follow the
[macOS Server Service Migration Guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf) to create a localhost macOS Web server that works with the new Server.app's **Profile Manager**. The challenge:

First, stop all services that want to bind to `http` port 80 and `https` post 443:
```
sudo apachectl stop
sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin stop devicemgr
```

Confirm the following breakage by browsing to http://localhost and https://new-server.domainname.tld/mydevices.

These commands launch the macOS web server, but break Profile Manager
```
sudo apachectl start
sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin start devicemgr
```

These commands launch Profile Manager, but break the macOS web server:
```
sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin start devicemgr
sudo apachectl start
```

Break this issue into four steps:
* Step 0: `Host` a basic native macOS web page using the default `apachectl` settings
* Step 1: `VirtualHost` a native macOS web page in a specific, non-`Default` `/Library/WebServer/Sites` directory
* Step 2: Copy Server.app v.5.7's Configuration and Website Data per the [macOS Server Service Migration Guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf)
* Step 3: Modify Server.app v.5.8's `/Library/Server/Web/Config/Proxy/apache_serviceproxy.conf` or  `/Library/Server/Web/Config/apache2/httpd_devicemanagement.conf` to host a web page the same page on port 80 (the first of these methods will also work for https port 443)

### `apachectl`-based

#### Step 0: `Host` a basic native macOS web page using the default `apachectl` settings
```
sudo apachectl start
open -a Safari http://localhost
```

#### Step 1: `VirtualHost` a native macOS web page in `/Library/WebServer/Sites/proxy.domainname.tld`
```
sudo mkdir /etc/apache2/sites
sudo vi /etc/apache2/httpd.conf
```
>`Include /private/etc/apache2/sites/*.conf`

If you've configured `named` to create the zone and domain `proxy.domainname.private`, this configuration file serve pages from http://proxy.domainname.private, e.g. http://proxy.domainname.private/proxy.pac. This `.conf` file is from Step 2 below.

`/etc/apache2/sites/0000_127.0.0.1_80_proxy.domainname.private.conf` 
```
<VirtualHost proxy.domainname.private:80>
	ServerName proxy.domainname.private
	ServerAdmin admin@domainname.tld
	DocumentRoot "/Library/WebServer/Sites/proxy.domainname.private"
	<IfModule dir_module>
		DirectoryIndex index.html
	</IfModule>
	CustomLog /var/log/apache2/access_log combinedvhost
	ErrorLog /var/log/apache2/error_log
	<IfModule mod_secure_transport.c>
		MSTEngine Off
		MSTCipherSuite HIGH, MEDIUM
		MSTProtocolRange TLSv1.2 TLSv1.2
		MSTProxyEngine On
		MSTProxyProtocolRange TLSv1.2 TLSv1.2
	</IfModule>
	<Directory "/Library/WebServer/Sites/proxy.domainname.private">
		Options All -Indexes -ExecCGI -Includes +MultiViews
		AllowOverride None
		Require all granted

		<IfModule mod_dav.c>
			DAV Off
		</IfModule>
#		<IfDefine !WEBSERVICE_ON>
#			Require all denied
#			ErrorDocument 403 /customerror/websitesoff403.html
#		</IfDefine>
	</Directory>
</VirtualHost>
```

To avoid caching issues, restart the web server using `apachectl stop`/`start`:
```
sudo apachectl configtest ; sudo apachectl stop ; sudo apachectl start ; sleep 1 ; nmap -p 80 localhost
```

#### Step 2: Copy Server.app v.5.7's Configuration and Website Data

This almost works up to (probably) TLS configuration details. It's a good exercise to run through to understand what may be required in Step 3. Put this configuration in the directory `/etc/apache2/Server_v57` and promote it if it's ever working and useful.

New server:
```
sudo rsync -a -e 'ssh -l admin' admin@old-server:/Library/Server/Web /Library/Server_v57
```

Follow the detailed instructions in [macOS Server Service Migration Guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf):
```
sudo rsync -a /Library/Server_v57/Web/Data/Sites /Library/WebServer/
find /Library/WebServer/Sites -type l -name 'default.html.*' -exec ls -l {} ';'
find /Library/WebServer/Sites -type l -name 'default.html.*' -exec sudo rm {} ';'
sudo cp -p /Library/WebServer/Documents/index.html.en /Library/WebServer/Sites/Default
sudo mkdir /etc/apache2/Server_v57
sudo cp -p /Library/Server_v57/Web/Config/apache2/httpd_server_app.conf /etc/apache2/Server_v57
sudo mkdir /etc/apache2/Server_v57/sites
sudo rsync -a /Library/Server_v57/Web/Config/apache2/sites/*.conf /etc/apache2/Server_v57/sites
find /etc/apache2/Server_v57/sites -name '*.conf' -exec sudo sed -i '' 's/DocumentRoot "\/Library\/Server\/Web\/Data\/Sites\/Default"/DocumentRoot "\/Library\/WebServer\/Sites\/Default"/' {} ';'
find /etc/apache2/Server_v57/sites -name '*.conf' -exec sudo sed -i '' 's/Directory "\/Library\/Server\/Web\/Data\/Sites\/Default"/Directory "\/Library\/WebServer\/Sites\/Default"/' {} ';'
find /etc/apache2/Server_v57/sites -name '*.conf' -exec sudo sed -i '' 's/<VirtualHost 127.0.0.1:34543>/<VirtualHost *:443>/' {} ';'
sudo sed -E -i '' 's/Listen[[:space:]]127.0.0.1:34543/Listen *:443/' /etc/apache2/Server_v57/sites/virtual_host_global.conf
sudo sed -E -i '' 's/Listen[[:space:]]127.0.0.1:34580/Listen *:80/' /etc/apache2/Server_v57/sites/virtual_host_global.conf
sudo mv /etc/apache2/Server_v57/sites/0000_127.0.0.1_34543_.conf /etc/apache2/Server_v57/sites/0000_127.0.0.1_443_.conf
sudo mv /etc/apache2/Server_v57/sites/0000_127.0.0.1_34580_.conf /etc/apache2/Server_v57/sites/0000_127.0.0.1_80_.conf
find /etc/apache2/Server_v57 -name '*.conf' -exec sudo sed -E -i '' 's/Include[[:space:]]+\/Library\/Server\/Web\/Config\/apache2\/sites\//Include \/etc\/apache2\/Server_v57\/sites\//' {} ';'
```

Now edit these `.conf` files line-by-line, following the `diff`'s in the [macOS Server Service Migration Guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf), and create a symbolic link from `apachectl`'s `httpd.conf` to `httpd_server_app.conf`.
```
sudo vi /etc/apache2/Server_v57/sites/0000_127.0.0.1_443_.conf
sudo vi /etc/apache2/Server_v57/sites/0000_127.0.0.1_80_.conf
sudo vi /etc/apache2/Server_v57/httpd_server_app.conf
sudo mv /etc/apache2/httpd.conf /etc/apache2/httpd.conf.orig
sudo ln -s /etc/apache2/Server_v57/httpd_server_app.conf /etc/apache2/httpd.conf
```

Note that the recommended `mod_authnz_od_apple` module to enable should read:
```
LoadModule authnz_od_apple_module /usr/libexec/apache2/mod_authnz_od_apple.so
```

A few helpful debugging commands:
```
egrep -e '^LoadModule.+SERVER_INSTALL_PATH_PREFIX' /Library/Server_v57/Web/Config/apache2/httpd_server_app.conf
sudo apachectl configtest
sudo less /private/var/log/apache2/error_log
sudo apachectl configtest ; sudo apachectl stop ; sudo apachectl start ; sleep 1 ; nmap -p 80 localhost
```

### Server.app-based

#### Step 3: Modify Server.app v.5.8's Apache Configuration to host `proxy.domainname.tld`

These Server.app Apache configuration files must be re-edited after every Server.app upgrade.

#### `VirtualHost` Method

```
sudo cp -p /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf.orig
sudo mkdir /Library/Server/Web/Config/Proxy/sites
sudo cp -p /etc/apache2/sites/0000_127.0.0.1_80_proxy.domainname.private.conf /Library/Server/Web/Config/Proxy/sites
```

Add this virtual host to the file `apache_serviceproxy.conf` [before](https://httpd.apache.org/docs/2.4/vhosts/examples.html) 
the other `VirtualHost` declarations in this `.conf` file.
```
sudo vi /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf
diff /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf.orig /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf
```

```
> # Host other virtual hosts; this line must appear first
> Include /Library/Server/Web/Config/Proxy/sites/*.conf
> 
```

#### `AliasMatch` Method

Use a simple `AliasMatch` to serve `*.pac` files over HTTP (whether at http://domainname.tld/proxy.pac or http://proxy.domainname.private/proxy.pac). Note that a router forwarding port 80 to the server will also serve these PAC files to the open internet with this configuration. Rather, only forward port 443 and leave port 80 for the LAN only.

```
sudo cp /Library/Server/Web/Config/apache2/httpd_devicemanagement.conf /Library/Server/Web/Config/apache2/httpd_devicemanagement.conf.orig
sudo vi /Library/Server/Web/Config/apache2/httpd_devicemanagement.conf
diff /Library/Server/Web/Config/apache2/httpd_devicemanagement.conf.orig /Library/Server/Web/Config/apache2/httpd_devicemanagement.conf
```

```
79a80,83
> # Serve *.pac at http://domainname.tld/proxy.pac or http://proxy.domainname.private/proxy.pac
> #AliasMatch ^/([^/]+\.pac)$ /Library/WebServer/Sites/proxy.domainname.private/$1
> 
> # See /Library/Server/Web/Config/Proxy/apache_serviceproxy.conf
```

Debug server.app's `.conf`:
```
sudo /Applications/Server.app/Contents/ServerRoot/usr/sbin/httpd-server-wrapper -t
sudo less /private/var/log/apache2/service_proxy_error.log
```

### Apache2 log file rotatation

This `logrotate` script will rotate the logs generated by the `Profile Manager`-based web server configuration above. It can 
easily be modified to an `apachectl`-based configuration. Note that the current Macports port file of `logrotate` appears to 
have a broken default launch daemon loader, so `sudo port load logrotate` doesn't work. Per `port notes logrotate`, do this 
step by hand:
```
sudo vi /opt/local/etc/logrotate.d/serveradmin_web
sudo cp /opt/local/share/logrotate/org.macports.logrotate.plist.example /Library/LaunchDaemons/org.macports.logrotate.plist
sudo launchctl load -w /Library/LaunchDaemons/org.macports.logrotate.plist
```

> `/opt/local/etc/logrotate.d/serveradmin_web`
```
/var/log/apache2/access_log /var/log/apache2/error_log /var/log/apache2/*.log {
	weekly
	missingok
	# rotate 52
	compress
	delaycompress
	notifempty
	create 640 root admin
	sharedscripts
	postrotate
		( serveradmin stop devicemgr ; serveradmin start devicemgr ) > /dev/null 2>&1
	endscript
}
```


## VPN (macOS `vpnd`, L2TP-IPSec-PSK)

First off, L2TP-IPSec-PSK is [only as strong as the PSK](https://discussions.apple.com/thread/4167809). Certificate-based VPN, 
like this [OpenVPN configuration](https://github.com/essandess/macos-openvpn-server) is strongly preferred. I'm including this 
migration because:
* It's simple and robust and works with native macOS's `vpnd`
* A strong PSK is easy to generate and use
* If this ever breaks with native macOS tools, it will be easy to modify to work with racoon
* I'm hopeful that someday someone figures out how to modify this approach to certificate-based IPSec, which appears possible just by looking at the defaults in
> `/Applications/Server.app/Contents/ServerRoot/usr/share/servermgrd/bundles/servermgr_vpn.bundle/Contents/Resources/com.apple.RemoteAccessServers.defaults.plist`.

Apple’s [Server.app migration guide](https://developer.apple.com/support/macos-server/macOS-Server-Service-Migration-Guide.pdf), doesn’t actually cover this VPN migration, in spite of this assertion:
> After migration you’ll have:<br/>
> • vpnd as your VPN service<br/>
> • The identical configuration as the macOS Server VPN service<br/>
> • A launchd job that starts the service after computer restarts

These steps provide a working `vpnd`-based L2TP-IPSec-PSK VPN service on new Macs. This is based in part on these threads:
* http://unixnme.blogspot.com/2016/05/how-to-setup-l2tp-vpn-server-on-mac-os.html
* https://discussions.apple.com/thread/1229769

Old server Server.app v.5.7:
```
Server.app v5.7>Users>Local Network Users, View: Show System Accounts
Highlight "VPN MPPE Key Access User"
Gear icon on bottom>Export Users…
Save As: ~/Downloads/vpn_0123456789ab.txt
```

```
scp -p ~/Downloads/vpn_0123456789ab.txt admin@new-server:~/Downloads
```

New server Server.app v.5.8:

```
Server.app v5.8>Users>Local Network Users, View: Show System Accounts
Gear icon on bottom>Import Users…> Local Network Directory
System Preferences>Sharing>Remote Login> Allow access for: Remove account "VPN MPPE Key Access User"
```

```
sudo security add-generic-password -a vpn_0123456789ab -s com.apple.ras -p "vpn_0123456789ab's password" /Library/Keychains/System.keychain
sudo security add-generic-password -a com.apple.ppp.l2tp -s com.apple.net.racoon -T /usr/sbin/racoon -p "SHARED-SECRET-PHRASE" /Library/Keychains/System.keychain
```

**Important:** ***Change this template password and PSK for these accounts using Keychain Access.app in the next step.***

New server Keychain Access.app:
```
Keychain Access.app>Keychains: System, Category: All Items, Search for "com.apple.ras", double-click, check "Show password"
Add a new, strong password to the account vpn_0123456789ab (not the initial template from above)
Keychain Access.app>Keychains: System, Category: All Items, Search for "com.apple.net.racoon", double-click, check "Show password"
Add a new, very, very strong random PSK to the account com.apple.ppp.l2tp (not the initial template from above)
```

New server Server.app v.5.8:
```
Server.app v5.8>Users>Local Network Users, View: Show System Accounts
Highlight "VPN MPPE Key Access User"
Gear icon on bottom>Change Password…
Use the exact same strong password as entered into the Keychain Access.app for account vpn_0123456789ab above.
```

New server:
```
sudo mkdir -p /Library/Server_v57/Server\ HD/Library/Preferences/SystemConfiguration
sudo rsync -a -e 'ssh -l admin' admin@old-server:/Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist /Library/Server_v57/Server\ HD/Library/Preferences/SystemConfiguration
sudo cp -p /Library/Server_v57/Server\ HD/Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist /Library/Preferences/SystemConfiguration
sudo cp -p /Library/Server_v57/Server\ HD/Applications/Server.app/Contents/ServerRoot/System/Library/LaunchDaemons/com.apple.ppp.l2tp.plist /Library/LaunchDaemons
sudo vi /Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist  # change `VPNHost` hostname, any config changes
sudo launchctl load -w /Library/LaunchDaemons/com.apple.ppp.l2tp.plist
```

Note: This uses Open Directory for authentication. I'd make a beer- or whiskey-based wager that it will work without Open 
Directory if the account `vpn_0123456789ab` is added to the `/Local/Default` node in Directory Utility, along with the 
appropriate edits to `PSKeyAccounts` in `/Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist`.

Debugging:
```
sudo -u admin dscl localhost list /LDAPv3/127.0.0.1/Users
sudo -u admin dscl localhost -read /LDAPv3/127.0.0.1/Users/vpn_0123456789ab
```

## OpenVPN

See the repo [macOS OpenVPN Server](https://github.com/essandess/macos-openvpn-server).


## Mail

Build a modern BSD-based mail server for macOS. This is planned to be a Frankenstein creation using modern BSD tools, 
integrated with Apple's latest Server.app with **Open Directory** certificate creation/management, the ability to deploy 
credentials using the **Profile Manager** MDM, and using, for as long as it or this Apple service lives, an old macOS 
Server.app v.5.7 to
[generate APNS Mail/Calendar/Address APNS certificates](https://github.com/st3fan/dovecot-xaps-daemon/issues/46) for push 
notifications on mobile devices. Except for APNS, there are good, viable alternatives to all these tools.

This section roughly follows these BSD- and Linux-based notes:
  * https://www.c0ffee.net/blog/mail-server-guide/
  * https://rspamd.com/doc/quickstart.html
  * https://thomas-leister.de/en/mailserver-debian-stretch/
  * https://arstechnica.com/information-technology/2014/02/how-to-run-your-own-e-mail-server-with-your-own-domain-part-1/
  * http://www.purplehat.org/?page_id=4

Specific configuration choices (e.g. amavisd+spamassassin versus rspamd) will be made along the way. It appears that rspamd is 
the tool of choice now, both for technology and the love it gets online. The initial run-through will use rspamd, 
expecting the follow [c0ffee.net](https://www.c0ffee.net/blog/mail-server-guide/)'s FreeBSD guide pretty closely for macOS.

### Copy the previous Server.app's Mail configuration

Old server:
```
( cd /Library/Server ; sudo tar cfpj ~/Downloads/Mail_Config.tbz ./Mail/Config )
scp ~/Downloads/Mail_Config.tbz admin@new-server:~/Downloads
```

New server:
```
( cd /Library/Server_v57 ; sudo tar xfpj ~/Downloads/Mail_Config.tbz )
```

Keep a copy of the old server's `serveradmin` Mail settings (compressed and encrypted):

Old server:
```
sudo serveradmin -x set mail | bzip2 -c > ~/Downloads/serveradmin_v57_mail.plist.bz2
gpg -ac ~/Downloads/serveradmin_v57_mail.plist.bz2
sudo chown admin:admin ~/Downloads/serveradmin_v57_mail.plist.bz2.asc
sudo chmod 640 ~/Downloads/serveradmin_v57_mail.plist.bz2.asc
scp -p ~/Downloads/serveradmin_v57_mail.plist.bz2.asc admin@new-server:~/Downloads
rm ~/Downloads/serveradmin_v57_mail.plist.bz2 ~/Downloads/serveradmin_v57_mail.plist.bz2.asc
```

### Mail server installation steps

#### `postfix`

##### Install `postfix`

```
port search postfix
port variants postfix
sudo port -pN install postfix +dovecot_sasl +ldap +pcre +postgresql96 +sasl +smtputf8 +tls
port notes postfix
```

Turn of macOS's native `postfix` MTA, if it's running. Leave its 
`com.apple.postfix.master` (`man 8 master`) and `com.apple.postfix.newaliases` (`man newaliases`) daemons running, which in any event to turn off would require an 
unnecessary cycle of `scrutil disable`, `scrutil enable` in Recovery Mode to handle the SIP protections on these plists:
```
sudo launchctl list | grep postfix
# Don't do this, which SIP will prevent anyway:
# sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.postfix.master.plist
```

##### Configure `postfix`

Configure `postfix` with an amalgam of modern BSD mail capabilities that also uses the latest Server.app's certificates and 
**Open Directory** LDAP authentication. Also configure the web-based configuration and monitoring tools to us
**Profile Manager**'s Apache web server as decribed above in the [Web](#web) section.

Postfix configuration, though powerful and comprehensive, is also Byzantine and error-prone. The best approach is to build the 
foundations step-by-step, changing up to three parameters each time, and reloading to make sure that everything is running 
correctly.

At the end of this section, a sucecssful `postfix` configuration will be able to send email using a simple `sendmail` test.

```
sudo cp -p /opt/local/etc/postfix/main.cf /opt/local/etc/postfix/main.cf.orig
sudo vi /opt/local/etc/postfix/main.cf
sudo port load postfix
# Make sure that PATH points to Macports `/opt/local/sbin/postfix`, not the native macOS `postfix` binary
which postfix
```

Create these directories and files, with appropriate permissions:
```
# Logging
sudo mkdir /opt/local/var/log/mail
sudo chmod go-rwx /opt/local/var/log/mail

# Aliases
sudo newaliases

# Create your own Diffie-Hellman parameters for TLS Forward Secrecy
sudo -u _postfix openssl dhparam -out /opt/local/var/lib/postfix/dh2048.pem 2048

# TLS authentication of mail relays (using Comcast as ISP example)
openssl s_client -showcerts -servername smtp.comcast.net -connect smtp.comcast.net:587  -starttls smtp < /dev/null > smtp_comcast_net.pem
# For smtp_tls_CAfile:
vi smtp_comcast_net.pem  # delete non-certificate outputs before 1st --- and after last ---
# For smtp_tls_CApath:
# break into three (or the necessary trust chain #) of .crt files delineated by
# '-----BEGIN CERTIFICATE-----'
sudo mkdir -p /opt/local/etc/postfix/etc/certificates
sudo cp smtp_comcast_net.pem [*.crt] /opt/local/etc/postfix/etc/certificates
sudo chgrp -R _postfix /opt/local/etc/postfix/etc

# SASL authentication for mail relays
sudo mkdir /opt/local/etc/postfix/sasl
sudo vi /opt/local/etc/postfix/sasl/passwd
sudo chgrp -R _postfix /opt/local/etc/postfix/sasl
sudo chmod -R o-rwx /opt/local/etc/postfix/sasl
sudo postmap /opt/local/etc/postfix/sasl/passwd
```

Checking and debugging after every few parameter changes.
```
man 5 postconf
sudo vi /opt/local/etc/postfix/main.cf
sudo bash -c 'postfix reload ; sleep 1 ; nmap -p 25 localhost ; lsof -i ":25" ; postfix status ; postfix check'
sendmail -t < ~/mail.txt
sudo less /opt/local/var/log/mail/postfix.log
mailq
# For `sendmail -v` without dovecot set up:
sudo postsuper -d ALL
```

`mail.txt`
```
To: me@isp.net
Subject: postfix configuration test
From: admin@domain.tld

My first SMTP email test.
```

#### `dovecot`

##### Install `dovecot`
```
sudo port -pN install dovecot2 +ldap +lucene +solr +postgresql92
sudo port -pN install dovecot2-antispam dovecot2-sieve
```

Note the inconsistency of PostgreSQL versions with `postfix` above. I'm adding the SQL variant "just in case" I need to use 
such a database, and will go back and fix later if this necessity arises.

##### Configure `dovecot`

#### LDAP configuration

#### Junkmail and Notjunkmail accounts?

#### Install Dovecot, perhaps dovecot-pigeonhole

#### LDAP Auth mechanism?

#### Install solr or some other indexing

#### Install rspamd, compare to other installs; what did macOS Server use? spamassassin

#### Install redis for rspamd

#### Configure postfix and Dovecot to worth with the milter

#### Configure DKIM in postfix and the DNS records

#### Test DKIM, DMARC, SPF

#### Create user-specific sieve scripts

#### Install APNS configuration using Server.app v5.7 certs

#### Install mailman

#### Make sure that this configuration works with Notes

#### Create S/MIME certs
