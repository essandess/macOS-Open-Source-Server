macOS-Open-Source-Server
========================

# macOS Open Source Server: Open Source macOS Server Services

An open source version of several useful [macOS
Server](https://apps.apple.com/us/app/macos-server/id883878097?mt=12)
services that are no longer supported. This [README.md](README.md) has
instructions for installing and configuring these services using
[MacPorts](https://www.macports.org).  See the [macOS Server Migration
Notes](macOS Server Migration Notes.md) for detailed notes on
migrating macOS Server.app v. 5.7 High Sierra to Server.app v. 5.8
Mojave.


Table of Contents
=================
  * [DNS](#dns)
  * [Mail](#mail)
  * [Calendar and Contacts](#calendar-and-contacts)
  * [VPN](#vpn)
  * [OpenVPN](#openvpn)


## DNS

Configure DNS with a "split horizon," so that the domain is bound to
an external IP address on the open internet by the DNS provider of
your choice, and an internal LAN IP address by the [DNS service](#dns)
on the server.

```bash
sudo port install dns-server
port notes dns-server
sudo port load bind9
```

It is necessary to reconfigure the installation for your own network
specifics and preferences by editing the files:
  
* `/opt/local/etc/named.conf`
* `/opt/local/var/named/db.*`
  
Refer to the `*.macports` template files and `man named` for details.


## Mail

```bash
sudo port install mail-server
port notes mail-server
sudo port load mail-server
```


## Calendar and Contacts

```bash
sudo port install calendar-contacts-server
port notes calendar-contacts-server
sudo port load calendar-contacts-server
```


## VPN

Configure macOS's native VPN (L2TP-IPSec-PSK) Server. This
configuration is based upon macOS Server.app's prior VPN server.

```bash
sudo port install macos-vpn-server
port notes macos-vpn-server
sudo port load macos-vpn-server
```

It is necessary to reconfigure the installation for your own network
specifics by editing the file:
* `/Library/Preferences/SystemConfiguration/com.apple.RemoteAccessServers.plist`
See `man 5 vpnd` for details.


## OpenVPN

See the repo [macOS OpenVPN Server](https://github.com/essandess/macos-openvpn-server).
