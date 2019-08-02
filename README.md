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
  * [VPN](#vpn)
  * [OpenVPN](#openvpn)
  * [Mail](#mail)
  * [Calendar and Contacts](#calendar-and-contacts)


## DNS

Configure DNS with a "split horizon," so that the domain is bound to
an external IP address on the open internet by the DNS provider of
your choice, and an internal LAN IP address by the [DNS service](#dns)
on the server.

```
sudo port install dns-server
port notes dns-server
sudo port load bind9
```

It is necessary to reconfigure the installation for your own network
specifics and preferences by editing the files:
  
* `/opt/local/etc/named.conf`
* `/opt/local/var/named/db.*`
  
Refer to the `*.macports` template files and `man named` for details.


## VPN

Configure macOS's native VPN (L2TP-IPSec-PSK) Server. This
configuration is based upon macOS Server.app's prior VPN server.

```
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


## Mail

MacPorts provides a basic, working, configurable mail server:
```
sudo port install mail server
```

This mail server uses [postfix](http://www.postfix.org/documentation.html) for the MTA,
[dovecot](https://www.dovecot.org) for the MDA, [solr](http://lucene.apache.org/solr/guide/) for fast search,
[Rspamd](https://www.rspamd.com) for a milter, and [clamav](https://www.clamav.net) for email virus scanning.
Surrogate TLS and DKIM configurations are created during the installation; these must be changed prior to
deployment. The configuration files in this port are a combination of macOS Server version 5.7's Mail server
setup, with many newer capabilities added. See the individual projects for configuration details, as well as
online guides, e.g. (mail-server-guide)[https://www.c0ffee.net/blog/mail-server-guide/], and the MacPorts
`mail-server` [Portfile](https://github.com/macports/macports-ports/blob/master/mail/mail-server/Portfile) itself:
```
port notes mail-server
less `port file mail-server`
port contents mail-server
```

Users must reconfigure the mail-server installation for their own system, network, and security model specifics
by editing all necessary files and checking file permissions. Full deployment also requires a working DNS
configuration on both the LAN and the internet (pre-installed with `mail-server`), including SPF, DMARC, and DKIM
records, trusted TLS certificates, port forwarding, possibly a mail relay, and more.

## Calendar and Contacts

Work in progress. See [macOS Server Migration Notes](./macOS%20Server%20Migration%20Notes.md#calendar-and-contacts). Based on Apple's
[ccs-calendarserver](https://github.com/apple/ccs-calendarserver).

