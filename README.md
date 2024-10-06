blacklist-scripts
=================
This is a collection of shell scripts that are intended to block Linux systems and OpenWRT routers from known sources of malicious traffic. These scripts use `iptables` with highly efficient `ipset` module to check incoming traffic against blacklists populated from publicly available sources.

[Emerging Threats](http://rules.emergingthreats.net/fwrules/) provides similar rules that essentially run `iptables` for *each* blacklisted IP which is extremely inefficient in case of large blacklists. Using `ipset` means using just one `iptables` rule to perform a very efficient lookup in hash structure created by `ipset`.


**Note:** This script is a quick hack suitable primarily for embedded devices (OpenWRT, LEDE) rather than a complete solution for server. For the latter, have a look at [FireHOL](http://firehol.org/) and its excellent [FireHOL IP Lists](http://iplists.firehol.org/) add-on. Have a look at the **FireHOL** section further down.

## Available blacklists
If you decide to use this script, these are the blacklists available by default:

* [Emerging Threats](http://rules.emergingthreats.net/fwrules/) - list of other known threats (botnet C&C, compromised servers etc) compiled from various sources, including [Spamhaus DROP](http://www.spamhaus.org/drop/), [Shadoserver](https://www.shadowserver.org/wiki/) and [DShield Top Attackers](http://www.dshield.org/top10.html)
* [www.blocklist.de](https://www.blocklist.de/en/index.html) - list of known password bruteforcers supplied by a network of [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) users
* [iBlocklist](https://www.iblocklist.com/lists.php) - various free and subscription based lists
* [Bogons](http://www.team-cymru.org/Services/Bogons/) - IP subnets that should never appear on public Internet; this includes [RFC 1918](http://tools.ietf.org/html/rfc1918) networks so running this on a machine in a private network will effectively **shut its networking down**

The script also creates an empty `manual-blacklist` set that can be used by the administrator for manual blacklisting. For example:

    ipset add manual-blacklist 217.146.93.122

Removal:

    ipset delete manual-blacklist 217.146.93.122

## OpenWRT
The script automatically detects OpenWRT environment (looking for `uci`) and will try to obtain the WAN interface name. The filtering will be then **limited to WAN interface only.**

Requirements:

* `opkg install ipset curl`

Installation:

    cp blacklist.sh /etc/firewall.user
    echo "01 01 * * * sh /etc/firewall.user" >>/etc/crontabs/root

The blacklist will be updated on daily basis.

Manual run:

    sh /etc/firewall.user
    
## Linux
Requirements:

* On Debian, Ubuntu and other `apt` systems: `apt-get install ipset curl`
* On RedHat, Fedora, CentOS and other RPM systems: `yum install ipset curl`

Installation:

    cp blacklist.sh /etc/cron.daily/blacklist

The blacklist will be updated on daily basis.

Manual run:

    sh /etc/cron.daily/blacklist
