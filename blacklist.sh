#!/bin/sh
# IP blacklisting script for Linux servers

# URLs for further blocklists are appended using the classical
# shell syntax:  "$URLS [SETNAME|]new_url"
URLS=""

# FireHOL level1 A firewall blacklist composed from IP lists                  (includes: bambenek_c2 dshield feodo fullbogons spamhaus_drop spamhaus_edrop sslbl ransomware_rw)
# WARNING! firehol-l1 list includes local and private IP ranges 
URLS="$URLS firehol-l1|https://iplists.firehol.org/files/firehol_level1.netset"

# FireHOL level2 Blocklists that track attacks, during about the last   [48h] (includes: blocklist_de dshield_1d  greensnow)
URLS="$URLS firehol-l2|https://iplists.firehol.org/files/firehol_level2.netset"

# FireHOL level3 Blocklists that track attacks, spyware, viruses        [30d] (includes: bruteforceblocker ciarmy dshield_30d dshield_top_1000 malc0de maxmind_proxy_fraud myip shunlist snort_ipfilter sslbl_aggressive talosintel_ipfilter vxvault)
# WARNING! firehol-l3 list includes github
# URLS="$URLS firehol-l3|https://iplists.firehol.org/files/firehol_level3.netset"

# FireHOL iblocklist
URLS="$URLS firehol-ibl|https://iplists.firehol.org/files/iblocklist_ciarmy_malicious.netset"

# EmergingThreats lists offensive IPs such as botnet command servers
URLS="$URLS emergingthreats.net|https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"    

# Cinsscore badguys
URLS="$URLS cinsscore.com|https://cinsscore.com/list/ci-badguys.txt"

# FireHOL adUser Blocklists that track abusers                          [24h] (includes: botscout_1d cleantalk_new_1d cleantalk_updated_1d php_commenters_1d php_dictionary_1d php_harvesters_1d php_spammers_1d stopforumspam_1d)
URLS="$URLS firehol-ad|https://iplists.firehol.org/files/firehol_abusers_1d.netset"

# FireHOL blocklist.net.ua
URLS="$URLS firehol-ua|https://iplists.firehol.org/files/blocklist_net_ua.ipset"


enable_whitelist () {
    # remove local and private ip
    sed -i '/192.88.99.0\/24/d' ${1}
    sed -i '/240.0.0.0\/4/d'    ${1}
    sed -i '/224.0.0.0\/4/d'    ${1}
    sed -i '/192.88.99.0\/24/d' ${1}    
    sed -i '/172.16.0.0\/12/d'  ${1}
    sed -i '/192.0.2.0\/24/d'   ${1}
    sed -i '/198.18.0.0\/15/d'  ${1}
    sed -i '/192.168.0.0\/16/d' ${1}
    sed -i '/169.254.0.0\/16/d' ${1}
    sed -i '/127.0.0.0\/8/d'    ${1}
    sed -i '/10.0.0.0\/8/d'     ${1}
    sed -i '/100.64.0.0\/10/d'  ${1}
}

#################################################################################

# iptables logging limit
LIMIT="10/minute"

link_set () {
  # if [ "$3" = "DROP" ]; then
      if ! iptables -nL | grep -qE "^DROP.*\s+match-set $2\s+.*$"; then
        if [ "$4" = "log" ]; then
            iptables -A "$1" -m set --match-set "$2" src,dst -m limit --limit "$LIMIT" -j LOG --log-prefix "DROP $2 "
        fi
        iptables -A "$1" -m set --match-set "$2" src -j DROP
        iptables -A "$1" -m set --match-set "$2" dst -j DROP
      fi
  # fi  
  # if [ "$3" = "ACCEPT" ]; then
  #   if ! iptables -nL | grep -qE "^ACCEPT.*\s+match-set $2\s+.*$"; then
  #     # if [ "$4" = "log" ]; then
  #     #     iptables -A "$1" -m set --match-set "$2" src,dst -m limit --limit "$LIMIT" -j LOG --log-prefix "ACCEPT $2 "
  #     # fi
  #     iptables -A "$1" -m set --match-set "$2" src -j ACCEPT
  #     iptables -A "$1" -m set --match-set "$2" dst -j ACCEPT
  #   fi
  # fi
}

# collect created set names to exclude them from blocklist chain purge stage
set_names=""
collect_set() {
  [ -n "${set_names}" ] && set_names="${set_names}|${1}" || set_names=${1}
}

# This is how it will look like on the server
blocklist_chain_name=blocklists

# check for dependencies - ipset and curl
if [ -z "$(which ipset 2>/dev/null)" ]; then
    echo "Cannot find ipset"
    echo "Run \"apt-get install ipset\" (Debian/Ubuntu) or \"yum install ipset\" (RedHat/CentOS/Fedora) or \"opkg install ipset\" (OpenWRT/LEDE)"
    exit 1
fi
if [ -z "$(which curl 2>/dev/null)" ]; then
    echo "Cannot find curl"
    echo "Run \"apt-get install curl\" (Debian/Ubuntu) or \"yum install curl\" (RedHat/CentOS/Fedora) or \"opkg install curl\" (OpenWRT/LEDE)"
    exit 1
fi

# check if we are on OpenWRT
if [ "$(which uci 2>/dev/null)" ]; then
    # we're on OpenWRT
    wan_iface=$(uci get network.wan.ifname)
    IN_OPT="-i $wan_iface"
    INPUT=input_rule
    FORWARD=forwarding_rule
    COMPRESS_OPT=""
else
    COMPRESS_OPT="--compressed"
    INPUT=INPUT
    FORWARD=FORWARD
fi

# create main blocklists chain
if ! iptables -nL | grep -q "Chain ${blocklist_chain_name}"; then
    iptables -N ${blocklist_chain_name}
fi

# inject references to blocklist in the beginning of input and forward chains
if ! iptables -nL ${INPUT} | grep -q ${blocklist_chain_name}; then
  iptables -I ${INPUT} 1 ${IN_OPT} -j ${blocklist_chain_name}
fi
if ! iptables -nL ${FORWARD} | grep -q ${blocklist_chain_name}; then
  iptables -I ${FORWARD} 1 ${IN_OPT} -j ${blocklist_chain_name}
fi

# create the "manual" whitelist set
# set_name="manual-whitelist"
# if ! ipset list | grep -q "Name: ${set_name}"; then
#     ipset create "${set_name}" hash:net
# fi
# link_set "${blocklist_chain_name}" "${set_name}" "ACCEPT" "$1"
# collect_set "${set_name}"

# create the "manual" blacklist set
# this can be populated manually using ipset command:
# ipset add manual-blacklist a.b.c.d
set_name="manual-blacklist"
if ! ipset list | grep -q "Name: ${set_name}"; then
    ipset create "${set_name}" hash:net
fi
link_set "${blocklist_chain_name}" "${set_name}" "DROP" "$1"
collect_set "${set_name}"

init_temp_files () {
  # initialize temp files
  unsorted_blocklist=$(mktemp)
  sorted_blocklist=$(mktemp)
  new_set_file=$(mktemp)
  headers=$(mktemp)
}

prune_temp_files () {
  # clean up temp files
  rm -f "${unsorted_blocklist}" "${sorted_blocklist}" "${new_set_file}" "${headers}"
}

# download and process the dynamic blacklists
for url in $URLS
do
    init_temp_files
    # download the blocklist
    set_name=$(echo "$url" | cut -d '|' -sf 1)
    if [ -z "$set_name" ]; then
        # set name is derived from source URL hostname
        set_name=$(echo "$url" | awk -F/ '{print substr($3,0,21);}')
    else
	      url=$(echo "$url" | cut -d '|' -sf 2)
    fi
    collect_set "$set_name"

    if ! curl --fail -m 60 -L -v -s ${COMPRESS_OPT} -k -H 'Accept: text/plain' "$url" >"${unsorted_blocklist}" 2>"${headers}"; then
      prune_temp_files
      continue
    fi

    if [ -z "$COMPRESS_OPT" ]; then
        if grep -qi 'content-encoding: gzip' "${headers}"; then
            mv "${unsorted_blocklist}" "${unsorted_blocklist}.gz"
            gzip -d "${unsorted_blocklist}.gz"
        fi
    fi
    
    cat ${headers} | grep "GET /"
    
    # clean local and private ip
    enable_whitelist ${unsorted_blocklist}
    
    sort -u <"${unsorted_blocklist}" | sed -nE 's/^(([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?).*$/\1/p' >"${sorted_blocklist}"
    
    # calculate performance parameters for the new set
    if [ "${RANDOM}" ]; then
        # bash
        tmp_set_name="tmp_${RANDOM}"
    else
        # non-bash
        tmp_set_name="tmp_$$"
    fi
    new_list_size=$(wc -l "${sorted_blocklist}" | awk '{print $1;}' )
    hash_size=$(expr $new_list_size / 2)

    if ! ipset -q list ${set_name} >/dev/null ; then
        ipset create ${set_name} hash:net family inet
    fi

    # start writing new set file
    echo "create ${tmp_set_name} hash:net family inet hashsize ${hash_size} maxelem ${new_list_size}" >>"${new_set_file}"

    # convert list of IPs to ipset statements
    while read line; do
        echo "add ${tmp_set_name} ${line}" >>"${new_set_file}"
    done <"$sorted_blocklist"

    # replace old set with the new, temp one - this guarantees an atomic update
    echo "swap ${tmp_set_name} ${set_name}" >>"${new_set_file}"

    # clear old set (now under temp name)
    echo "destroy ${tmp_set_name}" >>"${new_set_file}"

    # actually execute the set update
    ipset -! -q restore < "${new_set_file}"

    link_set "${blocklist_chain_name}" "${set_name}" "DROP" "$1"
    prune_temp_files
done
# escape special chars from set_names excluding '|'
set_names=$(printf '%s' "${set_names}" | sed 's/[.[\*^$()+?{]/\\&/g')
#purge not configured set names rules from blocklists chain of iptables
rules=$(iptables -S"${blocklist_chain_name}"|grep -E '^-A .*--match-set'|grep -vE "(${set_names})"|cut -d' ' -f2-)
printf '%s' "${rules}" | xargs -d '\n' -r -I {}  sh -c "iptables -D {}"
