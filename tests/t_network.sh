#!/usr/bin/env bash
# NAT / forwarding policy / firewall / IPv6 guard / IKE rate limit (iptables is a stateful stub)
. "$(dirname "$0")/lib.sh"

rules() { local c="$1" t="${2:-filter}" cmd="${3:-iptables}"; "$cmd" -t "$t" -S "$c" 2>/dev/null | sed -n "s/^-A $c //p"; }
pos()   { local n; n=$(grep -nxF -- "$1" <<<"$2" | head -1 | cut -d: -f1); echo "${n:-0}"; }   # 1-based line of an exact rule, 0 = absent
before() { local a b; a=$(pos "$1" "$3"); b=$(pos "$2" "$3"); [[ $a -gt 0 && $b -gt 0 && $a -lt $b ]]; }
P=10.30.0.0/16; TAG='-m comment --comment ikev2-mgr'

section "default policy after 'net apply'"
setup_ip; run net apply; t_eq "$RC" 0 "net apply exits 0"
F=$(rules IKEV2_FWD)
t_eq "$(rules FORWARD)" "$TAG -j IKEV2_FWD" "FORWARD contains exactly one tagged jump to IKEV2_FWD"
expected="-s $P -d 169.254.0.0/16 -j DROP
-s $P -d $P -j DROP
-s $P -d 1.1.1.1 -j ACCEPT
-s $P -d 8.8.8.8 -j ACCEPT
-s $P -d 10.0.0.0/8 -j DROP
-s $P -d 172.16.0.0/12 -j DROP
-s $P -d 192.168.0.0/16 -j DROP
-s $P -d 100.64.0.0/10 -j DROP
-s $P -j ACCEPT
-d $P -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
t_eq "$F" "$expected" "IKEV2_FWD has the expected rules in the expected order"
t_has "$(rules POSTROUTING nat)" "-s $P -o eth0 $TAG -j MASQUERADE" "NAT masquerade on the default interface"
t_has "$(rules FORWARD mangle)" "TCPMSS --clamp-mss-to-pmtu" "MSS clamp present"
t_has "$(rules INPUT)" "-p udp -m multiport --dports 500,4500 $TAG -j ACCEPT" "IKE/NAT-T accepted"
t_has "$(cat "$T/sysctl/99-ikev2.conf")" "net.ipv4.ip_forward=1" "sysctl drop-in written to the (overridable) directory"
check "metadata block comes first (cannot be overridden by later ACCEPT rules)" before "-s $P -d 169.254.0.0/16 -j DROP" "-s $P -j ACCEPT" "$F"
check "client isolation comes before the pushed-DNS exceptions" before "-s $P -d $P -j DROP" "-s $P -d 1.1.1.1 -j ACCEPT" "$F"
check "DNS exceptions come before the private-range blocks" before "-s $P -d 8.8.8.8 -j ACCEPT" "-s $P -d 10.0.0.0/8 -j DROP" "$F"

section "idempotent and clean"
a=$(cat "$T/state/iptables.json"); run net apply; run net apply
t_eq "$(cat "$T/state/iptables.json")" "$a" "re-applying changes nothing (no duplicate rules)"
iptables -A FORWARD -s 1.2.3.4 -j DROP; iptables -A INPUT -p tcp --dport 8080 -j ACCEPT   # somebody else's rules
run net apply
t_has "$(rules FORWARD)" "-s 1.2.3.4 -j DROP" "foreign FORWARD rule survives"
( . "$V"; net_clear ) >/dev/null 2>&1
t_eq "$(rules FORWARD)" "-s 1.2.3.4 -j DROP" "net_clear removes only our FORWARD rules"
t_eq "$(rules INPUT)" "-p tcp --dport 8080 -j ACCEPT" "net_clear removes only our INPUT rules"
t_eq "$(rules POSTROUTING nat)" "" "net_clear removes NAT rule"
check_not "net_clear deletes the IKEV2_FWD chain" iptables -S IKEV2_FWD
# rules written by v1.2.x (tagged ACCEPTs directly in FORWARD) are cleaned up on upgrade
iptables -I FORWARD 1 -s $P $TAG -j ACCEPT; iptables -I FORWARD 1 -d $P $TAG -j ACCEPT
run net apply; t_eq "$(rules FORWARD | grep -c ACCEPT)" 0 "legacy v1.2 tagged FORWARD ACCEPT rules are removed"
t_eq "$(rules FORWARD | grep -c IKEV2_FWD)" 1 "...and replaced by the chain jump"

section "switches: CLIENT_ISOLATION / BLOCK_PRIVATE / NAT / DNS / LOCAL_TS"
setup_ip; run set CLIENT_ISOLATION no; run net apply; F=$(rules IKEV2_FWD)
t_has "$F" "-s $P -d $P -j ACCEPT" "CLIENT_ISOLATION=no allows client-to-client"
t_hasnt "$F" "-s $P -d $P -j DROP" "...and drops nothing between clients"
check "client-to-client ACCEPT precedes the private-range DROPs (pool is inside 10/8)" before "-s $P -d $P -j ACCEPT" "-s $P -d 10.0.0.0/8 -j DROP" "$F"
run set CLIENT_ISOLATION yes; run set BLOCK_PRIVATE no; run net apply; F=$(rules IKEV2_FWD)
t_hasnt "$F" "-d 10.0.0.0/8" "BLOCK_PRIVATE=no: no RFC1918 drops"
t_has "$F" "-s $P -d 169.254.0.0/16 -j DROP" "...but link-local/metadata stays blocked"
run set BLOCK_PRIVATE yes; run set NAT no; run net apply; F=$(rules IKEV2_FWD)
t_eq "$(rules POSTROUTING nat)" "" "NAT=no: no masquerade"
t_has "$F" "-d $P -j ACCEPT" "NAT=no: inbound to clients allowed (routed setup)"
t_hasnt "$F" "RELATED,ESTABLISHED" "NAT=no: no conntrack-only rule"
run set NAT yes; run set DNS 10.0.0.2,9.9.9.9; run net apply; F=$(rules IKEV2_FWD)
check "private DNS server stays reachable (ACCEPT before the 10/8 DROP)" before "-s $P -d 10.0.0.2 -j ACCEPT" "-s $P -d 10.0.0.0/8 -j DROP" "$F"
run set DNS default; run set LOCAL_TS 10.0.0.0/8,192.168.1.0/24; run net apply; F=$(rules IKEV2_FWD)
check "split-tunnel route 10.0.0.0/8 is allowed ahead of the private drops" before "-s $P -d 10.0.0.0/8 -j ACCEPT" "-s $P -d 10.0.0.0/8 -j DROP" "$F"
check "split-tunnel route 192.168.1.0/24 is allowed" before "-s $P -d 192.168.1.0/24 -j ACCEPT" "-s $P -d 192.168.0.0/16 -j DROP" "$F"
check "client isolation still precedes split-tunnel exceptions (pool 10.30/16 is inside 10/8)" before "-s $P -d $P -j DROP" "-s $P -d 10.0.0.0/8 -j ACCEPT" "$F"
run set LOCAL_TS 0.0.0.0/0,192.168.1.0/24; run net apply; F=$(rules IKEV2_FWD)
t_hasnt "$F" "-d 0.0.0.0/0 -j ACCEPT" "an explicit 0.0.0.0/0 never becomes an allow-all exception"
t_has "$F" "-d 192.168.1.0/24 -j ACCEPT" "other listed routes do"
run set LOCAL_TS default; run set POOL 10.99.0.0/24; run net apply; F=$(rules IKEV2_FWD)
t_has "$F" "-s 10.99.0.0/24 -d 10.99.0.0/24 -j DROP" "a custom POOL is honoured everywhere"
t_hasnt "$F" "10.30.0.0/16" "no trace of the old pool"

section "IPv6 guard"
setup_ip; run net apply
t_eq "$(rules FORWARD filter ip6tables)" "" "default: no ip6tables FORWARD rules"
run set IPV6_BLOCK yes; run net apply
t_eq "$(rules FORWARD filter ip6tables)" "-m policy --dir in --pol ipsec $TAG -j DROP" "IPV6_BLOCK=yes drops IPv6 that came out of IPsec"
run set IPV6_BLOCK no; run net apply
t_eq "$(rules FORWARD filter ip6tables)" "" "IPV6_BLOCK=no removes the rule again"

section "IKE rate limit (brute-force brake)"
setup_ip; run net apply
t_hasnt "$(rules INPUT)" hashlimit "default: no rate limit"
run set IKE_RATE_LIMIT 60; run net apply; I=$(rules INPUT)
L="$TAG -p udp --dport 500 -m hashlimit --hashlimit-name ike2init4 --hashlimit-mode srcip --hashlimit-above 60/minute --hashlimit-burst 60 -j DROP"
t_has "$I" "$L" "limit rule present (firewall off)"
check "limit rule precedes the IKE ACCEPT" before "$L" "-p udp -m multiport --dports 500,4500 $TAG -j ACCEPT" "$I"
t_has "$(rules INPUT filter ip6tables)" "ike2init6" "IPv6 gets the limit as well"
names=$( { rules INPUT; rules INPUT filter ip6tables; } | grep -o -- '--hashlimit-name [^ ]*' | awk '{print length($2)}' | sort -nr | head -1 )
t_eq "$(( ${names:-99} <= 15 ? 1 : 0 ))" 1 "hashlimit names fit the 15 character kernel limit (longest: ${names:-?})"
run set FIREWALL_DUMMY 1 >/dev/null 2>&1
run fw on; I=$(rules INPUT); W=$(rules IKEV2_FW)
t_hasnt "$I" hashlimit "firewall on: the limit is not duplicated in INPUT"
L2="-p udp --dport 500 -m hashlimit --hashlimit-name ike2init4 --hashlimit-mode srcip --hashlimit-above 60/minute --hashlimit-burst 60 -j DROP"
check "firewall on: limit sits inside IKEV2_FW before its IKE ACCEPT" before "$L2" "-p udp -m multiport --dports 500,4500 -j ACCEPT" "$W"
run set IKE_RATE_LIMIT off; run fw off; run net apply; t_hasnt "$(rules INPUT)" hashlimit "off removes the rule"
run set IKE_RATE_LIMIT 60; STUB_IPT_FAIL=hashlimit run net apply; t_eq "$RC" 0 "missing hashlimit module: net apply still succeeds"
t_has "$OUT" "could not add the IKE rate limit" "...and says so"
t_has "$(rules FORWARD)" "IKEV2_FWD" "...with all other rules in place"

section "firewall (vpn fw)"
setup_ip; run fw on; t_eq "$RC" 0 "fw on"
W=$(rules IKEV2_FW)
for r in "-i lo -j ACCEPT" "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" "-p icmp -j ACCEPT" "-p tcp --dport 22 -j ACCEPT" "-p udp -m multiport --dports 500,4500 -j ACCEPT" "-p esp -j ACCEPT" "-j DROP"; do
  t_has "$W" "$r" "IKEV2_FW has: $r"
done
t_eq "$(tail -1 <<<"$W")" "-j DROP" "IKEV2_FW ends with DROP"
t_eq "$(rules INPUT | head -1)" "-j IKEV2_FW" "jump is the first INPUT rule"
t_has "$(rules IKEV2_FW filter ip6tables)" "-p ipv6-icmp -j ACCEPT" "IPv6 firewall accepts ICMPv6 (neighbour discovery)"
run fw ports "22 2222"; t_eq "$RC" 0 "fw ports accepts valid ports"; t_has "$(rules IKEV2_FW)" "--dport 2222" "new SSH port opened"
for bad in "22 99999" "0" "a" "22;reboot" "22,2222" ""; do run fw ports "$bad"; check_not "fw ports [$bad] refused" test $RC -eq 0; done
run set FW_EXTRA_TCP 443,8080; t_eq "$RC" 0 "set FW_EXTRA_TCP"
run net apply; t_has "$(rules IKEV2_FW)" "-p tcp --dport 8080 -j ACCEPT" "extra TCP ports are opened"
run fw off; t_eq "$(rules INPUT | grep -c IKEV2_FW)" 0 "fw off removes the jump"; check_not "fw off removes the chain" iptables -S IKEV2_FW
run fw status; t_eq "$RC" 0 "fw status works"
run net bogus; check_not "'net bogus' fails" test $RC -eq 0; t_has "$OUT" "Usage: vpn net apply" "...with a usage message"
STUB_IPT_FAIL="-t nat" run net apply; t_eq "$RC" 0 "a failing nat rule does not turn 'net apply' into a bogus usage error"
t_hasnt "$OUT" "Usage" "...and prints no usage text"

section "security extras use overridable paths"
setup_ip; ( . "$V"; cfg_set FW_SSH_PORTS "22 2222" ) >/dev/null
run security fail2ban; t_eq "$RC" 0 "fail2ban"; t_has "$(cat "$T/f2b/ikev2.local" 2>/dev/null)" "port = 22,2222" "jail written with the SSH ports"
run security autoupdate; t_eq "$RC" 0 "autoupdate"; t_has "$(cat "$T/apt/20auto-upgrades" 2>/dev/null)" "Unattended-Upgrade" "apt periodic config written"

summary "network"
