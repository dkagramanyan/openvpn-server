# Additional firewall rules, run by the entrypoint on every start (bash).
# Append to OVPN-FORWARD, which is rebuilt each time: rules there run after the
# guest isolation and before the rules that accept VPN traffic. Example:
#   iptables -A OVPN-FORWARD -s 10.0.70.5 -d 171.134.51.10 -j DROP
