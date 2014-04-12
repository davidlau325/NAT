IP="10.3.1.8"	# public interface
LAN="10.4.8.0"
MASK="27"

echo "1" >  /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F
iptables -t filter -A FORWARD -j QUEUE -p tcp -s ${LAN} ! -d ${IP} --dport 10000:12000
iptables -t mangle -A PREROUTING -j QUEUE -p tcp -d ${IP} --dport 10000:12000
iptables -t filter -A FORWARD -j QUEUE -p udp -s ${LAN} ! -d ${IP} --dport 10000:12000
iptables -t mangle -A PREROUTING -j QUEUE -p udp -d ${IP} --dport 10000:12000
./ipq_translate $IP $LAN $MASK
