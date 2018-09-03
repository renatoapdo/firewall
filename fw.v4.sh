#Firewall Linux.
# Dev by Renato Bueno
# Contato: renato@renatobueno.eti.br

#Definição e interfaces 
internet=ens3
local=ens4
ipLocal=192.168.1.0/24

# Politica padrao
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Contra Syn-floods
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT

# Port scanners ocultos
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT

# Proteção contra IP Bogons
iptables -A INPUT -s 10.0.0.0/8 -i $internet -j DROP
iptables -A INPUT -s 172.16.0.0/16 -i $internet -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i $internet -j DROP

#Compartilhamento de internet
iptables -t nat -A POSTROUTING -s $ipLocal -o $internet -d 224.0.0.0/24 -j RETURN
iptables -t nat -A POSTROUTING -s $ipLocal -o $internet -d 255.255.255.255/32 -j RETURN
iptables -t nat -A POSTROUTING -s $ipLocal ! -d $ipLocal -o $internet -p tcp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -A POSTROUTING -s $ipLocal ! -d $ipLocal -o $internet -p udp -j MASQUERADE --to-ports 1024-65535
iptables -t nat -A POSTROUTING -s $ipLocal ! -d $ipLocal -o $internet -j MASQUERADE

#PROXY
#iptables -A PREROUTING -s $ipLocal ! -d $ipLocal -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3129

#Localhost
iptables -A INPUT -d 127.0.0.1/32 -i lo -j ACCEPT
iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

#SSH
iptables -A INPUT -p tcp -m tcp --dport 65222 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --sport 65222 -m state --state RELATED,ESTABLISHED -j ACCEPT

#DNS CLient
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT

iptables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT

#DNS Server 
iptables -A INPUT -s $ipLocal -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -s $ipLocal -p udp -m udp --sport 53 -j ACCEPT

iptables -A INPUT -s $ipLocal -p tcp -m tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -d $ipLocal -p tcp -m tcp --sport 53 -j ACCEPT

iptables -A INPUT -s $ipLocal -p tcp -m tcp --dport 953 -j ACCEPT
iptables -A OUTPUT -d $ipLocal -p tcp -m tcp --sport 953 -j ACCEPT

# SNMP Cliente
iptables -A OUTPUT -p UDP -m udp --dport 161 -j ACCEPT
iptables -A INPUT -p UDP -m udp --sport 161 -j ACCEPT

#NTP
iptables -A INPUT -p udp -m udp --sport 123 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 123 -j ACCEPT

#TCP_Client
iptables -A OUTPUT -p tcp -m tcp --dport 20 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 20 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 21 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 21 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 22 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 22 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 53 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 53 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 80 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 80 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 443 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 443 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 465 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 465 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 587 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 587 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 8245 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 8245 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 8080 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 8080 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -m tcp --dport 65222 --sport 1024:65535 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 65222 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT
#DHCP
iptables -A INPUT -p udp -m udp --sport 68 --dport 67 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT

#ICMP
iptables -A INPUT -p icmp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

#SNMP
iptables -A INPUT -p udp -m udp --sport 161 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 161 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 161 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 161 -j ACCEPT

#SQUID
# Proxy forward
iptables -A INPUT -s $ipLocal -p tcp -m tcp --sport 1024:65535 --dport 3128 -j ACCEPT
iptables -A OUTPUT -d $ipLocal -p tcp -m tcp --sport 3128 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Proxy transparente
iptables -A INPUT -s $ipLocal -p tcp -m tcp --sport 1024:65535 --dport 3129 -j ACCEPT
iptables -A OUTPUT -d $ipLocal -p tcp -m tcp --sport 3129 --dport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT

#Zabbix Server
iptables -A INPUT -p tcp -m tcp --dport 10051 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --sport 10051 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 10050 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 10050 -j ACCEPT

#FORWARD 
iptables -A FORWARD -s $ipLocal -d 0/0 -j ACCEPT
iptables -A FORWARD -d $ipLocal -m state --state ESTABLISHED,RELATED -j ACCEPT

#DVR
#iptables -A FORWARD -d 192.168.3.251/32 -i br0 -p tcp -m tcp --dport 8000 -j ACCEPT
#iptables -A FORWARD -d 192.168.3.251/32 -i br0 -p tcp -m tcp --dport 6036 -j ACCEPT

#LOGs
iptables -A INPUT -p udp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "INPUT UDP Dropped "
iptables -A OUTPUT -p udp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "OUTPUT UDP Dropped "
iptables -A FORWARD -p udp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "FORWARD UDP Dropped "

iptables -A INPUT -p icmp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "INPUT ICMP Dropped "
iptables -A OUTPUT -p icmp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "OUTPUT ICMP Dropped "
iptables -A FORWARD -p icmp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "FORWARD ICMP Dropped "

iptables -A INPUT -p tcp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "INPUT TCP Dropped "
iptables -A OUTPUT -p tcp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "OUTPUT TCP Dropped "
iptables -A FORWARD -p tcp -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "FORWARD TCP Dropped "

iptables -A INPUT -f -m limit --limit 1/s -j LOG --log-level 7 --log-prefix "INPUT FRAGMENT Dropped "


