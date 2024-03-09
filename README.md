Slight modification of Coldbird's adhoc server (only tunnel.c is new) which allows multiplayer in the scenario where >1 devices that aren't able to run apps like zerotier or hamachi are behind NAT and want to play with people outside their local network. 
Requirements: 
  - ability to add routes to router manually and portforwarding for port 27313
  - ability to add ip addresses to the computer running the tunnel

This works by making the adhoc-server assign addresses from 192.168.1.0/28 subnet to the devices which are in different local networks.
The tunnel (which each participant has to run on a different pc) listens on each of these addresses on all ports the specific game needs.
One has add a route to the local router so that addresses in 192.168.1.0/28 are routed to gateway {ip address of the computer running the tunnel}.
Data sent to these addresses is forwarded to the correct receiving tunnel over TCP with the header format (lenght data, src_ip, dest_ip, src_port, dest_port, data).
A src_port of 0 means that the data was originally transfered over UDP. Therefore UDP does not preserve sender ports in this protocol.

Somebody has to set up the server and forward port 27312:
  - make server (libsqlite3-dev is a dependency)
  - for OpenBSD change CC to egcc
  - run server: ./server
  - server has to be run before the tunnels are run

How to set up tunnel (each participating local network has to run it):
  - add the addresses in the subnet to some interface (loopback doesn't work though I think)
    - on ubuntu:
      - sudo ip address add 192.168.1.1/32 dev wlan0 -> temporary
      - modify netplan -> permanent
    - on OpenBSD:
      - something with ifconfig -> temporary
      - inet 192.168.1.x 255.255.255.240 -> add these lines to /etc/hostname.{interface_name} for permanent
  - add route in router to point this subnet to the tunnel server ip
  - modify config file: each line has mac_addres -> local_ip_address mapping e.g. 11:22:33:44:55:66 -> 192.168.178.55
  - make tunnel
  - run tunnel: ./tunnel {modified adhoc-server address or domain name} {path to config file: default is ./config}
  - tunnel has to be run before anybody else from the local network connects to the adhoc-server!

How to add support for a game with product_code:
  - open the database.db with sqlite3
  - check if crosslink exists: select id_to from crosslinks where id_from = product_code;
  - if one exists use that result as your new product_code
  - else check if game exists: select * from productids where id = product_code;
    - if the game does not exist add it: insert into productids values(product_code, name_of_game);
  - now add the ports: e.g.
    - insert into ports values ("ULJM05800", "UDP", 10000);
    - insert into ports values ("ULJM05800", "TCP", 20001); etc.
