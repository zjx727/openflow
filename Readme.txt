++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
EE555 - Fall 2019 - Major Project - Design of OpenFlow controller using Python POX Library

README File
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

+++++
TEAM
+++++

+++++++++++++++++++++++++++++++
Files Submitted in the package
+++++++++++++++++++++++++++++++
[List of all the files submitted in the zip folder and a one line description of each file]
Scenario 1:
of_tutorial.py
Scenario 2:
topology2.py: The topology of scenario 2 
controller2.py: The controller that can realize the function of a router with three hosts
Scenario 3:
topology3.py:The topology of scenario 3
controller3.py: The controller that can communicate within the same network and different networks.
Scenario 4:
topology4.py:The topology of scenario 4
controller4.py: The controller that can communicate within the same network and three different networks.
firewall.py: The controller that can block the TCP packets.

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Scenario 1
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 1]
of_tutorial.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<of_tutorial.py> - < pox/pox/misc>
[Destination to be provided for each file that is relevant to scenario 1]

++++++++++++++++
Commands to Run:
++++++++++++++++
[Any special instructions we need to follow before running commands you will mention below for scenario 1]
[List of commands to run before we execute the test cases of scenario 1]
For the pox:
cd pox
 ./pox.py log.level --DEBUG misc.of_tutorial
(./pox.py log.level --DEBUG misc.of_tutorial misc.full_payload) 
In another terminal:
sudo mn --topo single,3 --mac --switch ovsk --controller remote

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating scenario 1]
In the "iperf UDP between h2 and h3", the UDP could run successfully however the pox would shows: the packet length is short.
If we use the second command in the pox, there is no warning message about the UDP length. But there are few packets showed as received out of order.

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Scenario 2
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 2]
topology2.py 
controller2.py
++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<topology2.py> - < ~/mininet/custom/>
<controller2.py> - < pox/pox/misc>
[Destination to be provided for each file that is relevant to scenario 2]

++++++++++++++++
Commands to Run:
++++++++++++++++
[Any special instructions we need to follow before running commands you will mention below for scenario 2]
[List of commands to run before we execute the test cases of scenario 2]
For the pox:
cd pox
 ./pox.py log.level --DEBUG misc.controller2 misc.full_payload
In another terminal:
sudo mn --custom topology2.py --topo mytopo --mac --controller remote
+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating scenario 2]

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Scenario 3
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 3]
topology3.py 
controller3.py
++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<topology3.py> - < ~/mininet/custom/>
<controller3.py> - < pox/pox/misc>
[Destination to be provided for each file that is relevant to scenario 3]

++++++++++++++++
Commands to Run:
++++++++++++++++
[Any special instructions we need to follow before running commands you will mention below for scenario 3]
[List of commands to run before we execute the test cases of scenario 3]
For the pox:
cd pox
 ./pox.py log.level --DEBUG misc.controller3 misc.full_payload
In another terminal:
sudo mn --custom topology3.py --topo mytopo --mac --controller remote

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating scenario 3]

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Scenario 4
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute scenario 4]
topology4.py 
controller4.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<topology4.py> - < ~/mininet/custom/>
<controller4.py> - < pox/pox/misc>
[Destination to be provided for each file that is relevant to scenario 4]

++++++++++++++++
Commands to Run:
++++++++++++++++
[Any special instructions we need to follow before running commands you will mention below for scenario 4]
[List of commands to run before we execute the test cases of scenario 4]
For the pox:
cd pox
 ./pox.py log.level --DEBUG misc.controller4 misc.full_payload
In another terminal:
sudo mn --custom topology4.py --topo mytopo --mac --controller remote

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating scenario 4]

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Bonus Scenario
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
[List of files that are to be used to execute Bonus Scenario]
firewall.py

++++++++++++++++++++++
Location to copy files
++++++++++++++++++++++
<firewall.py> - < pox/pox/misc>
[Destination to be provided for each file that is relevant to Bonus Scenario]

++++++++++++++++
Commands to Run:
++++++++++++++++
[Any special instructions we need to follow before running commands you will mention below for Bonus Scenario]
[List of commands to run before we execute the test cases of Bonus Scenario]
For the pox:
cd pox
 ./pox.py log.level --DEBUG misc.firewall misc.full_payload
In another terminal:
sudo mn --topo single,3 --mac --switch ovsk --controller remote

+++++++++++++++++++++++++++++++++
Special Notes or any observations
+++++++++++++++++++++++++++++++++
[Any special notes or observations that we need to take care while evaluating Bonus Scenario]
In the "iperf TCP block", there shows nothing in xterm but the pox would show "Ignore TCP".

Reference:
https://blog.csdn.net/hjxzb/article/details/80299311
https://github.com/tamaraanne/L3-Learning-Switch/blob/master/part_3/own.py
https://github.com/CPqD/RouteFlow/blob/master/pox/pox/misc/arp_responder.py
https://github.com/tyrenyabe/CSE461/blob/630b370bd8dc64981a42cc6ab3ef97cb9806bc30/Project2/part2/part2controller.py