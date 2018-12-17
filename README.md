# Firewall

Ying Chen

##### Test

1. a test.csv file for the unit test of the functions.

2. insert rules cover directions and protocols for all inbound, outbound, tcp, and udp; for IP address, insert single IP address, and IP address ranges, including edge cases, like 0.0.0.0, 0.0.0.1, 0.0.0.255, 1.0.0.0, 255.255.255.255; for port, insert single port number, and port ranges, including edge cases, e.g. port number 1 and 655535, port intervals for two distinct single port numbers for the same IP address, totally inclusive for one port range compared with another one, half inclusive, not inclusive at all for the same IP address.

3. test cases: 

   1) for situations with only the false of directions, it should block the traffic and return false;

   2) for situations with only the false of protocols, it should block the traffic and return false;

   3) for situations with only the false of IP address, it should block the traffic and return false;

   4) for situations with only the false of port numbers, it should block the traffic and return false;

   5) for situations match the four inputs, direction, protocol, port and IP address, it should allow the traffic and return true.

4. The code uses java 8 and maven to compile and run. All unit tests are tested and run in JUnit4. There is a test.csv file including all the test rules. Unit tests are all passed using "mvn compile" and "mvn test" commands.

5. The tests cover 100% of the method and more than 85% lines of the implementation class.

##### Design

1. A binary trie structure to store and search IP addresses, in order to save space and search time.
2. A list of start and end intervals to store and search ports.
3. four seperate inbound, outbound, tcp and udp trie structures to separate the directions and rules.
4. longest search time would be in the order of the longest length of IP addresses.
5. for sparse IP address store and loading, the trie structure could be not very balanced and take large memory. 
6. If there is more time for optimization, level-compressed trie, or multi-bit trie could be implemented to continously reduce search time and memory space, according to the papers searched online.

##### Interested teams

The Data Team

The Platform Team