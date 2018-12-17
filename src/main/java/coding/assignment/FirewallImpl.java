package coding.assignment;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Firewall Implementation class implementing Firewall Interface.
 *
 * @author Ying Chen
 * @since 12/17/2018
 * @version 1.0
 */
public class FirewallImpl implements Firewall {

    private String path;
    private AddressNode inboundTCPTrie;
    private AddressNode inboundUDPTrie;
    private AddressNode outboundTCPTrie;
    private AddressNode outboundUDPTrie;

    /**
     * Constructor for the class, takes a csv file path with all the rules initialized.
     * @param path String of the csv file path.
     */
    public FirewallImpl(String path) {
        this.path = path;
        this.inboundTCPTrie = new AddressNode(200, false);
        this.inboundUDPTrie = new AddressNode(200, false);
        this.outboundTCPTrie = new AddressNode(200, false);
        this.outboundUDPTrie = new AddressNode(200, false);
        readFile(path);
    }

    /**
     * Function to read the csv file and load all the rules.
     * @param path String of the csv file.
     */
    private void readFile(String path) {
        try (BufferedReader inputFile = new BufferedReader(
                new InputStreamReader(new FileInputStream(path),
                        Charset.defaultCharset()));) {
            String line;
            while ((line  = inputFile.readLine()) != null) {
                String[] inputs = line.split(",", -1);
                addToAddresses(inputs);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Take all the direction, protocol, port and IP address as inputs and add them into Trie structures.
     * @param inputs the String array of four inputs.
     * @throws UnknownHostException when there is any unknown host.
     */
    private void addToAddresses(String[] inputs) throws UnknownHostException {
        String direction = inputs[0];
        String protocol = inputs[1];
        String port = inputs[2];
        String ipAddress = inputs[3];
        switch (direction) {
            case "inbound":
                if (protocol.equals("tcp")) {
                    readIPAndPort(ipAddress, inboundTCPTrie, port);
                } else {
                    readIPAndPort(ipAddress, inboundUDPTrie, port);
                }
                break;
            case "outbound":
                if (protocol.equals("tcp")) {
                    readIPAndPort(ipAddress, outboundTCPTrie, port);
                } else {
                    readIPAndPort(ipAddress, outboundUDPTrie, port);
                }
                break;
        }
    }

    /**
     * Take IP address and port information and add to the Trie structure.
     * @param readIP the read IP address.
     * @param trie the Trie structure.
     * @param port the read port information.
     * @throws UnknownHostException when there is any unknown host.
     */
    private void readIPAndPort(String readIP, AddressNode trie, String port) throws UnknownHostException {
        if (readIP.indexOf('-') == -1) {
            dealIPToTrie(readIP, trie, port);
        } else {
            String[] ipRange = readIP.split("-", -1);
            long ipLo = ipToLong(InetAddress.getByName(ipRange[0]));
            long ipHi = ipToLong(InetAddress.getByName(ipRange[1]));
            for (long lo = ipLo; lo <= ipHi; lo++) {
                dealIPToTrie(longToIP(lo), trie, port);
            }
        }
    }

    /**
     * Helper function taking a single IP address and port information and add to the Trie.
     * @param ip a single IP address.
     * @param trie the Trie structure.
     * @param port the read port information.
     */
    private void dealIPToTrie(String ip, AddressNode trie, String port) {
        String binaryIP = ipToBinary(ip);
        int i = 0;
        AddressNode curr = trie;
        while (i < binaryIP.length()) {
            int node = binaryIP.charAt(i) - '0';
            if (curr.children[node] == null) {
                curr.children[node] = new AddressNode(node, false);
            }
            curr = curr.getChildren()[node];
            if (i == binaryIP.length() - 1) {
                curr.setEnd(true);
                if (curr.ports == null) {
                    curr.ports = new ArrayList<>();
                }
            }
            i++;
        }
        List<Interval> ports = curr.getPorts();
        mergePort(port, ports);
    }

    /**
     * Helper function taking a String of IP address and convert it into a 32bit binary number in
     * the form of a String.
     * @param ipAddress the given single IP address.
     * @return a String of 32bit binary number.
     */
    private String ipToBinary(String ipAddress) {
        String[] addresses = ipAddress.split("\\.", -1);
        String[] strs = new String[4];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            strs[i] = String.valueOf(Integer.toBinaryString(Integer.parseInt(addresses[i])));
            sb.append(strs[i]);
        }
        return sb.toString();
    }

    /**
     * Helper function taking a InetAddess IP and convert it into a specific long number.
     * Function attributed to StackOverFlow:
     * https://stackoverflow.com/questions/4256438/calculate-whether-an-ip-address-is-in-a-specified-range-in-java
     * @param ip a given InetAddress.
     * @return a long number specifically representing the IP address.
     */
    private long ipToLong(InetAddress ip) {
        byte[] bytes = ip.getAddress();
        long result = 0;
        for (byte octet : bytes) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    /**
     * Helper function taking a long number and convert back to the String of IP address.
     * @param lo a long number.
     * @return a String of valid IP address.
     * @throws UnknownHostException when there is any unknown host.
     */
    private String longToIP(long lo) throws UnknownHostException {
        InetAddress i= InetAddress.getByName(String.valueOf(lo));
        return i.getHostAddress();
    }

    /**
     * Merge a port or a port range into an existing list of port ranges.
     * @param port a given port or a port range.
     * @param ports a list of port intervals.
     */
    private void mergePort(String port, List<Interval> ports) {
        int start;
        int end;
        if (port.indexOf('-') != -1) {
            String[] range = port.split("-");
            start = Integer.parseInt(range[0]);
            end = Integer.parseInt(range[1]);
        } else {
            start = Integer.parseInt(port);
            end = start;
        }
        if (ports.isEmpty()) {
            ports.add(new Interval(start, end));
            return;
        }
        if (ports.contains(new Interval(start, end))) {
            return;
        }
        int index = 0;
        for (int i = 0; i < ports.size(); i++) {
            Interval current = ports.get(i);
            if (i + 1 < ports.size()) {
                if (current.getEnd() >= start - 1) {
                    if (ports.get(i + 1).getStart() > end + 1) {
                        current.setStart(Math.min(start, current.getStart()));
                        current.setEnd(Math.max(end, current.getEnd()));
                        return;
                    } else {
                        index = i;
                        break;
                    }
                } else if (ports.get(i + 1).getStart() > end + 1) {
                    index = i;
                    break;
                }
            } else if (current.getEnd() >= start - 1) {
                current.setStart(Math.min(start, current.getStart()));
                current.setEnd(Math.max(end, current.getEnd()));
                return;
            } else {
                index = i;
            }
        }
        if (index == ports.size() - 1) {
            ports.add(new Interval(start, end));
        } else if (ports.get(index).getEnd() < start - 1 && ports.get(index + 1).getStart() > end + 1) {
            ports.add(index + 1, new Interval(start, end));
        } else {
            Interval deleted = ports.remove(index + 1);
            Interval current = ports.get(index);
            current.setStart(Math.min(start, Math.min(current.getStart(), deleted.getStart())));
            current.setEnd(Math.max(end, Math.max(current.getEnd(), deleted.getEnd())));
        }

    }

    @Override
    public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
        switch (direction) {
            case "inbound":
                if (protocol.equals("tcp")) {
                    return accept_helper(inboundTCPTrie, port, ip_address);
                } else {
                    return accept_helper(inboundUDPTrie, port, ip_address);
                }
            case "outbound":
                if (protocol.equals("tcp")) {
                    return accept_helper(outboundTCPTrie, port, ip_address);
                } else {
                    return accept_helper(outboundUDPTrie, port, ip_address);
                }
        }
        return false;
    }

    /**
     * Helper function to check if the rule allows a traffic.
     * @param trie a designated Trie structure.
     * @param port int of the port information.
     * @param ip_address String of single IPv4 address.
     * @return true if there is a rule in the trie that allows traffic, and false otherwise.
     */
    private boolean accept_helper(AddressNode trie, int port, String ip_address) {
        String binaryIP = ipToBinary(ip_address);
        int i = 0;
        AddressNode curr = trie;
        while (i < binaryIP.length()) {
            int node = binaryIP.charAt(i) - '0';
            if (curr.children[node] == null) {
                return false;
            }
            curr = curr.children[node];
            i++;
        }
        return curr.isEnd() && containsPort(curr.getPorts(), port);
    }

    /**
     * Helper function to check if a given is contains in a given list of port intervals.
     * @param list a given list of port intervals.
     * @param port a given port int to be checked.
     * @return true if the given port in within the range of list.
     */
    private boolean containsPort(List<Interval> list, int port) {
        if (list == null) {
            return false;
        }
        for (int i = 0; i < list.size(); i++) {
            Interval current = list.get(i);
            if (i + 1 < list.size() && port > current.getEnd() && port < list.get(i + 1).getStart()) {
                return false;
            }
            if (port >= current.getStart() && port <= current.getEnd()) {
                return true;
            }
        }
        return false;
    }

    /**
     * The trie node structure to contain the binary information of IP address and ports.
     */
    class AddressNode {
        int address;
        AddressNode[] children;
        boolean isEnd;
        List<Interval> ports;

        /**
         * Constructor, to initiate an AddressNode instance.
         * @param address the given binary address node, 0 or 1.
         * @param isEnd boolean information to check whether it is the end of the IP address.
         */
        private AddressNode(int address, boolean isEnd) {
            this.address = address;
            this.isEnd = isEnd;
            if (isEnd) {
                ports = new ArrayList<>();
            } else {
                children = new AddressNode[2];
            }
        }

        /**
         * Getter to get the address number.
         * @return int of the address number 0 or 1.
         */
        private int getAddress() {
            return address;
        }

        /**
         * Getter to get the children of the next node array.
         * @return an AddressNode array with the length of two.
         */
        private AddressNode[] getChildren() {
            return children;
        }

        /**
         * Getter to check if the address node is in the end.
         * @return true if the address node is the end and false otherwise.
         */
        private boolean isEnd() {
            return isEnd;
        }

        /**
         * Getter to get the list of port ranges for the IP address.
         * @return a list of port intervals.
         */
        private List<Interval> getPorts() {
            return ports;
        }

        /**
         * Setter method to set if it is the end of the address node.
         * @param end the given boolean value.
         */
        private void setEnd(boolean end) {
            isEnd = end;
        }
    }

    /**
     * Port Interval class contains the start to the end of the port range.
     */
    class Interval {
        int start;
        int end;

        /**
         * Constructor to initiate a new instance of Interval.
         * @param start the start port int.
         * @param end the end port int.
         */
        private Interval(int start, int end) {
            this.start = start;
            this.end = end;
        }

        /**
         * Getter to get the start of the Interval.
         * @return an int value of the start.
         */
        private int getStart() {
            return start;
        }

        /**
         * Getter to get the end of the Interval.
         * @return an int value of the end.
         */
        private int getEnd() {
            return end;
        }

        /**
         * Setter to set the start.
         * @param start the given start int.
         */
        private void setStart(int start) {
            this.start = start;
        }

        /**
         * Setter to set the end.
         * @param end the given end int.
         */
        private void setEnd(int end) {
            this.end = end;
        }

    }
}
