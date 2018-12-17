package coding.assignment;

/**
 * Firewall Interface for Coding Assignment.
 *
 * @author Ying Chen
 * @since 12/15/2018
 * @version 1.0
 */
public interface Firewall {
    /**
     * Constructor, taking a single string argument, which is a file path to a CSV file,
     * in which each line contains exactly four columns: direction, protocol, ports, and IP address,
     * and loading "allow" rules for a host-based firewall.
     * @param path the csv file path.
     * @return an instance of Firewall Implementation class.
     */
    static Firewall create(String path) {
        return new FirewallImpl(path);
    }

    /**
     * Firewall function, takes exactly four arguments and returns a boolean: true,
     * if there exists a rule in the file that this object was initialized with that allows traffic
     * with these particular properties, and false otherwise.
     * @param direction String of "inbound" or "outbound".
     * @param protocol String of "tcp" or "udp".
     * @param port port Integer from 1-65535.
     * @param ip_address String of valid IPv4 address from 0.0.0.0 to 255.255.255.255.
     * @return true if there is a rule in the csv file that allows traffic, and false otherwise.
     */
    boolean accept_packet(String direction, String protocol, int port, String ip_address);
}
