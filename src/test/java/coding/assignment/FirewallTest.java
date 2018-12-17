package coding.assignment;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Firewall unit tester.
 *
 * @author Ying Chen
 * @since 12/15/2018
 * @version 1.0
 */
public class FirewallTest {

    Firewall firewall;

    @Before
    public void setUp() throws Exception {
        firewall = Firewall.create("test.csv");
    }

    @Test
    public void test_accept_packet_directionFalse() {
        Assert.assertFalse(firewall.accept_packet("outbound", "tcp", 80, "192.168.1.2"));
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 10000, "192.168.10.11"));
    }

    @Test
    public void test_accept_packet_protocolFalse() {
        Assert.assertFalse(firewall.accept_packet("outbound", "tcp", 1000, "192.168.48.92"));
        Assert.assertFalse(firewall.accept_packet("inbound", "udp", 8080, "255.255.255.1"));
    }

    @Test
    public void test_accept_packet_ipAddressFalse() {
        Assert.assertFalse(firewall.accept_packet("outbound", "udp", 500, "52.12.48.91"));
        Assert.assertFalse(firewall.accept_packet("outbound", "udp", 500, "52.12.48.96"));
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 80, "0.0.0.1"));
        Assert.assertFalse(firewall.accept_packet("outbound", "tcp", 65535, "0.0.0.0"));
        Assert.assertFalse(firewall.accept_packet("outbound", "tcp", 65535, "0.0.1.0"));
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 8000, "245.255.255.255"));
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 8080, "255.255.245.255"));
    }

    @Test
    public void test_accept_packet_portFalse() {
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
        Assert.assertFalse(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"));
        Assert.assertFalse(firewall.accept_packet("inbound", "udp", 499, "52.12.48.95"));
        Assert.assertFalse(firewall.accept_packet("outbound", "tcp", 20001, "192.168.10.11"));
        Assert.assertFalse(firewall.accept_packet("inbound", "tcp", 5001, "0.0.0.0"));
    }

    @Test
    public void test_accept_packet_true() {
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
        Assert.assertTrue(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        Assert.assertTrue(firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
        Assert.assertTrue(firewall.accept_packet("outbound", "tcp", 30000, "192.168.10.10"));
        Assert.assertTrue(firewall.accept_packet("outbound", "tcp", 20002, "192.168.10.20"));
        Assert.assertTrue(firewall.accept_packet("outbound", "udp", 999, "52.12.48.92"));
        Assert.assertTrue(firewall.accept_packet("outbound", "udp", 1500, "52.12.48.92"));
        Assert.assertTrue(firewall.accept_packet("outbound", "udp", 3000, "52.12.48.95"));
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 80, "0.0.0.0"));
        Assert.assertTrue(firewall.accept_packet("inbound", "udp", 1, "0.0.0.0"));
        Assert.assertTrue(firewall.accept_packet("outbound", "tcp", 65535, "0.0.0.255"));
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 60001, "0.255.0.1"));
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 65535, "0.255.255.255"));
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 8080, "255.255.255.0"));
        Assert.assertTrue(firewall.accept_packet("inbound", "tcp", 8080, "255.255.255.255"));
    }
}