package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.util.Arrays;
import java.util.List;
import java.nio.ByteBuffer;
import java.util.LinkedList;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	// ICMP Message
	public static final String ICMP_TIME_EXCEEDED = "Time exceeded.";
	public static final String ICMP_DESTINATION_NET_UNREACHABLE = "Destination net unreachable.";
	public static final String ICMP_DESTINATION_HOST_UNREACHABLE = "Destination host unreachable.";
	public static final String ICMP_DESTINATION_PORT_UNREACHABLE = "Destination port unreachable.";

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache(this);
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			if (ipPacket.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9") && ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
				UDP udpPacket = (UDP) ipPacket.getPayload();
				short udpDestinationPort = udpPacket.getDestinationPort();
				if (udpDestinationPort == UDP.RIP_PORT) {
					this.handleRipPacket(etherPacket, inIface, ((RIPv2)udpPacket.getPayload()).getCommand());
					break;
				}
			}
			this.handleIpPacket(etherPacket, inIface);
			break;
		case Ethernet.TYPE_ARP:
			ARP arpPacket = (ARP)etherPacket.getPayload();
			this.handleArpPacket(etherPacket, inIface, arpPacket.getOpCode());
			break;
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handling IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        { 
			System.out.println(ICMP_TIME_EXCEEDED);
			this.handleICMP(etherPacket,inIface,11,0);
			return; 
		}
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				byte protocol = ipPacket.getProtocol();
				if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
					System.out.println(ICMP_DESTINATION_PORT_UNREACHABLE);
					this.handleICMP(etherPacket,inIface,3,3);
				}
				// check if it's the ping echo request
				if (protocol == IPv4.PROTOCOL_ICMP && 
							((ICMP) ipPacket.getPayload()).getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
					System.out.println("echo reply");
					this.handleICMP(etherPacket,inIface,0,0);
				}
				return;
			}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forwarding IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch) {
			System.out.println(ICMP_DESTINATION_NET_UNREACHABLE);
			this.handleICMP(etherPacket,inIface,3,0);
			return;
		}

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) {
			// System.out.println(ICMP_DESTINATION_HOST_UNREACHABLE);
			// this.handleICMP(etherPacket,inIface,3,1);
			// enqueue the packet and generate an ARP requet
			Ethernet ether = this.generateArpPacket(etherPacket,inIface,true);
			this.arpCache.enqueuePacket(etherPacket, outIface, inIface, nextHop, ether);
			this.sendPacket(ether,outIface);
			return;
		}
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
	
	/**
	 * helper method to construct and send the ICMP 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 * @param type THE type of icmp message
	 * @param code THE code of icmp message
	 */
	 public void handleICMP(Ethernet etherPacket, Iface inIface, int type, int code){
		System.out.println("handleing ICMP");
		boolean arpMiss = false;
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		// set the ethernet header
		ether.setEtherType(Ethernet.TYPE_IPv4);
		// get the mac address of the outinterface by looking up the routeTable
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();
		int srcAddr = ipPacket.getSourceAddress();
		ether.setSourceMACAddress(this.routeTable.lookup(srcAddr).getInterface().getMacAddress().toBytes());
		int nextHop = 0;
		if (type != 3) nextHop = this.routeTable.lookup(dstAddr).getGatewayAddress();
		if (nextHop == 0) nextHop = srcAddr;
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if(arpEntry == null) {
			arpMiss = true;
			//ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		} else {
			ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		}
		// set the IP header
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(srcAddr);
		// set the ICMP header based on type
		icmp.setIcmpType((byte)type);
		icmp.setIcmpCode((byte)code);
		// set the payload
		byte[] payload = new byte[4+ipPacket.getHeaderLength()*4+8];
		byte[] serializedIPv4Packet = ipPacket.serialize();
		for (int i = 0; i<ipPacket.getHeaderLength()*4+8; i++) {
			payload[i+4] = serializedIPv4Packet[i];
		}
		data.setData(payload);
		// echo reply
		if (type == 0) {
			ip.setSourceAddress(ipPacket.getDestinationAddress());
			data.setData(ipPacket.getPayload().serialize());
		}
		// construct the packet
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);
		if (arpMiss) {
			Ethernet arpPacket = this.generateArpPacket(ether,inIface,true);
			//((ARP)arpPacket.getPayload()).setTargetProtocolAddress(nextHop);
			System.out.println(arpPacket.toString().replace("\n", "\n\t"));
			this.arpCache.enqueuePacket(ether, inIface, inIface, nextHop, arpPacket);
			this.sendPacket(arpPacket,inIface);
			return;
		}
		// forward the icmp packet
		this.sendPacket(ether,this.routeTable.lookup(srcAddr).getInterface());//
	 	System.out.println("*** -> ICMP packet: " +
                ether.toString().replace("\n", "\n\t"));
	 }

	/**
	 * helper method to handle the ARP request or reply
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 * @param type if the received packet is a request or reply.
	 */
	 private void handleArpPacket (Ethernet etherPacket, Iface inIface, short type) {
		// check the packet type
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP) { return; }
		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		if (type == ARP.OP_REQUEST) {
			// check the packet address 
			if (targetIp != inIface.getIpAddress()) {
				System.out.println("The ARP's ip isn't the interface's ip");
				return;
			}
			// construct an ARP reply
			Ethernet ether = this.generateArpPacket(etherPacket,inIface,false);
			// send ARP reply to the same interfece of received packet
			this.sendPacket(ether, inIface);
			System.out.println("Sending an ARP reply");
	 		System.out.println("*** -> ARP packet: " +
                ether.toString().replace("\n", "\n\t"));
			return;
		} else if (type == ARP.OP_REPLY) {
			synchronized(this.arpCache.waitingPackets){
				// update ARP cache, insert <sender's mac, sender's ip>
				//System.out.println("populating the ARP cache based on the reply");
				int receivedIP = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
				this.arpCache.insert(new MACAddress(arpPacket.getSenderHardwareAddress()),receivedIP);
				this.arpCache.sendWaitingPacketsForIP(receivedIP, inIface);
				System.out.println("Loaded changed ARP cache");
				System.out.println("----------------------------------");
				System.out.print(this.arpCache.toString());
				System.out.println("----------------------------------");
			}

		}
	 }

	/**
	 * helper method to construct the ARP packet. The packet is a reply by default.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 * @param request if the received packet is a request.
	 */
	 public Ethernet generateArpPacket (Ethernet etherPacket, Iface inIface, boolean request) {
		// construct an ARP reply
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

		ARP arpFields = new ARP();
		arpFields.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpFields.setProtocolType(ARP.PROTO_TYPE_IP);
		arpFields.setHardwareAddressLength((byte)Ethernet.DATALAYER_ADDRESS_LENGTH);
		arpFields.setProtocolAddressLength((byte)4);
		arpFields.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arpFields.setSenderProtocolAddress(inIface.getIpAddress());
		if (request){
			System.out.println("Generating an arp request.");
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			arpFields.setOpCode(ARP.OP_REQUEST);
			arpFields.setTargetHardwareAddress(new byte[Ethernet.DATALAYER_ADDRESS_LENGTH]);
			// ip of the mac we want. gateway
			int ipAddr = 0;
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			int dstAddr = ipPacket.getDestinationAddress();
			ipAddr = this.routeTable.lookup(dstAddr).getGatewayAddress();
			if (ipAddr==0) {ipAddr = dstAddr;}
			arpFields.setTargetProtocolAddress(ipAddr);
		} else {
			System.out.println("Generating an arp reply.");
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
			ARP arpPacket = (ARP)etherPacket.getPayload();
			arpFields.setOpCode(ARP.OP_REPLY);
			arpFields.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
			arpFields.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
		}
		ether.setPayload(arpFields);
		// System.out
		// 		.println("*** -> constructed arp packet: " + ether.toString().replace("\n", "\n\t"));
		return ether;
	 }



	/**
	 * rip starter. The method started when
	 */
	 public void startRip() {
		//System.out.println("!!! RIP START !!!");
		// initilize the routable with directly connected reachable subnets
		for (Iface iface: this.interfaces.values()){
			this.getRouteTable().insert(iface.getIpAddress() & iface.getSubnetMask(), 0, iface.getSubnetMask(), iface);
		}
		System.out.println("Loaded initilized route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
		//sending out rip request to all interfaces
		for (Iface iface: this.interfaces.values()){
			Ethernet etherPacket = this.generateRipPacket(null, iface, 0);
			this.sendPacket(etherPacket, iface);
		}
	
		RIPSender ripSender = new RIPSender(this);
		RIPTimer ripTimer = new RIPTimer(this);
	 }

	/**
	 * helper method to construct the RIP packet.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 * @param type if the generated packet is a request (0), a response (1), or an unsolicited response (2)
	 */
	private Ethernet generateRipPacket(Ethernet etherPacket, Iface inface, int type) {
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		UDP udp = new UDP();
		RIPv2 rip = new RIPv2();

		ether.setSourceMACAddress(inface.getMacAddress().toBytes());
		ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ip.setTtl((byte)15);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(inface.getIpAddress());
		ip.setDestinationAddress("224.0.0.9");
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		if(type == 0) {
			System.out.print("*** -> constructed rip request packet: " );
			rip.setCommand(RIPv2.COMMAND_REQUEST);
		} else if (type ==1) {
			System.out.print("*** -> constructed rip response packet: " );
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			ether.setDestinationMACAddress(etherPacket.getSourceMACAddress()); //interface'ip that send the request packet
			ip.setDestinationAddress(ipPacket.getSourceAddress()); //interface'ip that send the request packet
		} 
		// routing distance vector
		// send a list of routers which can be reached via this router
		List<RIPv2Entry> riPv2Entries = new LinkedList<RIPv2Entry>();
		synchronized(this.getRouteTable().getEntries()) {
			for (RouteEntry routeEntry: this.getRouteTable().getEntries()){
				RIPv2Entry ripEntry = new RIPv2Entry(routeEntry.getDestinationAddress(), routeEntry.getMaskAddress(), routeEntry.getCost());
				riPv2Entries.add(ripEntry);
			}
			
		}
		
		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);
		rip.setEntries(riPv2Entries);
		System.out.println(ether.toString().replace("\n", "\n\t"));
		return ether;
	}

	/**
	 * helper method to handle recieved rip packet
	 * @param ethernetPacket received packet
	 * @param inIface received interface
	 * @param ripCommand if it's a request or repsonse
	 */
	public void handleRipPacket(Ethernet ethernetPacket, Iface inIface, byte ripCommand) {
		switch(ripCommand) {
			case RIPv2.COMMAND_REQUEST:
				// send a response back to source with all entries in the route table
				System.out.println("reived RIP request, sending response.");
				Ethernet ether = this.generateRipPacket(ethernetPacket, inIface, 1);
				this.sendPacket(ether, inIface);
				break;
			case RIPv2.COMMAND_RESPONSE:
				// update the route table
				// if route entries update
				// broadcast rip response to all directedly connected neighbors. 
				System.out.println("reived RIP response, updating route table and sending response.");
				IPv4 ipPacket = (IPv4)ethernetPacket.getPayload();
				UDP udpPacket = (UDP) ipPacket.getPayload();
				RIPv2 rip = (RIPv2)udpPacket.getPayload();
				List<RIPv2Entry> ripEntries = rip.getEntries();
				for (RIPv2Entry ripEntry: ripEntries) {
					//router/node address, cost, nexthop
					int nodeAddr = ripEntry.getAddress() & ripEntry.getSubnetMask();
					synchronized(this.getRouteTable()){
						RouteEntry oldRouteEntry = this.getRouteTable().find(nodeAddr,ripEntry.getSubnetMask());
						if (oldRouteEntry == null) {
							this.getRouteTable().insert(ripEntry.getAddress(), 
								ipPacket.getSourceAddress(), 
								ripEntry.getSubnetMask(), 
								inIface,
								ripEntry.getMetric()+1,
								System.currentTimeMillis());
							for (Iface iface: this.interfaces.values()) {
								Ethernet ripUnsoResponse = this.generateRipPacket(null, iface, 2);
								this.sendPacket(ripUnsoResponse, iface);
							}
							// System.out.println("Loaded changed route table");
							// System.out.println("-------------------------------------------------");
							// System.out.print(this.getRouteTable().toString());
							// System.out.println("-------------------------------------------------");
						} else {
							if (oldRouteEntry.getCost() > ripEntry.getMetric()+1) {
								this.getRouteTable().update(ripEntry.getAddress(), 
									ripEntry.getSubnetMask(), 
									ipPacket.getSourceAddress(), 
									inIface,
									ripEntry.getMetric()+1,
									System.currentTimeMillis());
								for (Iface iface: this.interfaces.values()) {
									Ethernet ripUnsoResponse = this.generateRipPacket(null, iface, 2);
									this.sendPacket(ripUnsoResponse, iface);
								}
								// System.out.println("Loaded changed route table");
								// System.out.println("-------------------------------------------------");
								// System.out.print(this.getRouteTable().toString());
								// System.out.println("-------------------------------------------------");
							}
						}
					}
				}	
			 	break;
		}
	}

	 /*
	  * A thread keep sending unsolicited rip response
	  */
	 public class RIPSender implements Runnable{
		private Router router;
		private Thread taskThread;
		public RIPSender(Router router) {
			this.router = router;
			this.taskThread = new Thread(this);
			taskThread.start();
		}

		private Ethernet unsolicitedRipResponse(Iface inface) {
			Ethernet ether = new Ethernet();
			IPv4 ip = new IPv4();
			UDP udp = new UDP();
			RIPv2 rip = new RIPv2();

			ether.setSourceMACAddress(inface.getMacAddress().toBytes());
			ether.setDestinationMACAddress("ff:ff:ff:ff:ff:ff");
			ether.setEtherType(Ethernet.TYPE_IPv4);
			ip.setTtl((byte)15);
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ip.setSourceAddress(inface.getIpAddress());
			ip.setDestinationAddress("224.0.0.9");
			udp.setSourcePort(UDP.RIP_PORT);
			udp.setDestinationPort(UDP.RIP_PORT);
			rip.setCommand(RIPv2.COMMAND_RESPONSE);
			// routing distance vector
			// send a list of routers which can be reached via this router
			List<RIPv2Entry> riPv2Entries = new LinkedList<RIPv2Entry>();
			synchronized(this.router.getRouteTable().getEntries()) {
				for (RouteEntry routeEntry: this.router.getRouteTable().getEntries()){
					RIPv2Entry ripEntry = new RIPv2Entry(routeEntry.getDestinationAddress(), routeEntry.getMaskAddress(), routeEntry.getCost());
					riPv2Entries.add(ripEntry);
				}
				
			}
			
			ether.setPayload(ip);
			ip.setPayload(udp);
			udp.setPayload(rip);
			rip.setEntries(riPv2Entries);
			//System.out.println("*** -> constructed unso-rip packet: " + ether.toString().replace("\n", "\n\t"));
			return ether;
		}

		public void run() {
			while (true) {
				// Run every second
				long time1 = System.currentTimeMillis();
				try 
				{ Thread.sleep(10000); }
				catch (InterruptedException e) 
				{ break; }
				// send an unsolicited RIP response to all router's interfaces every 10 secs
				for (Iface iface: this.router.getInterfaces().values()) {
					System.out.println("sending unso-rip at interface: " + iface.getName());
					Ethernet ethernetPacket = this.unsolicitedRipResponse(iface);
					this.router.sendPacket(ethernetPacket, iface);
				}
			}
		}
	 }

	 /*
	  * A thread keep timing out expired route table entries
	  */
	 public class RIPTimer implements Runnable{
		private Router router;
		private Thread taskThread;
		public RIPTimer(Router router) {
			this.router = router;
			this.taskThread = new Thread(this);
			taskThread.start();
		}

		public void run() {
			while (true) {
				// Run every second
				try 
				{ Thread.sleep(1000); }
				catch (InterruptedException e) 
				{ break; }
				// Time out route table entries for which an update has not been received for more than 30 seconds.
				// in iterating, timed out: set cost = -1. After iterating, removed cost = -1
				boolean needRemove = false;
				for (RouteEntry entry: this.router.getRouteTable().getEntries()) {
					if (entry.getCost() > 1 && (System.currentTimeMillis() - entry.getLastUpdatedTime()) >= 30*1000) {
						entry.setCost(-1);
						needRemove = true;
						//System.out.println("in timeout " + IPv4.fromIPv4Address(entry.getDestinationAddress()) +" "+ (System.currentTimeMillis() - entry.getLastUpdatedTime())/1000);
					}
				}
				if(needRemove){
					synchronized(this.router.getRouteTable()){
						this.router.getRouteTable().getEntries().removeIf(entry -> entry.getCost()== -1);
						// System.out.println("Loaded timedOut route table");
						// System.out.println("-------------------------------------------------");
						// System.out.print(this.router.getRouteTable().toString());
						// System.out.println("-------------------------------------------------");					
					}
				}
			}
		}
	 }
}