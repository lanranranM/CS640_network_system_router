package edu.wisc.cs.sdn.vnet.rt;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;

import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * A cache of MAC address to IP address mappings.
 * @author Aaron Gember-Jacobson
 */
public class ArpCache implements Runnable
{		
	/** Entries in the cache; maps an IP address to an entry */
	private Map<Integer,ArpEntry> entries;
	//melody here
	public Map<Integer, List<WaitingPacket>> waitingPackets;
	private Router router; // link the router to the arpcache
	private Thread timeoutThread;
	//private Map<Integer, boolean> sentWaitingPacket;

	private class WaitingPacket {
		Ethernet etherPacket;
		int count;
		long lastSendTime;
		Iface outIface;
		Iface inIface;
		Ethernet arpRequest; // sending the same request while waiting

		public WaitingPacket (Ethernet etherPacket, Iface outIface, Iface inIface, Ethernet arpRequest) {
			this.etherPacket = etherPacket;
			this.outIface = outIface;
			this.inIface = inIface;
			this.count = 0;
			this.arpRequest = arpRequest;
			this.lastSendTime = System.currentTimeMillis();
		}

		public Ethernet getPacket() { return this.etherPacket; }
		public int getCount() { return this.count; }
		public void incrementCount() { this.count++; }
		public long getLastSendTime() { return this.lastSendTime; }
		public void setLastSendTime(long newTime) { this.lastSendTime = newTime; }
		public Iface getoutIface() { return this.outIface; }
		public Iface getinIface() { return this.inIface; }
		public Ethernet getArpRequest() { return this.arpRequest;}
		@Override
		public WaitingPacket clone() {
			WaitingPacket cloned = new WaitingPacket(this.etherPacket,this.outIface,this.inIface, this.arpRequest);
			// cloned.etherPacket = this.etherPacket;
			// cloned.count = this.count;
			cloned.lastSendTime = this.lastSendTime;
			cloned.outIface = this.outIface;
			//cloned.arpRequest = this.arpRequest;
			return cloned;
		}
	}
	/**
	 * Initializes an empty ARP cache for a router.
	 */
	public ArpCache(Router router) { 
		this.entries = new ConcurrentHashMap<Integer,ArpEntry>(); 
		this.waitingPackets = new ConcurrentHashMap<Integer, List<WaitingPacket>>();
		this.router = router;
		//this.sentWaitingPacket = new ConcurrentHashMap<Integer, boolean>();
		timeoutThread = new Thread(this);
		timeoutThread.start();
	}
	
	/**
	 * Insert an entry in the ARP cache for a specific IP address, MAC address
	 * pair.
	 * @param mac MAC address corresponding to IP address
	 * @param ip IP address corresponding to MAC address
	 */
	public void insert(MACAddress mac, int ip) { 
		this.entries.put(ip, new ArpEntry(mac, ip)); 
	}
	

	public void sendWaitingPacketsForIP(int ip, Iface inIface) {
		//melody: send corresponding ip's packet queue;
		//synchronized (this.waitingPackets) {
			List<WaitingPacket> prepareSendingPackets = this.waitingPackets.remove(ip);
			// if (prepareSendingPackets==null)
			for (WaitingPacket packet: prepareSendingPackets) {
				packet.getPacket().setDestinationMACAddress(this.lookup(ip).getMac().toString());
				System.out.println("*** -> sending waiting packet: " +
                packet.getPacket().toString().replace("\n", "\n\t"));
				this.router.sendPacket(packet.getPacket(), inIface);
			}
		//}
	}

	
	/**
	 * Checks if an IP->MAC mapping is the in the cache.
	 * @param ip IP address whose MAC address is desired
	 * @return the IP->MAC mapping from the cache; null if none exists 
	 */
	public ArpEntry lookup(int ip)
	{ 	
		return this.entries.get(ip); }
	
	/**
	 * Populate the ARP cache from a file.
	 * @param filename name of the file containing the static route table
	 * @param router the route table is associated with
	 * @return true if route table was successfully loaded, otherwise false
	 */
	public boolean load(String filename)
	{
		// Open the file
		BufferedReader reader;
		try 
		{
			FileReader fileReader = new FileReader(filename);
			reader = new BufferedReader(fileReader);
		}
		catch (FileNotFoundException e) 
		{
			System.err.println(e.toString());
			return false;
		}
		
		while (true)
		{
			// Read an ARP entry from the file
			String line = null;
			try 
			{ line = reader.readLine(); }
			catch (IOException e) 
			{
				System.err.println(e.toString());
				try { reader.close(); } catch (IOException f) {};
				return false;
			}
			
			// Stop if we have reached the end of the file
			if (null == line)
			{ break; }
			
			// Parse fields for ARP entry
			String ipPattern = "(\\d+\\.\\d+\\.\\d+\\.\\d+)";
			String macByte = "[a-fA-F0-9]{2}";
			String macPattern = "("+macByte+":"+macByte+":"+macByte
					+":"+macByte+":"+macByte+":"+macByte+")";
			Pattern pattern = Pattern.compile(String.format(
                        "%s\\s+%s", ipPattern, macPattern));
			Matcher matcher = pattern.matcher(line);
			if (!matcher.matches() || matcher.groupCount() != 2)
			{
				System.err.println("Invalid entry in ARP cache file");
				try { reader.close(); } catch (IOException f) {};
				return false;
			}

			int ip = IPv4.toIPv4Address(matcher.group(1));
			if (0 == ip)
			{
				System.err.println("Error loading ARP cache, cannot convert "
						+ matcher.group(1) + " to valid IP");
				try { reader.close(); } catch (IOException f) {};
				return false;
			}
			
			MACAddress mac = null;
			try
			{ mac = MACAddress.valueOf(matcher.group(2)); }
			catch(IllegalArgumentException iae)
			{
				System.err.println("Error loading ARP cache, cannot convert " 
						+ matcher.group(3) + " to valid MAC");
				try { reader.close(); } catch (IOException f) {};
				return false;
			}
			
			// Add an entry to the ACP cache
			this.insert(mac, ip);
		}
	
		// Close the file
		try { reader.close(); } catch (IOException f) {};
		return true;
	}
	
	public String toString()
	{
        String result = "IP\t\tMAC\n";
        for (ArpEntry entry : this.entries.values())
        { result += entry.toString()+"\n"; }
	    return result;
	}

	/**
	 * add the packet to the queue of waiting packets
	 * @param etherPacket packet waiting for the MAC for it's next hop IP
	 * @param outIface the interface that router sent this packet.
	 * @param ip the IP address that needs a mac
	 * @param arpRequest the same arp request send repeatdly for 3 times
	 */
	public void enqueuePacket(Ethernet etherPacket, Iface outIface, Iface inIface, int ip, Ethernet arpRequest) {
		if (waitingPackets.containsKey(ip)) {
			List<WaitingPacket> packetsQueue = this.waitingPackets.get(ip);
			WaitingPacket newPacket = new WaitingPacket(etherPacket, outIface, inIface, arpRequest);
			packetsQueue.add(newPacket);
		} else {
			List<WaitingPacket> packetsQueue = new ArrayList<> (Arrays.asList(new WaitingPacket(etherPacket, outIface, inIface, arpRequest)));
			this.waitingPackets.put(ip,packetsQueue);
		}
		// debug
		// System.out.println("waitingPacket");
		// this.waitingPackets.entrySet().forEach(entry -> {
		// 	System.out.println(IPv4.fromIPv4Address(entry.getKey()) + " " + entry.getValue().size());
		// 	// entry.getValue().forEach(e -> {System.out.print(e.toString() + " ");});
			
		// });
		// debug
	}

	/**
	 * Every seconds, generate the arp reply. check the expired packet.
	 * added the recieved-reply packet. 
	 */
	public void run()
	{
		while (true)
		{
			// Run every second
			try 
			{ Thread.sleep(1000); }
			catch (InterruptedException e) 
			{ break; }
			boolean remove = false;
			List <WaitingPacket> prepareToDeleteQueue = new ArrayList<WaitingPacket>();
			int prepareToDeleteIP = -1;
			// send arp request
			for (Map.Entry<Integer,List<WaitingPacket>> entry: this.waitingPackets.entrySet())
			{	
				// iterate the queue
				List <WaitingPacket> currentQueue = entry.getValue();
				for (Iterator<WaitingPacket> iterator = currentQueue.iterator(); iterator.hasNext();) { //WaitingPacket currentPacket: currentQueue
					WaitingPacket currentPacket = iterator.next();
					// if last time send request < 1s, do nothing
					if (System.currentTimeMillis() - currentPacket.getLastSendTime() < 1000) {continue;}
					// else check count, if <3, send another same request
					if (currentPacket.getCount() < 3) {
						System.out.println("sending arp request " + currentPacket.getCount() + "at iface: " + currentPacket.getoutIface().toString() );
						// System.out
						// 	.println("*** -> sending arp packet: " + currentPacket.getArpRequest().toString().replace("\n", "\n\t"));
						this.router.sendPacket(currentPacket.getArpRequest(), currentPacket.getoutIface());
						currentPacket.incrementCount();
						currentPacket.setLastSendTime(System.currentTimeMillis());
					} else {
						remove = true;
						// create a deepcody of the modification list
						for (WaitingPacket packet: currentQueue) {
							prepareToDeleteQueue.add(packet.clone());
						}
						prepareToDeleteIP = entry.getKey();
						break;
					}
				}
			}
			if(remove) {
				synchronized(this.waitingPackets){
					// send icmp to the pre-deleted packets
					// removed the queue
					//System.out.println("pre-del " + IPv4.fromIPv4Address(prepareToDeleteIP));
					this.waitingPackets.remove(prepareToDeleteIP); 
					for (Iterator<WaitingPacket> iterator = prepareToDeleteQueue.iterator(); iterator.hasNext();) {
						WaitingPacket currentPacket = iterator.next();
						this.router.handleICMP(currentPacket.getPacket(),currentPacket.getinIface(), 3, 1);
					}
					remove = false;
					prepareToDeleteQueue = null;
					prepareToDeleteIP = -1;
				}
			}
		}
	}
}
