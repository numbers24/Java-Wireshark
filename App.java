// App.java
package com.github.username;

import java.util.ArrayList;
import java.io.IOException;
import java.net.Inet4Address;

import com.sun.jna.Platform;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;

class TCP {

	String src_ip;
	String dst_ip;
	
	int src_port;
	int des_port;
	
	boolean syn_c;
	boolean fin_c;
	
	int complete;
	int incomplete;

	float partial;
	float total;

	double start;
	double finish;


	public TCP(String src_ip, String dst_ip, int src_port, int des_port, boolean syn_c, boolean fin_c, int complete, int incomplete, float partial, float total, double start, double finish){
		
		this.src_ip = src_ip;
		this.dst_ip = dst_ip;
		
		this.src_port = src_port;
		this.des_port = des_port;
		
		this.syn_c = syn_c;
		this.fin_c = fin_c;
		
		this.complete = complete;
		this.incomplete = incomplete;

		this.partial = partial;
		this.total = total;

		this.start = start;
		this.finish = finish;

	}
	
	public String getSrc_ip(){return src_ip;}
	public String getdst_ip(){return dst_ip;}

	public int getSrc_port(){return src_port;}
	public int getDes_port(){return des_port;}

	public boolean getSyn_c(){return syn_c;}
	public boolean getFin_c(){return fin_c;}

	public int getComplete(){return complete;}
	public int getIncomplete(){return incomplete;}
	
	public float getPartial(){return partial;}
	public float getTotal(){return total;}

	public double getStart(){return start;}
	public double getFinish(){return finish;}


	
	public void print(){
		double time = (finish-start)/1000000;
		if(!fin_c){
			incomplete+=complete;
			complete=0;
		}
		if(complete==0)
		System.out.println(src_ip + ", " + src_port + ", " + dst_ip + ", " + des_port + ", " + complete + ", " + incomplete);
		else
		System.out.println(src_ip + ", " + src_port + ", " + dst_ip + ", " + des_port + ", " + complete + ", " + incomplete + ", " + total + ", " + partial/time/125000 );
	}
}
public class App {

	static int check_number = 0;
	static int UDP_number = 0;
	static int TCP_number = 0;
	static int ICMP_number=0;
	static int Other_number=0;

	static float total_byte = 0;
	static float UDP_byte=0;
	static float ICMP_byte=0;
	static float Other_byte=0;

	static double first_pack_time = 0;
	static double last_pack_time = 0;
	static boolean first_packet_time= false;
	static boolean last_packet_time=false;
	
	
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        // New code below here
                  
       	final PcapHandle handle;
       	ArrayList<TCP> TCPs = new ArrayList<TCP>();

	handle = Pcaps.openOffline(args[0] );
	
        PacketListener listener = new PacketListener() {
                public void gotPacket(Packet packet) {
									
			if(first_packet_time==false)
			{
			first_pack_time = (double)handle.getTimestamp().getTime();
			first_packet_time=true;
			}
			last_pack_time = (double)handle.getTimestamp().getTime();
              					
			check_number = 1+ check_number;
		 	total_byte = total_byte + (float)packet.length();
			
			TcpPacket tcpPacket = packet.get(TcpPacket.class);
			if(tcpPacket!=null){
				
				

				//ip's
				IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
				String dst_ip = ipV4Packet.getHeader().getDstAddr().getHostAddress();
				String src_ip = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
				
				//ports
				int des_port = tcpPacket.getHeader().getDstPort().valueAsInt();
				int src_port = tcpPacket.getHeader().getSrcPort().valueAsInt();
				
				//timestamps
				double start = 0;
				double finish = 0;

				//flags for counts
				boolean syn_c = tcpPacket.getHeader().getSyn();
				if(syn_c) start=(double)handle.getTimestamp().getTime();
				boolean fin_c = tcpPacket.getHeader().getFin();
				if(fin_c) finish=(double)handle.getTimestamp().getTime();
				int complete = 0;
				int incomplete = 0;

				//bytes sizes
				float bsize = (float)packet.length();
				float partial = 0;
				float total = bsize;
				
				//update TCP list
				boolean exists = false;
				boolean prevfin = false;
				int index=0;
				
				
					

				for(TCP t : TCPs){
					if(t.getSrc_ip().equals(src_ip) && t.getdst_ip().equals(dst_ip) && t.getSrc_port()==src_port && t.getDes_port()==des_port){
						exists=true;
						index=TCPs.indexOf(t);
						
						complete = t.getComplete();
						incomplete = t.getIncomplete();
						
						syn_c = syn_c || t.getSyn_c();
						prevfin = t.getFin_c();
						fin_c = fin_c || prevfin;


						partial += t.getPartial();
						total += t.getTotal();

						if(start==0)
						start=t.getStart();
						if(finish==0)
						finish=t.getFinish();
					}
				}
				
				if((syn_c && !fin_c)||(syn_c && fin_c && !prevfin)){
					partial+=bsize;
					complete++;
				}
				else{
					incomplete++;
				}
				if(exists){
					TCPs.set(index,new TCP(src_ip,dst_ip,src_port,des_port,syn_c,fin_c,complete,incomplete,partial,total,start,finish));
				}
				else{
					TCPs.add(new TCP(src_ip,dst_ip,src_port,des_port,syn_c,fin_c,complete,incomplete,partial,total,start,finish));
				}
				
			}

			else if(packet.get(UdpPacket.class)!=null){
			   UDP_number = UDP_number + 1 ;
			   UDP_byte = UDP_byte + (float)packet.length();
			}
			
			else if(packet.get(IcmpV4CommonPacket.class)!=null){ 
				ICMP_number = ICMP_number + 1;
				ICMP_byte = ICMP_byte + (float)packet.length();
			}
			else{
				Other_number = Other_number + 1;
				Other_byte = Other_byte + (float)packet.length();
			}

						

                }
        };

        try {
		
	            int maxPackets = -1;
	                handle.loop(maxPackets, listener);
	            } catch (InterruptedException e) {
	                e.printStackTrace();
            }			



	double total_time = last_pack_time - first_pack_time;
	total_time = total_time/1000.0;
	
	System.out.println("TCP Summary Table");
	for(TCP t : TCPs){
		t.print();
	}
		System.out.println("\nAdditional Protocols Summary Table");
	
	System.out.println( "UDP, " + UDP_number + ", " + UDP_byte);
	System.out.println( "ICMP, " + ICMP_number + ", " + ICMP_byte);
	System.out.println( "Other, " + Other_number + ", " + Other_byte);
	//System.out.println( "Total bandwidth of the packet trace in Mbps, " + total_byte/total_time/125000.0);

        // Cleanup when complete
        handle.close();
    }
}