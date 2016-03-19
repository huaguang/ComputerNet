import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URL;
import java.util.Arrays;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
public class MyJpcap {
 public static void main(String[] args) throws Exception {
  args = new String[2];
  
  //tracert 180.97.33.108		//追踪百度
  args[0]="2";		//本机有四块虚拟网卡，可用的为第二块
  args[1]="www.baidu.com";
  
 /* if (args.length < 2) {
   System.out.println("Usage: java Traceroute <device index (e.g., 0, 1..)> <target host address>");
   System.exit(0);
  } // initialize Jpcap
*/  
  //1.获取网卡实例
  NetworkInterface device = JpcapCaptor.getDeviceList()[Integer.parseInt(args[0])];
  //2.打开网卡实例
  JpcapCaptor captor = JpcapCaptor.openDevice(device, 2000, false, 8000);
  InetAddress thisIP = null;
  //InetAddress desIp=null;
  //desIp=Inet4Address.getByName("www.baidu.com");
  //3、获取本网卡IPV4的地址
  for (NetworkInterfaceAddress addr : device.addresses)
   if (addr.address instanceof Inet4Address) {
    thisIP = addr.address;
    break;
   }
  // obtain MAC address of the default gateway
  InetAddress pingAddr = InetAddress.getByName(args[1]);
  captor.setFilter("tcp and dst host " + pingAddr.getHostAddress(), true);
  byte[] gwmac = null;
  while (true) {
   new URL("http://"+args[1]).openStream().close();
   Packet ping = captor.getPacket();
   if (ping == null) {
    System.out
      .println("cannot obtain MAC address of default gateway.");
    System.exit(-1);
   } else if (Arrays.equals(((EthernetPacket) ping.datalink).dst_mac,
     device.mac_address))
    continue;
   gwmac = ((EthernetPacket) ping.datalink).dst_mac;
   break;
  }
  // create ICMP packet
  ICMPPacket icmp = new ICMPPacket();
  icmp.type = ICMPPacket.ICMP_ECHO;
  icmp.seq = 100;
  icmp.id = 0;
  icmp.setIPv4Parameter(0, false, false, false, 0, false, false, false,
    0, 0, 0, IPPacket.IPPROTO_ICMP, thisIP,InetAddress.getByName(args[1]));
  icmp.data = "data".getBytes();
  EthernetPacket ether = new EthernetPacket();
  ether.frametype = EthernetPacket.ETHERTYPE_IP;
  ether.src_mac = device.mac_address;
  ether.dst_mac = gwmac;
  icmp.datalink = ether;
  icmp.hop_limit=1;
  captor.setFilter("icmp and dst host " + thisIP.getHostAddress(), true);
  JpcapSender sender = captor.getJpcapSenderInstance(); // JpcapSender
                // sender=JpcapSender.openDevice(device);
  sender.sendPacket(icmp);
  System.out.println("dstIp"+icmp.dst_ip+"\tsrcIp:"+icmp.src_ip);
  while (true) {
   ICMPPacket p = (ICMPPacket) captor.getPacket(); // System.out.println("received "+p);
   if (p == null) {
    System.out.println(icmp.hop_limit+++":Timeout");
   } else if (p.type == ICMPPacket.ICMP_TIMXCEED) {
    System.out.println(icmp.hop_limit + "(超时): " + p.src_ip);
    icmp.hop_limit++;
   } else if (p.type == ICMPPacket.ICMP_UNREACH) {
    System.out.println(icmp.hop_limit + "(不可达): " + p.src_ip);
    System.exit(0);
   } else if (p.type == ICMPPacket.ICMP_ECHOREPLY) {
    System.out.println(icmp.hop_limit + "(回复): " + p.src_ip);
    System.exit(0);
   } else
    continue;
   sender.sendPacket(icmp);
  }
 }
}


/*4(超时): /192.168.188.1
5(超时): /218.2.182.33
6(超时): /218.2.182.33
7(超时): /218.2.182.33
8(超时): /218.2.249.9
9(超时): /58.213.51.33
10(超时): /202.102.69.238
11(超时): /202.102.69.238
12(超时): /218.2.182.33
13(超时): /202.102.69.238
14(超时): /180.97.32.74
15(回复): /180.97.33.107*/


/*import java.net.InetAddress;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;

public class MyJpcap
{
	public static void main(String[] args) throws java.io.IOException{
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		if(args.length<1){
			System.out.println("Usage: java SentICMP <device index (e.g., 0, 1..)>");
			for(int i=0;i<devices.length;i++)
				System.out.println(i+":"+devices[i].name+"("+devices[i].description+")");
			System.exit(0);
		}
		int index=Integer.parseInt(args[0]);
		JpcapSender sender=JpcapSender.openDevice(devices[index]);

		ICMPPacket p=new ICMPPacket();
		p.type=ICMPPacket.ICMP_TSTAMP;
		p.seq=1000;
		p.id=999;
		p.orig_timestamp=123;
		p.trans_timestamp=456;
		p.recv_timestamp=789;
		p.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,IPPacket.IPPROTO_ICMP,
			InetAddress.getByName("www.yahoo.com"),InetAddress.getByName("www.amazon.com"));
		p.data="data".getBytes();

		EthernetPacket ether=new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_IP;
		ether.src_mac=new byte[]{(byte)0,(byte)1,(byte)2,(byte)3,(byte)4,(byte)5};
		ether.dst_mac=new byte[]{(byte)0,(byte)6,(byte)7,(byte)8,(byte)9,(byte)10};
		p.datalink=ether;

		//for(int i=0;i<10;i++)
			sender.sendPacket(p);
	}
	
}*/