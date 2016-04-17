import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.GregorianCalendar;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;

public class TraceRouter implements Runnable{

	public TraceRouter() throws IOException {
		int nisIndex;
		NetworkInterface[] nis=JpcapCaptor.getDeviceList();	//获取所有网卡设备
		if((nisIndex=chooseNIC(nis))==0){		//如果网卡数量为0,则退出程序。
			System.out.println("没有网卡");
			Main.receiveMessage("没有网卡");
			System.exit(1);
		}
		//获取网卡设备实例
		captor=JpcapCaptor.openDevice(nis[nisIndex],2000,true,8000);//(intrface, snaplen, promisc, to_ms)(nis[i]);
		for(NetworkInterfaceAddress addr:nis[nisIndex].addresses){
			if(addr.address instanceof Inet4Address){
				localAddr=addr.address;
				break;
			}
		}
		//根据网卡实例，获取MAC地址
		localMac=nis[nisIndex].mac_address;
		//获取发送数据包工具实例。
		sender=captor.getJpcapSenderInstance();
	}
	//从多个网卡设备中，判断哪一个网卡为物理网卡。
	int chooseNIC(NetworkInterface [] nis){
	/*	
		for(int i=0;i<nis.length;i++)
		{
			System.out.println(i);
		}
		*/
	/*
	    if(nis.length>0){
		for(int i=0;i<nis.length;i++){
			if(nis[i].description.contains("Ethernet Controller"))
				return i;
		}
	}
	return 0;*/

		return 2;
		
			}
	
	//获取目标主机MAC地址。
	public boolean setRemoteMac()
	{
		int i=0;
		try {
			captor.setFilter("tcp and dst host " + remoteAddr.getHostAddress(), true);
			 while (true) {
				   new URL("http://"+this.hostName).openStream().close();
				   Packet p = captor.getPacket();
				   if (p == null) {
				    System.out.println("cannot obtain MAC address of default gateway.");
				   // System.exit(-1);
				    if(i==5)
				    	return false;
				    else{
				    	i++;
				    	continue;
				   }
				   } else if (Arrays.equals(((EthernetPacket) p.datalink).dst_mac,this.localMac)){
					   i++;
					   continue;
				   }
					  
				   this.remoteMac = ((EthernetPacket) p.datalink).dst_mac;
				   break;
				  }
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}
	//从参数目标主机名，获取其IP地址
	public boolean setRemoteAddr(String host)
	{
		this.hostName=host;
		InetAddress remote=null;
		try {
			remote=InetAddress.getByName(host);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("获取远端网络地址失败");
			//System.exit(1);
			return false;
		}
		setRemoteAddr(remote);
		return true;
	}
	//初始化将要发送的包，发送的包为ICMP的ECHO类型包。
	public void initICMPPacket()
	{
		this.icmp=new ICMPPacket();
		icmp.type = ICMPPacket.ICMP_ECHO;	//ICMP类别码,请求回显
		icmp.seq = 100;
		icmp.id = 0;//Identifier.
		//
		icmp.setIPv4Parameter(0, false, false, false, 0, false, false, false, 0, 0, 0, IPPacket.IPPROTO_ICMP, localAddr,remoteAddr);
		icmp.data = "data".getBytes();
		EthernetPacket ether = new EthernetPacket();
		ether.frametype = EthernetPacket.ETHERTYPE_IP;
		ether.src_mac = this.localMac;
		ether.dst_mac = this.remoteMac;
		icmp.datalink = ether;
		try {
			//设置抓包过滤器，只抓类型为ICMP，目的地址为本机的包。
			captor.setFilter("icmp and dst host " + localAddr.getHostAddress(), true);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("过滤器设置失败");
		}
	}
	//主要过程，发送ICMP包。
	public String sendICMP(int ttl)
	{
		//将要返回的消息，包括三个时间ms，一个IP地址
		String str="";
		this.icmp.hop_limit=(short) ttl;
		//记录发包时间。
		long second=0;
		long millSecond=new GregorianCalendar().getTimeInMillis();
		//发送三个包。
		sender.sendPacket(icmp);
		sender.sendPacket(icmp);
		sender.sendPacket(icmp);
		ICMPPacket p = null;
		String ip=null;
		//boolean unreach=false;	//收到不可达包
		boolean reply=false;	//收到回复包。
		int nullAll=0;			//三个包都没有抓到。
		for(int i=0;i<3;i++)
		{
			//抓包并分析。
			/*dispatchPacket	@Deprecated
			public int dispatchPacket(int count,PacketReceiver handler)*/
			p = (ICMPPacket) captor.getPacket();
			if (p == null) {	//超时，未捕获到。
				str+="*\t";
				nullAll++;
			} else if (p.type == ICMPPacket.ICMP_TIMXCEED) {	//正常捕获，为ttl到0后被抛弃的返回信息的包。
				str+=String.valueOf(p.sec*1000+p.usec/1000-second*1000-millSecond)+"ms\t";
				ip=p.src_ip.getHostAddress();
			} else if (p.type == ICMPPacket.ICMP_UNREACH) {		//不可达
				str+=String.valueOf(p.sec*1000+p.usec/1000-second*1000-millSecond)+"ms\t";
			//	unreach=true;
				ip=p.src_ip.getHostAddress();
			} else if (p.type == ICMPPacket.ICMP_ECHOREPLY) {	//回复包。
				str+=String.valueOf(p.sec*1000+p.usec/1000-second*1000-millSecond)+"ms\t";
				ip=p.src_ip.getHostAddress();
				reply=true;
			} else {
				//str="wrong";
				//意外情况，暂不考虑
				str+="*\t";
				nullAll++;
			}
		}
		if(nullAll==3){
			str=ttl+"\t"+str+"\t"+"请求超时";
		}else{
			str=ttl+"\t"+str+ip;
		}
		//如果有不可达，则直接告知失败，
		//如果成功，在后面加，成功。
		if(reply){
			str+="\n追踪完成";
		}
		return str;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		String str;
		short i=1;
		while(i<31){
			str=sendICMP(i++);
			Main.receiveMessage(str);
			if(str.endsWith("追踪完成"))
				break;
		}
		
	}
	
	public InetAddress getRemoteAddr() {
		return remoteAddr;
	}
	public void setRemoteAddr(InetAddress remoteAddr) {
		this.remoteAddr = remoteAddr;
	}
	String hostName=null;	//主机名
	JpcapCaptor captor=null;	//抓取数据包工具实例
	JpcapSender sender=null;	//发送数据包工具实例
	InetAddress localAddr=null;	//本地IP地址
	InetAddress remoteAddr=null;//目的IP地址
	byte[]remoteMac=null;		//目的MAC地址
	byte[]localMac=null;		//本地IP地址
	ICMPPacket icmp=null;		//即将发送的ICMP数据包。
	
}
/*
 * setIPv4Parameter

public void setIPv4Parameter(int priority,
                             boolean d_flag,
                             boolean t_flag,
                             boolean r_flag,
                             int rsv_tos,
                             boolean rsv_frag,
                             boolean dont_frag,
                             boolean more_frag,
                             int offset,
                             int ident,
                             int ttl,
                             int protocol,
                             java.net.InetAddress src,
                             java.net.InetAddress dst)
Sets the IPv4 parameters
Parameters:
d_flag - IP flag bit: [D]elay
t_flag - IP flag bit: [T]hrough
r_flag - IP flag bit: [R]eliability
rsv_tos - Type of Service (TOS)
priority - Priority
rsv_frag - Fragmentation Reservation flag
dont_frag - Don't fragment flag
more_frag - More fragment flag
offset - Offset
ident - Identifier
ttl - Time To Live
protocol - Protocol 
This value is ignored when this packets inherits a higher layer protocol(e.g. TCPPacket)
src - Source IP address
dst - Destination IP address

 **/
 