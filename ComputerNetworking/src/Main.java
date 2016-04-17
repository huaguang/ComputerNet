import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class Main {
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		JFrame frame=new JFrame("TraceRouter");
		GridBagLayout layout=new GridBagLayout();
		frame.setLayout(layout);
		JLabel label=new JLabel("IP或者HostName:");
		JTextField text=new JTextField("www.baidu.com");
		but=new JButton("确定");
		JButton stopBut=new JButton("停止");
		frame.add(label);
		frame.add(text);
		frame.add(but);
		frame.add(stopBut);
		showJTA=new JTextArea();
		showJTA.setEditable(false);
		GridBagConstraints con=new GridBagConstraints();
		con.fill=GridBagConstraints.BOTH;
		con.gridwidth=1;
		con.weightx=0;
		con.weighty=0;
		layout.setConstraints(label, con);
		con.gridwidth=3;
		con.weightx=1;
		con.weighty=0;
		layout.setConstraints(text, con);
		con.gridwidth=1;
		con.weightx=0;
		con.weighty=0;
		layout.setConstraints(but, con);
		con.gridwidth=0;
		layout.setConstraints(stopBut, con);
		con.gridwidth=0;
		con.weightx=0;
		con.weighty=1;
		layout.setConstraints(showJTA, con);
		/*con.gridwidth=1;
		con.weightx=0;
		con.weighty=0;
		layout.setConstraints(label, con);*/
		frame.add(showJTA);
		frame.setSize(600, 400);
		frame.setVisible(true);
		try {
			tr=new TraceRouter();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		but.addActionListener(new ActionListener(){

			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				if("".equals(text.getText())){
					showJTA.setText("地址不能为空");
				}
				else{
					tr.setRemoteAddr(text.getText().trim());
					if(!tr.setRemoteMac()){
						showJTA.setText("获取远端MAC地址失败");
					}else{
						but.setEnabled(false);
						showJTA.setText("源地址:"+tr.localAddr.getHostAddress()+"\t 到"+tr.remoteAddr.getHostAddress()+"的路由\n");
						tr.initICMPPacket();
						trThread=new Thread(tr);
						trThread.start();
					}
				}
			}
			
		});
		stopBut.addActionListener(new ActionListener(){

			@SuppressWarnings("deprecation")
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				trThread.stop();
				but.setEnabled(true);
			}
			
		});
		frame.addWindowListener(new WindowAdapter(){
			@Override
			public void windowClosing(WindowEvent e) {
				// TODO Auto-generated method stub
				System.exit(1);
			}
			
		});
	}
	public static void receiveMessage(String str){
		if(str.endsWith("完成")){
			but.setEnabled(true);
		}
		showJTA.setText(showJTA.getText()+str+"\n");
	}
	static JTextArea showJTA=null;
	static TraceRouter tr=null;
	static Thread trThread=null;
	static JButton but=null;
}
