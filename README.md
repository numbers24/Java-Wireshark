# Java-Wireshark

TCP Flow reporting

This project will identify TCP flows and product a report characterizing then, as well basic information about other protocols, such as UDP and ICMP.  Your code will take a packet capture (pcap) file of recorded packets and produce the following two tables, in csv (comma separated value) format, that summarize the traffic. The first table, the TCP Summary Table, characterizes TCP flows and the second table, the Additional Protocols Table,  summarized all other protocols.


In order to read the pcap file and count the packets, look at the example source code -- see the tutorial an attachments). 

File Attachments: 

      

    The App.java file.
      
      

    Tutorial for starting project.
      
      

    2 test pcap files (small.pcap , http.pcap )
      
      

    2 example outputs on the pcap files. Your program should match the counts in these files. (small_pcap_out.txt , http_pcap_out.txt)
      

Use the following commands to run and test the code. (Put the pcap files in the compiled folder)

java -jar uber-pcap-1.1.0.jar small.pcap

java -jar uber-pcap-1.1.0.jar http.pcap
