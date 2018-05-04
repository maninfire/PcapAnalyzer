package com.tsz;

public class Main {

    public static void main(String[] args) {
	// write your code here

        if(args.length==2){
            anaylsepcap.openFile(args[0],args[1]);
        }else if(args.length==1){
            anaylsepcap.openFile(args[0],".//result.txt");
        }else {
            anaylsepcap.openFile("test.pcap",".//result.txt");
        }

        //ParsepcapFile.ParseFrame("");
    }
}
