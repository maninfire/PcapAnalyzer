package com.tsz;


import javafx.concurrent.Task;
import org.jnetpcap.PcapIf;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Administrator on 2016/3/4.
 */
public class PcapManager {
    private static final PcapManager pcapManager = new PcapManager();
    private Task<Void> task;
    private org.jnetpcap.Pcap pcap;
    //private NetworkAdapter networkAdapter;
    private String filterExp;               // libpcap捕获过滤表达式

    private PcapManager() {}

    public static PcapManager getInstance() {
        return pcapManager;
    }

    public static boolean compile(String interfaceName, String filter) {

        StringBuilder errBuf = new StringBuilder();
        org.jnetpcap.Pcap pcap = org.jnetpcap.Pcap.openLive(interfaceName,
                org.jnetpcap.Pcap.DEFAULT_SNAPLEN,
                org.jnetpcap.Pcap.DEFAULT_PROMISC,
                org.jnetpcap.Pcap.DEFAULT_TIMEOUT,
                errBuf);

        if (pcap == null) {
            System.err.println("Error while open device interface:" + errBuf);
            return false;
        }

        org.jnetpcap.PcapBpfProgram program = new org.jnetpcap.PcapBpfProgram();
        int optimize = 0;
        int netmask = 0xFFFFFF00;
        //if (pcap.compile(program, filter, optimize, netmask) != org.jnetpcap.Pcap.OK) {
       //     return false;
       // }

        pcap.close();
        return true;
//        int len = 64 * 1024;
//        int datalinkType = Ethernet.EthernetType.IP4.getId();
//        int optimize = 0;
//        int netmask = 0xFFFFFF00;
//        filterProgram = new PcapBpfProgram();
//        if (Pcap.compileNoPcap(len, datalinkType, filterProgram, filter, 0, netmask) != Pcap.OK) {
//            filterProgram = null;       // 如果编译失败将其置为null，避免错误使用
//            System.err.println("error");
//            return false;
//        }
//        return true;
    }

    public String getFilterExp() {
        return filterExp;
    }


    /**
     * 停止实时捕获
     */
    public void stopCapture() {
        if (task != null && task.isRunning()) {
            task.cancel();
        }
        if (pcap != null) {
            try {
                pcap.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 捕获离线网络数据包
     * @param file
     * @param listener
     */
    public void captureOffline(File file, OnCapturePacketListener listener) {
        if (file == null || !file.exists() || !file.isFile()) {
            System.err.println("Can not open file:" + file);
            return;
        }

        stopCapture();

        StringBuilder errBuf = new StringBuilder();
        org.jnetpcap.Pcap pcap = org.jnetpcap.Pcap.openOffline(file.getAbsolutePath(), errBuf);
        if (pcap == null) {
            System.err.println("Error while open device interface:" + errBuf);
            return;
        }

        task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {

                org.jnetpcap.packet.PcapPacket packet = new org.jnetpcap.packet.PcapPacket(org.jnetpcap.nio.JMemory.Type.POINTER);

                while (pcap.nextEx(packet) == org.jnetpcap.Pcap.NEXT_EX_OK) {
                    if (listener != null) {
                        //System.out.println(packet);
                        listener.onCapture(packet);
                    }
                }
                pcap.close();
                return null;
            }
        };
        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    /**
     * 数据包捕获监听
     */
    public interface OnCapturePacketListener {
        /**
         * 每当捕获到一个数据包时被调用
         * @param packet 被捕获的数据包，该数据包指向一个临时存储区，不要保存这个引用，
         *               如果需要保存数据包使用{@code new PcapPacket(packet);}创建一个新的副本
         */
        void onCapture(org.jnetpcap.packet.PcapPacket packet);
    }
}
