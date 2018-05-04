package com.tsz;

import javafx.concurrent.Task;
import javafx.stage.FileChooser;
import org.jnetpcap.Pcap;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class anaylsepcap {
    private static Task<Void> task;
    private static org.jnetpcap.Pcap pcap;
    protected static void openFile(String pcapPath) {
        FileChooser fileChooser = new FileChooser();
        File file;
        //fileChooser.setTitle(Config.getString("label_open_file"));
        fileChooser.setInitialDirectory(new File("."));
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("All Files", "*.*"),
                new FileChooser.ExtensionFilter("libpcap", "*.pcap")
        );
        if(pcapPath!=null){
            file = new File(pcapPath);//fileChooser.showOpenDialog(stage);
        }else {
            file = new File("D:\\Users\\zhangzhenguo\\IdeaProjects\\PcapAnalyzer-master\\teding.pcap");//fileChooser.showOpenDialog(stage);
        }

        if (file == null || !file.exists()) {
            System.err.println("Can't find file:" + file);
            return;
        }

        List<String> data = new ArrayList<>();
        List<String> data2 = new ArrayList<>();
        StringBuilder result=new StringBuilder();
        //data.clear();
        Config.setTimestamp(Config.DEFAULT_TIMESTAMP);

        // 捕获离线数据包
        selfcaptureOffline(file, packet -> {
            // 将第一个数据包的时间戳设置为起始时间
            if (Config.getTimestamp() <= Config.DEFAULT_TIMESTAMP) {
                Config.setTimestamp(packet.getCaptureHeader().timestampInMicros());
            }
            org.jnetpcap.packet.PcapPacket packetCopy = new org.jnetpcap.packet.PcapPacket(packet); // 获取副本
            //System.out.println(packetCopy);
            data2.add(packetCopy.toString());
            data.add(packetCopy.toString());
        });
        for(String i:data){
            result.append(i);
        }
        ParsepcapFile newFile=new ParsepcapFile();
        List<String> exkey=new ArrayList<>();
        //exkey.add("number");
        //exkey.add("timestamp");
        newFile.setexcludekey(exkey);
        newFile.Parseall(result.toString());
        //output(result.toString().getBytes());
        //System.out.println(data);
    }

    public void realine(String input){


    }

    public static void selfcaptureOffline(File file, PcapManager.OnCapturePacketListener listener) {
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

        //task = new Task<Void>() {
            //@Override
          //  protected Void call() throws Exception {

                org.jnetpcap.packet.PcapPacket packet = new org.jnetpcap.packet.PcapPacket(org.jnetpcap.nio.JMemory.Type.POINTER);

                while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK){//NEXT_EX_OK) {
                    if (listener != null) {
                        //System.out.println(packet);
                        listener.onCapture(packet);
                    }
                }
                pcap.close();
                return ;
          //  }
        //};
        //Thread thread = new Thread(task);
        //thread.setDaemon(true);
        //thread.start();
    }

    /**
     * 停止实时捕获
     */
    public  static void stopCapture() {
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

    public static void output(byte[] outputcontent,String path){
        OutputStream stream = null;
        try {
            //实例化对象
            if(path!=null){
                stream = new FileOutputStream(path);
            }else {
                stream = new FileOutputStream("D:\\Users\\zhangzhenguo\\IdeaProjects\\PcapAnalyzer\\show1.txt");
            }

            //要写入的字符串数据
            String strings = "OutputStreamp测试写入数据";
            //将字符串数据转换为字节数组
            byte[] bytes = strings.getBytes();
            //将字节数组写入到文件
            stream.write(outputcontent);
            //清空缓冲区，将写入的数据保存
            stream.flush();
            //写入成功后的提示语
            System.out.println("写入文件成功");

            //抛出异常
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            //如果stream被实例化
            if(stream != null){
                try {
                    //关闭字节流
                    stream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
