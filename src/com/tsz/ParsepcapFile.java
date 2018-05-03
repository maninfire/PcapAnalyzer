package com.tsz;

import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParsepcapFile {

    private static String regexIp="(Ip:[^\\n]*\\n)";
    private static String regexFrame="(Frame:[^\\n]*\\n)";
    private static String regexEth="(Eth:[^\\n]*\\n)";
    private static String regexTcp="(Tcp:[^\\n]*\\n)";
    private static String regexHttp="(Http:[^\\n]*\\n)";
    private static String regexUdp="(Udp:[^\\n]*\\n)";
    private static List<String> value;

    private static List<String> key;
    static StringBuilder newFile=new StringBuilder();

    public static void Jsonchange(String [] args){
        String str = "{\"result\":\"success\",\"message\":\"成功！\"}";
        JSONObject json = JSONObject.fromObject(str);
        System.out.println(json.toString());
    }

    public static void Jsonpack(){
        StringBuilder result=new StringBuilder();
        result.append("{");
        for(int i =0;i<key.size();i++){
            result.append(key.get(i));
            result.append(":");
            result.append(value.get(i));
            result.append(",");
        }
        result.append("}");
        newFile.append(result);
        //output(result.toString().getBytes());
    }


    public static void Parse( String Sfile ,String regex){
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(Sfile);
        List<String> temp=new ArrayList<String>();

        while(m.find()){
            temp.add(m.group());
        }
        key=new ArrayList<String>();
        Pattern pkey = Pattern.compile("(:[^=]*=)");
        Pattern pfuhao = Pattern.compile("(\\*\\*\\*[^=]*=)");
        value=new ArrayList<String>();
        Pattern pvalue = Pattern.compile("(=[^\\n]*\\n)");
        for(String s1:temp){
            Matcher mfuhao=pfuhao.matcher(s1);
            //跳过带星号的行
            if(mfuhao.find()){
                continue;
            }
            Matcher mkey = pkey.matcher(s1);
            //跳过空行
            if(!mkey.find()){
                continue;
            }

            String tkey=mkey.group();
            tkey=tkey.replaceAll("\\s", "");
            key.add(tkey.substring(1,tkey.length()-1));

            Matcher mvalue = pvalue.matcher(s1);
            if(!mvalue.find()){
                continue;
            }
            String tvalue=mvalue.group();
            value.add(tvalue.substring(1,tvalue.length()-1));
        }
    }


    public static void ParseFrame( String Sfile ){
        String s="Frame:\n" +
                "Frame:                                  number = 0\n" +
                "Frame:                               timestamp = 2018-05-03 11:11:07.691\n" +
                "Frame:                             wire length = 396 bytes\n" +
                "Frame:                         captured length = 396 bytes\n" +
                "Frame:";
        Parse(Sfile,regexFrame);
    }
    public static void ParseEth( String Sfile ){
        Parse(Sfile,regexEth);

    }


    public static void ParseIp( String Sfile ) {
        Parse(Sfile,regexIp);
    }

    public static void ParseTcp( String Sfile ) {
        Parse(Sfile,regexTcp);
    }

    public static void ParseUdp( String Sfile ) {
        Parse(Sfile,regexUdp);
    }

    public static void ParseHttp( String Sfile ) {
        Parse(Sfile,regexHttp);
        Jsonpack();
    }

}
