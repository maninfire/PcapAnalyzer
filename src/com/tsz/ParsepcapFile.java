package com.tsz;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private static List<String> excludekey;//这个标志用来剔除不需要的关键字
/*setexcludekey后自，jsonpack实现自动剔除的功能。如果不设置这个参数，默认为空就不会剔除任何参数*/
    static StringBuilder newFile=new StringBuilder();

    public ParsepcapFile(){
        excludekey=null;
    }
    public void setexcludekey(List<String> key){
        this.excludekey=key;
    }
    /**
     * 得到格式化json数据  退格用\t 换行用\r
     */
    public static String format(String jsonStr) {
        int level = 0;
        StringBuffer jsonForMatStr = new StringBuffer();
        for(int i=0;i<jsonStr.length();i++){
            char c = jsonStr.charAt(i);
            if(level>0&&'\n'==jsonForMatStr.charAt(jsonForMatStr.length()-1)){
                jsonForMatStr.append(getLevelStr(level));
            }
            switch (c) {
                case '{':
                case '[':
                    jsonForMatStr.append(c+"\n");
                    level++;
                    break;
                case ',':
                    jsonForMatStr.append(c+"\n");
                    break;
                case '}':
                case ']':
                    jsonForMatStr.append("\n");
                    level--;
                    jsonForMatStr.append(getLevelStr(level));
                    jsonForMatStr.append(c);
                    break;
                default:
                    jsonForMatStr.append(c);
                    break;
            }
        }

        return jsonForMatStr.toString();

    }

    private static String getLevelStr(int level){
        StringBuffer levelStr = new StringBuffer();
        for(int levelI = 0;levelI<level ; levelI++){
            levelStr.append("\t");
        }
        return levelStr.toString();
    }

    public static void Jsonchange(String s){

        Map map = new HashMap();

        map.put("1", "abc");

        map.put("2", "efg");

        JSONArray array_test = new JSONArray();

        array_test.add(map);

        JSONObject jsonObject = JSONObject.fromObject(map);
        System.out.println(jsonObject);
        String json = format(jsonObject.toString());
        System.out.println(json);
    }

    public static void Jsonpack(String symbols){
        Map<String,String> map = new HashMap<String, String>();
        for(int i =0;i<key.size();i++){
            int br=0;
            if(excludekey!=null){
                for(int j=0;j<excludekey.size();j++){
                    if(key.get(i).equals(excludekey.get(j))){
                        br=1;
                    }
                }
            }
            if(br==1){
                //br=0;
                continue;
            }
            map.put(key.get(i),value.get(i));
        }
        JSONArray array_json = new JSONArray();
        //Jsonchange("");
        array_json.add(map);
        JSONObject jsonObject = JSONObject.fromObject(map);
        String json = format(jsonObject.toString());
        /*
        StringBuilder result=new StringBuilder();
        result.append("{");
        for(int i =0;i<key.size();i++){
            result.append(key.get(i));
            result.append(":");
            result.append(value.get(i));
            result.append(",");
        }
        result.append("}");*/
        newFile.append(symbols);
        newFile.append(json);
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
        Jsonpack("Frame:");
    }
    public static void ParseEth( String Sfile ){
        Parse(Sfile,regexEth);
        Jsonpack("Eth:");
    }


    public static void ParseIp( String Sfile ) {
        Parse(Sfile,regexIp);
        Jsonpack("Ip:");
    }

    public static void ParseTcp( String Sfile ) {
        Parse(Sfile,regexTcp);
        Jsonpack("Tcp:");
    }

    public static void ParseUdp( String Sfile ) {
        Parse(Sfile,regexUdp);
        Jsonpack("Udp:");
    }

    public static void ParseHttp( String Sfile ) {
        Parse(Sfile,regexHttp);
        Jsonpack("Http:");
        //Jsonchange(newFile.toString());
    }
    public static void Parseall(String Sfile,String outPath){
        ParseFrame(Sfile);
        ParseEth(Sfile);
        ParseIp(Sfile);
        ParseTcp(Sfile);
        ParseUdp(Sfile);
        ParseHttp(Sfile);
        System.out.println(newFile);
        anaylsepcap.output(newFile.toString().getBytes(),outPath);
    }
}
