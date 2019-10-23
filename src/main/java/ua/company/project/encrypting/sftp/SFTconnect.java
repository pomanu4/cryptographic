package ua.company.project.encrypting.sftp;

import java.io.File;
import java.io.FileInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import java.util.zip.CheckedOutputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.FileSystemOptions;
import org.apache.commons.vfs2.VFS;
import org.apache.commons.vfs2.provider.sftp.SftpFileSystemConfigBuilder;

public class SFTconnect {
    
    public static void main(String[] args) {
        
        try {
//            String addres = "sftp://roman_k:5@7LArq@YyH^F*RD@81.171.1.153/home/roman_k" ;
            
            FileSystemOptions fsOptions = new FileSystemOptions();
            SftpFileSystemConfigBuilder.getInstance().setStrictHostKeyChecking(fsOptions, "no");
            SftpFileSystemConfigBuilder.getInstance().setUserDirIsRoot(fsOptions, false);
            SftpFileSystemConfigBuilder.getInstance().setTimeout(fsOptions, 60000);
//            SftpFileSystemConfigBuilder.getInstance().setUserInfo(fsOptions, new UserInfo() {
//                @Override
//                public String getPassphrase() {
//                    return "";
//                }
//
//                @Override
//                public String getPassword() {
//                   return ""; 
//                }
//
//                @Override
//                public boolean promptPassword(String string) {
//                    return true;
//                }
//
//                @Override
//                public boolean promptPassphrase(String string) {
//                    return true;
//                }
//
//                @Override
//                public boolean promptYesNo(String string) {
//                    return false;
//                }
//
//                @Override
//                public void showMessage(String string) {
//                    
//                }
//            });
            
            FileSystemManager fsManager = VFS.getManager();
            FileObject remoteFileObject = fsManager.resolveFile("sftp://roman_k:*****3@mcabinet.lgaming.net:5022/home/roman_k/"  + "doc.txt", fsOptions);
            CheckedOutputStream checkedOutputStream = new CheckedOutputStream(remoteFileObject.getContent().getOutputStream(), new CRC32());
            File file = new File("D:\\TASKS\\GPrecons\\GPoperations.txt");
            IOUtils.copy(new FileInputStream(file), checkedOutputStream);
            
//            JSch js = new JSch();
//            Session session = js.getSession("roman_k", "81.171.1.153", 5022);
//            session.setPassword("5@7LArq@YyH^F*RD");
//            session.setConfig("StrictHostKeyChecking", "no");
//            session.connect(60000);
//            Channel channel = session.openChannel("sftp");
//            channel.connect();
//            ChannelSftp sftpCann = (ChannelSftp) channel;
//            sftpCann.put("D:\\garbage\\doc.txt", "/home/roman_k/report/");
//            
//            sftpCann.exit();
//            channel.disconnect();
//            session.disconnect(); 
            
        } catch (Exception ex) {
            ex.printStackTrace();
        } 
        
    }
    
}
