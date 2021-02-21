package utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class FileOperation {

	 public static void copyFile(File sourcefile,File targetFile) throws IOException{
		 File parent = targetFile.getParentFile();
		 //�������·�������ڣ��򴴽�·��
		 if(!parent.exists()){
			parent.mkdirs();
		 }
	     //�½��ļ����������������л���        
		 FileInputStream input=new FileInputStream(sourcefile);	        
		 BufferedInputStream inbuff=new BufferedInputStream(input);	        
	     //�½��ļ���������������л���
	     FileOutputStream out=new FileOutputStream(targetFile);
	     BufferedOutputStream outbuff=new BufferedOutputStream(out);  
	     //��������   
	     byte[] b=new byte[1024*5];
	     int len=0;
	     while((len=inbuff.read(b))!=-1){
	    	 outbuff.write(b, 0, len);
	     }        
	        
	     outbuff.flush(); //ˢ�´˻���������                
	     inbuff.close();//�ر���  
	     outbuff.close();
	     out.close();
	     input.close();     
	 }
	 
	 public static void copyDirectiory(String sourceDir,String targetDir) throws IOException{	        	        
		 //�½�Ŀ��Ŀ¼
		 File source = new File(sourceDir);
		 File target = new File(targetDir);
		 if(!target.exists()){
			 target.mkdirs();
		 }        	        
		 //��ȡԴ�ļ��е��µ��ļ���Ŀ¼	        
		 File[] file=source.listFiles();
		 for (int i = 0; i < file.length; i++) {	            
			 if(file[i].isFile()){	                
				 //Դ�ļ�	                
				 File sourceFile=file[i];	                   
				 //Ŀ���ļ�	                
				 File targetFile=new File(new File(targetDir).getAbsolutePath()+File.separator+file[i].getName());	                	                
				 copyFile(sourceFile, targetFile);	            	           
			 }	            	            	            
			 if(file[i].isDirectory()){	               
				 //׼�����Ƶ�Դ�ļ���	               
				 String dir1=sourceDir+"\\"+file[i].getName();	               
				 //׼�����Ƶ�Ŀ���ļ���	               
				 String dir2=targetDir+"\\"+file[i].getName();	                	                
				 copyDirectiory(dir1, dir2);	            
			 }	        
		 }	        	    
	 }
	 
	 public static void delFolder(String folderPath) {
	     try {
	        delAllFile(folderPath); //ɾ����������������
	        String filePath = folderPath;
	        filePath = filePath.toString();
	        java.io.File myFilePath = new java.io.File(filePath);
	        myFilePath.delete(); //ɾ�����ļ���
	     } catch (Exception e) {
	       e.printStackTrace(); 
	     }
	}//ɾ��ָ���ļ����������ļ�param path �ļ�����������·��
	 
	 public static boolean delAllFile(String path) {
	       boolean flag = false;
	       File file = new File(path);
	       if (!file.exists()) {
	         return flag;
	       }
	       if (!file.isDirectory()) {
	         return flag;
	       }
	       String[] tempList = file.list();
	       File temp = null;
	       for (int i = 0; i < tempList.length; i++) {
	          if (path.endsWith(File.separator)) {
	             temp = new File(path + tempList[i]);
	          } else {
	              temp = new File(path + File.separator + tempList[i]);
	          }
	          if (temp.isFile()) {
	             temp.delete();
	          }
	          if (temp.isDirectory()) {
	             delAllFile(path + "/" + tempList[i]);//��ɾ���ļ���������ļ�
	             delFolder(path + "/" + tempList[i]);//��ɾ�����ļ���
	             flag = true;
	          }
	       }
	       return flag;
	     }
	 
	public static void traverseFolder(String path, ArrayList<File> fileList) {
		File dir = new File(path);
		if (dir.exists()) {
			File[] files = dir.listFiles();
			if (files.length == 0) {
				System.out.println("�ļ����ǿյ�!");
			} else {
				for (File file : files) {
					if (file.isDirectory()) {
						traverseFolder(file.getAbsolutePath(), fileList);
					} else {
						if(file.getName().contains(".java"))
						fileList.add(file);
					}
				}
			}
		} else {
			System.out.println("�ļ�������!");
		}		
	}
	 
}
