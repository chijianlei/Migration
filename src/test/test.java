package test;

import java.io.File;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecuteResultHandler;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;

public class test {
	public static void main(String[] args) throws Exception{	
		String test = "@@ -35,7 +35,7 @@";
		Pattern p = Pattern.compile("\\d{1,}");//���2��ָ�������ֵ����ٸ���  
		Matcher m = p.matcher(test);   
		while(m.find()) {
			System.out.println(m.group());
		}
	}

	private void test1() throws Exception, IOException {
		System.out.println("RunExec");
		String versionCommit="78351302b0761178581d92612b528f6eea529618";//��Ҫ������Commit Hash		
		String path="D:\\workspace\\eclipse2018\\Migration\\OpenNMT-py\\";//��Ӧ��Ŀ�ڱ���Repo��·��
		String line = "cmd.exe /C git checkout "+versionCommit;
		CommandLine cmdLine = CommandLine.parse(line);
		DefaultExecuteResultHandler resultHandler = new DefaultExecuteResultHandler();
		DefaultExecutor executor = new DefaultExecutor();	
		executor.setWorkingDirectory(new File(path));
		executor.setExitValue(1);	//��������ִ���˳�ֵΪ1���������ɹ�ִ�в���û�д����򷵻�1		 
		executor.execute(cmdLine, resultHandler);
		resultHandler.waitFor();
	}
}
