package collect.testcase;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;

/**
 * Count bug numbers for each repo and then sort them
 * @throws Exception 
 */

public class CountBugNum {
	private static HashMap<String, Integer> repoFreq = new HashMap<String, Integer>();
	
	public static void main(String[] args) throws Exception {
		String rootPath = "I:\\test";
		CountBugNum cb = new CountBugNum();
		cb.countRepos(rootPath);
	}
	
	public List<Map.Entry<String, Integer>> countRepos(String rootPath) throws Exception {
		File rootFile = new File(rootPath);
		File[] fileList = rootFile.listFiles();	
		for(int i=0;i<fileList.length;i++) {
			File cpFile = fileList[i];
			String cpPath = cpFile.getAbsolutePath();
			searchRepoName(cpPath);
		}
		List<Map.Entry<String, Integer>> list = new ArrayList<Map.Entry<String, Integer>>(repoFreq.entrySet());
		Collections.sort(list, new Comparator<Map.Entry<String, Integer>>() {   
		    public int compare(Map.Entry<String, Integer> o1, Map.Entry<String, Integer> o2) {      
		        return (o2.getValue() - o1.getValue()); 
		        //return (o1.getKey()).toString().compareTo(o2.getKey());
		    }
		});
        
        for(Map.Entry<String, Integer> mapping: list){ 
               System.out.println(mapping.getKey()+":"+mapping.getValue()); 
        }
        
        return list;
	}
	
	private static void searchRepoName(String cpPath) throws Exception {
		File cpFile = new File(cpPath);
//		System.out.println("Analyse:"+ cpFile.getName());
		String diffPath = cpFile.getAbsolutePath()+"\\diffs.txt";
		File diffFile = new File(diffPath);
		if(!diffFile.exists())
			throw new Exception("file is not existed!");
		List<String> lines = FileUtils.readLines(diffFile, "UTF-8");	
		String repoName = lines.get(0);	
		if(repoFreq.containsKey(repoName)) {
			repoFreq.put(repoName, repoFreq.get(repoName)+1);
		}else {
			repoFreq.put(repoName, 1);
		}
	}

	
}
