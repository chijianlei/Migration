package collect;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.annotation.processing.Filer;
import javax.lang.model.element.Element;
import javax.tools.FileObject;
import javax.tools.JavaFileObject;

import structure.API;
import structure.Migration;
import utils.ReadAPI;

import javax.tools.JavaFileManager.Location;

import gumtreediff.gen.srcml.SrcmlCppTreeGenerator;
import gumtreediff.gen.srcml.SrcmlJavaTreeGenerator;
import gumtreediff.matchers.MappingStore;
import gumtreediff.matchers.Matcher;
import gumtreediff.matchers.Matchers;
import gumtreediff.tree.TreeContext;

public class FileFilter {
	private static LinkedHashSet<API> apis = new LinkedHashSet<API>();
	
	public static void main(String[] args) throws Exception{	
		String path = "apis";
		apis = ReadAPI.readAPI(path);
//		for(String api : apis) {
//			System.out.println(api);
//		}
		FileFilter.Filter("J:\\test1\\");
	}
	
	public static void Filter(String path) throws Exception {
		File validFile = new File("validFiles.txt");
		BufferedWriter wr = new BufferedWriter(new FileWriter(validFile));
		File rootDir = new File(path);
		File[] dirs = rootDir.listFiles();
		HashMap<String, HashSet<String>> importMap = getImportList();
		HashSet<String> imports = new HashSet<String>();
		for(Map.Entry<String, HashSet<String>> entry : importMap.entrySet()) {
			String key = entry.getKey();
			imports.add(key);
		}
		for(File dir : dirs) {
			System.out.println("Analyse "+dir.getName());
			if(dir.listFiles().length!=3) {//两个commit文件夹，一个diffs文本文件
				wr.close();
				throw new Exception("Error!");
			}
			String diffPath = dir.getAbsolutePath()+"\\diffs.txt";
			File diffFile = new File(diffPath);
			BufferedReader br = new BufferedReader(new FileReader(diffFile));
			String tmpline = br.readLine();
			String oldCommit = tmpline.split(";")[0];
			String newCommit = tmpline.split(";")[1];
			while((tmpline=br.readLine())!=null) {
				String[] diff = tmpline.split(";");
				String srcDiff = diff[0];
				String tgtDiff = diff[1];
				String srcPath = dir.getAbsolutePath()+"\\"+oldCommit+"\\"+srcDiff;
				String tgtPath = dir.getAbsolutePath()+"\\"+newCommit+"\\"+tgtDiff;
				BufferedReader br1 = new BufferedReader(new FileReader(new File(srcPath)));
				BufferedReader br2 = new BufferedReader(new FileReader(new File(tgtPath)));
				String tmpline1 = "";
				Boolean preserve = false;
				Boolean containsImport = false;
				ArrayList<String> tmpImports = new ArrayList<String>();
				while((tmpline1=br1.readLine())!=null) {//从srcFile搜索包含API文件
					if(tmpline1.contains("import")) {
						if(tmpline1.split(" ").length<2)
							continue;
						String className = tmpline1.split(" ")[tmpline1.split(" ").length-1];
						className = className.substring(0, className.length()-1);//delete ";"
						if(imports.contains(className)) {
							containsImport = true;
							tmpImports.add(className);
						}
					}
					if(containsImport==true) {
						for(String imp : tmpImports) {
							HashSet<String> methods = importMap.get(imp);
							for(String tmp : methods) {
								if(tmpline1.contains(tmp)) {
									preserve = true;
									break;
								}
							}
						}
					}
				}
				br1.close();
				containsImport = false;//reset
				tmpImports = new ArrayList<String>();//reset
				while((tmpline1=br2.readLine())!=null) {//从tgtFile搜索包含API文件
					if(tmpline1.contains("import")) {
						if(tmpline1.split(" ").length<2)
							continue;
						String className = tmpline1.split(" ")[tmpline1.split(" ").length-1];
						className = className.substring(0, className.length()-1);//delete ";"
						if(imports.contains(className)) {
							containsImport = true;
							tmpImports.add(className);
						}
					}
					if(containsImport==true) {
						for(String imp : tmpImports) {
							HashSet<String> methods = importMap.get(imp);
							for(String tmp : methods) {
								if(tmpline1.contains(tmp)) {
									preserve = true;
									break;
								}
							}
						}
					}
				}
				br2.close();
				if(preserve==true) {
					wr.append(srcPath+";"+tgtPath);
					wr.newLine();
					wr.flush();
				}
			}
			br.close();
		}
		wr.close();
	}
	

	private static HashMap<String, HashSet<String>> getImportList() throws Exception {
		if(apis.size()==0)
			throw new Exception("error!");
		HashMap<String, HashSet<String>> importMap = new HashMap<String, HashSet<String>>();
		for(API api : apis) {
			String methodName = api.getMethodName();
			String importName = api.getLongName().substring(0, api.getLongName().lastIndexOf("."));
			if(!importMap.containsKey(importName)) {
				HashSet<String> list = new HashSet<String>();
				list.add(methodName);
				importMap.put(importName, list);
			}else {
				importMap.get(importName).add(methodName);
			}
		}
		return importMap;
	}
	
	public static ArrayList<Migration> readMigrationList(String path, String filter) throws Exception{
		ArrayList<Migration> migrates = new ArrayList<Migration>();
		File cpFile = new File(path);
		System.err.println("Analyse:"+ cpFile.getName());
		String diffPath = cpFile.getAbsolutePath()+"\\diffs.txt";
		File diffFile = new File(diffPath);
		if(!diffFile.exists())
			throw new Exception("file is not existed!");
		BufferedReader br = new BufferedReader(new FileReader(diffFile));
		String tmpline = br.readLine();
		String repoName = tmpline;
		tmpline = br.readLine();
		String srcHash = tmpline.split(";")[0];
		String dstHash = tmpline.split(";")[1];
		while((tmpline=br.readLine())!=null) {
			String path1 = tmpline.split(";")[0];
			String path2 = tmpline.split(";")[1];
			path1 = cpFile.getPath()+"//"+srcHash+"//"+path1;
			path2 = cpFile.getPath()+"//"+dstHash+"//"+path2;
			File srcFile = new File(path1);
			if (!srcFile.exists()) {
				br.close();
				throw new Exception("srcfile is not existed!");
			}
			System.out.println("Analyse:"+ srcFile.getName());
			File dstFile = new File(path2);	
			if (!dstFile.exists()) {
				br.close();
				throw new Exception("dstfile is not existed!");
			}
			TreeContext tc1 = new SrcmlJavaTreeGenerator().generateFromFile(srcFile);
			TreeContext tc2 = new SrcmlJavaTreeGenerator().generateFromFile(dstFile);
			Matcher m = Matchers.getInstance().getMatcher(tc1.getRoot(), tc2.getRoot());
	        m.match();
	        MappingStore mappings = m.getMappings();
			Migration mi = new Migration(tc1, tc2, mappings, srcFile.getAbsolutePath());
			mi.setRepoName(repoName);
			System.out.println("Mapping size: "+mappings.asSet().size());
			mi.setSrcHash(srcHash);
			mi.setDstHash(dstHash);
			migrates.add(mi);			
		}	
		br.close();
		return migrates;
	}
	
	
	
	
	
	
	
}
