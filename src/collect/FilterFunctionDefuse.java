package collect;

import gumtreediff.actions.model.Action;
import gumtreediff.io.TreeIoUtils;
import gumtreediff.matchers.MappingStore;
import gumtreediff.tree.ITree;
import gumtreediff.tree.TreeContext;
import structure.Boundary;
import structure.Definition;
import structure.Migration;
import structure.SubTree;
import utils.Defuse;
import utils.FileOperation;
import utils.Output;
import utils.Utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

public class FilterFunctionDefuse {

	public static void main (String args[]) throws Exception{
		String path = "J:\\Vulnerability_commit\\";
		String outMode = "lineNum";
		String numDir = "data_num\\";
		String varDir = "data_var\\";
		String checkDir = "data_check\\";
		if(outMode.equals("lineNum")) {
			FileOperation.delAllFile(numDir);
			FileOperation.delAllFile(varDir);
			FileOperation.delAllFile(checkDir);
		}
		File rootFile = new File(path);
		File[] fileList = rootFile.listFiles();
		FilterFunctionDefuse defuse = new FilterFunctionDefuse();
		for(int i=0;i<fileList.length;i++) {
			String cpPath = fileList[i].getAbsolutePath();
			defuse.collectDiffwithDefUse(cpPath, outMode, false, "");
		}		
	}
	
	public void collectDiffwithDefUse(String path, String outMode, 
		Boolean ifPrintDef, String filter) throws Exception {//获取DefUse		
		ArrayList<Migration> migrats = FileFilter.readMigrationList(path, filter);
		String repoName = "";
		if(migrats.size()!=0)
			repoName = migrats.get(0).getRepoName();
		else
			return;
		String txtName = (new File(path)).getName();
		String outPath3 = "data_num\\"+repoName+"_"+txtName+".txt";
		String outPath4 = "data_var\\"+repoName+"_"+txtName+"_defs_src.txt";
		String outPath5 = "data_var\\"+repoName+"_"+txtName+"_defs_dst.txt";
		String outPath6 = "data_check\\"+repoName+"_"+txtName+".txt";
		
		int errCount = 0;
		for(Migration migrat : migrats) {
			Defuse defuse = new Defuse();
			String miName_src = migrat.getMiName_src();
			String miName_dst = migrat.getMiName_dst();
			TreeContext sTC = migrat.getSrcT();
			TreeContext dTC = migrat.getDstT();
			MappingStore mappings = migrat.getMappings();
			HashMap<ITree, ITree> leaf2parblock_map_src = defuse.searchBlockMap(sTC);
			HashMap<ITree, ITree> leaf2parblock_map_dst = defuse.searchBlockMap(dTC);
			
			System.out.println("Analyse:"+miName_src);
			HashMap<String, LinkedList<Action>> actions = Utils.collectAction(sTC, dTC, mappings);					
			ArrayList<Integer> srcActIds = Utils.collectSrcActNodeIds(sTC, dTC, mappings, actions);
			System.out.println("ActionIDsize:"+srcActIds.size());
			for(int id : srcActIds) {
				System.out.println("Actionid:"+id);
			}			
			
			ArrayList<Definition> defs1 = defuse.getDef(sTC, "src");//先计算action,再收集defs
	        ArrayList<Definition> defs2 = defuse.getDef(dTC, "tgt");	        
	        HashMap<String, ArrayList<Definition>> defMap1 = defuse.transferDefs(defs1);
	        HashMap<String, ArrayList<Definition>> defMap2 = defuse.transferDefs(defs2);
	        HashMap<ITree, ArrayList<Definition>> blockMap1 = defuse.transferBlockMap(defs1, sTC, "src");
	        HashMap<ITree, ArrayList<Definition>> blockMap2 = defuse.transferBlockMap(defs2, dTC, "tgt");               
			System.out.println("def1size:"+defs1.size());
	        System.out.println("def2size:"+defs2.size());
	        System.out.println("def1Mapsize:"+defMap1.size());
	        System.out.println("def2Mapsize:"+defMap2.size());
	        System.out.println("block1size:"+blockMap1.size());
	        System.out.println("block2size:"+blockMap2.size());
	        
			ArrayList<ITree> functions_src = Utils.searchFunctions(sTC);
			System.out.println("function_size:"+functions_src.size());
			ArrayList<ITree> used_functions1 = new ArrayList<ITree>();
			ArrayList<ITree> used_functions2 = new ArrayList<ITree>();
	        HashMap<ITree, ITree> functionMap = new HashMap<ITree, ITree>();
	        for(ITree function_src : functions_src) {
	        	ITree function_dst = mappings.getDst(function_src);
	        	if(function_dst!=null) {
	        		functionMap.put(function_src, function_dst);
	        	}else {
	        		function_dst = search_DSTFunction(function_src, dTC, mappings);
	        		if(function_dst!=null) {
	        			functionMap.put(function_src, function_dst);
	        		}
	        	}
	        }

			for(Map.Entry<ITree, ITree> function_pair : functionMap.entrySet()) {					
				System.out.println("===================");				
				HashMap<String, String> replaceMap_src = new HashMap<String, String>();
				HashMap<String, String> replaceMap_dst = new HashMap<String, String>();
				HashSet<Definition> usedDefs1 = new HashSet<Definition>();				
				HashSet<Definition> usedDefs2 = new HashSet<Definition>();	
				ITree function_src = function_pair.getKey();	
				System.out.println("FCroot:"+function_src.getId());
				
				List<ITree> desList = function_src.getDescendants();
				desList.add(function_src);
				Boolean hasAction = false;
				for(ITree node : desList) {
					if(srcActIds.contains(node.getId())) {
						hasAction = true;
						break;
					}
				}
				System.out.println(hasAction);
				if(!hasAction)
					continue;//该function中不含有diff action，跳过
	    			
				Boundary bd_src = new Boundary();
				List<ITree> leaves1 = new ArrayList<ITree>();				
				bd_src = Utils.searchFunctionBoundary(function_src, sTC);
				if (!used_functions1.contains(function_src)) {
					used_functions1.add(function_src);
				}else {
					continue;
				}
				leaves1 = Utils.traverse2Leaf(function_src, leaves1);				
				
	    		Boolean same = false;
				int labelCount = 0;
				for(ITree leaf : leaves1) {
					String label = leaf.getLabel();
//					System.out.println("label:"+label);
					if(!label.equals(""))
						labelCount++;
					String type = sTC.getTypeLabel(leaf);
					if(type.equals("literal")) {
						leaf.setLabel(Output.deleteLiteral(leaf, sTC));	
					}								
					ArrayList<Definition> stringList = defMap1.get(label);
					if(stringList!=null) {
						ITree parBlock = leaf2parblock_map_src.get(leaf);
						ArrayList<Definition> blockList = blockMap1.get(parBlock);
						for(Definition def1 : stringList) {
							if(blockList!=null) {
								if(blockList.contains(def1)) {
									if(leaf.getId()>def1.getDefLabelID()) {
										leaf.setLabel("var");
										usedDefs1.add(def1);
										replaceMap_src.put(label, "var");
									}											
								}
							}							
							if(def1.getDefLabelID()==leaf.getId()) {
								leaf.setLabel("var");
								replaceMap_src.put(label, "var");
							}
//							System.out.println(leaf.getId()+","+def1.getDefLabelID());
//							System.out.println("Def:"+def1.getType()+","+def1.getVarName());
						}
					}
				}												
					
				if(labelCount==0)
					continue;				   			    					
				
				ITree function_dst = function_pair.getValue();
				Boundary bd_dst = new Boundary();
				List<ITree> leaves2 = new ArrayList<ITree>();
				bd_dst = Utils.searchFunctionBoundary(function_dst, dTC);
				if (!used_functions2.contains(function_dst)) {
					used_functions2.add(function_dst);
				}else {
					continue;
				}
				leaves2 = Utils.traverse2Leaf(function_dst, leaves2);	
				
				for(ITree leaf : leaves2) {
					String label = leaf.getLabel();
					String type = dTC.getTypeLabel(leaf);
					if(type.equals("literal")) {
						leaf.setLabel(Output.deleteLiteral(leaf, dTC));
					}	
					ArrayList<Definition> stringList = defMap2.get(label);
					if(stringList!=null) {
						ITree parBlock = leaf2parblock_map_dst.get(leaf);
						ArrayList<Definition> blockList = blockMap2.get(parBlock);
						for(Definition def2 : stringList) {
							if(blockList!=null) {
								if(blockList.contains(def2)) {
									if(leaf.getId()>def2.getDefLabelID()) {
										usedDefs2.add(def2);
										leaf.setLabel("var");
										replaceMap_dst.put(label, "var");
									}
//									System.out.println(leaf.getId()+","+def2.getDefLabelID());
//									System.out.println(def2.getType()+","+def2.getVarName());
								}
							}							
							if(def2.getDefLabelID()==leaf.getId()) {
								leaf.setLabel("var");
								replaceMap_dst.put(label, "var");
							}
						}
					}
					if(same==false) {
						for(ITree leaf1 : leaves1) {
							String label1 = leaf1.getLabel();
							if(label.equals(label1)) {
								same = true;
							}
						}
					}
				}//发现有不同subtree_src映射到同一subTree_dst情况，matching算法问题暂时无法解决
				 //处理措施为直接复制一份replaceMap_dst，跳过				
				
				if(same==false)
					continue;//no leaf is the same
				int sBeginLine = bd_src.getBeginLine();
				int sLastLine = bd_src.getLastLine();
				int sBeginCol = bd_src.getBeginCol();
				int sLastCol = bd_src.getLastCol();
				int dBeginLine = bd_dst.getBeginLine();
				int dLastLine = bd_dst.getLastLine();
				int dBeginCol = bd_dst.getBeginCol();
				int dLastCol = bd_dst.getLastCol();
				String diffLine_check = "STID:"+function_src.getId()+","
						+sBeginLine+","+sLastLine+","+sBeginCol+","+sLastCol+"->"
						+dBeginLine+","+dLastLine+","+dBeginCol+","+dLastCol;						
				String diffLine = miName_src+";"+miName_dst+";"
						+sBeginLine+","+sLastLine+","+sBeginCol+","+sLastCol+"->"
						+dBeginLine+","+dLastLine+","+dBeginCol+","+dLastCol;
//				if(noFunc)
//					diffLine_check = diffLine_check + ";no function";
				printLineNum(outPath3, outPath4, outPath5, diffLine, replaceMap_src, replaceMap_dst);
				printLineCheck(outPath6, diffLine_check);
			}				
		}			
		System.out.println("errCount:"+errCount);
	}
	
	private static ITree search_DSTFunction(ITree function_src, TreeContext dTC, MappingStore mappings) throws Exception {
		HashMap<ITree, Integer> candiMap = new HashMap<ITree, Integer>();
		List<ITree> desList = function_src.getDescendants();
		System.out.println("desSize:"+desList.size());
		for(ITree node_src : desList) {
			ITree node_dst = mappings.getDst(node_src);
			if(node_dst!=null) {
				ITree func_candi = null;
				List<ITree> pars = node_dst.getParents();
				for(ITree par: pars) {
					String type = dTC.getTypeLabel(par);
					if(type.equals("function")) {
						func_candi = par;
						break;
					}
				}
				if(func_candi!=null) {
					if (candiMap.get(func_candi)==null) {
						candiMap.put(func_candi, 1);
					}else
						candiMap.put(func_candi, candiMap.get(func_candi)+1);
				}else
					continue;					
			}else
				continue;
		}
		
		if(candiMap.size()==0)
			return null;
		
        // 通过ArrayList构造函数把map.entrySet()转换成list
        List<Map.Entry<ITree, Integer>> list = new ArrayList<Map.Entry<ITree, Integer>>(candiMap.entrySet());
        // 通过比较器实现比较排序
        Collections.sort(list, new Comparator<Map.Entry<ITree, Integer>>() {
            public int compare(Map.Entry<ITree, Integer> mapping1, Map.Entry<ITree, Integer> mapping2) {
                return mapping2.getValue().compareTo(mapping1.getValue());
            }
        });
        
        Map.Entry<ITree, Integer> firstMap = list.get(0);
        ITree function_dst = firstMap.getKey();
        if(function_dst==null)
        	throw new Exception("check the error");
        return function_dst;
	}
	
	static private void printLineCheck(String outPath6, String diffLine_check) throws IOException {
		File output6 = new File(outPath6);
		BufferedWriter wr6 = new BufferedWriter(new FileWriter(output6, true));
		wr6.append(diffLine_check);
		wr6.newLine();
		wr6.flush();
		wr6.close();
	}
	
	static private void printLineNum(String outPath3, String outPath4, String outPath5, String diffLine,
			HashMap<String , String> replaceMap_src, HashMap<String , String> replaceMap_dst) throws Exception {
		File output3 = new File(outPath3);
		BufferedWriter wr3 = new BufferedWriter(new FileWriter(output3, true));
		File output4 = new File(outPath4);
		BufferedWriter wr4 = new BufferedWriter(new FileWriter(output4, true));
		File output5 = new File(outPath5);
		BufferedWriter wr5 = new BufferedWriter(new FileWriter(output5, true));
        wr3.append(diffLine);
		wr3.newLine();
		wr3.flush();
		for(Map.Entry<String, String> entry : replaceMap_src.entrySet()) {
			String varName = entry.getKey();
			String label = entry.getValue();
			wr4.append(varName+"->"+label+";");
		}
		wr4.newLine();
		wr4.flush();
//		System.out.println("STID:"+srcT.getRoot().getId()+","+dstT.getRoot().getId());
//		System.out.println(replaceMap_dst.size());
		for(Map.Entry<String, String> entry : replaceMap_dst.entrySet()) {
			String varName = entry.getKey();
			String label = entry.getValue();
			wr5.append(varName+"->"+label+";");
		}
		wr5.newLine();
		wr5.flush();
		wr3.close();
		wr4.close();
		wr5.close();
	}
	
	static private String getDefTxt(HashSet<Definition> usedDefs1, HashSet<Definition> usedDefs2, 
			TreeContext tc1, TreeContext tc2, SubTree srcT, SubTree dstT) throws Exception {
		String buffer = "";
		for(Definition def : usedDefs1) {
			SubTree st = new SubTree(def.getRoot(), tc1, 0, "");
			String stat = Output.subtree2src(st);
			buffer = buffer +stat+" ; ";
		}
		String src = Output.subtree2src(srcT);
		buffer = buffer + src+"\t";
		for(Definition def : usedDefs2) {
			SubTree st = new SubTree(def.getRoot(), tc2, 0, "");
			String stat = Output.subtree2src(st);
			buffer += stat+" ; ";
		}
		String tar = Output.subtree2src(dstT);
		buffer += tar;
		if(buffer.contains("error")&&buffer.contains("situation"))
			return null;
		return buffer;
	}
	
	static private String getText(TreeContext tc1, TreeContext tc2, SubTree srcT, SubTree dstT) throws Exception {
		String buffer = "";
		String src = Output.subtree2src(srcT);
		String tar = Output.subtree2src(dstT);
		buffer = src+"\t"+tar;
		if(buffer.contains("error")&&buffer.contains("situation"))
			return null;
		return buffer;
	}
	
	static private void printTxt(String outPath, String outPath1, String outPath2, String buffer) throws Exception {
		File output = new File(outPath);		
		BufferedWriter wr = new BufferedWriter(new FileWriter(output, true));
		File output1 = new File(outPath1);
		File output2 = new File(outPath2);		
		BufferedWriter wr1 = new BufferedWriter(new FileWriter(output1, true));
		BufferedWriter wr2 = new BufferedWriter(new FileWriter(output2, true));
		String src = buffer.split("\t")[0];
		String dst = buffer.split("\t")[1];
		wr.append(buffer);
		wr.newLine();
		wr.flush();
		wr1.append(src);
		wr1.newLine();
		wr1.flush();
		wr2.append(dst);
		wr2.newLine();
		wr2.flush();
		wr.close();
		wr1.close();
		wr2.close();
	}
	
	static private void printJson(String jpath, int count, TreeContext srcT, TreeContext dstT) throws Exception {
		File dir = new File(jpath);
		if(!dir.exists()) {
			dir.mkdirs(); 
		}
		if(srcT!=null) {
			String out = jpath+"pair"+String.valueOf(count)+"_src.json";
			BufferedWriter wr = new BufferedWriter(new FileWriter(new File(out)));
			wr.append(TreeIoUtils.toJson(srcT).toString());
			wr.flush();
			wr.close();
		}
		if(dstT!=null) {
			String out1 = jpath+"pair"+String.valueOf(count)+"_tgt.json";
			BufferedWriter wr1 = new BufferedWriter(new FileWriter(new File(out1)));
			wr1.append(TreeIoUtils.toJson(dstT).toString());
			wr1.flush();
			wr1.close();
		}
	}
}
