package collect;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import gumtreediff.actions.ActionGenerator;
import gumtreediff.actions.model.Action;
import gumtreediff.gen.jdt.JdtTreeGenerator;
import gumtreediff.gen.srcml.SrcmlCppTreeGenerator;
import gumtreediff.io.TreeIoUtils;
import gumtreediff.matchers.MappingStore;
import gumtreediff.matchers.Matcher;
import gumtreediff.matchers.Matchers;
import gumtreediff.tree.ITree;
import gumtreediff.tree.Tree;
import gumtreediff.tree.TreeContext;
import split.Split;
import structure.API;
import structure.Boundary;
import structure.Definition;
import structure.Migration;
import structure.SubTree;
import structure.Transform;
import utils.Defuse;
import utils.FileOperation;
import utils.Output;
import utils.ReadAPI;
import utils.Utils;

/*
 * statement-level single line extraction
 */


public class FilterDefuse {
	private static LinkedHashSet<API> apis = new LinkedHashSet<API>();
	private static HashMap<SubTree, SubTree> treePairs = new HashMap<SubTree, SubTree>();
    private static int count = 0;
	
	public static void main (String args[]) throws Exception{
		String path = "J:\\Vulnerability_commit\\";
		String outMode = "json";
		String dataDir = "data\\";
		String numDir = "data_num\\";
		String checkDir = "data_check\\";
		String varDir = "data_var\\";
		if(outMode.equals("txt"))
			FileOperation.delAllFile(dataDir);
		if(outMode.equals("lineNum")) {
			FileOperation.delAllFile(numDir);
			FileOperation.delAllFile(varDir);
			FileOperation.delAllFile(checkDir);
		}
		if(outMode.equals("json")) {
			String jpath = "jsons\\";
			File jFile = new File(jpath);
			if(!jFile.exists())
				jFile.mkdirs();
			if(jFile.listFiles().length!=0&&outMode.equals("json"))
				throw new Exception("pls clean dir!");
		}		
		File rootFile = new File(path);
		File[] fileList = rootFile.listFiles();
		FilterDefuse defuse = new FilterDefuse();
		for(int i=0;i<fileList.length;i++) {
			String cpPath = fileList[i].getAbsolutePath();
			defuse.collectDiffwithDefUse(cpPath, outMode, true, false, "");
		}	
		System.out.println("DuplicateNum:"+count);
	}
	
	public void collectDiffwithDefUse(String path, String outMode, 
		Boolean ifOnlyChange, Boolean ifPrintDef, String filter) throws Exception {//获取DefUse	
		Split sp = new Split();			
		ArrayList<Migration> migrats = FileFilter.readMigrationList(path, filter);
		String repoName = "";
		if(migrats.size()!=0)
			repoName = migrats.get(0).getRepoName();
		else
			return;
		String txtName = (new File(path)).getName();
		String jpath = "jsons\\";
		File jFile = new File(jpath);
		if(!jFile.exists())
			jFile.mkdirs();

		String outPath = "data\\defuse_"+txtName+".txt";
		String outPath1 = "data\\src-val_"+txtName+".txt";
		String outPath2 = "data\\tgt-val_"+txtName+".txt";
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
			ArrayList<SubTree> changedSTree = new ArrayList<>();
			HashMap<String, LinkedList<Action>> actions = Utils.collectAction(sTC, dTC, mappings);					
			ArrayList<Integer> srcActIds = Utils.collectSrcActNodeIds(sTC, dTC, mappings, actions);
//			if(srcActIds.contains(2333)) {
//				System.out.println("indeed");
//			}else {
//				System.out.println("not contains");
//			}
			ArrayList<Definition> defs1 = defuse.getDef(sTC, "src");//先计算action,再收集defs
	        ArrayList<Definition> defs2 = defuse.getDef(dTC, "tgt");	        
	        HashMap<String, ArrayList<Definition>> defMap1 = defuse.transferDefs(defs1);
	        HashMap<String, ArrayList<Definition>> defMap2 = defuse.transferDefs(defs2);
	        HashMap<ITree, ArrayList<Definition>> blockMap1 = defuse.transferBlockMap(defs1, sTC, "src");
	        HashMap<ITree, ArrayList<Definition>> blockMap2 = defuse.transferBlockMap(defs2, dTC, "tgt");        
	        ArrayList<SubTree> sub1 = sp.splitSubTree(sTC, miName_src);//Subtree中割裂过block,注意
	        ArrayList<SubTree> sub2 = sp.splitSubTree(dTC, miName_src);//先计算action,再split ST
			HashMap<Integer, HashMap<String, String>> usedDefs2Map = new HashMap<Integer, HashMap<String, String>>();
	        
			System.out.println("def1size:"+defs1.size());
	        System.out.println("def2size:"+defs2.size());
	        System.out.println("def1Mapsize:"+defMap1.size());
	        System.out.println("def2Mapsize:"+defMap2.size());
	        System.out.println("block1size:"+blockMap1.size());
	        System.out.println("block2size:"+blockMap2.size());
	        
//	        for(SubTree st : sub1) {
//	        	ITree root = st.getRoot();
//	        	System.err.println("StID:"+root.getId());	             	       		       	
//	        }
	        if(ifOnlyChange==true) {
				for(SubTree st : sub1) {
					ITree t = st.getRoot();
//					System.out.println("StID:"+t.getId());
					List<ITree> nodeList = t.getDescendants();
					nodeList.add(t);
//					for(ITree node : nodeList) {
//						int id = node.getId();
//						System.out.println("nodeid:"+id);
//					}
		        	for(ITree node : nodeList) {
		        		int id = node.getId();		        		
		        		if(srcActIds.contains(id)) {
		        			changedSTree.add(st);
//		        			System.out.println("find a action subtree!"+t.getId());
		        			break;
		        		}
		        	}
				}//先找包含action的subtree	
	        }else {
	        	changedSTree = sub1;
	        }
			
	        System.out.println("subSize:"+sub1.size());	
			System.out.println("changeSize:"+changedSTree.size());	
			for(SubTree srcT : changedSTree) {					
//				System.out.println("===================");
				HashMap<String, String> replaceMap_src = new HashMap<String, String>();
				HashMap<String, String> replaceMap_dst = new HashMap<String, String>();
				HashSet<Definition> usedDefs1 = new HashSet<Definition>();				
				HashSet<Definition> usedDefs2 = new HashSet<Definition>();				
				ITree sRoot = srcT.getRoot();
//				System.out.println("CheckMapping "+sRoot.getId()+":"+srcT.getMiName());
				String src = Output.subtree2src(srcT);	
				
	    		if(outMode=="txt"&&(src.contains("error")&&src.contains("situation"))) {
	    			errCount++;
    				continue;		    				    			
	    		}
	    			
	    		Boolean same = false;
				ArrayList<ITree> leaves1 = new ArrayList<ITree>();				
				Utils.traverse2Leaf(sRoot, leaves1);
				int labelCount = 0;
				for(ITree leaf : leaves1) {
					String label = leaf.getLabel();
//					System.out.println("label:"+label);
					if(!label.equals(""))
						labelCount++;
					String type = sTC.getTypeLabel(leaf);
					if(type.equals("literal")) {
						leaf.setLabel(Output.deleteLiteral(leaf, sTC));
//						if(label.contains("\"")) 
//							replaceMap_src.put("@@"+label+"@@", "None");
//						else
//							replaceMap_src.put("$$"+label+"$$", "num");//replace Literal
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
				
				SubTree dstT = defuse.checkMapping(srcT, mappings, dTC, sub2);
				if(dstT==null)
					continue;//子树没有对应子树，被删除
				ITree dRoot = dstT.getRoot();
//	    		System.out.println(sRoot.getId()+"->"+dRoot.getId());	    		
	    		
				List<ITree> nodes1 = sRoot.getDescendants();
				nodes1.add(sRoot);//srcT所有节点
				List<ITree> nodes2 = dRoot.getDescendants();
				nodes2.add(dRoot);//dstT所有节点
				int sBeginLine = 0;
				int sLastLine = 0;
				int sBeginCol = 0;
				int sLastCol = 0;
				int dBeginLine = 0;
				int dLastLine = 0;
				int dBeginCol = 0;
				int dLastCol = 0;
				if(outMode=="lineNum") {
					for(ITree node : nodes1) {
						int line = node.getLine();
						int col = node.getColumn();
						int lastLine = node.getLastLine();
						int lastCol = node.getLastColumn();
						String type = sTC.getTypeLabel(node);
						if(!type.equals("block")) {//跳过block节点，该节点会导致lastline为大括号结束位置
							if(sBeginLine==0&&line!=0) {
								sBeginLine = line;
							}else if(line < sBeginLine&&line!=0) {
								sBeginLine = line;
							}//begin line
							if(sBeginCol==0&&col!=0) {
								sBeginCol = col;
							}else if(col < sBeginCol&&col!=0) {
								sBeginCol = col;
							}//begin col
							if(lastLine > sLastLine) {
								sLastLine = lastLine;
							}//last line
							if(lastCol > sLastCol) {
								sLastCol = lastCol;
							}//last col
//							if(sRoot.getId()==16329) {
//								System.err.println(node.getId()+type+":"+line+","+lastLine+","+col+","+lastCol);
//							}
						}else if(type.equals("empty_stmt"))//特殊情况	
							continue;
					}									
					for(ITree node : nodes2) {
						int line = node.getLine();
						int col = node.getColumn();
						int lastLine = node.getLastLine();
						int lastCol = node.getLastColumn();
						String type = sTC.getTypeLabel(node);
						if(!type.equals("block")) {//跳过block节点，该节点会导致lastline为大括号结束位置
							if(dBeginLine==0&&line!=0) {
								dBeginLine = line;
							}else if(line < dBeginLine&&line!=0) {
								dBeginLine = line;
							}//begin line
							if(dBeginCol==0&&col!=0) {
								dBeginCol = col;
							}else if(col < dBeginCol&&col!=0) {
								dBeginCol = col;
							}//begin col
							if(dLastLine < lastLine) {
								dLastLine = lastLine;
							}//last line
							if(dLastCol < lastCol) {
								dLastCol = lastCol;
							}//last col
						}else if(type.equals("empty_stmt"))//特殊情况	
							continue;						
					}
				}
				
				if(usedDefs2Map.get(dRoot.getId())==null) {
					ArrayList<ITree> leaves2 = new ArrayList<ITree>();
					Utils.traverse2Leaf(dRoot, leaves2);
					for(ITree leaf : leaves2) {
						String label = leaf.getLabel();
						String type = dTC.getTypeLabel(leaf);
						if(type.equals("literal")) {
							leaf.setLabel(Output.deleteLiteral(leaf, dTC));
//							if(label.contains("\"")) 
//								replaceMap_dst.put("@@"+label+"@@", "None");
//							else
//								replaceMap_dst.put("$$"+label+"$$", "num");//replace Literal
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
//										System.out.println(leaf.getId()+","+def2.getDefLabelID());
//										System.out.println(def2.getType()+","+def2.getVarName());
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
					}
					usedDefs2Map.put(dRoot.getId(), replaceMap_dst);
				}else {
					same = true;
					replaceMap_dst = usedDefs2Map.get(dRoot.getId());
				}//发现有不同subtree_src映射到同一subTree_dst情况，matching算法问题暂时无法解决
				 //处理措施为直接复制一份replaceMap_dst，跳过				
				
				src = Output.subtree2src(srcT);
	    		String tar = Output.subtree2src(dstT);
	    		if(outMode=="txt") {	    			
		    		if(tar.contains("error")&&tar.contains("situation")) {
		    			errCount++;
		    			continue;
		    		}
		    		if(((float)src.length()/(float)tar.length())<0.25||((float)tar.length()/(float)src.length())<0.25) {
		    			continue;
		    		}//长度相差太多的句子直接跳过
		    		if(ifOnlyChange==true) {
		    			if(src.equals(tar))
			    			continue;
		    		}//去掉相同句子
	    		}	    			    		

				if(same==false)
					continue;//no leaf is the same
				if(outMode=="txt") {
					if(ifPrintDef==true) {
						String buffer = getDefTxt(usedDefs1, usedDefs2, sTC, dTC, srcT, dstT);
					    printTxt(outPath, outPath1, outPath2, buffer);
					}else {
						String buffer = getText(sTC, dTC, srcT, dstT);
						printTxt(outPath, outPath1, outPath2, buffer);
					}
				}else if(outMode=="json") {
					srcT = absTree(srcT);
					dstT = absTree(dstT);
					TreeContext st = defuse.buildTC(srcT);
					TreeContext dt = defuse.buildTC(dstT);
					if(checkSim(st, dt)==false) {
						printJson(jpath, st, dt);
						treePairs.put(srcT, dstT);
					}					
				}else if(outMode=="lineNum") {
//					if(sRoot.getId()==806) {
//						for(Map.Entry<String, String> entry : replaceMap_src.entrySet()) {
//							String varName = entry.getKey();
//							String label = entry.getValue();
//							System.err.println(varName+"->"+label+";");
//						}
//					}
					String diffLine_check = "STID:"+srcT.getRoot().getId()+","
							+sBeginLine+","+sLastLine+","+sBeginCol+","+sLastCol+"->"
							+dBeginLine+","+dLastLine+","+dBeginCol+","+dLastCol;						
					String diffLine = miName_src+";"+miName_dst+";"
							+sBeginLine+","+sLastLine+","+sBeginCol+","+sLastCol+"->"
							+dBeginLine+","+dLastLine+","+dBeginCol+","+dLastCol;							
					printLineNum(outPath3, outPath4, outPath5, diffLine, replaceMap_src, replaceMap_dst);
					printLineCheck(outPath6, diffLine_check);
				}
			}				
		}			
		System.out.println("errCount:"+errCount);
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
	
	static private SubTree absTree(SubTree st) {
		ITree root = st.getRoot();
		List<ITree> desList = root.getDescendants();
		for(ITree node : desList) {
			String label = node.getLabel();
			try {
				Integer.parseInt(label);
				node.setLabel("num");
			} catch (Exception e) {
				// TODO: handle exception
			}
		}
		return st;
	}
	
	static private Boolean checkSim(TreeContext tc1, TreeContext tc2) {
		Boolean full_sim = false;
		Defuse defuse = new Defuse();
		for(Map.Entry<SubTree, SubTree> entry : treePairs.entrySet()) {
			SubTree st1 = entry.getKey();
			SubTree st2 = entry.getValue();
			try {
				TreeContext tc1_used = defuse.buildTC(st1);
				TreeContext tc2_used = defuse.buildTC(st2);
				Matcher m1 = Matchers.getInstance().getMatcher(tc1.getRoot(), tc1_used.getRoot());
	            m1.match();
	            MappingStore mappings1 = m1.getMappings();
	            ActionGenerator g1 = new ActionGenerator(tc1.getRoot(), tc1_used.getRoot(), mappings1); 
	            List<Action> actions1 = g1.generate();
				Matcher m2 = Matchers.getInstance().getMatcher(tc2.getRoot(), tc2_used.getRoot());
	            m2.match();
	            MappingStore mappings2 = m2.getMappings();
	            ActionGenerator g2 = new ActionGenerator(tc2.getRoot(), tc2_used.getRoot(), mappings2); 
	            List<Action> actions2 = g2.generate();
	            
	            if(actions1.size()==0&&actions2.size()==0) {
	            	full_sim = true;
	            	count++;
	            	return full_sim;
	            }
			} catch (Exception e) {
				continue;// TODO: handle exception
			}
		}
		return full_sim;
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
	
	static private void printJson(String jpath, TreeContext srcT, TreeContext dstT) throws Exception {
		File dir = new File(jpath);
		if(!dir.exists()) {
			dir.mkdirs(); 
		}
		File[] files = dir.listFiles();
		int fileSize = files.length;
		if(srcT!=null) {
			String out = jpath+"pair"+String.valueOf(fileSize/2)+"_src.json";
			BufferedWriter wr = new BufferedWriter(new FileWriter(new File(out)));
			wr.append(TreeIoUtils.toJson(srcT).toString());
			wr.flush();
			wr.close();
		}
		if(dstT!=null) {
			String out1 = jpath+"pair"+String.valueOf(fileSize/2)+"_tgt.json";
			BufferedWriter wr1 = new BufferedWriter(new FileWriter(new File(out1)));
			wr1.append(TreeIoUtils.toJson(dstT).toString());
			wr1.flush();
			wr1.close();
		}
	}
	
}
