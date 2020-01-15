package collect;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
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
import structure.Definition;
import structure.Migration;
import structure.SubTree;
import structure.Transform;
import utils.Defuse;
import utils.Output;
import utils.ReadAPI;
import utils.Utils;

public class FilterDefuse {
	private static LinkedHashSet<API> apis = new LinkedHashSet<API>();
	public static ArrayList<ITree> blocks1 = new ArrayList<ITree>();
	public static ArrayList<ITree> blocks2 = new ArrayList<ITree>();
	public static HashMap<ITree, ArrayList<ITree>> parBlockMap1 = new HashMap<ITree, ArrayList<ITree>>();
	public static HashMap<ITree, ArrayList<ITree>> parBlockMap2 = new HashMap<ITree, ArrayList<ITree>>();
	
	public static void main (String args[]) throws Exception{
		String path = "J:\\Vulnerability_commit\\";
		File rootFile = new File(path);
		File[] fileList = rootFile.listFiles();
		FilterDefuse defuse = new FilterDefuse();
		for(int i=0;i<fileList.length;i++) {
			String cpPath = fileList[i].getAbsolutePath();
			defuse.collectDiffwithDefUse(cpPath, "lineNum", true, false, "");
		}		
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
		int count = 0;//计数
		String txtName = (new File(path)).getName();
		String jpath = "jsons\\"+txtName+"\\";
		File jFile = new File(jpath);
		if(!jFile.exists())
			jFile.mkdirs();
		if(jFile.listFiles().length!=0&&outMode.equals("json"))
			throw new Exception("pla clean dir!");
		File output = new File("data\\defuse_"+txtName+".txt");
		BufferedWriter wr = new BufferedWriter(new FileWriter(output));
		File output1 = new File("data\\src-val_"+txtName+".txt");
		File output2 = new File("data\\tgt-val_"+txtName+".txt");		
		BufferedWriter wr1 = new BufferedWriter(new FileWriter(output1));
		BufferedWriter wr2 = new BufferedWriter(new FileWriter(output2));
		File output3 = new File("data_num\\"+repoName+"_"+txtName+".txt");
		BufferedWriter wr3 = new BufferedWriter(new FileWriter(output3));
//		ArrayList<String> includes1 = readIncludes("src");
//		ArrayList<String> includes2 = readIncludes("dst");
//		for(String include : includes1) {
//			wr1.append(include);
//			wr1.newLine();
//			wr1.flush();
//		}
//		for(String include : includes2) {
//			wr2.append(include);
//			wr2.newLine();
//			wr2.flush();
//		}
		
		int errCount = 0;
		for(Migration migrat : migrats) {
			blocks1.clear();
			blocks2.clear();
			parBlockMap1.clear();
			parBlockMap2.clear();
			String miName = migrat.getMiName();
			TreeContext sTC = migrat.getSrcT();
			TreeContext dTC = migrat.getDstT();
			MappingStore mappings = migrat.getMappings();
			
			System.out.println("Analyse:"+miName);
			Matcher m = Matchers.getInstance().getMatcher(sTC.getRoot(), dTC.getRoot());
	        m.match();
			ArrayList<SubTree> changedSTree = new ArrayList<>();
			HashMap<String, LinkedList<Action>> actions = Utils.collectAction(sTC, dTC, mappings);					
			ArrayList<Integer> srcActIds = Utils.collectSrcActNodeIds(sTC, dTC, actions);
			ArrayList<Definition> defs1 = getDef(sTC, "src");//先计算action,再收集defs
	        ArrayList<Definition> defs2 = getDef(dTC, "tgt");
	        HashMap<String, ArrayList<Definition>> defMap1 = transferDefs(defs1);
	        HashMap<String, ArrayList<Definition>> defMap2 = transferDefs(defs2);
	        HashMap<ITree, ArrayList<Definition>> blockMap1 = transferBlockMap(defs1, sTC, "src");
	        HashMap<ITree, ArrayList<Definition>> blockMap2 = transferBlockMap(defs2, dTC, "tgt");
			ArrayList<SubTree> sub1 = sp.splitSubTree(sTC, miName);//Subtree中割裂过block,注意
			sp.splitSubTree(dTC, miName);//先计算action,再split ST
	        
			System.out.println(defs1.size());
	        System.out.println(defs2.size());
	        System.out.println(defMap1.size());
	        System.out.println(defMap2.size());
	        System.out.println(blockMap1.size());
	        System.out.println(blockMap2.size());
	        
//	        for(SubTree st : sub1) {
//	        	ITree root = st.getRoot();
//	        	System.out.println("StID:"+root.getId());	             	       		       	
//	        }
	        if(ifOnlyChange==true) {
				for(SubTree st : sub1) {
					ITree t = st.getRoot();
					List<ITree> nodeList = t.getDescendants();
					nodeList.add(t);
		        	for(ITree node : nodeList) {
		        		int id = node.getId();
		        		if(srcActIds.contains(id)) {
		        			changedSTree.add(st);
//		        			System.out.println("find a action subtree!");
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
				HashSet<Definition> usedDefs1 = new HashSet<Definition>();
				HashSet<Definition> usedDefs2 = new HashSet<Definition>();
				ITree sRoot = srcT.getRoot();
//				System.out.println("CheckMapping "+sRoot.getId()+":"+srcT.getMiName());
				String src = Output.subtree2src(srcT);	
				
	    		if(outMode=="txt") {
	    			if(src.contains("error")&&src.contains("situation")) {
	    				errCount++;
	    				continue;
	    			}		    				    			
	    		}
	    			
	    		Boolean same = false;
				ArrayList<ITree> leaves1 = new ArrayList<ITree>();				
				Utils.traverse2Leaf(sRoot, leaves1);
				int labelCount = 0;
				for(ITree leaf : leaves1) {
					String label = leaf.getLabel();
//					System.out.println("label"+label);
					if(!label.equals(""))
						labelCount++;
					String type = sTC.getTypeLabel(leaf);
					if(type.equals("literal")) {
						leaf.setLabel(Output.deleteLiteral(leaf, sTC));
					}					
					ArrayList<Definition> stringList = defMap1.get(label);
					if(stringList!=null) {
						ITree parBlock = searchBlock(leaf, sTC);
						ArrayList<Definition> blockList = blockMap1.get(parBlock);
						for(Definition def1 : stringList) {
							if(blockList!=null) {
								if(blockList.contains(def1)) {
									if(leaf.getId()>def1.getDefLabelID()) {
										leaf.setLabel("var");
										usedDefs1.add(def1);									
									}											
								}
							}							
							if(def1.getDefLabelID()==leaf.getId()) {
								leaf.setLabel("var");
							}
//							System.out.println(leaf.getId()+","+def1.getDefLabelID());
//							System.out.println(def1.getType()+","+def1.getVarName());
						}
					}
				}
				if(labelCount<=1)
					continue;
				
				SubTree dstT = checkMapping(srcT, mappings, dTC);
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
						System.out.println("lastLine:"+lastLine);
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
					}									
					for(ITree node : nodes2) {
						int line = node.getLine();
						int col = node.getColumn();
						int lastLine = node.getLastLine();
						int lastCol = node.getLastColumn();
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
					}
				}
				
				ArrayList<ITree> leaves2 = new ArrayList<ITree>();
				Utils.traverse2Leaf(dRoot, leaves2);
				for(ITree leaf : leaves2) {
					String label = leaf.getLabel();
					String type = dTC.getTypeLabel(leaf);
					if(type.equals("literal")) {
						leaf.setLabel(Output.deleteLiteral(leaf, dTC));
					}	
					ArrayList<Definition> stringList = defMap2.get(label);
					if(stringList!=null) {
						ITree parBlock = searchBlock(leaf, dTC);
						ArrayList<Definition> blockList = blockMap2.get(parBlock);
						for(Definition def2 : stringList) {
							if(blockList!=null) {
								if(blockList.contains(def2)) {
									if(leaf.getId()>def2.getDefLabelID()) {
										usedDefs2.add(def2);
										leaf.setLabel("var");	
									}
//									System.out.println(leaf.getId()+","+def2.getDefLabelID());
//									System.out.println(def2.getType()+","+def2.getVarName());
								}
							}							
							if(def2.getDefLabelID()==leaf.getId()) {
								leaf.setLabel("var");
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
				src = Output.subtree2src(srcT);
	    		String tar = Output.subtree2src(dstT);
	    		if(outMode=="txt") {	    			
		    		if(tar.contains("error")&&tar.contains("situation")) {
		    			errCount++;
		    			continue;
		    		}		    			
	    		}
	    		if(ifOnlyChange==true) {
	    			if(src.equals(tar))
		    			continue;
	    		}
	    		
	    		if(((float)src.length()/(float)tar.length())<0.25||((float)tar.length()/(float)src.length())<0.25) {
	    			continue;
	    		}//长度相差太多的句子直接跳过
				if(same==false)
					continue;//no leaf is the same
				if(outMode=="txt") {
					if(ifPrintDef==true) {
						String buffer = "";
						String buffer1 = "";
						String buffer2 = "";
						for(Definition def : usedDefs1) {
							SubTree st = new SubTree(def.getRoot(), sTC, 0, "");
							String stat = Output.subtree2src(st);
							buffer = buffer +stat+" ; ";
							buffer1 = buffer1 +stat+" ; ";
						}
						src = Output.subtree2src(srcT);
						buffer = buffer + src+"\t";
						buffer1 += src;
						for(Definition def : usedDefs2) {
							SubTree st = new SubTree(def.getRoot(), dTC, 0, "");
							String stat = Output.subtree2src(st);
							buffer += stat+" ; ";
							buffer2 += stat+" ; ";
						}
						tar = Output.subtree2src(dstT);
						buffer += tar;
						buffer2 += tar;
						if(buffer.contains("error")&&buffer.contains("situation"))
							continue;
						wr.append(buffer);
						wr1.append(buffer1);
						wr2.append(buffer2);
						wr1.newLine();
						wr1.flush();
						wr2.newLine();
						wr2.flush();
						wr.newLine();
						wr.flush();
					}else {
			    		String buffer = src+"\t"+tar;
						if(buffer.contains("error")&&buffer.contains("situation"))
							continue;
						wr.append(buffer);
						wr1.append(src);
						wr2.append(tar);
						wr1.newLine();
						wr1.flush();
						wr2.newLine();
						wr2.flush();
						wr.newLine();
						wr.flush();
					}				
				}else if(outMode=="json") {
					TreeContext st = buildTC(srcT);
					TreeContext dt = buildTC(dstT);
					printJson(jpath, count, st, dt);
					count++;
				}else if(outMode=="lineNum") {
					wr3.append(migrat.getMiName()+":"+sBeginLine+","+sLastLine+","
							+sBeginCol+","+sLastCol+"->");
					wr3.append(dBeginLine+","+dLastLine+","
							+dBeginCol+","+dLastCol);
					wr3.newLine();
					wr3.flush();
				}
			}			
		}	
		wr.close();
		wr1.close();
		wr2.close();
		wr3.close();
		System.out.println("errCount:"+errCount);
	}
	
	
	static private ArrayList<ArrayList<SubTree>> searchQueue(Queue<SubTree> qe, ArrayList<SubTree> changedSTree, HashMap<String, ArrayList<Integer>> sDefMap) throws Exception {		
		ArrayList<ArrayList<SubTree>> resultList = new ArrayList<ArrayList<SubTree>>();
		HashMap<Integer, ArrayList<SubTree>> resultMap = new HashMap<Integer, ArrayList<SubTree>>();
		for(SubTree st : qe) {
			TreeContext tc = st.getTC();
			if(!changedSTree.contains(st))
				continue;//只考虑需要修改的语句
			ITree sRoot = st.getRoot();
			List<ITree> sLeaves = new ArrayList<ITree>();
			Utils.traverse2Leaf(sRoot, sLeaves);
			for(ITree leaf : sLeaves) {
				String type = tc.getTypeLabel(leaf);
				if(type.equals("name")) {
					String label = leaf.getLabel();
					ArrayList<Integer> map = sDefMap.get(label);
					if(map!=null) {
						if(map.size()==1) {
							int defID = map.get(0);
							if(resultMap.get(defID)==null) {
								ArrayList<SubTree> stList = new ArrayList<SubTree>();
								stList.add(st);
								resultMap.put(defID, stList);
							}else {
								resultMap.get(defID).add(st);
							}
						}else {//发现有多个def line同一个关键字的情况，可能发生在不同的method
							Collections.sort(map);
							ArrayList<Integer> subMap = new ArrayList<Integer>();
							for(int id : map) {//只取该条语句之前的subtree,抛弃掉之后的
								if(id<sRoot.getId())
									subMap.add(id);
							}
							if(subMap.size()==0)
								continue;//好像有defid全在rootid之后的情况，跳过
							int defID = subMap.get(subMap.size()-1);//取离该def最近的
							if(resultMap.get(defID)==null) {
								ArrayList<SubTree> stList = new ArrayList<SubTree>();
								stList.add(st);
								resultMap.put(defID, stList);
							}else {
								resultMap.get(defID).add(st);
							}
							System.out.println("mLine");
						}
					}
				}				
			}
		}
		for(Map.Entry<Integer, ArrayList<SubTree>> entry : resultMap.entrySet()) {
			ArrayList<SubTree> list = entry.getValue();
			if(list.size()>=2) {
				resultList.add(list);
			}
		}
		return resultList;
	}//搜索队列，找到有data dependency的语句
	
	private static Definition searchPramDef(ArrayList<Definition> defs, ITree node) {
		for(Definition def : defs) {
			ITree root = def.getRoot();
			if(root.equals(node))
				return def;
		}
		return null;
	}
	
	public ITree searchBlock(ITree node, TreeContext tc) {
		List<ITree> pars = node.getParents();
		for(ITree par : pars) {
			if(tc.getTypeLabel(par).equals("block")) {
				return par;
			}
		}
		return null;
	}
	
	private static SubTree checkMapping(SubTree st, MappingStore map, TreeContext tc2) throws Exception {
		ITree root = st.getRoot();
		ITree dstRoot = map.getDst(root);
		List<ITree> desList = root.getDescendants();
		ArrayList<ITree> seeds = new ArrayList<ITree>();
		Boolean sameLeaf = false;
		for(ITree node : desList) {
			ITree dst = map.getDst(node);
			if(dst!=null) {
				if(node.isLeaf()&&dst.isLeaf()) {
					if(legalLebelMap(node, dst)) {
						sameLeaf = true;
					}						
				}
				seeds.add(dst);
			}
		}
		System.out.println("SameLeaf:"+sameLeaf);
		System.out.println("Seeds:"+seeds.size());
		if(sameLeaf==false)
			return null;
		if(seeds.size()==0)
			return null;
		if(dstRoot==null) {
			ITree seed = seeds.get(0);
			List<ITree> pars = seed.getParents();
			System.out.println(pars.size());
			for(ITree par : pars) {	
				System.out.println(tc2.getTypeLabel(par));
				if(Utils.ifSRoot(tc2.getTypeLabel(par))) {
					dstRoot = par;
					break;
				}
			}
			if(dstRoot==null)
				return null;//有找不到SRoot的情况
			List<ITree> desList2 = dstRoot.getDescendants();
			for(ITree node : seeds) {
				if(!desList2.contains(node)) {
					return null;
				}
			}//是否允许两个子树中分布有不在这两颗子树内的mapping？
		}

		SubTree dstT = new SubTree(dstRoot, tc2, st.getStNum(), st.getMiName());
		return dstT;		
	}//检查与srcST符合的dstST mapping
	
	private static Boolean legalLebelMap(ITree src, ITree dst) {
		String label1 = src.getLabel();
		String label2 = dst.getLabel();
		Boolean isSame = false;
		if(label1==null||label2==null) {
			System.err.println("error label:"+src.getId());
			return isSame;
		}
		if(label1.equals(label2)&&!label1.equals("::")&&!label2.equals("::"))
			isSame = true;
		if(label1.equals("ros")&&label2.equals("rclcpp"))
			isSame = true;
		if(label1.equals("tf")&&label2.equals("tf2"))
			isSame = true;
		return isSame;
	}//label是否相同的相关规则
	
	public static TreeContext abstraSubTree(SubTree st, HashMap<String, String> varMap) {
		TreeContext origin = st.getTC();
		TreeContext subT = new TreeContext();
		subT.importTypeLabels(origin);
		ITree subRoot = st.getRoot();
		subT.setRoot(subRoot);
		List<ITree> descendants = subRoot.getDescendants();
		for(ITree node : descendants) {
			String label = node.getLabel();
			String type = subT.getTypeLabel(node);
			if (varMap.containsKey(label)) {
				System.out.println("find it!");
				node.setLabel("var");
			}
			if(type.equals("literal")) {
				if (label.contains("\"")) {
					label = "stringliteral";
				}else {
					label = "intliteral";
				}
				node.setLabel(label);
			}
		}
		return subT;
	}
	
	static private TreeContext abstraTotalTC(ArrayList<SubTree> stList, HashMap<String, String> varMap) {
		TreeContext origin = stList.get(0).getTC();
		TreeContext subT = new TreeContext();
		subT.importTypeLabels(origin);
		subT.registerTypeLabel(000, "Block");
		Tree blockRoot = new gumtreediff.tree.Tree(000, null);
		List<ITree> children = new ArrayList<ITree>();
		for(SubTree st : stList) {
			children.add(st.getRoot());
		}
		blockRoot.setChildren(children);
		subT.setRoot(blockRoot);
		List<ITree> descendants = blockRoot.getDescendants();
		for(ITree node : descendants) {
			String label = node.getLabel();
			String type = subT.getTypeLabel(node);
			if (varMap.containsKey(label)) {
				System.out.println("find it!");
				node.setLabel("var");
			}
			if(type.equals("literal")) {
				if (label.contains("\"")) {
					label = "stringliteral";
				}else {
					label = "intliteral";
				}
				node.setLabel(label);
			}
		}
		//创建block节点，输出拼起来的总图，然后把剩下的单行输出
		return subT;
	}
	
	public static TreeContext buildTC(SubTree st) {
		TreeContext origin = st.getTC();
		TreeContext subT = new TreeContext();
		ITree root = st.getRoot();
		subT.importTypeLabels(origin);
		subT.setRoot(root);
		//创建block节点，输出拼起来的总图，然后把剩下的单行输出
		return subT;
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
	
	public ArrayList<Definition> getDef(TreeContext tc, String from) throws Exception {
		ArrayList<Definition> defs = new ArrayList<Definition>();
		HashMap<ITree, ArrayList<ITree>> parBlockMap = new HashMap<ITree, ArrayList<ITree>>();
		ArrayList<ITree> blocks = new ArrayList<ITree>();
		ITree root = tc.getRoot();
		List<ITree> allNodes = root.getDescendants();
		for(ITree node : allNodes) {
			if(tc.getTypeLabel(node).equals("block")) {
				List<ITree> pars = node.getParents();
				ArrayList<ITree> parBlocks = new ArrayList<ITree>();
				for(ITree par : pars) {//search block parents
					String type = tc.getTypeLabel(par);
					if(type.equals("blcok")) {
						parBlocks.add(par);
					}
				}
				parBlockMap.put(node, parBlocks);
				blocks.add(node);		
			}else if(tc.getTypeLabel(node).equals("decl")) {
//				System.out.println("find def: "+node.getId());
				Definition def = new Definition();
				def.setRoot(node);
				Boolean hasName = false;
				List<ITree> children = node.getChildren();
				for(ITree child : children) {
					String type = tc.getTypeLabel(child);
					if(type.equals("type")) {
						String typeName = "";
						List<ITree> typeChilds = child.getChildren();
						for(ITree child1 : typeChilds) {
							if(child1.isLeaf()) {//单label情况
								String label = child1.getLabel();
								typeName = typeName+label;
								if(label==null)
									throw new Exception("check ITree: "+child1.getId());
							}else {
								for(ITree leaf : child1.getChildren()) {
									String label = leaf.getLabel();									
									typeName = typeName+label;
								}
							}
						}
						def.setType(typeName);	
					}else if(type.equals("name")) {
						String label = child.getLabel();
						if(label==null)
							throw new Exception("check ITree: "+child.getId());
						def.setVarName(label);//varName
						def.setDefLabelID(child.getId());
						hasName = true;
					}					
				}
				if(hasName==false) {
					continue;
				}
				List<ITree> pars = node.getParents();
				List<ITree> parBlocks = new ArrayList<ITree>();
				List<ITree> parList = new ArrayList<ITree>();
				Boolean first = true;
				for(ITree par : pars) {//search block parents
					String type = tc.getTypeLabel(par);
					if(type.equals("block")) {
						if(first==true) {
							def.setBlock(par);
							first = false;
						}
						parBlocks.add(par);
					}
					parList.add(par);
				}
				if(parBlocks.size()==0) {
					parBlocks.add(tc.getRoot());
					def.setBlock(tc.getRoot());
				}//全局节点没有父亲block，直接默认block为tc根节点
					
				def.setParBlocks(parBlocks);
				def.setParList(parList);
				defs.add(def);
			}			
		}
		if(from.equals("src")) {
			blocks1 = blocks;
			parBlockMap1 = parBlockMap;
		}else if(from.equals("tgt")) {
			blocks2 = blocks;
			parBlockMap2 = parBlockMap;
		}
		return defs;
	}
	
	public HashMap<ITree, ArrayList<Definition>> transferBlockMap(ArrayList<Definition> defs, TreeContext tc, String from) throws Exception {
		HashMap<ITree, ArrayList<Definition>> blockMap = new HashMap<ITree, ArrayList<Definition>>();
		ArrayList<ITree> blocks = new ArrayList<ITree>();
		if(from.equals("src")) {
			blocks = blocks1;
		}else if(from.equals("tgt")) {
			blocks = blocks2;
		}
		for(ITree block : blocks) {
			ITree parNode = block.getParent();
			String parType = tc.getTypeLabel(parNode);
			List<ITree> pars = block.getParents();
			List<ITree> blockList = new ArrayList<ITree>();
			blockList.add(block);
			for(ITree par : pars) {//search block parents
				String type = tc.getTypeLabel(par);
				if(type.equals("block")) {
					blockList.add(par);
				}
			}
			if(blockList.size()==0)
				throw new Exception("check parBlock: "+block.getId());
			ArrayList<Definition> defList = new ArrayList<Definition>();
			for(Definition def : defs) {
				ITree parBlcok = def.getBlock();
				if(isParameter(def, tc)==false) {//所有非参数且block位于目标block的父亲block列表中的def放入list
					if(blockList.contains(parBlcok)) {
						defList.add(def);
					}
				}else {
					ArrayList<ITree> nextBlocks = searchNextBlocks(def, tc);
					if(nextBlocks.contains(block)) {
						defList.add(def);
					}//参数def只在所有子block中生效
				}
				if(parBlcok.equals(tc.getRoot())) {
					if(isParameter(def, tc)==false) {
						defList.add(def);
					}					
				}//发现有全局变量情况，父亲节点没有root，单独处理，放入所有defList中
			}
			if(parType.equals("function")) {//function parameters
				for(ITree node : parNode.getChildren()) {
					String type = tc.getTypeLabel(node);
					if(type.equals("parameter_list")&&!node.isLeaf()) {
						List<ITree> desendants = node.getDescendants();
						for(ITree child : desendants) {
							if(tc.getTypeLabel(child).equals("decl")) {
								Definition def = searchPramDef(defs, node);
								defList.add(def);
							}
						}
					}
				}
			}
			blockMap.put(block, defList);
		}
		return blockMap;
	}
	
	private static ArrayList<ITree> searchNextBlocks(Definition def, TreeContext tc) throws Exception {
		ITree defRoot = def.getRoot();
		List<ITree> pars = defRoot.getParents();
		ITree func = null;
		if(!isParameter(def, tc))
			throw new Exception("Only used for parameters");
		for(ITree par : pars) {
			String type = tc.getTypeLabel(par);
			if(type.equals("function")||type.equals("constructor")) {
				func = par;
				break;
			}
		}
		if(func==null) {
			func = tc.getRoot();
			System.err.println("疑似全局变量 parsize:"+pars.size());
		}			
			
		List<ITree> des = func.getDescendants();
		ArrayList<ITree> childBlocks = new ArrayList<ITree>();
		for(ITree node : des) {
			String type = tc.getTypeLabel(node);
			if(type.equals("block"))
				childBlocks.add(node);
		}
		return childBlocks;
	}
	
	private static Boolean isParameter(Definition def, TreeContext tc) {
		Boolean isPatameter = false;
		ITree root = def.getRoot();
		ITree par = root.getParent();
		String type = tc.getTypeLabel(par);
		if(type.equals("parameter")) {
			isPatameter = true;
			return isPatameter;
		}else {
			return isPatameter;
		}
	}
	
	public HashMap<String, ArrayList<Definition>> transferDefs(ArrayList<Definition> defs) {
		HashMap<String, ArrayList<Definition>> defMap = new HashMap<String, ArrayList<Definition>>();
		for(Definition def : defs) {
			String var = def.getVarName();
			if(defMap.get(var)==null) {
				ArrayList<Definition> list = new ArrayList<Definition>();
				list.add(def);
				defMap.put(var, list);
			}else {
				defMap.get(var).add(def);
			}
		}
		return defMap;
	}
	
	private static ArrayList<String> readIncludes(String from) throws Exception {
		ArrayList<String> includes = new ArrayList<String>();
		String path = "tmp//includes.txt";
		File file = new File(path);
		BufferedReader br = new BufferedReader(new FileReader(file));
		String tmpline = "";
		while((tmpline=br.readLine())!=null) {
			String include = "";
			if(from=="src") {
				include = tmpline.split("\t")[0];
			}else if(from=="dst") {
				include = tmpline.split("\t")[1];
			}
			includes.add(include);
		}
		br.close();
		return includes;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
