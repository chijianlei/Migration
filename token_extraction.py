import subprocess
import logging
import understand
import sys
import os


def create_udb(udb_path, language, project_root):
    try:
        output = subprocess.check_output(
            "und create -db {udb_path} -languages {lang} add {project} analyze".format(udb_path=udb_path, lang=language, project=project_root),
            shell=True)
        logging.info(output)
    except subprocess.CalledProcessError as e:
        logging.exception(e.output)
        logging.fatal("udb creation failed")
        raise Exception


def normalization(token, defline):
    defs = defline.split(";")
    if len(defs) == 0:
        return token  # no def exists
    else:
        defs = defs[:-1]  # delete the last ";", it's useless
    for definition in defs:
        tmps = definition.split("->")
        var = tmps[0]
        replace_label = tmps[1]
        if token == var:
            return "var"
    return token


dataPath = "D:\\workspace\\Pycharm\\Understand_analysis\\data_num1\\"
defPath = "D:\\workspace\\Pycharm\\Understand_analysis\\data_var1\\"
gitRoot = "J:\\git_repo\\"
cpRoot = "J:\\Vulnerability_commit\\"
files = os.listdir(dataPath)
def_files = os.listdir(defPath)
for txtFile in files:
    txtName = txtFile.split(".")[0]
    srcName = txtName + "_src.txt"
    srcName1 = txtName + "_token_src.txt"
    dstName = txtName+"_dst.txt"
    dstName1 = txtName + "_token_dst.txt"
    src_defPath = defPath+txtName + "_defs_src.txt"
    dst_defPath = defPath+txtName + "_defs_dst.txt"
    txt = open(dataPath + txtFile, "r")
    txt_srcDef = open(src_defPath, "r")
    txt_dstDef = open(src_defPath, "r")
    lines = txt.readlines()
    lines_srcDef = txt_srcDef.readlines()
    lines_dstDef = txt_dstDef.readlines()
    repoName = txtFile.split("_")[0]
    cpName = txtFile.split("_")[1].split(".")[0]

    gitPath = gitRoot+repoName+"\\"
    diffPath = cpRoot+cpName+"\\diffs.txt"
    diffFile = open(diffPath, "r")
    diffLines = diffFile.readlines()
    old_commit = diffLines[1].split(";")[0]
    new_commit = diffLines[1].split(";")[1]
    os.chdir(gitPath)

    fileName = ""
    startLine_src = 0
    endLine_src = 0
    startCol_src = 0
    endCol_src = 0
    startLine_dst = 0
    endLine_dst = 0
    startCol_dst = 0
    endCol_dst = 0
    if len(lines) != 0:
        src = open("D:\\workspace\\Pycharm\\Understand_analysis\\seqs\\"+srcName, "w")
        # src1 = open("D:\\workspace\\Pycharm\\Understand_analysis\\seqs\\"+srcName1, "w")
        dst = open("D:\\workspace\\Pycharm\\Understand_analysis\\seqs\\"+dstName, "w")
        # dst1 = open("D:\\workspace\\Pycharm\\Understand_analysis\\seqs\\"+dstName1, "w")
        os.system("git checkout " + old_commit)
        old_path = "J:\\test\\old.udb"
        # create_udb(old_path, "java", gitPath)
        db = understand.open(old_path)
        lineNum = 0
        for line in lines:
            defLine_src = lines_srcDef[lineNum]  # the defLine_src in the same lineNum
            # J:\Vulnerability_commit\cp157\7acfa2fbb86f5d061ed03fdf1a4a8f0876c94cab\prov\src\main\java\org\bouncycastle\jcajce\provider\asymmetric\dh\IESCipher.java;J:\Vulnerability_commit\cp157\9385b0ebd277724b167fe1d1456e3c112112be1f\prov\src\main\java\org\bouncycastle\jcajce\provider\asymmetric\dh\IESCipher.java;56,57,1,23->56,57,1,23
            longName_src = line.split(";")[0]
            print("longName:", longName_src)
            tmps = longName_src.split("\\")
            fileName = tmps[len(tmps) - 1]
            exact_longName = ""
            begin_index = tmps.index("src")
            tmps = tmps[begin_index:len(tmps)]
            for tmp in tmps:
                exact_longName += tmp+"\\"
            exact_longName = exact_longName[:-1]
            print("exactName:", exact_longName)

            startLine_src = int(line.split(";")[2].split("->")[0].split(",")[0])
            endLine_src = int(line.split(";")[2].split("->")[0].split(",")[1])
            startCol_src = int(line.split(";")[2].split("->")[0].split(",")[2])
            endCol_src = int(line.split(";")[2].split("->")[0].split(",")[3])
            findFile = False
            begin = False  # in some cases, statements will begin with irrelevant lexeme
            print(startLine_src, endLine_src, startCol_src, endCol_src)
            for file in db.ents("File"):
                if exact_longName in file.longname():
                    print("find file:", fileName, file.longname())
                    lexemes = file.lexer().lexemes(startLine_src, endLine_src)
                    start_lexeme = file.lexer().lexeme(startLine_src, startCol_src-1)
                    type_exist = True  # in some cases, lexeme type is none
                    if start_lexeme is not None:
                        start_text = start_lexeme.text()
                        start_token = start_lexeme.token()
                        print("start_text:" + start_text)
                    else:
                        type_exist = False
                        print("error type!")
                    size = len(lexemes)
                    count = 0
                    fullText = ""
                    for lexeme in lexemes:
                        count += 1
                        if type_exist is True:
                            if (lexeme.text() != start_text or lexeme.token() != start_token) and begin is False:
                                continue
                            elif lexeme.text() == start_text or lexeme.token() == start_token:
                                begin = True
                        else:
                            continue
                        if lexeme.token() == "Comment":
                            continue  # skip the comment
                        if lexeme.token() == "Whitespace":
                            continue  # skip whitespaces in the beginning
                        if lexeme.token() == "Newline":
                            continue
                        text = str(lexeme.text())
                        if lexeme.token() == "Literal":
                            text = "num"  # replace Literal
                        if lexeme.token() == "String":
                            text = "\"\""  # replace String literal
                        text = normalization(text, defLine_src)  # normalization
                        text = text + " "
                        if count == size-1:
                            text = text.replace("}", "")
                            text = text.replace("{", "")
                            text = text.replace(";", "")  # delete { } and ; in the last token
                            # text = text.rstrip()
                        fullText += text
                        print(text, end="")
                    # for lexeme in lexemes:
                    #     src1.write(lexeme.text()+"("+lexeme.token()+")")
                    findFile = True
                    # fullText = normalization(fullText, defLine_src)
                    src.write(fullText)
            lineNum += 1
            print("\r\n-----------")
            src.write("\n------\n")
            # src1.write("------\n")
            if findFile is False:
                raise Exception

        os.system("git checkout " + new_commit)
        new_path = "J:\\test\\new.udb"
        # create_udb(new_path, "java", gitPath)
        db = understand.open(new_path)
        lineNum = 0
        for line in lines:
            defLine_dst = lines_dstDef[lineNum]  # the defLine_dst in the same lineNum
            # example:SimpleBindRequestTestCase.java:37,38,1,39->38,39,1,39
            longName_dst = line.split(";")[1]
            print("longName:", longName_dst)
            tmps = longName_dst.split("\\")
            fileName = tmps[len(tmps) - 1]
            exact_longName = ""
            begin_index = tmps.index("src")
            tmps = tmps[begin_index:len(tmps)]
            for tmp in tmps:
                exact_longName += tmp + "\\"
            exact_longName = exact_longName[:-1]  # delete the last \
            print("exactName:", exact_longName)
            startLine_dst = int(line.split(":")[2].split("->")[1].split(",")[0])
            endLine_dst = int(line.split(":")[2].split("->")[1].split(",")[1])
            startCol_dst = int(line.split(":")[2].split("->")[1].split(",")[2])
            endCol_dst = int(line.split(":")[2].split("->")[1].split(",")[3])
            findFile = False
            begin = False  # in some cases, statements will begin with irrelevant lexeme
            print(startLine_dst, endLine_dst, startCol_dst, endCol_dst)
            for file in db.ents("File"):
                if exact_longName in file.longname():
                    print("find file:", fileName, file.longname())
                    lexemes = file.lexer().lexemes(startLine_dst, endLine_dst)
                    start_lexeme = file.lexer().lexeme(startLine_dst, startCol_dst-1)
                    type_exist = True  # in some cases, lexeme type is none
                    if start_lexeme is not None:
                        start_text = start_lexeme.text()
                        start_token = start_lexeme.token()
                        print("start_text:"+start_text)
                    else:
                        type_exist = False
                        print("error type")
                    size = len(lexemes)
                    fullText = ""
                    count = 0
                    for lexeme in lexemes:
                        count += 1
                        if type_exist is True:
                            if (lexeme.text() != start_text or lexeme.token() != start_token) and begin is False:
                                continue
                            elif lexeme.text() == start_text or lexeme.token() == start_token:
                                begin = True
                        else:
                            continue
                        if lexeme.token() == "Comment":
                            continue  # skip the comment
                        if lexeme.token() == "Whitespace":
                            continue  # skip whitespaces
                        if lexeme.token() == "Newline":
                            continue
                        text = str(lexeme.text())
                        if lexeme.token() == "Literal":
                            text = "num"  # replace Literal
                        if lexeme.token() == "String":
                            text = "\"\""  # replace String literal
                        text = normalization(text, defLine_dst)  # normalization
                        text = text + " "
                        if count == size-1:
                            text = text.replace("}", "")
                            text = text.replace("{", "")
                            text = text.replace(";", "")  # delete { } and ; in the last token
                            # text = text.rstrip()
                        fullText += text
                        print(text, end="")
                    # for lexeme in lexemes:
                    #     dst1.write(lexeme.text()+"("+lexeme.token()+")")
                    # fullText = normalization(fullText, defLine_dst)
                    findFile = True
                    dst.write(fullText)
            lineNum += 1
            print("\r\n-----------")
            dst.write("\n------\n")
            # dst1.write("------\n")
            if findFile is False:
                raise Exception
        src.close()
        dst.close()
        # src1.close()
        # dst1.close()
