import argparse
import gzip
import os
import re

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputdir", help="分析対象のログを格納",default="logs")
    parser.add_argument("--filename", help="ログファイルの名前", default="mail.log")
    args = parser.parse_args()
    
    filename = os.path.join(args.inputdir,args.filename)
    
    content =[]
    
    with open(filename,mode="r") as f:
        c= f.read()
        content.append(c)

    with open(filename+".1",mode="r") as f:
        c= f.read()
        content.append(c)

    with gzip.open(filename+".2.gz",mode="rt") as f:
        c= f.read()
        content.append(c)

    with gzip.open(filename+".3.gz",mode="rt") as f:
        c= f.read()
        content.append(c)
    
    with gzip.open(filename+".4.gz",mode="rt") as f:
        c= f.read()
        #content.append(c)
    
    postfix_logs=[]
    dovecot_logs=[]
    for i in content:
        lines = i.splitlines()
        for j in lines:
            if re.search('postfix.*with cipher',j)!=None:
                ip=re.search(r'[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}.[\d]{1,3}',j)
                cipher=re.search('[^ \t]* with cipher [^ \t]*',j)
                log=ip.group(0)+","+cipher.group(0)
                postfix_logs.append(log)
            if re.search('dovecot.*with cipher',j)!=None:
                user=re.search('user=<[A-Za-z0-9\-]*>',j)
                ip=re.search('rip=[\d\.]*',j)
                cipher=re.search('[^ \t]* with cipher [^ \t]*',j)
                if user!=None and ip!=None:
                    log=user.group(0)[6:-1]+","+ip.group(0)[4:]+","+cipher.group(0)
                    dovecot_logs.append(log)

                
    postfix_logs=list(set(postfix_logs))
    dovecot_logs=list(set(dovecot_logs))
    with open("postfix.csv",mode="w") as f:
        print("ip,cipher",file=f)
        for log in postfix_logs:
            print(log,file=f)
    with open("dovecot.csv",mode="w") as f:
        print("username,ip,cipher",file=f)
        for log in dovecot_logs:
            print(log,file=f)
    
    

if __name__ == "__main__":
    main()