import os
bases=["D:/","C:/Users/20751/.m2/repository/com/github/zhkl0228"]
for base in bases:
    if not os.path.exists(base): continue
    for r,ds,fs in os.walk(base):
        if r.replace("\\","/").count("/")-base.count("/")>4: ds[:]=[]
        for f in fs:
            if "unidbg" in f.lower() and (f.endswith(".java") or f.endswith("-sources.jar")): print(os.path.join(r,f))
print("done")
