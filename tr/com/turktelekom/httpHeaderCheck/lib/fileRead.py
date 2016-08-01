import ipcalc

def readTargetsFromFile(args):
    targets = []
    try:
        ipEntries = [line.strip() for line in open(args.inputFileLocation[0], 'r')]  # ip'leri dosyadan oku

        for ipEntry in ipEntries:
            if(ipEntry.strip() == None or len(ipEntry)==0):
                continue
            elif(ipEntry[0]=="#"):
                continue
            elif(ipEntry[0].isdigit() and  "/" in ipEntry): #bir subnet belirtiyorsa, içindeki ip'leri tek tek ekle
                for ip in ipcalc.Network(ipEntry): #
                    targets.append(str(ip + ":80"))
                    targets.append(str(ip + ":443"))
            else:
                targets.append(ipEntry) #subnet değil de tekil bir IP ise, bunu ekle
    except FileNotFoundError:
        print("Could not find the Input file. Retry with -h option for help.")
        exit(-1)
    return targets
