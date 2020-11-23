import pyshark
from prettytable import PrettyTable
import pyfiglet

#pip3 install PrettyTable
#pip3 install pyshark




# 4 more modules to branch off from this file


#list of dictionaries used to catalog
#the list of unique IP's and their corresponding ports
#they tried to access as well as overall bytes sent from that IP
ipData = []

#colors used for initial Table Formating
R = "\033[0;91m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;94m"
N = "\033[0m" #put after each color set

def runTest():
    evaluate = True
    while (evaluate):

        print("\n"+Y+"q"+N+" to exit")
        fileTouse = input("Input a .pcap file for us to evalutate: ")

        try:
            capture = pyshark.FileCapture(fileTouse)
            print("Got it!")
        except FileNotFoundError:
            if fileTouse == "q":
                return
            print(R+"That file is not found, or was input incorrectly."+N)
            continue

        print("Are there any particular features you want to analyze?")
        print(Y+"1"+N+": Standard deviation of interpacketspacing")
        print(Y+"2"+N+": Byte volume per port")
        print(Y+"3"+N+": Port access attempts from origin IP address")
        print(Y+"4"+N+": General analysis")
        choice = input(Y+"1"+N+","+ Y+" 2"+N+","+Y+" 3"+N+","+Y+" 4"+N+": ")
        print("Working on "+ fileTouse+"...")



        #1st table seen, the overall pcap summary Table
        #currently shows example of how threatening packets could be reported based off
        #of numerical data we deem hostile
        pcapSum = PrettyTable(["Packet #", "Source IP", "Destination IP",
        "SRC_Port", "DST_Port", "URL","Protocol","Length", "Threat"])

        #blacklist IP
        blacklist = []
        bl = open("bl.txt","r")
        for line in bl:
            blacklist.append(line.strip())
        packetsTotal = 1

        #the static capture on 'test.pcap'


        #for loop to iterate through all packets seen
        for packet in capture:
            proto = ""
            urlSrc = ""
            urlDest = ""
            #used try to account for attribute errors in individual packets
            try:
                packetsTotal += 1
                #parse out details from each packet
                protocol = packet.highest_layer
                source_address = packet.ip.src
                source_port = packet[packet.transport_layer].srcport
                destination_address = packet.ip.dst
                destination_port = packet[packet.transport_layer].dstport
                length = packet.length

                if protocol == "DNS":
                    urlSrc = packet.dns.qry_name
                    urlDest = packet.dns.resp_name


                #checks if ipData is empty, adds 1st packet if so
                if not ipData:
                    ipData.append({'IP' : source_address,
                         "portsAccessed" : [[destination_port, int(length)]],
                         "Volume": int(length)})
        ################################################################################
            #not empty, checking for double IPs, or if we need to add a new one
                else:
                    #iterrate over unique IP data list so far
                    for i in range(len(ipData)):

                        #checks if current IP matches any in our current analysis
                        if ipData[i]['IP'] == source_address:
                            #add port Accessed to the already detected IP
                            for w in range(len(ipData[i]['portsAccessed'])):
                                if ipData[i]['portsAccessed'][w][0] == destination_port:
                                    ipData[i]['portsAccessed'][w][1]+=int(length)
                                    break
                                elif w == len(ipData[i]['portsAccessed'])-1:
                                    ipData[i]['portsAccessed'].append([destination_port, int(length)])


                            #add byte Volume to already detected IP
                            ipData[i]['Volume']+=int(length)
                        #will add number of accesses to each port in next iteration
                        #breaks b/c we have found a match, no need to go further
                            break

                        #else if no matches so far and we are at the end of our unqiue
                        #IP data points
                        elif i == len(ipData)-1:
                            #add a new IP data point to the ipData
                            ipData.append({'IP' : source_address,
                                  "portsAccessed" : [[destination_port, int(length)]],
                                  "Volume": int(length)})


                #here we add an IP to the blacklist
                #(hardcoded as of now for demo purposes)
                #if packetsTotal == 23:
                #    blacklist.append(packet.ip.src)
                #checks future IPs on blacklist and flags them in summary (RED)
                if packet.ip.src in blacklist:
                    pcapSum.add_row([packetsTotal, R+source_address+N ,
                    R+destination_address+N ,R+source_port+N , R+destination_port+N ,
                    urlSrc, protocol, R+length+N, R+"THREAT"+N])
                #adds to summary table (GREEN)
                else:
                    pcapSum.add_row([packetsTotal, source_address , destination_address ,
                    source_port , destination_port , urlSrc, protocol, length, G+"PASS"+N])

            except AttributeError as e:
                pass

        #prints summary table w/ THREAT & PASS values (hardcoded)
        print(pcapSum)
        #creates numerical analysis table to input into ML model, eventually
        #outputting some heuristic for how well we could determine the numerical ipData
        #represents a threat
        ipStats = PrettyTable(["IP" , "Ports Accessed", "Byte Volume"])
        #populate table with ipData
        for x in ipData:
            if(x['IP'] in blacklist):
                ipStats.add_row([R+x['IP']+N, R+str(x['portsAccessed']), R+str(x['Volume'])+N])
            else:
                ipStats.add_row([x['IP'], x['portsAccessed'], x['Volume']])
            # else:
            #     ipStats.add_row([x['IP'], x['portsAccessed'], x['Volume']])
            #prints ipData table, shows input to ML model
        print(ipStats)
        print("\n")
        ck = input("Do you want to run another test ("+Y+"y"+N+") or ("+Y+"n"+N+"): ")
        if ck == "n":
            evaluate = False
            print(Y + "Going back to main module" + N)



    #stdev(thisTable) = hueristic.
    #other modules....
