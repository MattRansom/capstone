import pyshark
from prettytable import PrettyTable
import pyfiglet

#pip3 install PrettyTable
#pip3 install pyshark

#list of dictionaries used to catalog
#the list of unique IP's and their corresponding ports
#they tried to access as well as overall bytes sent from that IP
ipData = []

#colors used for initial Table Formating
R = "\033[0;31;40m"
G = "\033[0;32;40m"
Y = "\033[0;33;40m"
B = "\033[0;34;40m"
N = "\033[0m" #put after each color set

intro = pyfiglet.figlet_format("ATH", font = "slant" )
print(intro)
print("Welcome to Autonomous Threat Hunting! \nCreated by")
print("\tEthan Dupre (Nightdragon)")
print("\tBrody Jenkins (Iceboy)")
print("\tSean Bowman (The Witch Nurse) \n\t"+
"Matthew Stevenson Ransom (Dr. Gabbagoo)\n")
start = True

while(start):
    setting = input("Enter "+Y+"1"+N+" for testing, "+Y+"2"+N+
    " for System Administration: ")
    ###########################    admin code    ##################################
    if setting == "1":
        start = False
    elif setting == "2":
        user = input("Username: ")
        pwd = input("Password: ")
        admin = False

        while(user != "1" or pwd != "1"):
            print("Wrong username or password. Try again")
            user = input("Username: ")
            pwd = input("Password: ")
        admin = True
        print("Welcome Administrator. What can we help you with?\n")
        print(Y+"1"+N+": Edit blacklisted IPs")
        print(Y+"2"+N+": View Blacklisted IPs")
        print(Y+"3"+N+": Exit Administration mode and go to testing")


        while(admin):
            choice = input("Edit"+Y+" 1"+N+", "+ "View"+Y+" 2"+N+", "+"Exit"+Y+" 3"+N+": ")
            ######################### editing #####################################
            if choice == "1":
                bl = open("bl.txt", "r+")
                print(bl.read())
                ec= input("Editing, add "+Y+"(1)"+N+" or remove "+Y+"(2)"+N+": ")

                if ec == "1": ###### adding ip ###########################
                    addip = input("IP to add (Format \"123.45.678.910\"): ")

                    bl.write(addip)
                    bl.write("\n")
                    bl.close()
                    print("Added "+addip+"!")

                elif ec == "2": ######## removing ip #################
                    remip = input("remove which IP? (Format \"123.45.678.910\"): ")
                    with open("bl.txt","r") as bl:
                        lines = bl.readlines()
                    with open("bl.txt","w") as bl:
                        for line in lines:
                            if line.strip("\n") != remip:
                                bl.write(line)
                    print("Removed "+remip+"!")
                else:
                    print("Bad input")

            ######################### viewing #####################################
            elif choice == "2":
                bl = open("bl.txt","r")
                print("\nViewing blacklist\n")
                print(bl.read())
                bl.close()
                con = input("Press any key to continue")
            ######################### exiting #####################################
            elif choice == "3":
                chk = input("Are you sure you want to leave"+
                " ("+Y+"y"+N+" or "+Y+"n"+N+")?")
                if chk == "y":
                    admin = False
                else:
                    admin = True
            else:
                print("Bad input. Try again.")
                admin = False



###############################################################################
evaluate = True
while (evaluate):

    print("\nq to exit")
    fileTouse = input("Input a .pcap file for us to evalutate: ")

    try:
        capture = pyshark.FileCapture(fileTouse)
        print("Got it!")
    except FileNotFoundError:
        if fileTouse == "q":
            exit()
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
    "SRC_Port", "DST_Port", "Length", "Threat"])

    #blacklist IP
    blacklist = []
    bl = open("bl.txt","r")
    for line in bl:
        blacklist.append(line.strip())
    packetsTotal = 1

    #the static capture on 'test.pcap'


    #for loop to iterate through all packets seen
    for packet in capture:
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

            #checks if ipData is empty, adds 1st packet if so
            if not ipData:
                ipData.append({'IP' : source_address,
                     "portsAccessed" : [destination_port],
                     "Volume": int(length)})
    ################################################################################
        #not empty, checking for double IPs, or if we need to add a new one
            else:
                #iterrate over unique IP data lsit so far
                for i in range(len(ipData)):

                    #checks if current IP matches any in our current analysis
                    if ipData[i]['IP'] == source_address:
                        #add port Accessed to the already detected IP
                        if ipData[i]['portsAccessed'].count(destination_port) == 0:
                           ipData[i]['portsAccessed'].append(destination_port)

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
                              "portsAccessed" : [destination_port],
                              "Volume": int(length)})

            #here we add an IP to the blacklist
            #(hardcoded as of now for demo purposes)
            #if packetsTotal == 23:
            #    blacklist.append(packet.ip.src)
            #checks future IPs on blacklist and flags them in summary (RED)
            if packet.ip.src in blacklist:
                pcapSum.add_row([packetsTotal, R+source_address+N ,
                R+destination_address+N ,R+source_port+N , R+destination_port+N ,
                R+length+N, R+"THREAT"+N])
            #adds to summary table (GREEN)
            else:
                pcapSum.add_row([packetsTotal, source_address , destination_address ,
                source_port , destination_port , length, G+"PASS"+N])

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
        #prints ipData table, shows input to ML model
    print(ipStats)
    print("\n")
    ck = input("Do you want to run another test ("+Y+"y"+N+") or ("+Y+"n"+N+")?")
    if ck == "n":
        evaluate = False
        print("Have a super excellent day.")
