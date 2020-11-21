import pyshark
from prettytable import PrettyTable
import pyfiglet

#pip3 install PrettyTable
#pip3 install pyshark

#list of dictionaries used to catalog
#the list of unique IP's and their corresponding ports
#they tried to access as well as overall bytes sent from that IP

#TO DO
# records edit/viewing
#admins add/remove/view
#make record txt


#colors used for initial Table Formating
R = "\033[0;31;40m"
G = "\033[0;92m"
Y = "\033[0;93m"
B = "\033[0;34;40m"
N = "\033[0m" #put after each color set
def runAdmin():
    start = True
    while(start):
        # setting = input("Enter "+Y+"1"+N+" for testing, "+Y+"2"+N+
        # " for System Administration, " +Y+"3"+N+" to exit program: ")
        # ###########################    admin code    ##################################
        # if setting == "1":
        #     start = False
        # elif setting == "2":
            user = input("Username: ")
            pwd = input("Password: ")
            admin = False

            numAttempts = 1
            while((user != "1" or pwd != "1") and numAttempts < 3):
                print("Wrong username or password. Try again")
                user = input("Username: ")
                pwd = input("Password: ")
                numAttempts+=1
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
                    " ("+Y+"y"+N+" or "+Y+"n"+N+")? ")
                    if chk == "y":
                        admin = False
                        return
                    else:
                        admin = True
                else:
                    print("Bad input. Try again.")
