#!/bin/bash
 
#HDD memory analysis automation 
	FIRST=$(timedatectl | grep Local | awk '{print $5}' | sed 's/://g')
	function CHECKIFROOT(){
	if [ "$(whoami)" == "root" ]
	then echo "[+] You're root"
	else echo "[-] Not root, must be run as a root:)" && exit
	fi
	}
	CHECKIFROOT

#function that ask for file-name and check existence:
	function IFEXIST(){
	echo "[*]enter a file name:"
	read ANSWER
	RESULT=$(find /-name $ANSWER 2>/dev/null)
	if [ -z $RESULT ] 
	then echo ">>-No such file-<< :(" && exit
	else echo "[*]File Exist :)"
	fi
	}
	IFEXIST

#function that install relevant tools:
	function FULLTOOL(){
	sudo apt install bulk-extractor
	sudo apt-get --assume-yes install binwalk
	sudo apt-get --assume-yes install foremost
	sudo apt-get --assume-yes install strings
	sudo apt-get --assume-yes install wget
	}
	FULLTOOL	

#Download relevant tool (:volatility:) order information in directories of Datacarving (:with relevant tools:) and show where the pcap file saved:
	cd /home/kali/Desktop
	mkdir Datacarving
	mkdir Datacarving/Vol
	cd /home/kali/Desktop/Datacarving/Vol
	wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip && sudo chmod 777 -R volatility_2.6_lin64_standalone.zip 
	sudo unzip volatility_2.6_lin64_standalone.zip && chmod 777 -R volatility_2.6_lin64_standalone && cd volatility_2.6_lin64_standalone && mv volatility_2.6_lin64_standalone vol 
	cd /home/kali/Desktop
	mkdir Datacarving/STRINGS
	mkdir Datacarving/BINWALK
	binwalk $RESULT >> Datacarving/BINWALK/Binwalk
	foremost -i $RESULT -t all -o Datacarving/Foremost 
	strings $RESULT >> Datacarving/STRINGS/Strings
	bulk_extractor $RESULT -o Datacarving/Bulkoutput 
	sudo chmod 777 -R Datacarving
	cp $RESULT /home/kali/Desktop/Datacarving/Vol/volatility_2.6_lin64_standalone/$ANSWER
	echo 
	echo
	if [ -e /home/kali/Desktop/Datacarving/Bulkoutput/packets.pcap ]
	then echo "[*] a pcap file with network activity from the memory file has been saved in Datacarving/bulk-output/packets.pcap"
	fi
	
	
#Validate the input file, if can be analyzed by Volatility:
	function VOLCHK(){
	VOLCHECK=$(/home/kali/Desktop/Datacarving/Vol/volatility_2.6_lin64_standalone/./vol -f $ANSWER imageinfo | grep -i suggested | awk '{print $4}' | awk -F , '{print $1}')
	if [ "$VOLCHECK" == "No" ]
	then echo "file can't be analyzed by volatility"
	else echo "file can be analyzed by volatility, proceed" 
	RUN
	fi
	}
#Display running processes
	mkdir /home/kali/Desktop/Datacarving/Reports
	function RUN(){
	COMMAND='pslist pstree psscan'
	for i in $COMMAND
	do /home/kali/Desktop/Datacarving/Vol/volatility_2.6_lin64_standalone/./vol -f $ANSWER --profile $VOLCHECK $i >> /home/kali/Desktop/Datacarving/Reports/process && sudo chmod 777 -R /home/kali/Desktop/Datacarving/Reports/process
	done	
	
#2.4 Display network:
	COMMAND='sockets connscan sockscan netscan connection'
	for i in $COMMAND
	do /home/kali/Desktop/Datacarving/Vol/volatility_2.6_lin64_standalone/./vol -f $ANSWER --profile $VOLCHECK $i >> /home/kali/Desktop/Datacarving/Reports/network && sudo chmod 777 -R /home/kali/Desktop/Datacarving/Reports/network
	done
	
#Display registry:
	COMMAND='hivescan hivelist lsadump shellbags'
	for i in $COMMAND
	do /home/kali/Desktop/Datacarving/Vol/volatility_2.6_lin64_standalone/./vol -f $ANSWER --profile $VOLCHECK $i >> /home/kali/Desktop/Datacarving/Reports/registry && sudo chmod 777 -R /home/kali/Desktop/Datacarving/Reports/registry
	done
	}
	VOLCHK

#Results:
	ls Datacarving/Bulkoutput >> /home/kali/Desktop/Datacarving/report
	sudo chmod 777 -R /home/kali/Desktop/Datacarving/report
	echo "number of files extracted from Bulk extractor" >> /home/kali/Desktop/Datacarving/report && ls /home/kali/Desktop/Datacarving/Bulkoutput | wc -l >> /home/kali/Desktop/Datacarving/report 
	echo  "report file has been saved in /home/kali/Desktop/Datacarving/report"

	
	LAST=$(timedatectl | grep Local | awk '{print $5}' | sed 's/://g')
	TIME=$(expr $LAST - $FIRST)
	echo "Total time it was taken to analyze the file" >> /home/kali/Desktop/Datacarving/report 
	echo $TIME >> /home/kali/Desktop/Datacarving/report

#compress Datacarving in zip file and show where it's saved
	cd /home/kali/Desktop
	zip -qr Datacarving.zip Datacarving && sudo chmod 777 -R Datacarving.zip
	echo "zipped directory has been saved on the Desktop"
