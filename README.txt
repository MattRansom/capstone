IC470 Capstone Team 7

Ethan Dupre
Brody Jenkins
Matthew Stevenson Ransom
Sean Bowman

Milestone 4 README.txt

Command to run:

  python3 cap2.py

  est. time: 1-1.5 seconds

Needed Libraries:
  pip3 install pyshark
  pip3 install PrettyTable

Takes a static captured pcap files and creates a list of the packets captured.
With that list, we populate an overall summary table which is currently
hard-coded in order to express a visual representation of what it would look
like if we were to find threats and how that would be presented in a table
format for easy comprehension. Next, after we populate the summary table,
we create a table of unique IP addresses, the ports that IP accessed, and the
total volume (bytes) that was sent from that IP. Currently, the features
that are engineered are not particularly interesting, however, the scalability
of the code is enormous and in future iterations will allow a greater
breadth of data collection at minimal development time commitment. The number
of ports accessed, time between sent messages to a single port, as well as
the number of IPs accessing a single IP:port pair, are all easily created
features we see being important in upcoming iterations as we move to train the
ML model. We see overtime, being able to insert this ipData table into the ML
model, and get a heuristic in return that represents how well/poorly this
module of numerical data science could determine if a threat is contained within
the IP data. Additionally, we hope to scale this program past static
pre-recorded pcap files, and allow seamless live-capture capabilities of
traffic on the network.
