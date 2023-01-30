This Python code, analyzes log files of connections to Zoom and provides statistical information about Zoom sessions and meetings.

A Zoom session is a client's (user) session to Zoom. It consists of
a group of Zoom connections from the same client, all within a specific time duration and attributable to a single session. Every session consists of one persistent TCP connection to an MMR server, with possibly at least one UDP connection to the same MMR (depending on the client's connectivity method) and more TCP connections to other server types for different purposes.
A Zoom meeting is between at least two clients (sessions) serviced by a single Multimedia Router (MMR).

This code's input is the log file's name in the current directory. The log file contains all the connections to Zoom. The format of this file must follow Vertica's standard output (delimiter: '|') analyzing Zeek's logs, otherwise appropriate changes in the code would be necessary. Fields must be as the following:

- epoch time
- originator's IP address
- originator's port number
- responder's IP address
- responder's port number
- transport protocol
- Zoom server type (i.e., mmr, zc, web, xmpp, cdn, rwg, and blank for unknown)
- duration of connection
- connection state
- history field
- number of packets sent by the originator
- number of bytes sent by the originator
- number of packets sent by the responder
- number of bytes sent by the responder.

The main output of the program includes:

- number of unique clients (hence identified Zoom sessions)
- number of unique client IPs
- number of unique MMRs
- number of all connections to MMRs
- number of Zoom meetings
- average number of MMR connections per client
- average number of distinct clients per IP
- list of all the Zoom sessions, with their timings and different connections
- list of all the Zoom meetings, with their timings and number of users

Besides the main output, this program records the number of connections to each type of Zoom server from each Zoom session in separate files,
and the timings (start and end) of all TCP and UDP connections to MMRs to be used in further analysis and visualizations.

The code fragment below shows the first iteration on the file to find and create a list of distinct Zoom sessions based on the number of distinct client IPs, distinct MMRs, and the start/end time of the connections.
In this iteration, we only look at connections to MMRs. 

## Output

The following, shows the summary part of the result of this code, running on the Conn logs to Zoom on September 22, 2021, at 1:00 PM. 

```
Rows in the input file =  87116
Unique clients identified =  2016
Unique client IPs =  326
Unique MMRs =  296
All connections to MMRs =  8480
Meetings identified =  531
Average number of MMR connections per client =  4.21
Average number of distinct clients per IP =  6.18

Top 10 meetings with highest participation count: 
{'MMR': '149.137.21.115', '#_of_users': 52, 'start': 1632337229.730482, 'end': 1632341025.2673402}
{'MMR': '149.137.21.129', '#_of_users': 47, 'start': 1632337275.03694, 'end': 1632340100.8459601}
{'MMR': '149.137.21.43', '#_of_users': 41, 'start': 1632337284.222251, 'end': 1632340591.686825}
{'MMR': '149.137.20.35', '#_of_users': 33, 'start': 1632337226.07388, 'end': 1632339883.168814}
{'MMR': '149.137.21.34', '#_of_users': 32, 'start': 1632337202.474286, 'end': 1632340470.009383}
{'MMR': '65.39.152.115', '#_of_users': 32, 'start': 1632340454.379923, 'end': 1632343944.8512032}
{'MMR': '149.137.20.80', '#_of_users': 31, 'start': 1632337208.540666, 'end': 1632342931.979093}
{'MMR': '149.137.20.74', '#_of_users': 31, 'start': 1632337294.466649, 'end': 1632347128.1984541}
{'MMR': '149.137.21.84', '#_of_users': 24, 'start': 1632337213.328107, 'end': 1632340447.9263911}
{'MMR': '149.137.21.210', '#_of_users': 24, 'start': 1632337256.001338, 'end': 1632340230.248307}

GPVPN (136.159.199 subnet) TCP sessions =  193
GPVPN (136.159.199 subnet) ICMP sessions =  606
GPVPN (136.159.199 subnet) other sessions =  0 
```
