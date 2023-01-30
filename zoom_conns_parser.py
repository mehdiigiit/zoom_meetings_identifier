# Usage:
# $ echo INPUT_FILE_NAME | python3 zoom_conns_parser.py > OUTPUT_FILE_NAME
#
# This program analyzes log files of connections to Zoom
# and provides statistical information about Zoom sessions and meetings.
#
# Zoom session = A client's (user) session to Zoom. It consists of
# a group of Zoom connections from the same client all within a specific time duration
# and are attributable to a single session. Every session consists of one persistent TCP
# connection to a MMR server, with possibly at least one UDP connection to the same MMR
# (depending on the client's connectivity method) and more TCP connections to other
# server types for different purposes.
#
# Zoom meeting = A Zoom meeting between at least two clients (sessions)
# serviced by a single Multimedia Router (MMR).
#
# INPUT: The name of the log file in the current directory.
# The log file contains all the connections to the Zoom.
# The format of this file must follow Vertica's standard output
# (delimiter: '|') analyzing Zeek's (Bro) logs.
# Fields must be as the following:
# (1) epoch time
# (2) Originator's IP
# (3) Originator's port
# (4) Responder's IP
# (5) Responder's port
# (6) Protocol
# (7) Zoom server type (mmr, zc, web, xmpp, cdn, rwg, or blank for unknown)
# (8) Duration
# (9) Connection state
# (10) History
# (11) Originator's packets
# (12) Originator's bytes
# (13) Responder's packets
# (14) Responder's bytes.
#
# OUTPUT: The program's output may be stored in the desired given output file.
# The main output of the program includes:
# (1) Number of unique clients (hence identified Zoom sessions)
# (2) Number of unique client IPs
# (3) Number of unique MMRs
# (4) Number of all connections to MMRs
# (5) Number of Zoom meetings
# (6) Average number of MMR connections per client
# (7) Average number of distinct clients per IP
# (8) List of all the Zoom sessions, with their timings and different connections
# (9) List of all the Zoom meetings, with their timings and number of users
#
# Besides the main output, this program records the number of connections to each
# type of Zoom server from each Zoom session in separate files (named as distribution_TYPE.txt),
# as well as the timings (start and end) of all TCP and UDP connections to MMRs
# (also in separate files named as timings_tcp.txt and timings_udp.txt),
# for use in further analysis and visualizations.

import collections

def zoom_conns_parser():
    FILE = input("Enter the file name to parse: ")
    CLIENT_ACTIVE_ZONE = 5.0

    while FILE == '':
        FILE = input("Empty file name! Try again: ")

    times_tcp_file = open("timings_tcp.txt", "w")
    times_udp_file = open("timings_udp.txt", "w")
    dist_tcp = open("distribution_tcp.txt", "w")
    dist_udp = open("distribution_udp.txt", "w")
    dist_zc = open("distribution_zc.txt", "w")
    dist_cdn = open("distribution_cdn.txt", "w")
    dist_web = open("distribution_web.txt", "w")
    dist_xmpp = open("distribution_xmpp.txt", "w")
    dist_rwg = open("distribution_rwg.txt", "w")
    dist_unk = open("distribution_unk.txt", "w")
    dist_usr = open("distribution_users.txt", "w")

    try:
        f = open(FILE, 'r')
        sessions = []
        tcp_times = []
        udp_times = []
        fileLines = 0
        MMRcount = 0
        gpvpnTCP = 0
        gpvpnICMP = 0
        gpvpnUDP = 0

        # ================================================================================
        # First iteration to find and create a list of distinct Zoom sessions based on
        # distinct clients' IPs, distinct MMRs, and the start/end time of the connections.
        # In this iteration we only look at connections to MMRs. We also count connections
        # from gpvpn subnet, separating TCPs, ICMPs, and OTHs.
        # ================================================================================
        for line in f:
            fileLines += 1
            stype = line.rstrip().split(' | ')[6].rstrip()
            startTime = float(line.rstrip().split(' | ')[0].rstrip())
            dur = line.rstrip().split(' | ')[7].rstrip()
            duration = float(dur if dur != '' else '0')
            endTime = startTime + duration
            origIP = line.rstrip().split(' | ')[1].rstrip()
            respIP = line.rstrip().split(' | ')[3].rstrip()
            proto = line.rstrip().split(' | ')[5].rstrip()

            if stype == 'mmr':
                MMRcount += 1
                # Getting the session with the same origIP and respIP, within this connection's timeframe.
                client_index = next((index for (index, element) in enumerate(sessions) if element["origIP"] == origIP
                                     and element["respIP"] == respIP and startTime - element["endTime"] <
                                     CLIENT_ACTIVE_ZONE and element["startTime"] - startTime < CLIENT_ACTIVE_ZONE), -1)

                # If there is no such session.
                if client_index == -1:

                    # If THIS connection is not from a gpvpn IP then create a session for it.
                    if '136.159.199' not in origIP:
                        sessions.append({'startTime': startTime, 'endTime': endTime, 'origIP': origIP, 'respIP': respIP,
                                         proto: 1})
                        if proto == 'tcp':
                            tcp_times.append([startTime, endTime])
                        elif proto == 'udp':
                            udp_times.append([startTime, endTime])
                    # If THIS connection is from a gpvpn IP count it (TCP and ICMP).
                    elif proto == 'tcp':
                        gpvpnTCP += 1
                    elif proto == 'icmp':
                        gpvpnICMP += 1
                    else:
                        gpvpnUDP += 1

                # If there is such session, add THIS connection to its information.
                else:
                    if proto not in sessions[client_index].keys():
                        sessions[client_index][proto] = 1
                    else:
                        sessions[client_index][proto] += 1
                    if proto == 'tcp':
                        tcp_times.append([startTime, endTime])
                    elif proto == 'udp':
                        udp_times.append([startTime, endTime])

            # Counting all gpvpn connections in the first iteration.
            elif '136.159.199' in origIP:
                if proto == 'tcp':
                    gpvpnTCP += 1
                elif proto == 'icmp':
                    gpvpnICMP += 1
                else:
                    gpvpnUDP += 1

        f.close()

    except IOError:
        print("Error: File does not appear to exist.")
        return 0

    # ================================================================================
    # Second iteration to assign each Zoom connection to the corresponding session.
    # The remaining connections are toward different Zoom server types (zc, web, xmpp,
    # cdn, and unknown) and they will be counted towards the identified sessions.
    # ================================================================================
    f = open(FILE, 'r')
    for newline in f:
        stype = newline.rstrip().split(' | ')[6].rstrip()

        # Ignore the connections to MMRs as they are already processed.
        if stype == 'mmr':
            continue

        # If the server type is not declared, specify it as 'unknown'.
        if stype == '':
            stype = 'unknown'
        startTime = float(newline.rstrip().split(' | ')[0].rstrip())
        origIP = newline.rstrip().split(' | ')[1].rstrip()

        # Find the list of sessions with the same origIP as THIS connection, where THIS connection's startTime
        # falls into the CLIENT_ACTIVE_ZONE of those sessions' either startTime or endTime. This list records
        # the indices of those sessions.
        clients_indices = [index for (index, element) in enumerate(sessions) if element["origIP"] == origIP and
                           startTime - element["endTime"] < CLIENT_ACTIVE_ZONE and element["startTime"] -
                           startTime < CLIENT_ACTIVE_ZONE]

        # If there is at least one such session.
        if len(clients_indices) > 0:

            # Create a list in which each element records the index of those sessions, as well as the differences
            # between their startTime/endTime with THIS connection's startTime. The goal is to find the smallest
            # difference which gives us the most probable corresponding session for THIS connection.
            starts_ends_times_apart = []
            for c in clients_indices:
                starts_ends_times_apart.append({'index': c, 'fromStart': abs(sessions[c]['startTime'] - startTime),
                                                'fromEnd': abs(sessions[c]['endTime'] - startTime)})

            # Find the smallest diff (explained just above) and record the session's index in cln.
            diff = starts_ends_times_apart[0]['fromStart']
            cln = starts_ends_times_apart[0]['index']
            for t in starts_ends_times_apart:
                if t['fromStart'] < diff:
                    diff = t['fromStart']
                    cln = t['index']
                if t['fromEnd'] < diff:
                    diff = t['fromEnd']
                    cln = t['index']

            # If there is no connection to such server type already found for this session, create it for the session.
            if stype not in sessions[cln].keys():
                sessions[cln][stype] = 1

            # Otherwise, just add it.
            else:
                sessions[cln][stype] += 1

    f.close()

    # Logging the timings of TCP and UDP connections into the conns_times.txt file.
    for sess_elem in tcp_times:
        times_tcp_file.write(str(sess_elem))
        times_tcp_file.write("\n")
    times_tcp_file.close()

    for sess_elem in udp_times:
        times_udp_file.write(str(sess_elem))
        times_udp_file.write("\n")
    times_udp_file.close()

    rows1 = sessions.copy()
    allMMRs = []

    # =============================================================
    # Finding distinct meetings with the number of clients for each
    # =============================================================

    # Iterates through the sessions, each time taking the first session as the reference and finding all the sessions
    # that belong to the same meeting as this session. It creates a list of all remaining sessions to be parsed in the
    # next iteration.
    while len(rows1) > 0:
        thisMMR = rows1[0]['respIP']
        thisStartTime = rows1[0]['startTime']
        thisEndTime = rows1[0]['endTime']
        rows2 = []
        usersOfMMR = 0

        # Iterates through all sessions to find sessions that belong to this meeting.
        for n in rows1:

            # Checks the sessions to the same MMR.
            if thisMMR == n['respIP']:

                # If the startTime and endTime of the sessions are less than 5 minutes apart, then
                # they belong to the same meeting. Counts them.
                if abs(thisStartTime - n['startTime']) < 600 and abs(thisEndTime - n['endTime']) < 600:
                    usersOfMMR += 1

                # Otherwise, if a session to the same MMR starts and ends during this meeting, then
                # count it towards this meeting.
                elif n['startTime'] > thisStartTime and n['endTime'] < thisEndTime:
                    usersOfMMR += 1

                # If not, append it to rows2 to be checked by other meetings (that are to the same MMR).
                else:
                    rows2.append(n)

            # Append it to rows2 to be checked by other meetings (that are to different MMRs).
            # At the end of the iteration, rows2 will contain all the undetermined sessions.
            else:
                rows2.append(n)

        # At the end of the iteration, if there was any user for this meeting (which must be at least 1 I suppose!),
        # then append it to the list of all meetings.
        if usersOfMMR > 0:
            allMMRs.append({'MMR': thisMMR, '#_of_users': usersOfMMR, 'start': thisStartTime, 'end': thisEndTime})

        # Replacing rows1 by rows2 of the remaining sessions for the next iteration.
        del rows1
        rows1 = rows2.copy()
        del rows2

    # ===================================
    # Finalizing the results and printing
    # ===================================

    # Sorting out the sessions and meetings lists
    sortedSessions = sorted(sessions, key=lambda d: d['startTime'])
    sortedMeetings = sorted(allMMRs, key=lambda d: d['#_of_users'], reverse=True)

    for sess in sortedSessions:
        if 'tcp' in sess.keys():
            dist_tcp.write(str(sess['tcp']))
            dist_tcp.write("\n")
        else:
            dist_tcp.write("0\n")
    dist_tcp.close

    for sess in sortedSessions:
        if 'udp' in sess.keys():
            dist_udp.write(str(sess['udp']))
            dist_udp.write("\n")
        else:
            dist_udp.write("0\n")
    dist_udp.close

    for sess in sortedSessions:
        if 'zc' in sess.keys():
            dist_zc.write(str(sess['zc']))
            dist_zc.write("\n")
        else:
            dist_zc.write("0\n")
    dist_zc.close

    for sess in sortedSessions:
        if 'cdn' in sess.keys():
            dist_cdn.write(str(sess['cdn']))
            dist_cdn.write("\n")
        else:
            dist_cdn.write("0\n")
    dist_cdn.close

    for sess in sortedSessions:
        if 'web' in sess.keys():
            dist_web.write(str(sess['web']))
            dist_web.write("\n")
        else:
            dist_web.write("0\n")
    dist_web.close

    for sess in sortedSessions:
        if 'xmpp' in sess.keys():
            dist_xmpp.write(str(sess['xmpp']))
            dist_xmpp.write("\n")
        else:
            dist_xmpp.write("0\n")
    dist_xmpp.close

    for sess in sortedSessions:
        if 'rwg' in sess.keys():
            dist_rwg.write(str(sess['rwg']))
            dist_rwg.write("\n")
        else:
            dist_rwg.write("0\n")
    dist_rwg.close

    for sess in sortedSessions:
        if 'unknown' in sess.keys():
            dist_unk.write(str(sess['unknown']))
            dist_unk.write("\n")
        else:
            dist_unk.write("0\n")
    dist_unk.close

    for meet in sortedMeetings:
        dist_usr.write(str(meet['#_of_users']))
        dist_usr.write("\n")
    dist_usr.close

    # Number of distinct MMRs (hence meetings) and clients (hence sessions)
    uniqMMRs = len(collections.Counter(e['respIP'] for e in sessions))
    uniqClientIPs = len(collections.Counter(e['origIP'] for e in sessions))
    uniqClients = len(sessions)
    uniqMeetings = len(allMMRs)

    # Printing out results
    print()
    print("Rows in file = ", fileLines)
    print("Unique Clients = ", uniqClients)
    print("Unique Client IPs = ", uniqClientIPs)
    print("Unique MMRs = ", uniqMMRs)
    print("All Connections to MMRs = ", MMRcount)
    print("Meetings = ", uniqMeetings)
    print("Average number of MMR connections per client = ", round(float(MMRcount)/float(uniqClients), 2))
    print("Average number of distinct clients per IP = ", round(float(uniqClients)/float(uniqClientIPs), 2))
    print()

    print("Top 10 MMRs: ")
    topMeetingsCount = 0
    if len(sortedMeetings) >= 10:
        topMeetingsCount = 10
    else:
        topMeetingsCount = len(sortedMeetings)
    for i in range(topMeetingsCount):
        print(sortedMeetings[i])
    print()

    print("GPVPN (136.159.199 subnet) TCP sessions = ", gpvpnTCP)
    print("GPVPN (136.159.199 subnet) ICMP sessions = ", gpvpnICMP)
    print("GPVPN (136.159.199 subnet) other sessions = ", gpvpnUDP, "\n")

    print("List of all the Zoom sessions:", "\n")
    for d in sortedSessions:
        print(d)

    print()
    print("List of all the Zoom meetings:", "\n")
    for m in sortedMeetings:
        print(m)

if __name__ == '__main__':
    zoom_conns_parser()