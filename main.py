# DroneKit-Python program based on the "Simple Go To (Copter)" example.
# Time is synchronized to simulation clock through the "simtime" library.

import helper
import math
import ns3interface
import simtime
import struct
import sys
import time
import datetime



# pip install --user dronekit
from dronekit import connect, VehicleMode, LocationGlobalRelative
from pymavlink import mavutil

ta = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
print ta

# Synchronize time.time() and time.sleep(n) with simulation clock
simtime_port = int(sys.argv[1])
simtime.connect(simtime_port)

# Parse other commandline arguments
uav_name, mavlink_sysid, mavlink_port = sys.argv[2].split(':')
mavlink_sysid = int(mavlink_sysid)
mavlink_port = int(mavlink_port)

# Connect to the ns3 network simulator
ns3interface.connect('127.0.0.1', mavlink_sysid - 1)

# Connect to the Vehicle
vehicle = connect(
    'tcp:127.0.0.1:{}'.format(mavlink_port),
    source_system=mavlink_sysid + 100)

# ArduCopter initialisation can take a really long time
vehicle.wait_ready('gps_0', 'armed', 'mode', 'attitude', timeout=100)

# Don't try to arm until autopilot is ready
while not vehicle.is_armable:
    print(" Waiting for vehicle to initialise...")
    time.sleep(2)

print("Arming motors")
# Copter should arm in GUIDED mode
vehicle.mode = VehicleMode("GUIDED")
vehicle.armed = True

# Confirm vehicle armed before attempting to take off
while not vehicle.armed:
    print(" Waiting for arming...")
    time.sleep(1)

print("Taking off!")
target_altitude = 5 + mavlink_sysid * 2
ShortestDistance = 2
ts = time.time()


vehicle.simple_takeoff(target_altitude)  # Take off to target altitude
# Wait until the vehicle reaches a safe height before processing the goto
#  (otherwise the command after Vehicle.simple_takeoff will execute
#   immediately).
while True:
#    print(" Current altitude: {}".format(vehicle.location.global_relative_frame.alt))
    # Break and return from function just below target altitude.
    if vehicle.location.global_relative_frame.alt >= target_altitude * 0.95:
        print("Reached target altitude")
        break
    time.sleep(1)

#ending the running
end1=0
end2=0
end3=0
end4=0
end5=0
end6=0
end7=0
end8=0
end9=0
end10=0

# uavs behavior ---------

# base station

# We will store the position and heading of each UAV (except base)  as well as
# the absolute timestamp we receive each piece of information
uav_positions = dict()

# This is our control loop (10 Hz)
while True:
    time.sleep(1 / 10.0)

    # Update this node's position in the uav_positions dictionary
    uav_positions[ns3interface.local_id()] = (
        vehicle.location.global_relative_frame.lat,
        vehicle.location.global_relative_frame.lon,
        vehicle.location.global_relative_frame.alt,
        vehicle.heading,
        time.time()
    )

    # Broadcast it to the other agents
    ns3interface.sendto(struct.pack("<dddHd",
        uav_positions[ns3interface.local_id()][0], # lat
        uav_positions[ns3interface.local_id()][1], # lon
        uav_positions[ns3interface.local_id()][2], # alt
        uav_positions[ns3interface.local_id()][3], # heading
        uav_positions[ns3interface.local_id()][4]  # timestamp
    ), ns3interface.BROADCAST)

    # Process incoming messages
    while ns3interface.message_available():
        payload, sender = ns3interface.recvfrom()
        uav_positions[sender] = struct.unpack("<dddHd", payload)

    # Delete entries that have not been updated for more than one second
    for uav_id in list(uav_positions.keys()):
        if uav_positions[uav_id][4] + 1.0 < time.time():
            del uav_positions[uav_id]



    for uav_id, (lat, lon, alt, heading, timestamp) in uav_positions.items():
        if uav_id == 0:
            seqnum = 1
            #position in map in relation to base (+1, +1,5)
            lat = vehicle.location.global_relative_frame.lat
            lon = vehicle.location.global_relative_frame.lon
            startMissionPoint = LocationGlobalRelative(lat, lon, target_altitude)
            MissionPoint = LocationGlobalRelative(-27.60345,-48.51828,target_altitude) #50m
            vehicle.simple_goto(startMissionPoint)


            while True:

                # Set airspeed using attribute
                vehicle.groundspeed = 10 #m/s

                currentPosition = vehicle.location.global_relative_frame
                distanceOfBegin = helper.get_distance_metres(startMissionPoint, currentPosition)

                while (distanceOfBegin > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfBegin = helper.get_distance_metres(startMissionPoint, currentPosition)
                    time.sleep(.1)

                distanceOfEnd = helper.get_distance_metres(MissionPoint, currentPosition)

                while (distanceOfEnd > ShortestDistance):
                    distanceOfEnd = helper.get_distance_metres(MissionPoint, currentPosition)
                    currentPosition = vehicle.location.global_relative_frame
                    vehicle.simple_goto(MissionPoint)
                    time.sleep(.1)

                # Land
               # print("Landing UAV 1!")
                #vehicle.mode = VehicleMode("RTL")

                # Process incoming messages
                # while ns3interface.message_available():
                #     payload, sender = ns3interface.recvfrom()
                #     seqnum, lat, lon = struct.unpack("<Idd", payload)
                #     distance = helper.get_distance_metres(
                #         LocationGlobalRelative(lat, lon),
                #         vehicle.location.global_relative_frame
                #     )
                #     print('[{}] The misson vehicle 1 received a message of base: seqnum={} distance={} meters'.format(time.time(),seqnum, distance))

                if uav_id != ns3interface.local_id():
                    # Print list of current uav_positions entries
                    print('[{}] UAV {} currently knows about {}'.format(
                        time.time(),
                        ns3interface.local_id(),
                        ', '.join(map(str, sorted(uav_positions)))
                    ))

                    time.sleep(.1)


        else:
            #position in map in relation to base (+1, +1,5)
            lat = vehicle.location.global_relative_frame.lat
            lon = vehicle.location.global_relative_frame.lon
            startMissionPoint = LocationGlobalRelative(lat, lon, target_altitude)
	    pointA = LocationGlobalRelative(-27.60302,-48.51832, target_altitude) #100m
            pointB = LocationGlobalRelative(-27.60211,-48.51831, target_altitude) #200m
            pointC = LocationGlobalRelative(-27.60122,-48.51829, target_altitude) #300m
            pointD = LocationGlobalRelative(-27.60032,-48.51829, target_altitude) #400m
            pointE = LocationGlobalRelative(-27.59942,-48.51830, target_altitude) #500m
            pointF = LocationGlobalRelative(-27.59852,-48.51832, target_altitude) #600m
            pointG = LocationGlobalRelative(-27.59762,-48.51832, target_altitude) #700m
            pointH = LocationGlobalRelative(-27.59672,-48.51832, target_altitude) #800m
            pointI = LocationGlobalRelative(-27.59582,-48.51831, target_altitude) #900m
            pointJ = LocationGlobalRelative(-27.59493,-48.51827, target_altitude) #1000m
            vehicle.simple_goto(startMissionPoint)

            while True:

                # Set airspeed using attribute
                vehicle.groundspeed = 20 #m/s
                currentPosition = vehicle.location.global_relative_frame
                distanceOfBegin = helper.get_distance_metres(startMissionPoint, currentPosition)

                while (distanceOfBegin > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfBegin = helper.get_distance_metres(startMissionPoint, currentPosition)
                    time.sleep(.1)

                distanceOfPointA = helper.get_distance_metres(pointA, currentPosition)

                while (distanceOfPointA > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointA = helper.get_distance_metres(pointA, currentPosition)
                    vehicle.simple_goto(pointA)	    
		    if distanceOfPointA < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
		
                    time.sleep(.1)
		    

                distanceOfPointB = helper.get_distance_metres(pointB, currentPosition)

                while (distanceOfPointB > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointB = helper.get_distance_metres(pointB, currentPosition)
                    vehicle.simple_goto(pointB)
		    if distanceOfPointB < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

                distanceOfPointC = helper.get_distance_metres(pointC, currentPosition)

      		while (distanceOfPointC > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointC = helper.get_distance_metres(pointC, currentPosition)
                    vehicle.simple_goto(pointC)
		    if distanceOfPointC < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

		distanceOfPointD = helper.get_distance_metres(pointD, currentPosition)

      		while (distanceOfPointD > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointD = helper.get_distance_metres(pointD, currentPosition)
                    vehicle.simple_goto(pointD)
		    if distanceOfPointD < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

		distanceOfPointE = helper.get_distance_metres(pointE, currentPosition)

      		while (distanceOfPointE > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointE = helper.get_distance_metres(pointE, currentPosition)
                    vehicle.simple_goto(pointE)
		    if distanceOfPointE < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

		distanceOfPointF = helper.get_distance_metres(pointF, currentPosition)

      		while (distanceOfPointF > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointF = helper.get_distance_metres(pointF, currentPosition)
                    vehicle.simple_goto(pointF)
		    if distanceOfPointF < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

		distanceOfPointG = helper.get_distance_metres(pointG, currentPosition)

      		while (distanceOfPointG > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointG = helper.get_distance_metres(pointG, currentPosition)
                    vehicle.simple_goto(pointG)
		    if distanceOfPointG < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)

		distanceOfPointH = helper.get_distance_metres(pointH, currentPosition)

      		while (distanceOfPointH > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointH = helper.get_distance_metres(pointH, currentPosition)
                    vehicle.simple_goto(pointH)
		    if distanceOfPointH < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)


		distanceOfPointI = helper.get_distance_metres(pointI, currentPosition)

      		while (distanceOfPointI > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointI = helper.get_distance_metres(pointI, currentPosition)
                    vehicle.simple_goto(pointI)
		    if distanceOfPointI < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)


		distanceOfPointJ = helper.get_distance_metres(pointJ, currentPosition)

      		while (distanceOfPointJ > ShortestDistance):
                    currentPosition = vehicle.location.global_relative_frame
                    distanceOfPointJ = helper.get_distance_metres(pointJ, currentPosition)
                    vehicle.simple_goto(pointJ)
		    if distanceOfPointJ < 5:
			vehicle.groundspeed = 1.5 #m/s
                        time.sleep(.2)
                    time.sleep(.1)



                # Land
                print("UAV 2 complete mission!")
#                vehicle.mode = VehicleMode("LAND")


                # Process incoming messages
                # while ns3interface.message_available():
                #     payload, sender = ns3interface.recvfrom()
                #     seqnum, lat, lon = struct.unpack("<Idd", payload)
                #     distance = helper.get_distance_metres(
                #         LocationGlobalRelative(lat, lon),
                #         vehicle.location.global_relative_frame
                #     )
                #     print('[{}] The misson vehicle 2 received a message of base: seqnum={} distance={} meters'.format(time.time(),seqnum, distance))
                #
                # if uav_id != ns3interface.local_id():
                #     # Print list of current uav_positions entries
                #     print('[{}] UAV {} currently knows about {}'.format(
                #         time.time(),
                #         ns3interface.local_id(),
                #         ', '.join(map(str, sorted(uav_positions)))
                #     ))
                #
                #     time.sleep(.1)

        

    for uav_id in list(uav_positions.keys()):
        vehicle.mode = VehicleMode("LAND")
        while not vehicle.armed:
             vehicle.close()
             time.sleep(1)
             break

sf = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
print ("total of experiment--->", sf)
sys.exit("End of experiment scenario 2 nodes 1km!")
