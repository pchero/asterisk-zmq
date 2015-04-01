import zmq
import sys

port = "967"

if len(sys.argv) != 1:
    print "Usage: python", sys.argv[0]
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

# Action: ParkedCalls
# ActionID: <value>
# ParkingLot: <value>

#for request in range (1,10):
cmd = "{\"Action\": \"ParkedCalls\"}"
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
