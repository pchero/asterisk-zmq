import zmq
import sys

port = "967"
if len(sys.argv) > 1:
    port =  sys.argv[1]
    int(port)

if len(sys.argv) > 2:
    port1 =  sys.argv[2]
    int(port1)

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
if len(sys.argv) > 2:
    socket.connect ("tcp://localhost:%s" % port1)
print "Connected!"

#for request in range (1,10):
#print "Sending request ", request,"..."
socket.send ("{\"action\": \"SIPpeers\", \"actionID\": \"123\"}")
#  Get the reply.
message = socket.recv()
print "Received reply ", request, "[", message, "]"
