import zmq
import sys

port = "967"

if len(sys.argv) == 1:
    print "Usage: python", sys.argv[0], "<peer_name>"
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

#for request in range (1,10):
cmd = "{\"Action\": \"SIPShowPeer\", \"Peer\": \"%s\"}" % (sys.argv[1])
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
