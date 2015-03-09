import zmq
import sys

port = "967"

if len(sys.argv) != 4:
    print "Usage: python", sys.argv[0], "<channel name>, <context>, <exten>"
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

#for request in range (1,10):
cmd = "{\"Action\": \"BlindTransfer\", \"Channel\": \"%s\", \"Context\": \"%s\", \"Exten\": \"%s\"}" % (sys.argv[1], sys.argv[2], sys.argv[3])
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
