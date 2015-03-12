import zmq
import sys

port = "967"

if len(sys.argv) != 5:
    print "Usage: python", sys.argv[0], "<channel name> <context> <exten> <priority>"
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

# Action: Redirect
# ActionID: <value>
# Channel: <value>
# ExtraChannel: <value>
# Exten: <value>
# ExtraExten: <value>
# Context: <value>
# ExtraContext: <value>
# Priority: <value>
# ExtraPriority: <value>

#for request in range (1,10):
cmd = "{\"Action\": \"Redirect\", \"Channel\": \"%s\", \"Context\": \"%s\", \"Exten\": \"%s\", \"Priority\": \"%s\"}" % (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
