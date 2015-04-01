import zmq
import sys

port = "967"

if len(sys.argv) != 4:
    print "Usage: python", sys.argv[0], "<channel 1> <channel 2> <tone>"
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

# Action: Bridge
# ActionID: <value>
# Channel1: <value>
# Channel2: <value>
# Tone: <value>

# ActionID - ActionID for this transaction. Will be returned.
# Channel1 - Channel to Bridge to Channel2.
# Channel2 - Channel to Bridge to Channel1.
# Tone - Play courtesy tone to Channel 2.
#     no
#     Channel1
#     Channel2
#     Both

cmd = "{\"Action\": \"Bridge\", \"Channel1\": \"%s\", \"Channel2\": \"%s\", \"Tone\": \"%s\"}" % (sys.argv[1], sys.argv[2], sys.argv[3])
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
