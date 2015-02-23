import zmq
import sys

port = "968"
if len(sys.argv) > 1:
    port =  sys.argv[1]
    int(port)

if len(sys.argv) > 2:
    port1 =  sys.argv[2]
    int(port1)

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.SUB)
socket.connect ("tcp://localhost:%s" % port)
if len(sys.argv) > 2:
    socket.connect ("tcp://localhost:%s" % port1)
print "Connected!"

socket.setsockopt(zmq.SUBSCRIBE, "{")
while 1:
    string = socket.recv()
    print "%s" % (string)

