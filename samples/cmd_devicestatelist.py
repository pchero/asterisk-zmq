# cmd_devicestatelist.py
#  Created on: Mar 12, 2015
#      Author: pchero


import zmq
import sys

port = "967"

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected!"

#for request in range (1,10):
cmd = "{\"Action\": \"DeviceStateList\"}"
print cmd
socket.send(cmd)
#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
