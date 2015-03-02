import zmq
import sys
from doctest import Example

port = "967"

if len(sys.argv) == 1:
    print "Usage: python", sys.argv[0], "<call_to_address>"
    sys.exit()

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
print "Connected to asterisk-zmq "



#     ActionID - ActionID for this transaction. Will be returned.
#     Channel - Channel name to call.
#     Exten - Extension to use (requires Context and Priority)
#     Context - Context to use (requires Exten and Priority)
#     Priority - Priority to use (requires Exten and Context)
#     Application - Application to execute.
#     Data - Data to use (requires Application).
#     Timeout - How long to wait for call to be answered (in ms.).
#     CallerID - Caller ID to be set on the outgoing channel.
#     Variable - Channel variable to set, multiple Variable: headers are allowed.
#     Account - Account code.
#     EarlyMedia - Set to true to force call bridge on early media..
#     Async - Set to true for fast origination.
#     Codecs - Comma-separated list of codecs to use for this call.
#     ChannelId - Channel UniqueId to be set on the channel.
#     OtherChannelId - Channel UniqueId to be set on the second local channel.

# Example
# Action: Originate
# Channel: Local/1@dummy 
# Application: ((Asterisk cmd System|System))
# Data: /path/to/script

cmd = "{\"Action\": \"Originate\", \"Channel\":\"%s\", \"Application\":\"park\", \"CallerID\": \"Test Call\"}" % (sys.argv[1])
print cmd
socket.send(cmd)
print "Request sent"

#  Get the reply.
message = socket.recv()
print "Received reply [", message, "]"
