

#### Compiler and tool definitions shared by all build targets #####
CC = gcc
UNAME := $(shell uname)
# -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
BASICOPTS = -Wall -g -pthread -pipe -g3 -O6 -fPIC -DAST_MODULE=\"res_zmq_manager\"
CFLAGS = $(BASICOPTS)

# Define the target directories.
TARGETDIR_res_zmq_manager.so=build


all: $(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.so

## Target: res_zmq_manager.so
CFLAGS_res_zmq_manager.so = \
	-I/usr/include/ \
	-I/usr/local/include/ \
	-I/opt/asterisk/include/
CPPFLAGS_res_zmq_manager.so = 
OBJS_res_zmq_manager.so =  \
	$(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.o

# WARNING: do not run this directly, it should be run by the master Makefile
SHAREDLIB_FLAGS_res_zmq_manager.so = 

PKGCONFIG="pkg-config"
OSLDLIBS=

ifeq ($(UNAME), Linux)
	SHAREDLIB_FLAGS_res_zmq_manager.so = -shared -Xlinker -x -Wl,--hash-style=gnu -Wl,--as-needed -rdynamic
endif

ifeq ($(UNAME), Darwin)
	PKGCONFIG=$(shell if [ "x$(HOMEBREW_PREFIX)" == "x" ];then echo "/usr/local/bin/pkg-config"; else echo "$(HOMEBREW_PREFIX)/bin/pkg-config"; fi)

	# Link or archive
	SHAREDLIB_FLAGS_res_zmq_manager.so = -bundle -Xlinker -macosx_version_min -Xlinker 10.4 -Xlinker -undefined -Xlinker dynamic_lookup -force_flat_namespace
	OSLDLIBS=/usr/lib/bundle1.o
endif

JANSSON_DEFS=$(shell $(PKGCONFIG) jansson --cflags 2>/dev/null)
JANSSON_LIB=$(shell $(PKGCONFIG)  jansson --libs  2>/dev/null)

ZMQ_DEFS=$(shell $(PKGCONFIG) libzmq --cflags 2>/dev/null)
ZMQ_LIB=$(shell $(PKGCONFIG)  libzmq --libs  2>/dev/null)

CFLAGS_res_zmq_manager.so += $(ZMQ_DEFS)
LDLIBS_res_zmq_manager.so = $(OSLDLIBS) $(ZMQ_LIB)

$(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.so: $(TARGETDIR_res_zmq_manager.so) $(OBJS_res_zmq_manager.so) $(DEPLIBS_res_zmq_manager.so)
	$(LINK.c) $(CFLAGS_res_zmq_manager.so) $(CPPFLAGS_res_zmq_manager.so) -o $@ $(OBJS_res_zmq_manager.so) $(SHAREDLIB_FLAGS_res_zmq_manager.so) $(LDLIBS_res_zmq_manager.so)


# Compile source files into .o files
$(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.o: $(TARGETDIR_res_zmq_manager.so) src/res_zmq_manager.c
	$(COMPILE.c) $(CFLAGS_res_zmq_manager.so) $(CPPFLAGS_res_zmq_manager.so) -o $@ src/res_zmq_manager.c



#### Clean target deletes all generated files ####
clean:
	rm -f \
		$(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.so \
		$(TARGETDIR_res_zmq_manager.so)/res_zmq_manager.o
	rm -f -r $(TARGETDIR_res_zmq_manager.so)


# Create the target directory (if needed)
$(TARGETDIR_res_zmq_manager.so):
	mkdir -p $(TARGETDIR_res_zmq_manager.so)


# Enable dependency checking
#.KEEP_STATE:
#.KEEP_STATE_FILE:.make.state.GNU-amd64-Linux
