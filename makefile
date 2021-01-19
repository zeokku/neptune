PBUF_IN_DIR=protobufs
PBUF_SRC:=$(wildcard $(PBUF_IN_DIR)/*.proto)
PBUF_OUT_DIR=packets
PBUF_OBJ=packets.o

FLAGS=-Wall -std=c++11

PBUF_LIB = /usr/lib/libprotobuf-lite.a #-lprotobuf-lite

#-Wl,-Bstatic
LIBS= /usr/lib/libwolfssl.a $(PBUF_LIB) #-lwolfssl 

SRC:=$(wildcard  *.cpp) $(wildcard  *.hpp)
OUT_EXE=neptune

OBJ_FOLDER=obj

#SUBDIRS = foo bar baz
#subdirs:
#        for dir in $(SUBDIRS); do \
#          $(MAKE) -C $$dir; \
#        done


# $(PBUF_IN_DIR)/*

# force
# make -B ...

all: compile_protobufs compile

protobufs: $(PBUF_SRC)
	protoc -I=./$(PBUF_IN_DIR) --cpp_out=$(PBUF_OUT_DIR) $(PBUF_SRC)

PBUF_CC = $(wildcard  $(PBUF_OUT_DIR)/*.pb.cc)

packets: protobufs $(PBUF_CC)
	g++ $(FLAGS) -c $(PBUF_CC) $(PBUF_LIB) -o $(OBJ_FOLDER)/$(PBUF_OBJ)

SABER_SRC=$(wildcard saber/*.c) $(SABER_COMMON_SRC)

saber: $(SABER_SRC)
	$(foreach file,$(SABER_SRC), \
		g++ $(FLAGS) -c $(file) -o $(OBJ_FOLDER)/saber_$(notdir $(basename $(file))).o ; \
	)

#ar rvs $(OBJ_FOLDER)/saber.a $(wildcard $(OBJ_FOLDER)/saber/*.o)

OBJ_FILES=$(wildcard $(OBJ_FOLDER)/*.o)

compile: $(SRC)
	g++ $(FLAGS) $(SRC) $(OBJ_FILES) $(LIBS) -o $(OUT_EXE)

run: compile 	
	./$(OUT_EXE)	

networking_test:
	g++ $(FLAGS) networking/client.cpp $(OBJ_FOLDER)/$(PBUF_OBJ) -l protobuf -o networking/client
	g++ $(FLAGS) networking/server.cpp $(OBJ_FOLDER)/$(PBUF_OBJ) -l protobuf -o networking/server