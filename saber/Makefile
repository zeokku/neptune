CC 		  = g++
CFLAGS  = -Wall -Wextra -Wmissing-prototypes -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native 
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native -std=c99 
CLANG   = clang -march=native -O3 -fomit-frame-pointer -fwrapv -Qunused-arguments
RM 		  = /bin/rm


all: test/PQCgenKAT_kem \
     test/test_kex \
     test/kem \

SOURCES = pack_unpack.c poly.c fips202.c verify.c cbd.c SABER_indcpa.c kem.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h 

OBJ_FOLDER = obj

saber.a: $(SOURCES) $(HEADERS) rng.o
	# $(foreach file,$(SOURCES), \
	# 	$(CC) $(CFLAGS) -lcrypto -lwolfssl -c $(file) -o $(OBJ_FOLDER)/$(notdir $(basename $(file))).o ; \
	# )

	$(CC) $(CFLAGS) -c $(SOURCES)

	mv *.o ./$(OBJ_FOLDER)

	ar rvs saber.a $(wildcard $(OBJ_FOLDER)/*.o)

# undefined reference problem is caused by order of files supplied to linker, so moving lib at the end fixes the issue

test/test_kex: saber.a $(SOURCES) $(HEADERS) rng.o test/test_kex.c
	$(CC) $(CFLAGS) -o $@ test/test_kex.c saber.a -lcrypto -lwolfssl

test/PQCgenKAT_kem: $(SOURCES) $(HEADERS) rng.o test/PQCgenKAT_kem.c 
	$(CC) $(NISTFLAGS) -o $@ $(SOURCES) rng.o test/PQCgenKAT_kem.c -lcrypto -lwolfssl

test/kem: $(SOURCES) $(HEADERS) rng.o test/kem.c
	$(CC) $(CFLAGS) -o $@ $(SOURCES) rng.o test/kem.c -lcrypto -lwolfssl

rng.o: rng.c
	$(CC) $(NISTFLAGS) -c rng.c -lcrypto -lwolfssl -o $@ 

# fips202.o: fips202.c
# 	$(CLANG) -c $^ -o $@

.PHONY: clean test

test: 
	./test/test_kex
	./test/PQCgenKAT_kem
	./test/kem

clean:
	-$(RM) -f *.o
	-$(RM) -rf test/test_kex
	-$(RM) -rf test/kem
	-$(RM) -rf test/PQCgenKAT_kem
	-$(RM) -f *.req
	-$(RM) -f *.rsp
