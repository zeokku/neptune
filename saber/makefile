CC 		  = g++
CFLAGS  = -Wall -Wextra -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native

# for some reason using .c for kem resulted in reference error, while using .cpp works as intended

saber_complete: saber_each common
# ar rvs saber_complete.a $(wildcard ./a/*.a) obj/rng.o

SABER_FLAVORS = light_saber saber fire_saber

SABER_SOURCES = $(wildcard $(SABER_FLAVOR)/*.c) $(wildcard $(SABER_FLAVOR)/*.cpp)

define \n


endef

saber_each: 

	$(foreach SABER_FLAVOR,$(SABER_FLAVORS), \
		rm $(SABER_FLAVOR)/obj/*.o ${\n}\
\
		$(CC) $(CFLAGS) -c $(SABER_SOURCES) ${\n}\
\
		mv *.o $(SABER_FLAVOR)/obj ${\n}\
\
		ar rvs _static/$(SABER_FLAVOR).a $(wildcard ./$(SABER_FLAVOR)/obj/*.o) ${\n}\
	)

common: rng.o verify.o

rng.o: rng.c
	$(CC) $(NISTFLAGS) -c $^ -o _common/$@ 

verify.o: verify.c
	$(CC) $(NISTFLAGS) -c $^ -o _common/$@ 