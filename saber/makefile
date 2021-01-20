CC 		  = g++
CFLAGS  = -Wall -Wextra -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native



saber_complete: saber_each rng.o
	ar rvs saber_complete.a $(wildcard ./a/*.a) rng.o


SABER_FLAVORS = light_saber saber fire_saber

SABER_SOURCES = $(wildcard $(SABER_FLAVOR)/*.c)

define \n


endef

saber_each: 
	$(foreach SABER_FLAVOR,$(SABER_FLAVORS), \
		$(CC) $(CFLAGS) -c $(SABER_SOURCES) ${\n}\
\
		mv *.o $(SABER_FLAVOR)/obj ${\n}\
\
		ar rvs a/$(SABER_FLAVOR).a $(wildcard ./$(SABER_FLAVOR)/obj/*.o) ${\n}\
	)


rng.o: rng.c
	$(CC) $(NISTFLAGS) -c $^ -o $@ 