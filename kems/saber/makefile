CC 		  = g++
CFLAGS  = -Wall -Wextra -Wredundant-decls\
	-O3 -fomit-frame-pointer -march=native
NISTFLAGS  = -Wno-unused-result -O3 -fomit-frame-pointer -march=native

# for some reason using .c for kem resulted in reference error, while using .cpp works as intended

saber_complete: clean_static saber_each common
# ar rvs saber_complete.a $(wildcard ./a/*.a) obj/rng.o

clean_static:
	rm -f _static/*.a

SABER_FLAVORS = light_saber saber fire_saber

SABER_SOURCES = $(wildcard $(SABER_FLAVOR)/*.c) $(wildcard $(SABER_FLAVOR)/*.cpp)

define \n


endef

saber_each: 

	$(foreach SABER_FLAVOR,$(SABER_FLAVORS), \
		rm -f $(SABER_FLAVOR)/obj/*.o ${\n}\
\
		$(CC) $(CFLAGS) -c $(SABER_SOURCES) ${\n}\
\
		mv *.o $(SABER_FLAVOR)/obj ${\n}\
\
		ar rvs _static/$(SABER_FLAVOR).a $(wildcard ./$(SABER_FLAVOR)/obj/*.o) ${\n}\
	)

COMMON_SRC = rng.c verify.c fips202.c

common: $(COMMON_SRC)
	$(CC) $(NISTFLAGS) -c $^

	mv *.o _common