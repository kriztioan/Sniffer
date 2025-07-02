PROGS:=sniffer
CPP_FILES:=$(wildcard *.c)
OBJ_FILES:=$(patsubst %.c,%.o,$(CPP_FILES))
DEP_FILES:=deps.d
LIBS:=-lpcap
CPPFLAGS:=-MMD -MF $(DEP_FILES)

all: $(PROGS)

-include $(DEP_FILES)

$(PROGS): $(OBJ_FILES)
	$(CC) -o $(PROGS) $(OBJ_FILES) $(LIBS) $(CPPFLAGS)

%.o: %.c
	$(CC) -c $< $(CPPFLAGS)

clean:
	$(RM) $(DEP_FILES) $(OBJ_FILES) $(PROGS)
