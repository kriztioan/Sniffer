PROG:=sniffer
CPP_FILES:=$(wildcard *.c)
OBJ_FILES:=$(patsubst %.c,%.o,$(CPP_FILES))
LIBS:=-lpcap

$(PROG): $(OBJ_FILES)
	$(CC) -o $(PROG) $(OBJ_FILES) $(LIBS)

%.o: %.c
	$(CC) -c $<

clean:
	$(RM) *.o $(PROG)
