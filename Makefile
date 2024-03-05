CC = egcc
CFLAGS_SERVER = -I. -fpack-struct
OBJ_SERVER = main.o user.o status.o util.o
SERVER = server
OBJ_TUNNEL = tunnel.o util.o
TUNNEL = tunnel

LIBS_SERVER = -lsqlite3
LIBS_TUNNEL = -lpthread

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(SERVER): $(OBJ_SERVER)
	$(CC) -o $@ $^ $(LIBS_SERVER) $(CFLAGS)

$(TUNNEL): $(OBJ_TUNNEL)
	$(CC) -o $@ $^ $(LIBS_TUNNEL)

clean:
#	rm -rf $(TARGET) *.o *~
	rm -rf *.o *~
