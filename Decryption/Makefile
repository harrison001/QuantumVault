CC = djgpp-gcc
CFLAGS = -O2 -Wall

all: combined_decrypt

# Combined decryption program supporting both key file and password modes
combined_decrypt: combined_decrypt.o aes.o security_check.o
	$(CC) -o combined_decrypt.exe combined_decrypt.o aes.o security_check.o $(CFLAGS)

# Object files
aes.o: aes.c aes.h
	$(CC) -c aes.c $(CFLAGS)

combined_decrypt.o: combined_decrypt.c aes.h security_check.h
	$(CC) -c combined_decrypt.c $(CFLAGS)

security_check.o: security_check.c security_check.h
	$(CC) -c security_check.c $(CFLAGS)

clean:
	rm -f *.o *.exe

.PHONY: all clean 