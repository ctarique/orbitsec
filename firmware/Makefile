CC = gcc
# Point the compiler to the local include folder AND the Homebrew OpenSSL include folder
CFLAGS = -Wall -Wextra -I./include -I/opt/homebrew/opt/openssl@3/include
# Point the linker to the Homebrew OpenSSL library folder and link libcrypto
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lcrypto

TARGET = orbitsec_decoder
SRC = src/decrypt_and_verify.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)