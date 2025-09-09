CC = gcc
CFLAGS = --std=c99 -Wall -Wextra -Werror -O2
LDFLAGS =

TARGET = main
SRC = main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf $(TARGET)

