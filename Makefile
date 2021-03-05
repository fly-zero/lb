.PHONY: all

all: lb

lb: load_balance.o
	g++ $< -o $@ -lpcap

load_balance.o: load_balance.cpp
	g++ -c -Wall -Werror $< -o $@