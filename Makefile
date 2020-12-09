all: airodump

airodump: main.o
	g++ -o airodump main.o -lpcap

main.o: main.cpp beacon.h
	g++ -Wall -c -o main.o main.cpp 

clean:
	rm airodump *.o