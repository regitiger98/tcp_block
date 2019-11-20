all : tcp_block

tcp_block: main.o pkt.o
	g++ -o tcp_block main.o pkt.o -lpcap

pkt.o: pkt.cpp pkt.h
	g++ -c -o pkt.o pkt.cpp

main.o: main.cpp pkt.h
	g++ -c -o main.o main.cpp

clean:
	rm -f tcp_block *.o
