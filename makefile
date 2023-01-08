LDLIBS += -lpcap

all:airodump

airodump:  CAirodump.o main.o CAirodump.h
	g++ -g CAirodump.o main.o -o $@ -lncurses ${LDLIBS}  

CAirodump.o : CAirodump.h CAirodump.cpp 
	$(CC) -g -c -o $@ CAirodump.cpp 

main.o: CAirodump.h main.cpp 
	$(CC) -g -c -o $@ main.cpp



clean:
	rm -f airodump *.o
