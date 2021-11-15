SRC_PATH= src/*

CCPP=g++
CPLUS_INCLUDE_PATH = includes/

all:
	make init-bin
	$(CCPP) -o2 -I $(CPLUS_INCLUDE_PATH) $(SRC_PATH) -lpcap -o bin/wireview.out

init-bin:
	mkdir -p bin
	mkdir -p bin/Debug
	
all-debug:
	make init-bin
	$(CCPP) -g -DDEBUG -I $(CPLUS_INCLUDE_PATH) $(SRC_PATH) -lpcap -o bin/Debug/wireview.out

clean:
	rm -f -r bin/
