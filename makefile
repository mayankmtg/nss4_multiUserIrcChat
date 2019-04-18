all: servermake clientmake
servermake: server.cpp
			g++ -std=c++11 -pthread server.cpp -o nssserver -lcrypto -g
clientmake: client.cpp
			g++ -std=c++11 -pthread client.cpp -o nssclient -lcrypto -g
