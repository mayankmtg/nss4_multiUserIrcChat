all: servermake clientmake
servermake: server.cpp
			g++ -std=c++11 -pthread server.cpp -o server
clientmake: client.cpp
			g++ -std=c++11 -pthread client.cpp -o client
