#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <thread>

using namespace std;

void throw_error(string ss){
    cerr << "error:\t " << ss << endl;
    exit(0);
}
class read_thread_handler{
    public:
        void operator()(int sockfd){
            while(1==1){
                // cout << "waiting to read"<< endl;
                char buff[1024];
                int read_size = read(sockfd,buff,1024);
                if(read_size==-1){
                    throw_error("reading socket failed");
                }
                else if(read_size==0){
                    return;
                }
                string ret_str = string(buff,read_size);
                cout << ret_str<< endl;
            }
        }
};

class write_thread_handler{
    public:
        void operator()(int sockfd){
            while(1==1){
                // cout << "waiting to write"<< endl;
                string input;
                cin >> input;
                int sendRet = send(sockfd,input.c_str(), input.length(), 0);
                if(sendRet==-1){
                    throw_error("writing socket failed");
                }
            }
            return;
        }
};



int main(int argc, const char* argv[]){
    if(argc!=2){
        throw_error("./client.cpp <port>");
    }
    int port = atoi(argv[1]);
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1){
        throw_error("creating socket");
    }
    struct sockaddr_in svrAdd;
    bzero((char*) &svrAdd, sizeof(svrAdd));
    svrAdd.sin_family = AF_INET;
    svrAdd.sin_port = port;
    int connectRet = connect(sockfd, (struct sockaddr* ) &svrAdd, sizeof(svrAdd));
    if(connectRet==-1){
        throw_error("connecting to server");
    }
    thread read_thread(read_thread_handler(), sockfd);
    thread write_thread(write_thread_handler(), sockfd);
    read_thread.join();
    write_thread.join();
    // string input;
    // cin >> input;
    // send(sockfd,input.c_str(), input.length(), 0);
    return 0;
}