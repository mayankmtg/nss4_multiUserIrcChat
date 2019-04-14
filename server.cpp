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
        void operator()(int sockfd, int threadNo){
            while(1==1){
                cout << "waiting to read"<< endl;
                char buff[1024];
                int read_size = read(sockfd,buff,1024);
                if(read_size==-1){
                    throw_error("reading socket failed");
                }
                else if(read_size == 0){
                    return;
                }
                string ret_str = string(buff,read_size);
                cout << ret_str<< endl;
                string input = to_string(threadNo);
                int sendRet = send(sockfd,input.c_str(), input.length(), 0);
                if(sendRet==-1){
                    throw_error("writing socket failed");
                }
            }
        }
};

class write_thread_handler{
    public:
        void operator()(int sockfd, int threadNo){
            while(1==1){
                cout << "waiting to write"<< endl;
                string input = to_string(threadNo);
                int sendRet = send(sockfd,input.c_str(), input.length(), 0);
                if(sendRet==-1){
                    throw_error("writing socket failed");
                }
            }
            return;
        }
};

class thread_handler{
    public:
        void operator()(int sockfd, struct sockaddr_in svrAdd, int svrAddLen, int threadNo){
            int acceptFd = accept(sockfd,(struct sockaddr *)&svrAdd,(socklen_t*) &svrAddLen);
            if(acceptFd==-1){
                throw_error("accepting connection");
            }
            thread read_thread(read_thread_handler(), acceptFd, threadNo);
            // thread write_thread(write_thread_handler(), acceptFd, threadNo);
            read_thread.join();
            // write_thread.join();
            return;
        }
};


int main(int argc, const char* argv[]){
    if(argc!=2){
        throw_error("./server.cpp <port>");
    }
    int port = atoi(argv[1]);

    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if(sockfd == -1){
        throw_error("socket creation");
    }
    struct sockaddr_in svrAdd;
    bzero((char*) &svrAdd, sizeof(svrAdd));
    svrAdd.sin_family = AF_INET;
    svrAdd.sin_addr.s_addr = INADDR_ANY;
    svrAdd.sin_port = port;
    int bindRet = bind(sockfd, (struct sockaddr*) &svrAdd, sizeof(svrAdd));
    if(bindRet==-1){
        throw_error("binding socket");
    }
    int listenRet = listen(sockfd, 5);
    if(listenRet==-1){
        throw_error("listening on port");
    }
    // thread t1(thread_handler(), "abc", "def");
    // t1.join();
    // cout << "Ending" << endl;
    int svrAddLen = sizeof(svrAdd);
    int no_of_threads = 3;
    thread client_handler[no_of_threads];
    for (int i=0;i<no_of_threads;i++){
        client_handler[i] = thread(thread_handler(),sockfd, svrAdd, svrAddLen, i);
    }
    for (int i=0;i<no_of_threads;i++){
        client_handler[i].join();
    }
    
    
    // cout << "accepting"<< endl;
    // int acceptFd = accept(sockfd,(struct sockaddr *)&svrAdd,(socklen_t*) &svrAddLen);
    // if(acceptFd==-1){
    //     throw_error("accepting connection");
    // }


    // char buff[100];
    // ssize_t valread = read(acceptFd,buff, 100);
    // cout << buff<< endl;
    // string input;
    // cin >> input;
    // send(acceptFd,input.c_str(), input.length(), 0);
    // cin >> input;
    // send(acceptFd,input.c_str(), input.length(), 0);

    // thread read_thread(read_thread_handler(), acceptFd);
    // thread write_thread(write_thread_handler(), acceptFd);
    // read_thread.join();
    // write_thread.join();
    return 0;
}