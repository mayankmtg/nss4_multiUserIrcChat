#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <iostream>
#include <list>
#include <fstream>
#include <dirent.h>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <algorithm>
#include <utility> 
#include <sys/xattr.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <shadow.h>
#include <openssl/evp.h>
#include <sys/wait.h>
#include <thread>

using namespace std;

struct group_type{
	int admin;
	vector<int> user_ids;
	string group_name;
	int group_id;
};

struct group_invite{
	int from_uid;
	int to_uid;
	string group_name;
	int status;
};

static string rootDir = "/home/mayank/simple_slash";

// uid, socket
vector< tuple < int, int, pair< string, string > > > logged_in_clients;

vector<group_type> all_groups;
vector<group_invite> all_invites;

void throw_error(string ss){
	cerr << "error:\t " << ss << endl;
	exit(0);
}
uid_t getProcessRuid(){
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	int retVal = getresuid(&ruid, &euid, &suid);
	if(retVal!=0){
		cout << "Error: In getting ruid"<< endl;
		exit(0);
	}
	return ruid;
}

string getProcessUsername(uid_t ruid){
	struct passwd * pwuid = getpwuid(ruid);
	string username = "";
	if(pwuid){
		username = string(pwuid->pw_name);
	}
	else{
		cout << "Error: In getting username"<< endl;
		exit(0);
	}
	return username;
}
string getProcessGroupname(uid_t ruid){
	struct passwd * pwuid = getpwuid(ruid);
	string groupname = "";
	if(pwuid){
		struct group * grpstruct= getgrgid(pwuid->pw_gid);
		if(grpstruct!=NULL){
			groupname = grpstruct->gr_name;
		}
		else{
			cout << "Error: In getting groupname"<< endl;
		}
		return groupname;
	}
	else{
		cout << "Error: In getting groupname"<< endl;
		exit(0);
	}
	return groupname;
}

string getProcessDirectory(){
	char pwd[200];
	char* check = getcwd(pwd, 200);
	if(check == NULL){
		cout << "Error: In getting present working directory"<< endl;
		exit(0);
	}
	string retString = pwd;
	return retString;
}

string getProcessHomeDir(string username){
	struct passwd * pwnam = getpwnam(username.c_str());
	if(pwnam){
		return string(pwnam->pw_dir);
	}
	else{
		throw_error("Cannot get user");
	}
	return NULL;

}

string getProcessPasswordHash(string username){
	struct spwd* shadowpwd = getspnam(username.c_str());
	if(shadowpwd == (struct spwd*) 0 ){
		cout << "Error: In getting password from shadows file"<< endl;
		exit(0);
	}
	string retString = shadowpwd->sp_pwdp;
	int pos = retString.find('$');
	for (int i=0;i<2;i++){
		pos = retString.find('$', pos+3);
	}
	retString = retString.substr(pos+3);
	return retString;
}


string getProcessPasswordSalt(string username){
	struct spwd* shadowpwd = getspnam(username.c_str());
	if(shadowpwd == (struct spwd*) 0 ){
		cout << "Error: In getting password from shadows file"<< endl;
		exit(0);
	}
	string retString = shadowpwd->sp_pwdp;
	int pos = retString.find('$');
	for (int i=0;i<2;i++){
		pos = retString.find('$', pos+3);
	}
	retString = retString.substr(0,pos);
	return retString;
}

pair<string, string> getKeyIVfromPassword(const char* password){
	const EVP_CIPHER *cipher;
	const EVP_MD *dgst = NULL;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	// const char *password = password.c_str();
	const unsigned char *salt = NULL;
	int i;

	OpenSSL_add_all_algorithms();

	cipher = EVP_get_cipherbyname("aes-256-cbc");
	if(!cipher) {
		cout << "Error: no such cipher" << endl;
		exit(0);
	}

	dgst=EVP_get_digestbyname("md5");
	if(!dgst) {
		cout << "Error: no such digest" << endl;
		exit(0);
	}

	if(!EVP_BytesToKey(cipher, dgst, salt,(unsigned char *) password,strlen(password), 1, key, iv)){
		cout << "Error: EVP_BytesToKey failed" << endl;
		exit(0);
	}

	string key_string = "";
	for(i=0; i<cipher->key_len; ++i){
		char buff[4];
		sprintf(buff, "%02x", key[i]);
		key_string += string(buff);
	}

	string iv_string = "";
	for(i=0; i<cipher->iv_len; ++i){
		char buff[4];
		sprintf(buff, "%02x", iv[i]);
		iv_string += string(buff);
	}

	pair<string, string> retPair;
	retPair.first = key_string;
	retPair.second = iv_string;
	return retPair;
}

void writeKeyIvToFile(string filename, string key_string, string iv_string){
	ofstream outfile;
	outfile.open(filename.c_str());
	outfile << key_string << endl;
	outfile << iv_string << endl;
	outfile.close();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;
	if(!(ctx = EVP_CIPHER_CTX_new())){
		throw_error("encryption standard");
	}
	if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1){
		throw_error("encryption standard");
	}
	if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1){
		throw_error("encryption standard");
	}
	ciphertext_len = len;
	if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1){
		throw_error("encryption standard");	
	} 
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext){
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		throw_error("decryption process");
	}
	if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1){
		throw_error("decryption process");
	}

	if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1){
		throw_error("decryption process");
	}
	plaintext_len = len;

	if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1){
		throw_error("decryption process");
	} 
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

string decrypt_mod(string encrypted_string, string key, string iv){
	unsigned char buff[1024];
	int len = decrypt((unsigned char *)encrypted_string.c_str(), encrypted_string.length(), (unsigned char *)key.c_str(), (unsigned char *)iv.c_str(), buff);
	string decrypted_string = string((const char *) buff, (const char *) buff + len);
	decrypted_string = decrypted_string.substr(0,len);
	return decrypted_string;
}

string encrypt_mod(string plaintext_string, string key, string iv){
	unsigned char buff[500];
	int len = encrypt((unsigned char*)plaintext_string.c_str(), plaintext_string.length(), (unsigned char *) key.c_str(), (unsigned char*)iv.c_str(), buff);
	buff[len] = '\0';
	string encrypted_string = string((const char*) buff, (const char*) buff + len);
	return encrypted_string;
}

void send_enc(int sockfd, string plaintext, string key, string iv){
	string encrypted_text = encrypt_mod(plaintext, key, iv);
	int sendRet = send(sockfd, encrypted_text.c_str(), encrypted_text.length(), 0);
	if(sendRet == -1){
		throw_error("sending script error");
	}
}

string read_dec(int sockfd, string key, string iv ){
	char buff[1024];
	int read_size = read(sockfd,buff,1024);
	if(read_size==-1){
		throw_error("reading socket failed");
	}
	else if(read_size == 0){
		return NULL;
	}
	string ret_str = string(buff,read_size);
	return decrypt_mod(ret_str,key,iv);
}


class read_thread_handler{
	public:
		void operator()(int sockfd){
			while(1==1){
				cout << "waiting to read"<< endl;
				char buff[1024];
				cout << "waiting" << endl;
				int read_size = read(sockfd,buff,1024);
				if(read_size==-1){
					throw_error("reading socket failed");
				}
				else if(read_size == 0){
					return;
				}
				string ret_str = string(buff,read_size);
				cout << ret_str<< endl;
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
			thread read_thread(read_thread_handler(), acceptFd);
			// thread write_thread(write_thread_handler(), acceptFd, threadNo);
			read_thread.join();
			// write_thread.join();
			return;
		}
};


class client_handler{
	public:
		void operator()(int sockfd, pair<string, string> shared_secret, int client_uid){
			while(1==1){
				string client_str = read_dec(sockfd, shared_secret.first, shared_secret.second);
				string command;
				string argument;
				int pos = client_str.find("|||");
				if(pos==string::npos){
					command = client_str;
					argument = "";
				}
				else{
					command = client_str.substr(0,pos);
					argument = client_str.substr(pos+3);
				}

				if(command == "/who"){
					ostringstream ss;
					for (int i=0;i<logged_in_clients.size();i++){
						ss << get<0>(logged_in_clients[i]) << " " << getProcessUsername(get<0>(logged_in_clients[i])) << endl;
					}
					string ss_str = ss.str();
					send_enc(sockfd,ss_str,shared_secret.first, shared_secret.second);
				}
				else if(command == "/write_all"){
					for (int i=0;i < logged_in_clients.size();i++){
						int fd = get<1>(logged_in_clients[i]);
						pair<string, string> this_secret = get<2>(logged_in_clients[i]);
						if(fd != sockfd){
							send_enc(fd,argument,this_secret.first, this_secret.second);
						}
					}
				}
				else if(command == "/create_group"){
					struct group_type new_group;
					new_group.admin = client_uid;
					new_group.group_id = all_groups.size();
					new_group.group_name = "g" + to_string(all_groups.size());
					new_group.user_ids.push_back(client_uid);
					all_groups.push_back(new_group);
					send_enc(sockfd,new_group.group_name,shared_secret.first, shared_secret.second);
				}
				else if(command == "/group_invite"){
					pos = argument.find("|||");
					string group_name = argument.substr(0,pos);
					string invite_uid = argument.substr(pos+3);
					int invite_uid_int = stoi(invite_uid);
					struct group_type temp_group;
					int flag=0;
					for (int i=0;i<all_groups.size();i++){
						if(all_groups[i].group_name == group_name){
							flag = 1;
							temp_group = all_groups[i];
							break;
						}
					}
					string message;
					if(flag==0){
						message = "Group Name entered incorrect";
						send_enc(sockfd,message,shared_secret.first, shared_secret.second);
						continue;
					}
					// TODO:: if the person who has not created the group invites for the group
					flag=0;
					int send_fd;
					pair<string,string> send_key;
					for (int i=0;i< logged_in_clients.size();i++ ){
						if(get<0>(logged_in_clients[i]) == invite_uid_int){
							flag=1;
							send_fd = get<1>(logged_in_clients[i]);
							send_key = get<2>(logged_in_clients[i]);
							break;
						}
					}
					if(flag==0){
						message = "Invalid User id entered";
						send_enc(sockfd,message,shared_secret.first, shared_secret.second);
						continue;
					}
					struct group_invite new_invite;
					new_invite.from_uid = client_uid;
					new_invite.to_uid = invite_uid_int;
					new_invite.group_name = group_name;
					new_invite.status = 0;
					all_invites.push_back(new_invite);
					message = "Invite::"+ group_name + "::" + to_string(client_uid) + "::" + invite_uid;
					send_enc(send_fd, message, send_key.first, send_key.second);
				}
				else if(command == "/group_invite_accept"){
					int flag = 0;
					struct group_type* temp_group;
					for (int i=0;i<all_groups.size();i++){
						if(all_groups[i].group_name == argument){
							temp_group = &all_groups[i];
							flag=1;
							break;
						}
					}
					string message;
					if(flag == 0){
						message = "Group name does not exists";
						send_enc(sockfd,message,shared_secret.first, shared_secret.second);
						continue;
					}
					for (int i=0;i<all_invites.size();i++){
						if(all_invites[i].group_name == temp_group->group_name && all_invites[i].to_uid == client_uid && all_invites[i].status == 0){
							all_invites[i].status = 1;
							temp_group->user_ids.push_back(client_uid);
						}
					}
					message = "Added to Group Successfully";
					send_enc(sockfd, message, shared_secret.first, shared_secret.second);

				}
				else if(command == "/request_public_key"){
					send_enc(sockfd,client_str,shared_secret.first, shared_secret.second);
				}
				else if(command == "/send_public_key"){
					send_enc(sockfd,client_str,shared_secret.first, shared_secret.second);
				}
				else if(command == "/init_group_dhxchg"){
					int flag = 0;
					struct group_type temp_group;
					for (int i=0;i<all_groups.size();i++){
						if(all_groups[i].group_name == argument && all_groups[i].admin == client_uid){
							flag=1;
							temp_group = all_groups[i];
							break;
						}
					}
					int g = 199, p=997;
					string message;
					if(flag == 0){
						message = "Invalid request";
						send_enc(sockfd,message,shared_secret.first, shared_secret.second);
						continue;
					}
					vector< pair<int,int> > private_ids; 

					for (int i=0;i<temp_group.user_ids.size();i++){
						for(int j=0;j<logged_in_clients.size();j++){
							if(temp_group.user_ids[i]==get<0>(logged_in_clients[j])){
								message = "givemedh";
								send_enc(get<1>(logged_in_clients[j]), message, get<2>(logged_in_clients[j]).first, get<2>(logged_in_clients[j]).second);
								string pk = read_dec(get<1>(logged_in_clients[j]),get<2>(logged_in_clients[j]).first, get<2>(logged_in_clients[j]).second);
								private_ids.push_back(make_pair(get<1>(logged_in_clients[j]),stoi(pk)));
							}
						}
					}
					int mul = 1;
					for(int i=0;i<private_ids.size();i++){
						mul*=private_ids[i].second;
					}
					int result = (int)pow(g,mul) % p;
					for (int i=0;i<temp_group.user_ids.size();i++){
						for(int j=0;j<logged_in_clients.size();j++){
							if(temp_group.user_ids[i]==get<0>(logged_in_clients[j])){
								message = to_string(result);
								send_enc(get<1>(logged_in_clients[j]), message, get<2>(logged_in_clients[j]).first, get<2>(logged_in_clients[j]).second);
							}
						}
					}
				}
				else{
					send_enc(sockfd,client_str,shared_secret.first, shared_secret.second);
				}
				// cout << "Running" << endl;
			}

		}
};

class kdc_handler{
	public:
		void operator()(int port_kdc, int port_svr, pair<string,string> currKeyIv){
			int sockfd = socket(AF_INET,SOCK_STREAM,0);

			if(sockfd == -1){
				throw_error("socket creation");
			}
			
			struct sockaddr_in svrAdd;
			bzero((char*) &svrAdd, sizeof(svrAdd));
			svrAdd.sin_family = AF_INET;
			svrAdd.sin_addr.s_addr = INADDR_ANY;
			svrAdd.sin_port = port_kdc;
			int bindRet = bind(sockfd, (struct sockaddr*) &svrAdd, sizeof(svrAdd));
			
			if(bindRet==-1){
				throw_error("binding socket");
			}
			
			int listenRet = listen(sockfd, 5);
			
			if(listenRet==-1){
				throw_error("listening on port");
			}
			
			int svrAddLen = sizeof(svrAdd);
			while(1==1){
				int acceptFd = accept(sockfd,(struct sockaddr *)&svrAdd,(socklen_t*) &svrAddLen);
				
				if(acceptFd==-1){
					throw_error("accepting connection");
				}
				char buff[1024];
				int read_size = read(acceptFd,buff,1024);
				
				if(read_size==-1){
					throw_error("reading socket failed");
				}
				else if(read_size == 0){
					return;
				}
				
				string client_str = string(buff,read_size);
				int pos = client_str.find("|||");
				string nonce = client_str.substr(0,pos);
				string uid_client = client_str.substr(pos+3);
				// cout << nonce << " " << uid_client << endl;
				string password_str = to_string(rand() % 1000);
				pair<string,string> shared_secret = getKeyIVfromPassword(password_str.c_str());
				
				string ticket_key_iv_string = shared_secret.first + "|||" + shared_secret.second + "|||" + uid_client;
				string ticket = encrypt_mod(ticket_key_iv_string,currKeyIv.first, currKeyIv.second);

				string send_string = nonce + "|||" + to_string(port_svr) + "|||" + shared_secret.first + "|||" + shared_secret.second + "|||" + ticket;
				pair<string,string> client_secret = getKeyIVfromPassword(getProcessPasswordHash(getProcessUsername(stoi(uid_client))).c_str());
				string cipherT = encrypt_mod(send_string,client_secret.first, client_secret.second);
				send(acceptFd,cipherT.c_str(),cipherT.length(),0);
			}

			return;
		}
};

class svr_handler{
	public:
		void operator()(int port,pair<string, string> currKeyIv){
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
			
			int svrAddLen = sizeof(svrAdd);
			pair<string, string> shared_key;
			vector<thread> all_clients_threads;
			while(1==1){
				int acceptFd = accept(sockfd,(struct sockaddr *)&svrAdd,(socklen_t*) &svrAddLen);
				if(acceptFd==-1){
					throw_error("accepting connection");
				}
				char rec_buff[1024];
				int read_size = read(acceptFd,rec_buff,1024);
				
				if(read_size==-1){
					throw_error("reading socket failed");
				}
				else if(read_size == 0){
					return;
				}
				
				string rec_string = string(rec_buff,read_size);
				int pos = rec_string.find("|||");
				string rec_type = rec_string.substr(0,pos);
				rec_string = rec_string.substr(pos+3);
				if(rec_type == "chrp"){
					pos = rec_string.find("|||");
					string ticket = rec_string.substr(0,pos);
					rec_string = rec_string.substr(pos+3);
					
					string ticket_dec = decrypt_mod(ticket, currKeyIv.first, currKeyIv.second);
					pos = ticket_dec.find("|||");
					string ticket_key = ticket_dec.substr(0,pos);
					ticket_dec = ticket_dec.substr(pos+3);
					
					pos = ticket_dec.find("|||");
					string ticket_iv = ticket_dec.substr(0,pos);

					string uid_client = ticket_dec.substr(pos+3);
					cout << uid_client << endl;
					shared_key = make_pair(ticket_key,ticket_iv);
					
					string nonce_dec = decrypt_mod(rec_string, shared_key.first, shared_key.second);
					
					// cout << nonce_dec<< endl;
					int nonce_dec_int = stoi(nonce_dec);
					int nonce_new = rand() % 10;
					string send_string = to_string(nonce_dec_int-1) + "|||" + to_string(nonce_new);
					string nonce_new_enc = encrypt_mod(send_string,shared_key.first, shared_key.second);
					int sendRet = send(acceptFd,nonce_new_enc.c_str(), nonce_new_enc.length(), 0);
					if(sendRet==-1){
						throw_error("writing socket failed");
					}

					char final_buff[1024];
					read_size = read(acceptFd,final_buff,1024);
					
					if(read_size==-1){
						throw_error("reading socket failed");
					}
					else if(read_size == 0){
						return;
					}
					
					rec_string = string(final_buff,read_size);
					string nonce_3_resp = decrypt_mod(rec_string, shared_key.first, shared_key.second);
					string status = "Success";
					if(nonce_3_resp != to_string(nonce_new-1)){
						status = "Failed";
					}
					string status_enc = encrypt_mod(status, shared_key.first, shared_key.second);
					sendRet = send(acceptFd, status_enc.c_str(), status_enc.length(), 0);
					if(sendRet == -1){
						throw_error("writing socket failed");
					}
					if(status == "Success"){
						all_clients_threads.push_back(thread(client_handler(), acceptFd, shared_key, stoi(uid_client)));
						logged_in_clients.push_back(make_tuple(stoi(uid_client), acceptFd, shared_key));
					}
				}

			}
			for (int i=0;i<all_clients_threads.size();i++){
				all_clients_threads[i].join();
			}

		}
};




int main(int argc, const char* argv[]){
	// port for kdc = 8000
	int port_kdc = 8001;
	// port for server = 8080
	int port_svr = 8080;

	// Process Variables
	uid_t currUid = getProcessRuid();
	string currUser = getProcessUsername(currUid);
	// string currGroup = getProcessGroupname(currUid);
	// string currDirec = getProcessDirectory();
	string  currPasswordHash = getProcessPasswordHash(currUser);
	pair<string, string> currKeyIv = getKeyIVfromPassword(currPasswordHash.c_str());
	// 

	string all_users[] = {"v1", "v2", "v3"};
	
	int all_users_len = *(&all_users + 1) - all_users;
	for(int i=0;i<all_users_len;i++){
		string userPasswordHash = getProcessPasswordHash(all_users[i]);
		string userHomeDirec = getProcessHomeDir(all_users[i]);
		string userKeyDirec = userHomeDirec + "/keys";
		mkdir(userKeyDirec.c_str(),0777);
		pair<string,string> key_iv = getKeyIVfromPassword(userPasswordHash.c_str());
		writeKeyIvToFile(userKeyDirec + "/user.key", key_iv.first, key_iv.second);
		writeKeyIvToFile("/home/fr/keys/"+all_users[i]+".key",key_iv.first, key_iv.second);
	}

	thread kdc_thread = thread(kdc_handler(), port_kdc, port_svr, currKeyIv);
	thread svr_thread = thread(svr_handler(), port_svr, currKeyIv);
	kdc_thread.join();
	svr_thread.join();
	return 0;
}