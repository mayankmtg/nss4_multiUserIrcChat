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

static string rootDir = "/home/mayank/simple_slash";

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


class read_thread_handler{
	public:
		void operator()(int sockFd){
			while(1==1){
				cout << "waiting to read"<< endl;
				char buff[1024];
				cout << "waiting" << endl;
				int read_size = read(sockFd,buff,1024);
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
				
				string ticket_key_iv_string = shared_secret.first + "|||" + shared_secret.second;
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
					shared_key = make_pair(ticket_dec.substr(0,pos), ticket_dec.substr(pos+3));
					
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
				}
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