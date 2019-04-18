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

string authentication_init(int port, uid_t uid, string curr_key, string curr_iv){
	int nonce_1 = rand() % 10;
	cout << "Nonce 1: " << nonce_1 << endl;
	int uid_int = (int) uid;
	string nonce_1_str = to_string(nonce_1) + "|||" + to_string(uid_int);

	int kdc_fd = socket(AF_INET,SOCK_STREAM,0);
	if(kdc_fd==-1){
		throw_error("creating socket");
	}

	struct sockaddr_in kdc_svrAdd;
	bzero((char*) &kdc_svrAdd, sizeof(kdc_svrAdd));
	kdc_svrAdd.sin_family = AF_INET;
	kdc_svrAdd.sin_port = port;
	
	int connectRet = connect(kdc_fd, (struct sockaddr* ) &kdc_svrAdd, sizeof(kdc_svrAdd));
	
	if(connectRet==-1){
		throw_error("connecting to server");
	}
	
	int sendRet = send(kdc_fd,nonce_1_str.c_str(), nonce_1_str.length(), 0);
	
	if(sendRet==-1){
		throw_error("writing socket failed");
	}

	char kdc_resp_buff[1024];
	int read_size = read(kdc_fd,kdc_resp_buff,1024);
	if(read_size==-1){
		throw_error("reading socket failed");
	}
	else if(read_size==0){
		return NULL;
	}
	string kdc_resp_enc = string(kdc_resp_buff,read_size);
	string kdc_resp = decrypt_mod(kdc_resp_enc, curr_key, curr_iv);
	return kdc_resp;
}

bool authentication_chrp(int port, pair<string,string> shared_chat_client_secret, string ticket){
	int svr_fd = socket(AF_INET,SOCK_STREAM,0);
	if(svr_fd==-1){
		throw_error("creating socket");
	}

	struct sockaddr_in svr_svrAdd;
	bzero((char*) &svr_svrAdd, sizeof(svr_svrAdd));
	svr_svrAdd.sin_family = AF_INET;
	svr_svrAdd.sin_port = port;
	
	int connectRet = connect(svr_fd, (struct sockaddr* ) &svr_svrAdd, sizeof(svr_svrAdd));
	
	if(connectRet==-1){
		throw_error("connecting to server");
	}
	int nonce_2 = rand() % 10;
	cout << "Nonce 2: " << nonce_2 << endl;
	string nonce_2_str = to_string(nonce_2);
	string nonce_2_enc = encrypt_mod(nonce_2_str, shared_chat_client_secret.first, shared_chat_client_secret.second);
	
	string send_string = "chrp|||" + ticket + "|||" + nonce_2_enc;
	int sendRet = send(svr_fd, send_string.c_str(),send_string.length(),0);
	if(sendRet == -1 ){
		throw_error("sending error");
	}
	
	char buff[1024];
	int read_size = read(svr_fd,buff,1024);
	if(read_size==-1){
		throw_error("reading socket failed");
	}
	else if(read_size==0){
		return false;
	}
	string read_string = string(buff,read_size);
	string read_string_dec = decrypt_mod(read_string, shared_chat_client_secret.first, shared_chat_client_secret.second);
	int pos = read_string_dec.find("|||");
	string nonce_2_resp = read_string_dec.substr(0,pos);
	string nonce_3_str = read_string_dec.substr(pos+3);
	cout << "Nonce 2 resp: " << nonce_2_resp << endl;
	if(nonce_2_resp != to_string(nonce_2-1)){
		throw_error("Authentication Error");
	}
	int nonce_3 = stoi(nonce_3_str);
	nonce_3_str = to_string(nonce_3-1);
	string nonce_3_enc = encrypt_mod(nonce_3_str, shared_chat_client_secret.first, shared_chat_client_secret.second);
	nonce_3_enc = nonce_3_enc;
	sendRet = send(svr_fd, nonce_3_enc.c_str(), nonce_3_enc.length(), 0);
	if(sendRet == -1 ){
		throw_error("sending error");
	}

	char buff_status[1024];
	read_size = read(svr_fd,buff_status,1024);
	if(read_size==-1){
		throw_error("reading socket failed");
	}
	else if(read_size==0){
		return false;
	}
	read_string = string(buff_status,read_size);
	read_string_dec = decrypt_mod(read_string, shared_chat_client_secret.first, shared_chat_client_secret.second);
	if(read_string_dec=="Success"){
		return true;
	}
	return false;
}


int main(int argc, const char* argv[]){
	
	int port_kdc = 8001;
	// int port_svr = 8080;
	

	// Process Variables
	uid_t currUid = getProcessRuid();
	string currUser = getProcessUsername(currUid);
	string currGroup = getProcessGroupname(currUid);
	string currDirec = getProcessDirectory();
	string currPasswordHash = getProcessPasswordHash(currUser);
	//
	pair<string,string> key_iv = getKeyIVfromPassword(currPasswordHash.c_str());


	string kdc_resp= authentication_init(port_kdc, currUid, key_iv.first, key_iv.second);
	
	string nonce, port_svr_str, shared_key, shared_iv, ticket;
	
	int pos = kdc_resp.find("|||");
	nonce = kdc_resp.substr(0,pos);
	kdc_resp = kdc_resp.substr(pos+3);
	
	pos = kdc_resp.find("|||");
	port_svr_str = kdc_resp.substr(0,pos);
	int port_svr = stoi(port_svr_str);
	kdc_resp = kdc_resp.substr(pos+3);
	
	pos = kdc_resp.find("|||");
	shared_key = kdc_resp.substr(0,pos);
	kdc_resp = kdc_resp.substr(pos+3);
	
	pos = kdc_resp.find("|||");
	shared_iv = kdc_resp.substr(0,pos);
	kdc_resp = kdc_resp.substr(pos+3);

	pos = kdc_resp.find("|||");
	ticket = kdc_resp.substr(0,pos);
	kdc_resp = kdc_resp.substr(pos+3);

	// cout << nonce << port_svr_str << shared_key << shared_iv << ticket << endl;
	pair<string,string> shared_chat_client_secret = make_pair(shared_key, shared_iv);
	
	bool chrp_status = authentication_chrp(port_svr, shared_chat_client_secret, ticket);
	if(!chrp_status){
		throw_error("Authentication Issue");
	}
	cout << "Authentication Successful"<< endl;
	
	
	// thread read_thread(read_thread_handler(), sockfd);
	// thread write_thread(write_thread_handler(), sockfd);
	// read_thread.join();
	// write_thread.join();
	
	
	// string input;
	// cin >> input;
	// send(sockfd,input.c_str(), input.length(), 0);
	return 0;
}