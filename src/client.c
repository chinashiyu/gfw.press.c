/**
 *
 *    GFW.Press
 *    Copyright (C) 2016  chinashiyu ( chinashiyu@gfw.press ; http://gfw.press )
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *    
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

extern int get_password_key(char * password, char * key);

extern int decrypt(char *key, char *in, int inl, char *out);

extern int encrypt_net(char *key, char *in, int in_len, char *out);

/** 数据块(含噪音)最大值，768K */
static int BUFFER_MAX = 1024 * 768;

/**  缓冲区最小值，128K */
static int BUFFER_SIZE_MIN = 1024 * 128;

/**  缓冲区最大值，512K */
static int BUFFER_SIZE_MAX = 1024 * 512;

/**  缓冲区自动调整的步长值，128K */
/** static int BUFFER_SIZE_STEP = 1024 * 128; */

/**  加密数据长度值加密后的字节长度，固定30个字节，解密后固定14个字节 */
static int ENCRYPT_SIZE = 30;

/**  噪音数据最大长度，4K */
static int NOISE_MAX = 1024 * 4;

/** 数据块大小的字符串长度 14 */
static int SIZE_SIZE = 14;

/**  IV字节长度，16 */
static int IV_SIZE = 16;

/** 节点地址 */
static char * server_host;

/** 节点端口 */
static int server_port = 0;

/** 代理端口 */
static int listen_port = 0;

/** 连接密码 */
static char * password;

/** 加密KEY */
static char * key;

/** IO线程参数结构 */
struct IO {

	int socket_agent;

	int socket_server;

};

#if !defined(SO_NOSIGPIPE)
#define SO_NOSIGPIPE MSG_NOSIGNAL
#endif

/** 客户端主线程 */
static pthread_t thread_id_main;

/** 监听端口socket */
static int socket_client;

/** 主线程运行状态：0，停止，1，运行 */
static int main_thread_status = 0;

/**
 * 获取当前时期时间
 */
void datetime(char *_datetime) {

	time_t _time = time(NULL);

	struct tm *_tm = localtime(&_time);

	sprintf(_datetime, "%02d-%02d-%02d %02d:%02d:%02d", _tm->tm_year + 1900, _tm->tm_mon + 1, _tm->tm_mday, _tm->tm_hour, _tm->tm_min, _tm->tm_sec);

}

/**
 * 打印信息
 */
void _log(char * message) {

	char * _datetime = malloc(22);

	datetime(_datetime);

	_datetime[21] = '\0';

	printf("\n[%s] %s\n", _datetime, message);

	free(_datetime);

}

/**
 * 返回数据块数据长度和噪音长度
 */
int get_block_sizes(char *head, int *sizes) {

	if (strlen(head) != 14) {

		return -1;

	}

	int data, noise;

	sscanf(head, "%08d,%05d", &data, &noise);

	sizes[0] = data;

	sizes[1] = noise;

	if (sizes[0] < 1 || sizes[0] > BUFFER_SIZE_MAX || sizes[1] < 0) {

		return -1;

	}

	if (sizes[0] + sizes[1] > BUFFER_MAX) {

		return -1;

	}

	return 2;

}

/**
 * 浏览器IO线程
 */
void *thread_io_agent(void *_io) {

	struct IO io = *((struct IO*) _io);

	while (main_thread_status == 1) {

		char *buffer = malloc(BUFFER_SIZE_MIN + 1);

		/** 接收浏览器数据 */
		int recvl = recv(io.socket_agent, buffer, BUFFER_SIZE_MIN, 0);

		/** printf("\nrecvl from agent: %d\n" , recvl); */

		if (recvl < 1) {

			free(buffer);

			break;

		}

		/** printf("\nrecvl from agent: %s\n" , buffer); */

		buffer[recvl] = '\0';

		int outl = recvl + ENCRYPT_SIZE + NOISE_MAX;

		char *out = malloc(outl + 1);

		int _outl = encrypt_net(key, buffer, recvl, out);

		out[_outl] = '\0';

		free(buffer);

		/** 发送数据到服务器 */
		int sendl = send(io.socket_server, out, _outl, 0);

		/** printf("\nsend to server: %d\n" , sendl); */

		free(out);

		if (sendl < 1) {

			break;

		}

	}

	pthread_exit(0);

}

/**
 * 服务器IO线程
 */
void *thread_io_server(void *_io) {

	struct IO io = *((struct IO*) _io);

	while (main_thread_status == 1) {

		char *head = malloc(ENCRYPT_SIZE + 1);

		/** 接收服务器头数据 */
		int head_len = recv(io.socket_server, head, ENCRYPT_SIZE, 0);

		/** printf("\nrecvl from server head: %d\n" , head_len); */

		if (head_len != ENCRYPT_SIZE) {

			free(head);

			break;

		}

		head[ENCRYPT_SIZE] = '\0';

		char *head_out = malloc(SIZE_SIZE + 1);

		if (decrypt(key, head, head_len, head_out) == -1) {

			free(head_out);

			break;

		}

		head_out[SIZE_SIZE] = '\0';

		/** printf("\nrecvl from server head: %s\n" , head_out); */

		free(head);

		int *sizes = malloc(2 * sizeof(int));

		if (get_block_sizes(head_out, sizes) == -1) {

			free(head_out);

			free(sizes);

			break;

		}

		int data = (int) sizes[0];

		int noise = (int) sizes[1];

		free(head_out);

		free(sizes);

		int size = data + noise;

		char *in = malloc(size + 1);

		int _size = 0;

		for (; _size < size;) {

			/** 接收服务器数据 */
			int recvl = recv(io.socket_server, &in[_size], (size - _size), 0);

			if (recvl < 1) {

				break;

			}

			_size += recvl;

		}

		/** printf("\nrecvl from server body: %d\n" , _size); */

		if (_size != size) {

			free(in);

			break;

		}

		in[size] = '\0';

		int outl = data - IV_SIZE;

		char * out = malloc(outl + 1);

		if (decrypt(key, in, data, out) == -1) {

			free(in);

			free(out);

			break;

		}

		out[outl] = '\0';

		/** printf("\nrecvl from server body: %d\n%s\n" , outl, out); */

		free(in);

		/** 转发数据到浏览器 */
		int sendl = send(io.socket_agent, out, outl, 0);

		/** printf("\nsend to agent: %d\n" , sendl); */

		free(out);

		if (sendl < 1) {

			break;

		}

	}

	pthread_exit(0);

}

/**
 * 设置socket超时, 180秒
 */
void set_timeout(int socket) {

	struct timeval tv;

	tv.tv_sec = 180;

	tv.tv_usec = 0;

	setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

	setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

	/** 忽略中止信号 */
	int optVal = 1;

	setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &optVal, sizeof(optVal));

}

/**
 * 连接服务器
 */
int connect_server() {

	int socket_server = socket(AF_INET, SOCK_STREAM, 0);

	if (socket_server == -1) {

		_log("连接服务器失败：无法进行网络操作");

		return -1;

	}

	struct sockaddr_in sockaddr_server;

	memset(&sockaddr_server, 0, sizeof(sockaddr_server));

	sockaddr_server.sin_family = AF_INET;

	/** htonl(INADDR_LOOPBACK); */
	sockaddr_server.sin_addr.s_addr = inet_addr(server_host);

	sockaddr_server.sin_port = htons(server_port);

	if (connect(socket_server, (struct sockaddr *) &sockaddr_server, sizeof(struct sockaddr)) == -1) {

		char message[128];

		sprintf(message, "连接服务器失败：%s:%d", server_host, server_port);

		_log(message);

		return -1;

	}

	return socket_server;

}

/**
 * 客户端线程
 */
void *thread_client(void *_socket_agent) {

	pthread_detach(pthread_self());

	struct IO io;

	io.socket_agent = *((int *) _socket_agent);

	io.socket_server = connect_server();

	if (io.socket_server == -1) {

		close(io.socket_server);

		pthread_exit(0);

	}

	set_timeout(io.socket_agent);

	set_timeout(io.socket_server);

	pthread_t thread_id_agent;

	pthread_create(&thread_id_agent, NULL, thread_io_agent, (void *) &io);

	pthread_t thread_id_server;

	pthread_create(&thread_id_server, NULL, thread_io_server, (void *) &io);

	pthread_join(thread_id_agent, NULL);

	pthread_join(thread_id_server, NULL);

	close(io.socket_agent);

	close(io.socket_server);

	pthread_exit(0);

}

int check_config() {

	if (server_host == NULL || strlen(server_host) < 7 || server_port == 0 || password == NULL || strlen(password) < 8 || listen_port == 0) {

		_log("配置信息不完整");

		return -1;

	}

	return 0;

}

/**
 *设置配置
 */
int set_config(char *_server_host, char *_server_port, char *_password, char *_listen_port) {

	if (_server_host == NULL || _server_port == NULL || _password == NULL || _listen_port == NULL || strlen(_server_host) < 7 || strlen(_server_port) < 2 || strlen(_listen_port) < 2 || strlen(_password) < 8) {

		_log("配置信息不完整");

		return -1;

	}

	server_host = malloc(128);

	password = malloc(64);

	key = malloc(25);

	memcpy(server_host, _server_host, strlen(_server_host));

	server_host[strlen(_server_host)] = '\0';

	//server_host = _server_host;

	server_port = atoi(_server_port);

	listen_port = atoi(_listen_port);

	memcpy(password, _password, strlen(_password));

	password[strlen(_password)] = '\0';

	//password = _password;

	get_password_key(password, key);

	key[24] = '\0';

	return 0;

}

/**
 * 从配置文件 client.json 初始化配置
 */
int load_config() {

	char *_server_host = malloc(128);

	char *_server_port = malloc(8);

	char *_password = malloc(32);

	char *_listen_port = malloc(8);

	char * text = malloc(2048);

	FILE* file;

	if ((file = fopen("client.json", "r+")) == NULL) {

		free(_server_host);

		free(_server_port);

		free(_password);

		free(_listen_port);

		free(text);

		return -1;

	}

	int pos = 0;

	while (!feof(file)) {

		fscanf(file, "%s", &text[pos]);

		pos = strlen(text);

	}

	if (pos == 0) {

		free(_server_host);

		free(_server_port);

		free(_password);

		free(_listen_port);

		free(text);

		return -1;

	}

	fclose(file);

	char _text[pos + 1];

	int _pos = 0;

	int i;

	for (i = 0; i < pos; i++) {

		char c = text[i];

		if (c != '{' && c != '}' && c != '"') {

			_text[_pos++] = c;

		}

	}

	free(text);

	if (_pos == 0) {

		free(_server_host);

		free(_server_port);

		free(_password);

		free(_listen_port);

		return -1;

	}

	_text[_pos] = '\0';

	sscanf(_text, "ServerHost:%[^,],ServerPort:%[0-9],ProxyPort:%[0-9],Password:%[^,]", _server_host, _server_port, _listen_port, _password);

	int r = set_config(_server_host, _server_port, _password, _listen_port);

	free(_server_host);

	free(_server_port);

	free(_password);

	free(_listen_port);

	return r;

}

/**
 * 打印配置信息
 */
void print_config() {

	char * _datetime = malloc(21);

	datetime(_datetime);

	int pl = strlen(password);

	char _password[pl + 1];

	memset(_password, '*', pl);

	_password[pl] = '\0';

	printf("\n[%s] 节点地址：%s\n[%s] 节点端口：%d\n[%s] 代理端口：%d\n[%s] 连接密码：%s\n", _datetime, server_host, _datetime, server_port, _datetime, listen_port, _datetime, _password);

	free(_datetime);

}

/**
 * 客户端主线程
 */
void* main_thread() {

	print_config();

	if (check_config() == -1) {

		pthread_exit(0);

	}

	socket_client = socket(AF_INET, SOCK_STREAM, 0);

	if (socket_client == -1) {

		_log("无法进行网络操作，已停止运行并退出");

		pthread_exit(0);

	}

	const int optVal = 1;

	setsockopt(socket_client, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal));

	struct sockaddr_in sockaddr_client;

	memset(&sockaddr_client, 0, sizeof(sockaddr_client));

	sockaddr_client.sin_family = AF_INET;

	sockaddr_client.sin_addr.s_addr = htonl(INADDR_ANY);

	sockaddr_client.sin_port = htons(listen_port);

	int _bind = bind(socket_client, (struct sockaddr *) &sockaddr_client, sizeof(struct sockaddr));

	if (_bind == -1) {

		close(socket_client);

		char message[128];

		sprintf(message, "绑定端口%d失败，客户端主线程已停止运行并退出", listen_port);

		_log(message);

		pthread_exit(0);

	}

	int _listen = listen(socket_client, 1024);

	if (_listen == -1) {

		close(socket_client);

		char message[128];

		sprintf(message, "监听端口%d失败，客户端主线程已停止运行并退出", listen_port);

		_log(message);

		pthread_exit(0);

	}

	for (; main_thread_status == 1;) {

		struct sockaddr_in sockaddr_agent;

		socklen_t sockaddr_size = sizeof(struct sockaddr_in);

		int socket_agent = accept(socket_client, (struct sockaddr *) &sockaddr_agent, &sockaddr_size);

		if (socket_agent == -1) {

			if (main_thread_status == 0) {

				pthread_exit(0);

			}

			_log("接收浏览器连接时发生错误");

			continue;

		}

		pthread_t thread_id;

		pthread_create(&thread_id, NULL, thread_client, (void *) &socket_agent);

	}

	pthread_exit(0);

}

/**
 * 启动客户端主线程
 */
int _start() {

	_log("客户端主线程开始运行......");

	main_thread_status = 1;

	pthread_create(&thread_id_main, NULL, main_thread, NULL);

	pthread_join(thread_id_main, NULL);

	return 0;

}

/**
 * 停止客户端主线程
 */
int _stop() {

	main_thread_status = 0;

	close(socket_client);

	pthread_cancel(thread_id_main);

	_log("客户端主线程运行结束");

	return 0;

}

