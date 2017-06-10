/* File: auth.c
 * ------------
 * 注：核心函数为Authenticaiton()，由该函数执行801.1X认证
 */

int Authenticaiton(const char *UserName, const char *Password, const char *DeviceName);
void LogoffConnect();


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <gcrypt.h>	// GNU cryptographic function library (libgcrypt)

#include "debug.h"

// 自定义常量
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const char H3C_VERSION[16]="EN V3.60-6210"; // 华为客户端版本号
const char H3C_KEY[]      ="HuaWei3COM1X";  // H3C的固定密钥

uint8_t	ClientMAC[6];		//本地MAC地址
uint8_t ServerMAC[6] = {0};
int sockfd; //raw socket fd
char renewcmd[64];
struct sockaddr_ll sockaddrll;

// 子函数声明
void printtime();

static void SendStartPkt(int sockfd, const uint8_t mac[]);
static void SendLogoffPkt(int sockfd, const uint8_t mac[]);
static void SendResponseIdentity(int sockfd,
		const uint8_t request[],
		const uint8_t ethhdr[],
		const uint8_t ip[4],
		const char    username[]);
static void SendResponseMD5(int sockfd,
		const uint8_t request[],
		const uint8_t ethhdr[],
		const char username[],
		const char passwd[]);
static void SendResponseNotification(int sockfd,
		const uint8_t request[],
		const uint8_t ethhdr[]);


static void GetMacFromDevice(uint8_t mac[6], const char *devicename);
static void GetIpFromDevice(uint8_t ip[4], const char DeviceName[]);
static void MakeClientVersion(uint8_t area[]);
static void MakeMD5(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[]);
static void MakeBase64(char area[]);


extern void ExitAuth(int sig_num);
extern int OpenRawSocket(const char *device, struct sockaddr_ll *sockaddrll);
extern int GetNextPacket(int sockfd, uint8_t *captured, uint8_t *desmac, uint8_t *srcmac);
extern int SendPacket(int sockfd, uint8_t *packet, int size,struct sockaddr_ll sockaddrll);
/**
 * 函数：Authenticaiton()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 *
 */
 
 
void printtime()
{
    time_t now;
    struct tm *timenow;
    time(&now);
    timenow = localtime(&now);
    fprintf(stderr, "[%02d:%02d:%02d]", timenow->tm_hour, timenow->tm_min, timenow->tm_sec);
}

void LogoffConnect()
{
    DPRINTF("Getting off line...\n");
    SendLogoffPkt(sockfd, ClientMAC);
}


int Authentication(const char *UserName, const char *Password, const char *DeviceName)
{
	/* 打开适配器(网卡) */
	sockfd = OpenRawSocket(DeviceName, &sockaddrll);
	if (sockfd < 0) {
		DPRINTF("Error:Open device failed!\n");
		raise(SIGUSR1);
	}

	/* 查询本机ClientMAC地址 */
	GetMacFromDevice(ClientMAC, DeviceName);
	
	int retcode;
	uint8_t	captured[1600];
	uint8_t	ethhdr[14]; // ethernet header
	uint8_t	ip[4];	// ip address

    START_AUTHENTICATION:
	{
		fprintf(stderr, "**********************Begin to login...**********************\n");
		SendStartPkt(sockfd, ClientMAC);
		printtime();
		fprintf(stderr, "Finding authentication Server.");
		DPRINTF("[0] Client start:\n");
		
		alarm(30);          //设置查找服务器超时时间

		/* 等待认证服务器的回应 */
		bool serverIsFound = false;
		while (!serverIsFound)
		{
			retcode = GetNextPacket(sockfd, captured, ClientMAC, NULL);
			if (retcode == 1 && (EAP_Code)captured[18] == REQUEST)
			{
				serverIsFound = true;
				alarm(0);       //取消超时设置
				memcpy(ServerMAC, captured + 6, 6);     //获取认证服务器MAC
				fprintf(stderr, "\n");
			}
			else
			{	// 延时后重试
				sleep(1); 
				fprintf(stderr, ".");
				SendStartPkt(sockfd, ClientMAC);
				// NOTE: 这里没有检查网线是否接触不良或已被拔下
			}
		}
		
	    memcpy(ethhdr+0, ServerMAC, 6);
		memcpy(ethhdr+6, ClientMAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 若收到的第一个包是Request Notification
		if ((EAP_Type)captured[22] == NOTIFICATION)
		{
		    printtime();
		    fprintf(stderr, "Checking client version...\n");
			DPRINTF("[%d] Server: Request Notification!\n", (EAP_ID)captured[19]);
			// 发送Response Notification
			SendResponseNotification(sockfd, captured, ethhdr);
			DPRINTF("[%d] Client: Response Notification.\n", (EAP_ID)captured[19]);
		}
		
		// 进入循环体
		for (;;)
		{
			// 捕获数据包
           while(GetNextPacket(sockfd, captured, ClientMAC, ServerMAC) != 1);
			// 根据收到的Request，回复相应的Response包
			if((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
					case IDENTITY:
						DPRINTF("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
						GetIpFromDevice(ip, DeviceName);
						SendResponseIdentity(sockfd, captured, ethhdr, ip, UserName);
						DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
						break;
					case MD5:
					    printtime();
					    fprintf(stderr, "Checking user password...\n");
						DPRINTF("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
						SendResponseMD5(sockfd, captured, ethhdr, UserName, Password);
						DPRINTF("[%d] Client: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
						break;
					case NOTIFICATION:
						DPRINTF("[%d] Server: Request Notification!\n", (EAP_ID)captured[19]);
						SendResponseNotification(sockfd, captured, ethhdr);
						DPRINTF("[%d] Client: Response Notification.\n", (EAP_ID)captured[19]);
						break;
					default:
						DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
						DPRINTF("Error! Unexpected request type\n");
						exit(-1);
						break;
				}
		    }
			else if ((EAP_Code)captured[18] == FAILURE)
			{	// 处理认证失败信息
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				printtime();
				fprintf(stderr, "Login server failed.\n");
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09 && msgsize>0)
				{	// 输出错误提示消息
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2535:Service is paused
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效
					raise(SIGUSR1);
					exit(-1);
				}
				else if (errtype==0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{	// 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					exit(-1);
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%d] Server: Success.\n", captured[19]);
				// 刷新IP地址
				printtime();
				fprintf(stderr, "Refreshing IP address...\n");
				sprintf(renewcmd, "dhclient %s", DeviceName);
				system(renewcmd);
				break;
			}
			else
			{
				DPRINTF("[%d] Server: (H3C data)\n", captured[19]);
				// TODO: 这里没有处理华为自定义数据包 
			}
		}

		fprintf(stderr, "**********************Login successful！**********************\n");
	}		
	/**********************************************************************
	//登录成功
	//在此切换成守护进程模式
	**********************************************************************/
	//KEEP_ALIVE:
	daemon(0,0);
	{
		for (;;)
		{
			// 捕获数据包
           	while(GetNextPacket(sockfd, captured, ClientMAC, ServerMAC) != 1);
			// 根据收到的Request，回复相应的Response包
			if((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
					case IDENTITY:
						DPRINTF("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
						GetIpFromDevice(ip, DeviceName);
						SendResponseIdentity(sockfd, captured, ethhdr, ip, UserName);
						DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
						break;
					default:
						DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
						DPRINTF("Error! Unexpected request type\n");
						exit(-1);
						break;
				}
		    }
		}
	}
	return (0);
}



static
void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{

	int	fd;
	int	err;
	struct ifreq	ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return;
}

static
void GetIpFromDevice(uint8_t ip[4], const char DeviceName[])
{
	int fd;
	struct ifreq ifr;

	assert(strlen(DeviceName) <= IFNAMSIZ);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd>0);

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
		struct sockaddr_in *p = (void*) &(ifr.ifr_addr);
		memcpy(ip, &(p->sin_addr), 4);
	}
	else
	{
		// 查询不到IP时默认填零处理
		memset(ip, 0x00, 4);
	}

	close(fd);
	return;
}


static
void SendStartPkt(int sockfd, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x01;	// Type=Start
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 发包
	SendPacket(sockfd, packet, sizeof(packet), sockaddrll);
}



	static
void SendResponseIdentity(int sockfd, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	uint8_t	packet[128];
	size_t len;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY
			||(EAP_Type)request[22] == AVAILABLE);

	// Fill Ethernet header
	memcpy(packet, ethhdr, 14);

	// 802,1X Authentication
	// {
	packet[14] = 0x1;	// 802.1X Version 1
	packet[15] = 0x0;	// Type=0 (EAP Packet)
	//response[16~17]留空	// Length

	// Extensible Authentication Protocol
	// {
	packet[18] = (EAP_Code) RESPONSE;	// Code
	packet[19] = request[19];		// ID
	//response[20~21]留空			// Length
	packet[22] = (EAP_Type) IDENTITY;	// Type
	// Type-Data
	// {
	len = 23;
	packet[len++] = 0x15;	  // 上传IP地址
	packet[len++] = 0x04;	  //
	memcpy(packet+len, ip, 4);//
	len += 4;			  //
	packet[len++] = 0x06;		  // 携带版本号
	packet[len++] = 0x07;		  //
	MakeBase64((char*)packet+len);//
	len += 28;			  //
	packet[len++] = ' '; // 两个空格符
	packet[len++] = ' '; //
	usernamelen = strlen(username); //末尾添加用户名
	memcpy(packet+len, username, usernamelen);
	len += usernamelen;
	assert(len <= sizeof(packet));
	// }
	// }
	// }

	// 补填前面留空的两处Length
	eaplen = htons(len-18);
	memcpy(packet+16, &eaplen, sizeof(eaplen));
	memcpy(packet+20, &eaplen, sizeof(eaplen));

	// 发送
	SendPacket(sockfd, packet, len, sockaddrll);
}


	static
void SendResponseMD5(int sockfd, const uint8_t request[], const uint8_t ethhdr[], const char username[], const char passwd[])
{
	uint16_t eaplen;
	size_t   usernamelen;
	size_t   len;
	uint8_t  packet[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	eaplen = htons(22+usernamelen);
	len = 14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	// Fill Ethernet header
	memcpy(packet, ethhdr, 14);

	// 802,1X Authentication
	// {
	packet[14] = 0x1;	// 802.1X Version 1
	packet[15] = 0x0;	// Type=0 (EAP Packet)
	memcpy(packet+16, &eaplen, sizeof(eaplen));	// Length

	// Extensible Authentication Protocol
	// {
	packet[18] = (EAP_Code) RESPONSE;// Code
	packet[19] = request[19];	// ID
	packet[20] = packet[16];	// Length
	packet[21] = packet[17];	//
	packet[22] = (EAP_Type) MD5;	// Type
	packet[23] = 16;		// Value-Size: 16 Bytes
	MakeMD5(packet+24, request[19], passwd, request+24);
	memcpy(packet+40, username, usernamelen);
	// }
	// }

	SendPacket(sockfd, packet, len, sockaddrll);
}


	static
void SendLogoffPkt(int sockfd, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;	// Version=1
	packet[15] = 0x02;	// Type=Logoff
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 发包
    SendPacket(sockfd, packet, sizeof(packet), sockaddrll);

	
}


// 函数: XOR(data[], datalen, key[], keylen)
//
// 使用密钥key[]对数据data[]进行异或加密
//（注：该函数也可反向用于解密）
	static
void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int	i,j;

	// 先按正序处理一遍
	for (i=0; i<dlen; i++)
		data[i] ^= key[i%klen];
	// 再按倒序处理第二遍
	for (i=dlen-1,j=0;  j<dlen;  i--,j++)
		data[i] ^= key[j%klen];
}



	static
void MakeClientVersion(uint8_t area[20])
{
	uint32_t random;
	char	 RandomKey[8+1];

	random = (uint32_t) time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);// 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); // （需调整为网络字节序）
	memcpy(area+16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}


	static
void SendResponseNotification(int sockfd, const uint8_t request[], const uint8_t ethhdr[])
{
	uint8_t	packet[60];
	size_t len;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == NOTIFICATION);

	// Fill Ethernet header
	memcpy(packet, ethhdr, 14);

	// 802,1X Authentication
	// {
	packet[14] = 0x1;	// 802.1X Version 1
	packet[15] = 0x0;	// Type=0 (EAP Packet)
	packet[16] = 0x00;	// Length
	packet[17] = 0x31;	//

	// Extensible Authentication Protocol
	// {
	packet[18] = (EAP_Code) RESPONSE;	// Code
	packet[19] = (EAP_ID) request[19];	// ID
	packet[20] = packet[16];		// Length
	packet[21] = packet[17];		//
	packet[22] = (EAP_Type) NOTIFICATION;	// Type

	len=23;
	/* Notification Data (44 Bytes) */
	// 其中前2+20字节为客户端版本
	packet[len++] = 0x01; // type 0x01
	packet[len++] = 22;   // lenth
	MakeClientVersion(packet+len);
	len += 20;

	memset(packet+len, 0, 60-len);
/*
	// 最后2+20字节存储加密后的Windows操作系统版本号
	response[i++] = 0x02; // type 0x02
	response[i++] = 22;   // length
	FillWindowsVersionArea(response+i);
	i += 20;
*/
	// }
	// }

	//pcap_sendpacket(handle, response, sizeof(response));
	SendPacket(sockfd, packet, sizeof(packet), sockaddrll);
}

static
void MakeMD5(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
	uint8_t	msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
	size_t	msglen;
	size_t	passlen;

	passlen = strlen(passwd);
	msglen = 1 + passlen + 16;
	assert(sizeof(msgbuf) >= msglen);

	msgbuf[0] = id;
	memcpy(msgbuf+1,	 passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);

	// Calls libgcrypt function for MD5 generation
	gcry_md_hash_buffer(GCRY_MD_MD5, digest, msgbuf, msglen);
}


	static
void MakeBase64(char area[])
{
	uint8_t version[20];
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/"; // 标准的Base64字符映射表
	uint8_t	c1,c2,c3;
	int	i, j;

	// 首先生成20字节加密过的H3C版本号信息
	MakeClientVersion(version);

	// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[ (c1&0xfc)>>2                               ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)               ];
		area[j++] = Tbl[               ((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[                                c3&0x3f     ];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[               ((c2&0x0f)<<2)];
	area[27] = '=';
}

