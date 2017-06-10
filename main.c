/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

/* 子函数声明 */
extern int Authentication(const char *UserName, const char *Password, const char *DeviceName);
extern void ExitAuth(int sig_num);
extern void LogoffConnect();


int getprocname(char *proname);
char PIDpath[64] = "/var/run/";
const char CFGpath[64]="/usr/local/cuit-client/cuit-client.cfg";
char Proname[32] = {0};
char cmd[64];
/**
 * 函数：main()
 *
 * 检查程序的执行权限，检查命令行参数格式。
 * 允许的调用格式包括：
 * 	cuit-client  username  password
 * 	cuit-client  username  password  eth0
 * 	cuit-client  username  password  eth1
 * 若没有从命令行指定网卡，则默认将使用eth0
 */
int main(int argc, char *argv[])
{
	int flag=1;
	char *UserName;
	char username[128];
	char *Password;
	char password[128];
	char *DeviceName;
	char devicename[32];        
	FILE* PIDfd;	
	FILE* CFGfd;
	
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		fprintf(stderr, "权限不足:运行本客户端程序需要root权限\n");
		fprintf(stderr, "(RedHat/Fedora下使用su命令切换为root)\n");
		fprintf(stderr, "(Ubuntu/Debian下在命令前添加sudo)\n");
		exit(-1);
	}
	
	if(getprocname(Proname)<0)
	{
	     fprintf(stderr, "获取进程名失败!\n");
	     return 0;
	}
	
    strcat(PIDpath, Proname);
    strcat(PIDpath, ".pid");
    
        /*注册信号*/   
    signal(SIGUSR1, ExitAuth);
    signal(SIGINT,  ExitAuth);

    if(access(PIDpath, F_OK) == -1)
    {
        PIDfd = fopen(PIDpath, "w");
        fprintf(PIDfd, "%d", getpid());
        fclose(PIDfd);
    }
    else
    {   
        fprintf(stderr, "已存在一个运行中的客户端的实例,是否断开连接并退出？\n[y/n]");
        while(1)
        {
            switch(getchar())
            {
                case 'y':
                case 'Y':
                    raise(SIGUSR1);
                    sprintf(cmd, "pkill %s", Proname);
                    system(cmd); 
                    return 0;
                case 'n':
                case 'N':
                    return 0;
                default:
                fprintf(stderr, "是否断开连接并退出？\n[y/n]");
                break;
            }
            while((getchar())!='\n');
        }
    }    
	
	if(argc == 2 || argc >=5)
	{
		fprintf(stderr, "参数错误！\n");
		fprintf(stderr,	"正确的调用格式如下：\n");
		fprintf(stderr,	"    %s username password\n", argv[0]);
		fprintf(stderr,	"    %s username password eth0\n", argv[0]);
		fprintf(stderr,	"    %s username password eth1\n", argv[0]);
		fprintf(stderr, "(注：若不指明网卡，默认情况下将使用eth0)\n");
		raise(SIGUSR1);
		return -1;
	}
	
	if(argc == 1)
	{
		if(access(CFGpath, F_OK)==-1)
		{
			fprintf(stderr, "配置文件不存在\n");
			fprintf(stderr, "帐号:");
			scanf("%s", username);
			fprintf(stderr, "密码:");
			scanf("%s", password);
			fprintf(stderr, "网卡(默认请输入:eth0):");
			scanf("%s", devicename);
			flag = 1;
        	while(flag)
		    {
		    	fprintf(stderr, "是否保存配置信息?\n[y/n]:");
		    	while((getchar())!='\n');
		        switch(getchar())
		        {
		            case 'y':
		            case 'Y':
						flag = 0;
						CFGfd = fopen(CFGpath, "w");
						fprintf(CFGfd, "%s\n", username);
						fprintf(CFGfd, "%s\n", password);
						fprintf(CFGfd, "%s\n", devicename);
						fclose(CFGfd);
		               	break;
		            case 'n':
		            case 'N':
		            	flag = 0;
		                break;
		            default:
		            	break;
		        }
		    }
        }
		else
		{
			fprintf(stderr, "读取配置文件...\n");
			CFGfd = fopen(CFGpath, "r");
			fscanf(CFGfd, "%s\n", username);
			fscanf(CFGfd, "%s\n", password);
			fscanf(CFGfd, "%s\n", devicename);
        	fclose(CFGfd);
		}
		UserName = username;
		Password = password;
		DeviceName = devicename;
	}
	
	if(argc >= 3)
	{
		UserName = argv[1];
		Password = argv[2];
		DeviceName = "eth0";	
		if(argc >= 4)
		{
			DeviceName = argv[3];
		}
		
		flag = 1;
        while(flag)
		{
		   fprintf(stderr, "是否更新配置信息?\n[y/n]:");
		   
		   switch(getchar())
		   {
		   		case 'y':
		        case 'Y':
					flag = 0;
					CFGfd = fopen(CFGpath, "w");
					fprintf(CFGfd, "%s\n", UserName);
					fprintf(CFGfd, "%s\n", Password);
					fprintf(CFGfd, "%s\n", DeviceName);
					fclose(CFGfd);
					break;
		        case 'n':
		        case 'N':
		           	flag = 0;
		            break;
		        default:
		            break;
		     }
		     while((getchar())!='\n');
		  }
	}

    signal(SIGTERM, ExitAuth);
    signal(SIGALRM, ExitAuth);
 

	/* 调用子函数完成802.1X认证 */
	Authentication(UserName, Password, DeviceName);

	return 0;
}

int getprocname(char *proname)
{
    const char Exelink[]  = "/proc/self/exe";
    char Propath[128];
    int len;
    int i;
    
    len = readlink(Exelink , Propath, 128);
    if(len <= 0)
    {
	    return -1;
    }
    else
    {
        for(i=len-1;i>=0;i--)
        {
            if(Propath[i]=='/')
            break;
        }
        memcpy(proname, Propath+i+1, len-i-1);
    }
    return 0;
}

