#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

extern char PIDpath[64];

void ExitAuth(int sig_num)
{
	switch(sig_num)
	{
		case SIGALRM:             //查找服务器超时
			fprintf(stderr, "\nConnect Authentication server time out.\n");
		//	unlink(PIDpath);
		//	exit(0);
			break;
		case SIGTERM:             //终止进程信号
		case SIGINT: 
		//	unlink(PIDpath);	  //Ctrl+C 信号
			fprintf(stderr, "\nClient Eixt by User.\n");
		//	exit(0);
			break;
		case SIGUSR1:             //打开网卡失败
		//  unlink(PIDpath);
		//	exit(0);
			break;
		default:
			break;
	}
	unlink(PIDpath);
	exit(0);
}
