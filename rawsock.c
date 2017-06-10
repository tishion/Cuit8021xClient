#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>


int OpenRawSocket(const char *device, struct sockaddr_ll *sockaddrll)
{
    int fd;
    struct ifreq ifr;
    
    strcpy(ifr.ifr_name, device);
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) 
    {
      return fd;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, strlen(device));
    if (ioctl(fd, SIOCGIFINDEX, &ifr)) 
    {
        return -1;
    }
    
    memset(sockaddrll, 0, sizeof(sockaddrll));
    sockaddrll->sll_ifindex = ifr.ifr_ifindex;
    sockaddrll->sll_pkttype = PF_PACKET;
    sockaddrll->sll_protocol = htons(ETH_P_ALL);
    
    return fd;
}

    

 int GetNextPacket(int sockfd, uint8_t *captured, uint8_t *desmac, uint8_t *srcmac)
 {
        int n;
        memset(captured, 0, 1600);
        n = recvfrom(sockfd, captured, 1600, 0, NULL, 0);       
        if(n <= 0)
        {
            return n;
        }
        if(memcmp(captured, desmac, 6) != 0)
        {
             return -1;
        }
        if(srcmac != NULL)
        {
            if(memcmp(captured + 6, srcmac, 6) != 0)
            {
               return -1;
            }
        }
        return 1;
 }

 int SendPacket(int sockfd, uint8_t *packet, int size,struct sockaddr_ll sockaddrll)
 {
    size_t n;
    n = sendto(sockfd, packet, size, 0, (struct sockaddr*)&sockaddrll, sizeof(sockaddrll));
    return n;
 }
