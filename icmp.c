#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <netinet/tcp.h>
#include<stdlib.h>
#include<sys/time.h>
#include <time.h>
#include<netdb.h>
#include<arpa/inet.h>
#include<netinet/ip.h>

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
struct icmphdr
{
    u8 type;
    u8 code;
    u16 checksum;
    union
    {
        struct
        {
            u16 id;
            u16 sequence;
        }echo;
        
        u32 gateway;
        struct
        {
            u16 unused;
            u16 mtu;
        }frag; //pmtu发现
    }un;
    
    //u32  icmp_timestamp[2];//时间戳
    //ICMP数据占位符
    u8 data[0];
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
};

#define NETWORK_UNREACHABLE (-3)
#define ICMP_ECHOREPLY              0     /*Echo Reply*/
#define ICMP_DEST_UNREACH       3     /*Destination Unreachable*/
#define ICMP_SOURCE_QUENCH    4     /*Source Quench */
#define ICMP_REDIRECT          5     /*Redirect (change route)*/
#define ICMP_ECHO           8     /*Echo Request*/
#define ICMP_TIME_EXCEEDED     11    /*Time Exceeded*/
#define ICMP_PARAMETERPROB     12    /*Parameter Problem*/
#define ICMP_TIMESTAMP        13    /*Timestamp Request*/
#define ICMP_TIMESTAMPREPLY    14    /*Timestamp Reply*/
#define ICMP_INFO_REQUEST  15    /*Information Request*/
#define ICMP_INFO_REPLY              16    /*Information Reply*/
#define ICMP_ADDRESS           17    /*Address Mask Request*/
#define ICMP_ADDRESSREPLY 18    /*Address Mask Reply*/
#define NR_ICMP_TYPES          18

struct timeval tv_interval,tv_recv, tv_send;

struct timeval IcmpTvsub(struct timeval end, struct timeval begin)
{
	struct timeval tv;
	tv.tv_sec = end.tv_sec - begin.tv_sec;
	tv.tv_usec = end.tv_usec - begin.tv_usec;
	if (tv.tv_usec < 0)
	{
		tv.tv_sec --;
		tv.tv_usec += 1000000;
	}
	return tv;
}

int CheckSum(uint16_t *addr, int len)
{
    int nleft = len;
    uint16_t *w = addr;
    int sum = 0;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
		sum += *w++;
		nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
		*(uint16_t *)(&answer) = *(uint16_t *)w ;
		sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = (~sum);				/* truncate to 16 bits */
    return(answer); 
}

int SendIcmpPack(int sockfd, unsigned int dst_ip)
{
	static unsigned long seq = 0;
    struct sockaddr_in to_ip;
    unsigned long saddr = htonl(dst_ip);
    struct icmphdr *head;
    uint8_t outpack[64];
    int cs = 64 ;
    int ret;
    struct in_addr addr;
	int ident = getpid( ) & 0xFFFF;

    /*填充远端地址结构体*/
    bzero(&to_ip, sizeof(struct sockaddr_in));
    bzero(outpack, sizeof(outpack));
    to_ip.sin_family = AF_INET;
    to_ip.sin_addr.s_addr = saddr;

    /*制作ICMP包头*/
    head = (struct icmphdr *)outpack;
    head->type = ICMP_ECHO;
    head->code = 0;
    head->checksum = 0;
    head->un.echo.sequence = htons(++seq);;
    head->un.echo.id = ident;
    head->checksum = CheckSum((uint16_t *)head, cs);
	gettimeofday(&tv_send,NULL);
    /*发送ICMP报文*/
    ret = sendto(sockfd, (char *)outpack, cs, 0, (struct sockaddr *)&to_ip, sizeof(struct sockaddr_in));
    if (ret < 0)
    {
		printf("sendto icmp packet error:%s\r\n", strerror(errno));
		return -1;
    }
    return 0;
}


int RecvIcmpPack(int sockfd, unsigned short timeout , int dst_ip)
{
	struct timeval tv;
	int rtt;
	fd_set rfd;
	struct sockaddr_in from_ip;
	struct ip *ip=NULL;
	int dst_addr = htonl(dst_ip);
	int from_len = sizeof(struct sockaddr_in);
	int ident = getpid( ) & 0xFFFF;
	struct icmphdr *head;
	uint8_t inpack[128];
	int ret;
	
	unsigned int orig_time = time(NULL);
    unsigned int current_time = 0;
    unsigned int timeout_dval = 0;
	
select_again:
	current_time = time(NULL);
    timeout_dval = current_time - orig_time;
    if (timeout <= timeout_dval)
    {
        printf("recv_icmp_pack:select time out\n");
        return -2;
    }
    timeout -= timeout_dval;
	
	bzero(&from_ip, sizeof(struct sockaddr_in));
	bzero(inpack, sizeof(inpack));

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	FD_ZERO(&rfd);
	FD_SET(sockfd, &rfd);

	ret = select(sockfd + 1, &rfd, NULL, NULL, &tv);
	if (ret < 0)
	{
		if (errno == EINTR)
		{
			goto select_again;
		}
		return -1;
	}
	
	if (ret == 0)
	{
		return -2;
	}

	/*接收ICMP响应报文*/
	ret = recvfrom(sockfd, (char *)inpack, sizeof(inpack), 0, (struct sockaddr *)&from_ip, &from_len);
	if (ret < 0)
	{
		printf("recv error: %s\r\n", strerror(errno));
		return -1;
	}
	else if (ret == 0)
	{
		printf("recv datalen is zero\r\n");
		return -1;
	}
	
    if(0 != memcmp(&dst_addr,&from_ip.sin_addr.s_addr,4))
    {
        goto select_again;
    }
	
	head = (struct icmphdr *)(inpack + 20);
	ip= (struct ip*)inpack;   
	if (head->type == ICMP_ECHOREPLY)
	{
		if ((head->un.echo.id == ident))
		{
			gettimeofday(&tv_recv,NULL);
			tv_interval = IcmpTvsub(tv_recv,tv_send);
			rtt = tv_interval.tv_sec*1000+tv_interval.tv_usec/1000;
			printf("recv %d byte from%s: icmp_seq=%u ttl=%d rtt=%d ms\n",ret,inet_ntoa(*(struct in_addr*)&dst_addr),ntohs(head->icmp_seq),ip->ip_ttl,rtt);
			return 0;
		}
		else
		{
			printf("recv echo.id is incorrect(%d,%d)\n", head->un.echo.id, ident);
			goto select_again;
		}

	}
	else if(head->type==ICMP_DEST_UNREACH)
    {
        printf("recv destination unreachable\n");
        return NETWORK_UNREACHABLE;
    }
    else if(head->type==ICMP_ECHO)
    {
        if (head->un.echo.id == ident)
        {
            printf("recv error !!!  head->type = %d\n",head->type);
        }
        else
        {
            goto select_again;
        }
    }	
	else
	{
		goto select_again;
	}
	printf("recv data type is wrong\r\n");
    
	return -1;    
}
int CheckIcmp(int sockfd , unsigned int dst_ip)
{
	int ret;
	struct in_addr ipdata;
	
	ipdata.s_addr = htonl(dst_ip);
	
	ret = SendIcmpPack(sockfd, dst_ip);

	if (ret < 0)
	{
		printf("send icmp pack error\n");
		return -1;		
	}
	else
	{
		printf("*****ICMP send one packet success(%s)!*****\n", inet_ntoa(ipdata));
	}
	
	ret = RecvIcmpPack(sockfd, 5 ,dst_ip);

	if (ret < 0)
	{
		if (ret == -1)
		{	      
			printf("ICMP recv icmp packet error\n");
		}
		else
		{
			printf("ICMP Recv icmp packet timeout\n");
		}

		return -1;
	}
	else
	{
		printf("*****ICMP resv one packet success!*****\n");
	}
	return 0;
}

int main(int argc, char*argv[])
{
	int ret;
	int fd;
	unsigned int ip;
	struct hostent *host;
	
	if (2 > argc)
        {
                printf("please input the ping dstip\n");
                return -1;
        }
	
	host = gethostbyname(argv[1]);
	if(!host)
	{
		printf("Get IP address error!");
		return -1;
	}
	//别名
	for(int i=0; host->h_aliases[i]; i++)
	{
		printf("Aliases %d: %s\n", i+1, host->h_aliases[i]);
	}
	//地址类型
	printf("Address type: %s\n", (host->h_addrtype==AF_INET) ? "AF_INET": "AF_INET6");
	//IP地址
	for(int i=0; host->h_addr_list[i]; i++)
	{
		printf("IP addr %d: %s\n", i+1, inet_ntoa( *(struct in_addr*)host->h_addr_list[i] ) );
	}

	inet_aton(inet_ntoa( *(struct in_addr*)host->h_addr_list[0] ), (struct in_addr*)&ip);
	ip = ntohl(ip);
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (0 > fd)
	{
		printf("create socket error\n");
		return -1;
	}
	while(1)
	{
		ret = CheckIcmp(fd, ip);
		if (0 > ret)
		{
			return -1;
		}
		sleep(1);
	}
	
}
