
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>

int recv_sock, send_sock;
struct sockaddr_in dest_in;

struct pesudo_udphdr { 
	unsigned int saddr, daddr; 
	unsigned char unused; 
	unsigned char protocol; 
	unsigned short udplen; 
}; 

unsigned short in_cksum(unsigned short *addr, int len) 
{ 
	int sum=0; 
	unsigned short res=0; 
	while( len > 1)  { 
		sum += *addr++; 
		len -=2; 
	} 
	if( len == 1) { 
		*((unsigned char *)(&res))=*((unsigned char *)addr); 
		sum += res; 
	} 
	sum = (sum >>16) + (sum & 0xffff); 
	sum += (sum >>16) ; 
	res = ~sum; 
	return res; 
}

int check_dns_query(char *buff, int n)
{
	char *ip_buff = buff;
	struct iphdr* ip = (struct iphdr*)ip_buff; 
	struct udphdr * udp = (struct udphdr*) (ip_buff + sizeof(struct iphdr ));

	if (ip->protocol != IPPROTO_UDP )
	{
		return 1;
	}
	
	if (udp->dest != ntohs(53))
	{
		return 2;
	}
	
	printf("DNS Query comming.\n");
	
	char *p = ip_buff + 12;               //ip头部的source从12字节开始  
	printf("recv:%d, IP:%d.%d.%d.%d:%d => %d.%d.%d.%d:%d\n", n,
			p[0]&0XFF,p[1]&0XFF,p[2]&0XFF,p[3]&0XFF, htons(udp->dest),
			p[4]&0XFF,p[5]&0XFF,p[6]&0XFF,p[7]&0XFF, htons(udp->source)); 

	return 0;
}

int echo_dns_query(char *buff, int n)
{
	u_int32_t tmpaddr;
	u_int16_t tmpport;
	char check_buf[512] = {0};

	char *ip_buff = buff;

	struct iphdr* ip = (struct iphdr*)ip_buff; 
	struct udphdr * udp = (struct udphdr*) (ip_buff + sizeof(struct iphdr ));
	char *query = (char *)( ip_buff + sizeof(struct iphdr ) + sizeof(struct udphdr));
	
	// 
	query[2] |= 0x80;

	//
	tmpaddr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmpaddr;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip_buff, sizeof(struct iphdr));  

	{
		printf("ip_len:%d\n", ntohs(ip->tot_len));
	}

	tmpport = udp->source;
	udp->source = udp->dest;
	udp->dest = tmpport;
	udp->check = 0;
	
	{
		int udp_len = n - sizeof(struct iphdr );
		
		memset(check_buf, 0x0, 512);
		memcpy(check_buf + sizeof(struct pesudo_udphdr), (char*)udp, udp_len);
		struct pesudo_udphdr * pudph = (struct pesudo_udphdr *)check_buf;

		pudph->saddr = ip->saddr ; 
		pudph->daddr = ip->daddr; 
		pudph->unused=0; 
		pudph->protocol=IPPROTO_UDP; 
		pudph->udplen=htons(udp_len);

		udp->check = in_cksum((unsigned short *)check_buf, 
				udp_len +  sizeof(struct pesudo_udphdr) );
	}

	//
	dest_in.sin_family = AF_INET;  
	dest_in.sin_addr.s_addr = ip->daddr;
	dest_in.sin_port = udp->dest;
		
	/*Sendto*/  
	if((sendto(send_sock, ip_buff, n , 0,   
					(struct sockaddr *)&dest_in, 
					sizeof(dest_in))) < 0)  
	{	
		printf("sendto error:%d:%s\n", errno, strerror(errno)); 
	}else{  
		printf("send OK\n");  
	}  

	return 0;
}

int main(argc,argv)
	int argc;
	char *argv[];
{
	char buffer[2048];  
	char *iphead, *p;  
	int n ;
	struct ifreq ifr;

	//send_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (send_sock < 0)
	{
		printf("create send sock failed.\n");
		return 0;
	}
	
	int one = 1;  
	const int *val = &one;  
	if(setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{  
		perror("setsockopt() error");  
		exit(-1);  
	}

	recv_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	if (recv_sock < 0)
	{
		printf("create recv sock failed.\n");
		return 0;
	}

	strcpy(ifr.ifr_name, "eth1");
	if(ioctl(recv_sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		perror("siocgifflags");
		exit(0);
	}


	while (1)
	{
		if((n = recvfrom(recv_sock, buffer, 2048, 0, NULL, NULL)) < 42){  
			printf("Too short\n");  
		}else{  
			if (check_dns_query(buffer + 14, n - 14) == 0)  	
				echo_dns_query(buffer + 14, n - 14);
		}
	}

	return 0;
}

