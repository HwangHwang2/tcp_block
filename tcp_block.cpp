#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <memory.h>
#include <netdb.h>
#include <sys/types.h>

#define max(a,b) (a > b ? a : b) 
#define min(a,b) (a < b ? a : b) 

#define ETHERNET_header_end 14
#define ETHERTYPE 12
#define ETHERNET_DESTINATION_MAC_ADDR 0
#define ETHERNET_SOURCE_MAC_ADDR 6
#define MAC_address_length 6
#define IPv4_address_length 4
#define IPv4_SOURCE_IP_ADDR 12
#define IPv4_DESTINATION_IP_ADDR 16
#define IPv4_total_length 2
#define IPv4_checksum 10
#define TCP_SOURCE_PORT_NUM 0
#define TCP_DESTINATION_PORT_NUM 2
#define TCP_port_length 2
#define TCP_SEQ_NUM 4
#define TCP_ACK_NUM 8
#define TCP_Flag 13
#define TCP_FIN_Flag 7
#define TCP_RST_Flag 5
#define TCP_checksum 16

#define Forward_FIN_flag 1
#define Backward_FIN_flag 0
// 0 -> RST, 1 -> FIN

uint32_t pow(uint32_t a, uint32_t n){ // return a^n
	uint32_t result = 1;
	while(n--){
		result *= a;
	}
	return result;
}

void copy_6byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 6; i++){
        dst[i] = src[i];
    }
}
void copy_4byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 4; i++){
        dst[i] = src[i];
    }
}
void copy_2byte(uint8_t * src, uint8_t * dst){
    for(int i = 0; i < 2; i++){
        dst[i] = src[i];
    }
}

void usage() {
	printf("tcp_block <interface> <host>\n");
	printf("tcp_block wlan0 test.gilgil.net\n");
}

char * host_name;
int host_name_len;

uint8_t ipv4_protocol_id;
uint16_t ethernet_protocol_type;

// Layer 7
bool Data_checking(u_char * packet, uint32_t start, uint32_t end){  
 	if(start >= end) return true;

	if(strncmp((const char *)(packet + start), "GET", 3) == 0 ||
	strncmp((const char *)(packet + start), "POST", 4) == 0 ||
	strncmp((const char *)(packet + start), "HEAD", 4) == 0 ||
	strncmp((const char *)(packet + start), "PUT", 3) == 0 ||
	strncmp((const char *)(packet + start), "DELETE", 6) == 0 ||
	strncmp((const char *)(packet + start), "OPTIONS", 7) == 0) {
		// \x0d \x0a -> end of string
		const char * ptr = strstr((const char *)(packet + start), "Host:");
		if(ptr != NULL){
			char save_string[101] = "";
			for(int i = 6;; i++){
				if(strncmp((ptr + i), "\x0d", 1) == 0) break;
				strncat(save_string, (ptr + i), 1);
			}
			printf("[Work] Packet Hostname: %s\n", save_string);
			int cmp_len = strlen(save_string);

			if(strncmp((const char *)save_string, host_name, max(host_name_len, cmp_len)) == 0){
				printf("[Success] Correct HostName\n");
				return false;
			}
			else printf("[Work] Different HostName\n\n");
		}
		else printf("[Work] No HostName..\n");
	}
	return true;
}

typedef struct _tcp_pseudo_checksum {
    uint8_t src_ip_addr[4];
	uint8_t dst_ip_addr[4];
	uint8_t reserved;
	uint8_t protocol_id;
	uint16_t tcp_length;
} tcp_pseudo_checksum;

uint16_t CheckSum(uint16_t * buffer, uint32_t size){ //16t 2byte , 32t 4byte
    uint32_t checksum = 0;
    while(size > 1){
        checksum += *buffer++;
        size -= sizeof(uint16_t);
    }
    if(size) checksum += *(uint16_t *)buffer;

    checksum  = (checksum >> 16) + (checksum & 0xffff); //checksum 계산시 삐져나오는 비트들 처리!
    checksum += (checksum >> 16);
    return (uint16_t)(~checksum);
}

void Forward_RST(pcap_t * handle, uint8_t * packet, uint32_t seq_num, uint32_t ack_num, uint32_t ipv4_header_end, uint32_t tcp_header_end, uint16_t tcp_pseudo_checksum_result){

	*(uint32_t *)(packet + TCP_SEQ_NUM + ipv4_header_end) = seq_num;
	*(uint32_t *)(packet + TCP_ACK_NUM + ipv4_header_end) = ack_num;

	uint8_t save_tcp_flag = 0b00010100; //flag를 설정한다. rst와 ack에 1을 설정.
	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;	//대입

	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = 0x0000; //체크섬에다가 일단 0 넣어서 초기화.
	uint16_t ipv4_checksum_result = CheckSum((uint16_t *)(packet + ETHERNET_header_end), ipv4_header_end - ETHERNET_header_end);//checnsum 구하기
	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = ipv4_checksum_result; //체크섬 결과를 ipchecksum에 저장.

	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = 0x0000; // 똑같이 초기화. 
	uint16_t tcp_checksum = CheckSum((uint16_t *)(packet + ipv4_header_end), tcp_header_end - ipv4_header_end);//checksum 구하기 (http 날아갔으니 가능)
	uint32_t tcp_checksum_tmp = tcp_checksum + tcp_pseudo_checksum_result; //수도체크섬을 넣어서 다시 체크섬을 구함.
	tcp_checksum_tmp  = (tcp_checksum_tmp >> 16) + (tcp_checksum_tmp & 0xffff);
	tcp_checksum_tmp += (tcp_checksum_tmp >> 16); 
	uint16_t tcp_checksum_result = (uint16_t)(~tcp_checksum_tmp); //구하는거 반복
	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = tcp_checksum_result; 

	if(pcap_sendpacket(handle, packet, tcp_header_end) != 0) printf("[Error] Failed to send Forward RST packet..\n");
	else printf("[Success] Forward RST packet sended successfully.\n");// handle을 통해 전송.
}
void Forward_FIN(pcap_t * handle, uint8_t * packet, uint32_t seq_num, uint32_t ack_num, uint32_t ipv4_header_end, uint32_t tcp_header_end, uint16_t tcp_pseudo_checksum_result){
	//flag만 다르고 나머지 다 똑같다.
	*(uint32_t *)(packet + TCP_SEQ_NUM + ipv4_header_end) = seq_num;
	*(uint32_t *)(packet + TCP_ACK_NUM + ipv4_header_end) = ack_num;

	uint8_t save_tcp_flag = 0b00010001;
	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;	

	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = 0x0000;
	uint16_t ipv4_checksum_result = CheckSum((uint16_t *)(packet + ETHERNET_header_end), ipv4_header_end - ETHERNET_header_end);
	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = ipv4_checksum_result;

	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = 0x0000;
	uint16_t tcp_checksum = CheckSum((uint16_t *)(packet + ipv4_header_end), tcp_header_end - ipv4_header_end);
	uint32_t tcp_checksum_tmp = tcp_checksum + tcp_pseudo_checksum_result;
	tcp_checksum_tmp  = (tcp_checksum_tmp >> 16) + (tcp_checksum_tmp & 0xffff);
	tcp_checksum_tmp += (tcp_checksum_tmp >> 16);
	uint16_t tcp_checksum_result = (uint16_t)tcp_checksum_tmp;
	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = tcp_checksum_result;

	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;

	if(pcap_sendpacket(handle, packet, tcp_header_end) != 0) printf("[Error] Failed to send Forward FIN packet..\n");
	else printf("[Success] Forward FIN packet sended successfully.\n");
}
void Backward_RST(pcap_t * handle, uint8_t * packet, uint32_t seq_num, uint32_t ack_num, uint32_t ipv4_header_end, uint32_t tcp_header_end, uint16_t tcp_pseudo_checksum_result){

	*(uint32_t *)(packet + TCP_SEQ_NUM + ipv4_header_end) = seq_num;
	*(uint32_t *)(packet + TCP_ACK_NUM + ipv4_header_end) = ack_num;

	uint8_t save_tcp_flag = 0b00010100; // ACK 빼도 작동
	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;	

	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = 0x0000;
	uint16_t ipv4_checksum_result = CheckSum((uint16_t *)(packet + ETHERNET_header_end), ipv4_header_end - ETHERNET_header_end);
	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = ipv4_checksum_result;

	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = 0x0000;
	uint16_t tcp_checksum = CheckSum((uint16_t *)(packet + ipv4_header_end), tcp_header_end - ipv4_header_end);
	uint32_t tcp_checksum_tmp = tcp_checksum + tcp_pseudo_checksum_result;
	tcp_checksum_tmp  = (tcp_checksum_tmp >> 16) + (tcp_checksum_tmp & 0xffff);
	tcp_checksum_tmp += (tcp_checksum_tmp >> 16);
	uint16_t tcp_checksum_result = (uint16_t)tcp_checksum_tmp;
	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = tcp_checksum_result;

	if(pcap_sendpacket(handle, packet, tcp_header_end) != 0) printf("[Error] Failed to send Backward RST packet..\n");
	else printf("[Success] Backward RST packet sended successfully.\n");
}
void Backward_FIN(pcap_t * handle, uint8_t * packet, uint32_t seq_num, uint32_t ack_num, uint32_t ipv4_header_end, uint32_t tcp_header_end, uint16_t tcp_pseudo_checksum_result){

	*(uint32_t *)(packet + TCP_SEQ_NUM + ipv4_header_end) = seq_num;
	*(uint32_t *)(packet + TCP_ACK_NUM + ipv4_header_end) = ack_num;

	uint8_t save_tcp_flag = 0b00010001;
	*(packet + TCP_Flag + ipv4_header_end) = save_tcp_flag;	

	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = 0x0000;
	uint16_t ipv4_checksum_result = CheckSum((uint16_t *)(packet + ETHERNET_header_end), ipv4_header_end - ETHERNET_header_end);
	*(uint16_t *)(packet + IPv4_checksum + ETHERNET_header_end) = ipv4_checksum_result;

	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = 0x0000;
	uint16_t tcp_checksum = CheckSum((uint16_t *)(packet + ipv4_header_end), tcp_header_end - ipv4_header_end);
	uint32_t tcp_checksum_tmp = tcp_checksum + tcp_pseudo_checksum_result;
	tcp_checksum_tmp  = (tcp_checksum_tmp >> 16) + (tcp_checksum_tmp & 0xffff);
	tcp_checksum_tmp += (tcp_checksum_tmp >> 16);
	uint16_t tcp_checksum_result = (uint16_t)tcp_checksum_tmp;
	*(uint16_t *)(packet + TCP_checksum + ipv4_header_end) = tcp_checksum_result;

	if(pcap_sendpacket(handle, packet, tcp_header_end) != 0) printf("[Error] Failed to send Backward FIN packet..\n");
	else printf("[Success] Backward FIN packet sended successfully.\n");
}

void block_packet(pcap_t * handle, uint8_t * packet, uint32_t packet_size, uint32_t ipv4_header_end, uint32_t tcp_header_end){
//client가 server 통신 사이를 차단하기 위해 client와 server에게 rst(일방적 종료)또는 fin(서로 연결 끊음) (연결 끊을때)을 보냄. 
//client가 server에게 보낸 패킷을 볼 수 있다고 가정
// server 에게 보내는 패킷을 forward 반대는 backward
// forward: client주소 --> server 주소
// backward: server주소 --> client 주소
//forward는 주소를 바꿀 필요 없기 때문에 패킷을 거의 그대로 씀 
//backward는 주소를 바꿔줘야한다.

	uint8_t src_mac_addr[MAC_address_length];//6
	uint8_t dst_mac_addr[MAC_address_length];//6
	uint8_t src_ip_addr[IPv4_address_length];//4
	uint8_t dst_ip_addr[IPv4_address_length];//4
	uint8_t src_port_num[TCP_port_length];//2
	uint8_t dst_port_num[TCP_port_length];//2   //로 바꿔준다.

	copy_6byte(packet + ETHERNET_SOURCE_MAC_ADDR, src_mac_addr);
	copy_6byte(packet + ETHERNET_DESTINATION_MAC_ADDR, dst_mac_addr);
	copy_4byte(packet + IPv4_SOURCE_IP_ADDR + ETHERNET_header_end, src_ip_addr);
	copy_4byte(packet + IPv4_DESTINATION_IP_ADDR + ETHERNET_header_end, dst_ip_addr);
	copy_2byte(packet + TCP_SOURCE_PORT_NUM + ipv4_header_end, src_port_num);
	copy_2byte(packet + TCP_DESTINATION_PORT_NUM + ipv4_header_end, dst_port_num);

	*(uint16_t *)(packet + IPv4_total_length + ETHERNET_header_end) = htons(tcp_header_end - ETHERNET_header_end); 
	//fin을 만들기 위해 http를 날려야 함 ->totla length를 바꿔줌 
	//htons little endian을 big endian으로 바꿔준다  host to network short(s 면 2바이트로 바꾸고 l이면 4바이트로 바꿈)
		//tcp header end에서 ethernet header end를 뺴면 ipv4와 tcp의 length 가 된다.

	uint8_t * forward_packet = new uint8_t[tcp_header_end]; //forward packet 에게 tcp header end의 길이 만큼 할당
	for(int i = 0; i < tcp_header_end; i++) forward_packet[i] = packet[i]; //forward packet에게 복사
	uint8_t * backward_packet = new uint8_t[tcp_header_end];
	for(int i = 0; i < tcp_header_end; i++) backward_packet[i] = packet[i];// backward에게도 복사

	uint32_t now_TCP_SEQ_NUM = *(uint32_t *)(packet + TCP_SEQ_NUM + ipv4_header_end); //TCP seq num의 위치에다가 ipv4 header lenght를 더함.
	uint32_t now_TCP_ACK_NUM = *(uint32_t *)(packet + TCP_ACK_NUM + ipv4_header_end); //마찬가지 
	uint32_t new_TCP_SEQ_NUM = htonl(ntohl(now_TCP_SEQ_NUM) + (packet_size - tcp_header_end));//http 의 크기를 구하기 위해서 전체 length에서 tcp 끝 위치를 뺀다!
	//ntohl: big -> little l: 4byte 
// backward의 seq = 기존 패킷의 ack
// backward의 ack = 기존 패킷의 seq + data length
// forward의 seq = backward의 ack와 동일
// forward의 ack = backward의 seq 와 동일 = (기존패킷의 ack)


	tcp_pseudo_checksum tcp_pseudo_check; // 12byte
	copy_4byte(src_ip_addr, tcp_pseudo_check.src_ip_addr);
	copy_4byte(dst_ip_addr, tcp_pseudo_check.dst_ip_addr);
	tcp_pseudo_check.reserved = 0x00;
	tcp_pseudo_check.protocol_id = 0x6;
	tcp_pseudo_check.tcp_length = htons(tcp_header_end - ipv4_header_end); // tcp header + tcp data size
	uint16_t tcp_pseudo_checksum_result = CheckSum((uint16_t *)&tcp_pseudo_check, sizeof(tcp_pseudo_checksum));

	copy_6byte(dst_mac_addr, backward_packet + ETHERNET_SOURCE_MAC_ADDR);
	copy_6byte(src_mac_addr, backward_packet + ETHERNET_DESTINATION_MAC_ADDR);
	copy_4byte(dst_ip_addr, backward_packet + IPv4_SOURCE_IP_ADDR + ETHERNET_header_end);
	copy_4byte(src_ip_addr, backward_packet + IPv4_DESTINATION_IP_ADDR + ETHERNET_header_end);
	copy_2byte(dst_port_num, backward_packet + TCP_SOURCE_PORT_NUM + ipv4_header_end);
	copy_2byte(src_port_num, backward_packet + TCP_DESTINATION_PORT_NUM + ipv4_header_end);
	
	if(Forward_FIN_flag) Forward_FIN(handle, forward_packet, new_TCP_SEQ_NUM, now_TCP_ACK_NUM, ipv4_header_end, tcp_header_end, tcp_pseudo_checksum_result);
	else Forward_RST(handle, forward_packet, new_TCP_SEQ_NUM, now_TCP_ACK_NUM, ipv4_header_end, tcp_header_end, tcp_pseudo_checksum_result);

	if(Backward_FIN_flag) Backward_FIN(handle, backward_packet, now_TCP_ACK_NUM, new_TCP_SEQ_NUM, ipv4_header_end, tcp_header_end, tcp_pseudo_checksum_result);
	else Backward_RST(handle, backward_packet, now_TCP_ACK_NUM, new_TCP_SEQ_NUM, ipv4_header_end, tcp_header_end, tcp_pseudo_checksum_result);
		// src 와 dst는 checksum result를 변화하지 않음 -> pseudo check 그대로 사용
	
	printf("\n");
}

void Data_check(pcap_t * handle, u_char * packet, uint32_t start, uint32_t max_size, uint32_t ipv4_header_end, uint32_t tcp_header_end){
	uint32_t end = start + 32;
	end = min(end, max_size);
	if(!Data_checking(packet, start, end)){ 
	// false: Host name 찾음
	//Host name이 있으면 false --> block packet 을 실행하고 없으면 skip
		block_packet(handle, packet, max_size, ipv4_header_end, tcp_header_end);
		
	}
}

// Layer 4
uint32_t TCP_check(u_char * packet, uint32_t start){
	uint32_t tcp_start = start;
	uint32_t tcp_header_length = (packet[tcp_start + 12] & 0xf0) >> 2;
	return tcp_start + tcp_header_length;
}

// Layer 3
uint32_t IPv4_check(u_char * packet, uint32_t start){
	uint32_t ipv4_start = start;
	uint32_t ipv4_header_length = (packet[ipv4_start] & 0x0f) * 4;
	ipv4_protocol_id = packet[ipv4_start + 9];
	return ipv4_start + ipv4_header_length;
}

// Layer 2
uint32_t Ethernet_print(u_char * packet){
    uint16_t protocol_type = 0;
    for(int i = 12; i < 14; i++){
      protocol_type += packet[i] * pow(256, 13-i);
    }
    ethernet_protocol_type = protocol_type;
    return 14; // ethernet header end
}

int main(int argc, char* argv[]){
	
	if (argc != 3){
		usage();
		return -1;
	}

	char * dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	host_name = argv[2];
	host_name_len = strlen(host_name);

	printf("\n<Host Filtering>\n\n");
	while (true) {
		struct pcap_pkthdr * header;
		const u_char * packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		int ethernet_header_end = 0;
		int ipv4_header_end = 0;//기존의 Ethernet header의 길이에다가 ipv4 header의 길이를 더함.
		int tcp_header_end = 0;//위의 것에 tcp header의 길이를 더함.
		
		ethernet_header_end = Ethernet_print((u_char *)packet);// Ethernet 헤더 길이인 14를 출력
		if(ethernet_protocol_type == 0x0800){ // IPv4 인지 체크 
			ipv4_header_end = IPv4_check((u_char *)packet, ethernet_header_end);
		}
		if(ipv4_protocol_id == 0x6){ // IPv4일때 -> TCP인지 체크
			tcp_header_end = TCP_check((u_char *)packet, ipv4_header_end);
		}
		Data_check(handle, (u_char *)packet, tcp_header_end, header->caplen, ipv4_header_end, tcp_header_end);
		//Handle은 핸들 패킷은 패킷 tcp header end의 다음부터 체크하는거니까 여기가 시작이고 
		// header-> caplen은 전체 length니깐 끝부분을 의미
		// ipv4header end는 datacheck할때 써먹음 tcpend도 마찬가지
		// Host를 판별하고 차단하는 부분
		//protocol type , ip 초기화
	
	}

	pcap_close(handle);
	return 0;
}
