#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include "beacon.h"
#include "station.h"
#include <string>
#include <cstring>

using namespace ::std;
int num_04=0;

int beacon_cnt=0;
int station_cnt=0;
void usage(){
	cout << "syntax : airodump <interface>" <<endl;
	cout << "sample : airodump mon0" <<endl;
}
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
}__attribute__((__packed__));


struct ieee80211_Beacon_frame{
    u_int8_t    type;
    u_int8_t    control_field;
    u_int16_t   duration;
    u_int8_t    rcv_addr[6];
    u_int8_t    src_addr[6];
    u_int8_t    bSS_id[6];
}__attribute__((__packed__));

struct ieee80211_wireless_LAN{
    u_int8_t parameter[12];
    u_int8_t tag_num;
    u_int8_t length; 
    char essid[20]={0,};
    u_int8_t ch;
}__attribute__((__packed__));
struct ieee80211_wireless_LAN2{
    u_int8_t tag_num;
    u_int8_t length; 
    char essid[20]={0,};
    u_int8_t ch;
}__attribute__((__packed__));
string toString(uint8_t* mac_){
    int flag=0;
	char buf[32];
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac_[0],
		mac_[1],
		mac_[2],
		mac_[3],
		mac_[4],
		mac_[5]);
    for(int i=0;i<6;i++){
        if(mac_[i]==0xff)
            flag++;
    }
    if(flag==6){
        return "(not associated)";
    }
	return std::string(buf);
}
void dump(u_int8_t* mac){
    for(int i=0;i<6;i++){
        printf("%02x:",mac[i]);
    }
    printf("\n");
}
void dump2(char* essid,u_int8_t length){
    int cnt=0;
    for (int i=0;i<length;i++){
        if(essid[i]==NULL){
            cnt++;
        }
    }
    if(cnt==length){
        printf("<length: %d>",length);
    }
    else{
    for (int i=0;i<length;i++){
        printf("%c",essid[i]);
        if(essid[i]==NULL){
            cnt++;
        }
    }
    }
    printf("\n");
}
int main(int argc, char** argv)
{
    bMember beacon_table[1000];
    sMember station_table[1000];
    char* dev=argv[1];
	if (argc != 2) {
		usage();
		return -1;
	}
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s! - %s\n", dev, errbuf);
        return -1;
    }
    int beacon[100];
    int beacon_len=0;
    int count_num=0;
    while(1){
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        int packet_len = header->caplen;
        if (res == 0){
           continue;
        }
        if (res == -1 || res == -2) {
           printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
           break;
        }
        struct ieee80211_radiotap_header* radhdr;
        radhdr=(struct ieee80211_radiotap_header*)packet;
        if(radhdr->it_len==24){
            struct ieee80211_Beacon_frame* BFR;
            struct ieee80211_wireless_LAN* WLAN;
            struct ieee80211_wireless_LAN2* WLAN2;
            BFR=(struct ieee80211_Beacon_frame*)(packet+24);
            WLAN=(struct ieee80211_wireless_LAN*)(packet+48);
            WLAN2=(struct ieee80211_wireless_LAN2*)(packet+48);
            if(BFR->type==0x80){
                int b_flag=0;
                string newbssid;
                int idx=0;
                newbssid=toString(BFR->bSS_id);

                for(int i=0;i<beacon_cnt;i++){
                    if(beacon_table[i].get_bssid()==newbssid)
                    {
                        b_flag=1;
                        idx=i;
                    }
                }
                if(b_flag==1)
                beacon_table[idx].inc_B();
                else{
                    string newessid(WLAN->essid);
                    int st_length=WLAN->length;
                    beacon_table[beacon_cnt].set_bMember(newbssid,newessid,st_length);
                    beacon_cnt++;

                }
            }
            if(BFR->type==0x40){
                num_04++;
                cout<<num_04<<endl;
                int s_flag=0;
                string newbssid;
                int idx=0;
                newbssid=toString(BFR->bSS_id);
                string newstation;
                newstation=toString(BFR->src_addr);
                for (int i=0;i<station_cnt;i++){
                    if(station_table[i].get_station()==newstation)
                    {
                        s_flag=1;
                        idx=i;
                    }
                }
               if(s_flag==0){
                   string newprobe(WLAN2->essid);
                   int st_length=WLAN2->length;
                   station_table[station_cnt].set_sMember(newbssid,newstation,newprobe,st_length);
                   station_cnt++;
               }
            }

           
        }
        
        system("clear");
        printf("BSSID                   BEACONS         ESSID\n");     
        for(int i=0;i<beacon_cnt;i++){
            cout << beacon_table[i].get_bssid() <<'\t' ;
            cout << beacon_table[i].get_beacons() <<'\t'<<'\t';
            cout <<beacon_table[i].get_essid()<<endl;
        }
        if(station_cnt>0)
        {
            printf("\n");
            printf("BSSID                   Station                 Probe\n");
        }
        for(int i=0;i<station_cnt;i++){
            cout<<station_table[i].get_bssid()<<'\t';
            cout<<station_table[i].get_station()<<'\t';
            cout<<station_table[i].get_probe()<<endl;
        }
        
    }

}