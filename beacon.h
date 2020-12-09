#include<string>
#include<cstring>


using namespace std;

class bMember{
private:
    string bssid;
    int beacons;
    //int power;
    //string enc;
    string essid;
    int st_len;

public:
    bMember(){

	}
	bMember(string bssid,string essid){
		this->bssid = bssid;
		//power 	= 0;
		beacons = 0;
        //this->enc=enc;
		this->essid	=essid;
	}
    void set_bMember(string bssid,string essid,int st_len){
		this->bssid = bssid;
		//power 	= 0;
		beacons = 0;
        //this->enc=enc;
		this->essid	=essid ;
        this->st_len=st_len;
	}
	void updateB(const u_char* packet);
	
	void inc_B(){
		beacons++;
	}
    string get_bssid(){
        return bssid;
    }
    int get_beacons(){
        return beacons;
    }
    string get_essid(){
        string str=essid;
        const char *newessid=new char[st_len+1];
        newessid=essid.c_str();
        char *nessid=new char[st_len+1];
        for(int i=0;i<st_len;i++){
            nessid[i]=newessid[i];
        }
        string rt_st(nessid);
        const char *cstr=str.c_str();
        if(cstr[0]==0x00){
            string mid=to_string(st_len);
            string rt="<length : "+mid+">";
            return rt;
        }
        else
        return rt_st;
    }
	void printB(){
		printf("%s %d %s\n",bssid,beacons,essid);
	}
};