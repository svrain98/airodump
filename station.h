#include<string>
#include<cstring>


using namespace std;

class sMember{
private:
    string bssid;
    string station;
    string probe;
    int st_len;

public:
    sMember(){

	}
	sMember(string bssid,string station,string probe){
		this->bssid = bssid;
        this->station=station;
		this->probe	=probe;
	}
    void set_sMember(string bssid,string station,string probe,int st_len){
		this->bssid = bssid;
        this->station=station;
		this->probe	=probe;
        this->st_len=st_len;
	}

    string get_bssid(){
        return bssid;
    }
    string get_station(){
        return station;
    }

    string get_probe(){
        string str=probe;
        const char *newessid=new char[st_len+1];
        newessid=probe.c_str();
        char *nessid=new char[st_len+1];
        for(int i=0;i<st_len;i++){
            nessid[i]=newessid[i];
        }
        string rt_st(nessid);
        return rt_st;
    }
};