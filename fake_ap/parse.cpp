#include "parse.h"

parse::parse(int argc, char *argv[]){
    this->interface=argv[1];
    check_argc(argc);
}
void parse::check_argc(int argc){
    if(argc!=2){
        cout << "< Usage > : < interface > \n";
        exit(1);
    }
}
char *parse::using_interface(){
    return this->interface;
}
void parse::show_me(int range, uint8_t *data){
    for(int i=0; i<range; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",data[i]);
    }
    cout << endl;
}
uint8_t *parse::check_tag(uint8_t *data, int &datalen, uint8_t &taglen, bool &get_check){
    if(datalen < taglen)
        return data;
    else if(taglen!=0){
        data += taglen;
        datalen -=taglen;
    }
    get_check=true;
    return data;
}
uint8_t *parse::check_tag(uint8_t *data, int &datalen, uint8_t &taglen){
    if(datalen < taglen)
        return data;
    else if(taglen!=0){
        data += taglen;
        datalen -=taglen;
    }
    return data;
}
void parse::show_ap(map<keydata,valuedata>&map_beacon){
    map<keydata,valuedata>::iterator bea_it;
    char mac[18]{0};
    int sequence = 1;
    cout << "\t\t\t  * AP LIST *\n";
    for(bea_it = map_beacon.begin(); bea_it!=map_beacon.end(); advance(bea_it,1)){
         bea_it->second.sequence=sequence;
         printf("       %2d  ",bea_it->second.sequence);
         convert_type(mac,(uint8_t*)bea_it->first.bssid,0);
         cout << "    " << mac << "     ";
         printf("channel(%3d)     ",bea_it->second.channel);
         cout << bea_it->second.essid << "      "<<endl;
         sequence++;
    }
}
void parse::scanning(map<keydata, valuedata>&map_beacon, atomic<bool> &run){
    cout << "\n\t\t    < Scanning Activate 'S' or 's' = Stop >\n";
    map<keydata, valuedata>::iterator bea_it;
    keydata k;
    valuedata v;
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const uint8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(this->interface,BUFSIZ,1,1,errbuf);
    uint8_t *save_packet;
    while(run)
    {
       ret=pcap_next_ex(pcd, &pkthdr, &packet);

       switch (ret)
       {
           case 1:
           {
               int packet_len=pkthdr->len;
               v.save_length = pkthdr->len;
               struct radiotap_header *radio = (struct radiotap_header*)packet;
               struct ieee80211_common *common = (struct ieee80211_common*)(packet+radio->header_length);
               if(common->frame_control_field==BEACON)
               {
                    save_packet=(uint8_t*)packet;
                    struct ieee80211_probe_request_or_beacon_frame *beacon = (struct ieee80211_probe_request_or_beacon_frame*)(packet+radio->header_length);
                    packet+=radio->header_length+sizeof(ieee80211_probe_request_or_beacon_frame)+sizeof(ieee80211_wireless_lan_mg_beacon);
                    memcpy(k.bssid,beacon->src_addr,6);
                    bool get_data_check1{false},get_data_check2{false};
                    while(packet_len > 0){
                        if(get_data_check1&&get_data_check2){
                            v.sequence++;
                            break;
                        }
                        struct tagpara_common *tag_com = (struct tagpara_common*)packet;
                        switch (tag_com->tagnum)
                        {
                            case 0:
                            {
                                if(get_data_check1==true)
                                    break;
                                memset(v.essid,0,32);
                                packet+=sizeof(struct tagpara_common);
                                memcpy(v.essid,packet,tag_com->taglen);
                                packet = check_tag((uint8_t*)packet,packet_len,tag_com->taglen,get_data_check1);
                                get_data_check1=true;
                            }
                            break;
                            case 3:
                            {
                                if(get_data_check2==true)
                                    break;
                                struct tagpara_ds_para_set *para_set = (struct tagpara_ds_para_set *)packet;
                                v.channel=para_set->current_channel;
                                packet += sizeof(struct tagpara_ds_para_set);
                                packet = check_tag((uint8_t*)packet,packet_len,tag_com->taglen,get_data_check2);
                                get_data_check2=true;
                            }
                            break;
                            case 61:
                            {
                                if(get_data_check2==true)
                                    break;
                                struct ht_information *hi = (struct ht_information *)packet;
                                v.channel=hi->primary_channel;
                                packet += sizeof(struct ht_information);
                                packet = check_tag((uint8_t*)packet,packet_len,tag_com->taglen,get_data_check2);
                                get_data_check2=true;
                            }
                            break;
                            default:
                            {
                                packet +=sizeof(struct tagpara_common);
                                packet = check_tag((uint8_t*)packet,packet_len,tag_com->taglen);
                            }
                            break;
                        }
                    }

                    if((bea_it = map_beacon.find(k)) == map_beacon.end()){
                        memcpy(v.all_packet,save_packet,v.save_length);
                        map_beacon.insert(pair<keydata, valuedata>(k,v));
                        char str[18]{0};
                        convert_type(str,k.bssid,0);
                        cout << " \t\t" << str << "\t" << v.channel << "\t" << v.essid << " length:" << v.save_length << endl;
                    }
               }
           }
           break;
           case 0:
               continue;
           case -1:
           {
               cout << ">> Error \n";
               pcap_close(pcd);
               sleep(1);
               pcd = pcap_open_live(this->interface, BUFSIZ, 1 , 1, errbuf);
           }
           break;
           case -2:
           {
               cout << "EOF\n";
           }
           break;
           default:
           break;
       }
       if(kbhit())
       {
           run=false;
           system("clear");
           pcap_close(pcd);
           break;
       }
    }
}
void parse::ask_ap(){
    cout << " >> Create Fake AP " << endl;
    cout << "   >> How many AP's would you like to target? = ";
    cin >> this->ap_count;
    cout << "     >> Select the AP number = ";
    this->ap_num = new int[this->ap_count];
    for(int i=0; i < this->ap_count; i++)
        cin >> this->ap_num[i];
    cout << "       >> How may AP's do you create? = ";
    cin >> this->create_ap_count;
}
void parse::select_ap(map<keydata,valuedata>&map_beacon){
    map<keydata, valuedata>::iterator bea_it;
    for(int i=0; i<this->create_ap_count; i++)
    {
        for(bea_it = map_beacon.begin(); bea_it !=map_beacon.end(); ++bea_it)
        {
            for(int i=0; i<this->ap_count; i++)
                if(bea_it->second.sequence == this->ap_num[i])
                    make_packet((uint8_t*)bea_it->second.all_packet, bea_it->second.save_length, this->create_ap_count);
        }
    }
}

void parse::make_packet(uint8_t *packet, int packet_length, int count){
    for(int i=0; i<packet_length; i++)
    {
        if(i%16==0)
            cout << endl;
        printf("%02x ",packet[i]);
    }
    cout << endl;
    //add channel thread
    uint8_t make_packet[count][packet_length]; //upgrade size beacase add char or minus char
    struct radiotap_header *rh = (struct radiotap_header*)packet;
    packet+=rh->header_length+sizeof(ieee80211_probe_request_or_beacon_frame)+sizeof(ieee80211_wireless_lan_mg_beacon);

    bool get_data_check1{false};
    while(packet_length > 0){
        if(get_data_check1){
            break;
        }
        struct tagpara_common *tag_com = (struct tagpara_common*)packet;

        switch (tag_com->tagnum)
        {
            case 0:
            {
                string ssid{0};
                uint8_t *blank=0x00;
                packet+=sizeof(struct tagpara_common);
                cout << "\t  >> Please enter the name of the ap you want to change = ";
                cin >> ssid;
                const char *ssid_char = ssid.c_str();

                if((uint8_t)ssid.length()-tag_com->taglen>0)
                {
                    cout << "hello galaxy  !!!\n";
                    memmove(packet,packet+1,ssid.length()-tag_com->taglen);//http://myeonguni.tistory.com/1507
                    //space add -> string add.. debug word 15 a
                    cout << "hello galaxy1  !!!\n";
                    //memcpy(packet,(uint8_t*)ssid_char,ssid.length());
                    cout << "hello galaxy2  !!!\n";
                    for(int i=0; i<304; i++) //compare
                    {
                        if(i%16==0)
                            cout << endl;
                        printf("%02x ",packet[i]);
                    }
                    cout << endl;
                }
                else if((uint8_t)ssid.length()-tag_com->taglen<0)
                {
                    cout << "so small" <<endl;
                }
                else
                {
                    cout << "temp\n";
                }

                packet = check_tag((uint8_t*)packet,packet_length,tag_com->taglen, get_data_check1);
                get_data_check1=true;
            }
            break;
            default:
            {
                packet +=sizeof(struct tagpara_common);
                packet = check_tag((uint8_t*)packet,packet_length,tag_com->taglen);
            }
            break;
        }
        //send
    }
}
