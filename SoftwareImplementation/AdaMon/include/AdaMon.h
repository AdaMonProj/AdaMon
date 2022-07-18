#ifndef _AdaMon_H_
#define _AdaMon_H_

#include "hashfunc.h"
#include "util.h"
#include<iostream>
#include<bitset>
#include<cmath>
#include<string>
#include<fstream>
#include<array>
#include<memory>
#include<vector>
#include<set>
#include<unordered_map>
using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::vector;
using std::array;
using std::unordered_map;


#define MAX_UINT8 255
#define MAX_UINT16 65535
#define MAX_UINT32 4294967295


class Bitmap_Arr{       // layer1: T_B
public:
    uint32_t memory;        //kB
    static const uint32_t bitmap_size = 6;      //b (bits)
    uint32_t bitmap_num;      //L_1
    vector<uint32_t> raw;  
    array<uint32_t, bitmap_size> patterns;
    array<double,bitmap_size + 1> cardinalitys;
    static const uint32_t FULL_PAT  = (1 << bitmap_size) - 1;
    int capacity;
    static constexpr double thresh_ratio = 1.256 / 2;  //error removal
#define BITMAP_FULL_FLAG -1

    Bitmap_Arr(uint32_t memory_);    
    uint32_t get_bitmap(uint32_t bitmap_pos);
    bool check_bitmap_full(uint32_t input_bitmap);
    bool check_flow_full(array<uint64_t,2>& hash_flowid);
    bool set_bit(uint32_t bit_pos);
    bool process_packet(array<uint64_t,2>& hash_flowid, array<uint64_t,2>& hash_element);
    int get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, double Gamma);
};


class HLL_Arr{         // layer2: T_H
public:
    uint32_t memory;         //kB
#define HASH_SEED_1 92317
#define HASH_SEED_2 37361 
    static const uint32_t register_num = 64;    //m
    static const uint32_t register_size = 4;
    static const uint32_t HLL_size = register_num * register_size;
    uint32_t HLL_num;        //L_2
    double alpha_m, alpha_m_sqm, alpha_m_sqm_vhll, LC_thresh, LC_thresh_vhll; 
    vector<uint8_t> HLL_raw;
    vector<uint16_t> reg_sums;
    array<double,1<<register_size> exp_table;
    static constexpr double thresh_ratio = 2.103 / 2;

    HLL_Arr(uint32_t memory_);
    uint32_t get_counter_val(uint32_t HLL_pos,uint32_t bucket_pos);
    void set_counter_val(uint32_t HLL_pos,uint32_t bucket_pos,uint32_t val_);
    void process_packet(string flowid, array<uint64_t,2>& hash_flowid, array<uint64_t,2>& hash_element);
    int get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, double Gamma);
    int get_cardinality(uint32_t HLL_pos);

    class Table_Entry{
    public:
        string flowid;          //FLOW ID
        uint16_t min_reg_sum;   //RS register sum
        Table_Entry():flowid(""), min_reg_sum(0){}
    };
    static const uint32_t tab_size = 2048;     //Z=2048
    vector<Table_Entry> hash_table;   //T_{SC}
    void insert_hashtab(string flowid, uint16_t selected_sum, uint64_t hahsres64);
};

class AdaMon{
public:
    Bitmap_Arr layer1;     //T_B
    HLL_Arr layer2;        //T_H
    double layer1_ratio;   //pi
    double Gamma_1 = -1, Gamma_2 = -1;

    AdaMon(uint32_t memory_size, double layer1_ratio_);
    uint32_t process_packet(string flowid,string element);
    uint32_t get_flow_cardinality(string flowid);
    void report_superspreaders(vector<IdSpread>& superspreaders);
    void update_collision_rate();
    void Obtain_Gamma();
private:
    double collision_rate_1 = 0;
    double collision_rate_2 = 0;
    double collision_thresh = 0.05;
};


AdaMon::AdaMon(uint32_t memory_size, double layer1_ratio_): layer1_ratio(layer1_ratio_),
layer1(memory_size * layer1_ratio_), layer2(memory_size * (1 - layer1_ratio_)){
}

#endif
