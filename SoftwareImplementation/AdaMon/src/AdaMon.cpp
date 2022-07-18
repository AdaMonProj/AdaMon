#include <iostream>
#include "AdaMon.h"
#include <malloc.h>
#include <bitset>
#include <vector>
#include <algorithm>
#include <fstream>

namespace metadata{
    uint32_t bits_bias;
    uint32_t uint32_pos;
    uint32_t inner_bias;
    int shift_;
};

Bitmap_Arr::Bitmap_Arr(uint32_t memory_): memory(memory_), bitmap_num(memory * 1024 * 8 / bitmap_size), raw(memory*1024*8/32) {
    for(size_t i = 0;i < raw.size();i++) raw[i] = 0;
    for(size_t i = 0;i < bitmap_size;i++) patterns[i] = 1 << i;
    
    double ln_bmsize = log(bitmap_size);
    double ln_bmsize_minu1 = log(bitmap_size - 1);

    // for(size_t i = 1;i <= bitmap_size;i++) cardinalitys[i] = ( ln_bmsize - log(i) ) / (ln_bmsize - ln_bmsize_minu1);
    for(size_t i = 1;i <= bitmap_size;i++) cardinalitys[i] = bitmap_size * log(bitmap_size / static_cast<double>(i));
    cardinalitys[0] = cardinalitys[1]; 
    capacity = floor(cardinalitys[1] * 2);
    // cout<< "The capacity of layer1 is " << capacity << endl;
    cout<< "The number of LC(bitmap)s in layer 1: " << bitmap_num << endl;
}

uint32_t Bitmap_Arr::get_bitmap(uint32_t bitmap_pos){
    using namespace metadata;
    bits_bias = bitmap_pos * bitmap_size;
    uint32_pos =  bits_bias / 32;
    inner_bias = bits_bias % 32;
    uint32_t end_bit_idx = inner_bias + bitmap_size - 1;
    uint32_t res;
    if (end_bit_idx < 32) {
        res = raw[uint32_pos] >> inner_bias;
    } else {
        res = (raw[uint32_pos + 1] << (32 - inner_bias)) + (raw[uint32_pos] >> inner_bias);
    }
    res &= FULL_PAT;
    return res;
}

uint32_t zero_pos;
bool has_zero = false;

bool Bitmap_Arr::check_bitmap_full(uint32_t input_bitmap){
    if( input_bitmap == FULL_PAT )
        return true;  
    has_zero = false;
    for(size_t i=0;i<bitmap_size;i++){
        if( (patterns[i] & input_bitmap) == 0){
            if(has_zero)
                return false;
            else
                has_zero = true;
            zero_pos = i;
        }   
    }
    set_bit(zero_pos);  //set the last zero bit to 1
    return true;
}

bool Bitmap_Arr::check_flow_full(array<uint64_t,2>& hash_flowid){
    array<uint32_t,2> L1_pos;
    L1_pos[0] = static_cast<uint32_t>(hash_flowid[0]>>32) % bitmap_num;
    L1_pos[1] = static_cast<uint32_t>(hash_flowid[0]) % bitmap_num;
    uint32_t tmp_bitmap = get_bitmap(L1_pos[0]);
    if(check_bitmap_full(tmp_bitmap) == false){
        return false;
    } else {   //the hashed bitmap(linear-counting) has been full, so we check the other one.  
        tmp_bitmap = get_bitmap(L1_pos[1]);
        if(check_bitmap_full(tmp_bitmap) == true)
            return true;
        else
            return false;
    }
}

bool Bitmap_Arr::set_bit(uint32_t bit_pos){
    using namespace metadata;
    uint32_t temp = inner_bias + bit_pos;
    if(temp <= 31)
        raw[uint32_pos] |= (1<<temp); 
    else{
        temp -= 32;
        raw[uint32_pos + 1] |= (1<<temp); 
    }
    return false;
}

bool Bitmap_Arr::process_packet(array<uint64_t,2>& hash_flowid, array<uint64_t,2>& hash_element){
    array<uint32_t,2> L1_pos;
    L1_pos[0] = static_cast<uint32_t>(hash_flowid[0]>>32) % bitmap_num;
    L1_pos[1] = static_cast<uint32_t>(hash_flowid[0]) % bitmap_num;
    uint32_t hashres32 = static_cast<uint32_t>(hash_element[0] >> 32);
    bool tmpidx = (hashres32 >> 16) & 1;
    uint32_t update_pos = L1_pos[tmpidx];  //(hashres32>>16) % 2
    uint32_t tmp_bitmap = get_bitmap(update_pos);
    if(check_bitmap_full(tmp_bitmap) == false){
        uint32_t update_bit = static_cast<uint16_t>(hashres32) % bitmap_size;
        set_bit(update_bit);
        return false;
    } else {   
        uint32_t another_pos = L1_pos[!tmpidx];
        tmp_bitmap = get_bitmap(another_pos);
        if(check_bitmap_full(tmp_bitmap) == true)
            return true;
        else
            return false;
    }
}

int Bitmap_Arr::get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, double Gamma){
    array<uint32_t,2> L1_pos;
    L1_pos[0] = static_cast<uint32_t>(hash_flowid[0]>>32) % bitmap_num;
    L1_pos[1] = static_cast<uint32_t>(hash_flowid[0]) % bitmap_num;

    double min_cardinality = 1000;
    bool all_full = true;
    array<uint32_t,2> bitmaps;
    for(size_t i = 0;i < L1_pos.size();i++){
        uint32_t tmp_bitmap = get_bitmap(L1_pos[i]);
        bitmaps[i] = tmp_bitmap;
        size_t zeros_num = 0;
        for(size_t bit_pos = 0;bit_pos < bitmap_size;bit_pos++){
            if( (tmp_bitmap & patterns[bit_pos]) == 0)
                zeros_num++;
        }
        min_cardinality = min(cardinalitys[zeros_num] , min_cardinality);
        if(zeros_num > 1)
            all_full = false;
    }
    if(all_full)
        return BITMAP_FULL_FLAG;
    
    if (Gamma >= 0.95) {     // use VB_f
        double zeros_num = 0; 
        for (size_t i = 0; i < 2;i++){
            uint32_t tmp_bitmap = bitmaps[i];
            for(size_t bit_pos = 0;bit_pos < bitmap_size;bit_pos++){
                if( (tmp_bitmap & patterns[bit_pos]) == 0)
                    zeros_num++;
            } 
        }
        return round(2 * bitmap_size * log(2 * bitmap_size / zeros_num));
    } else {             // use 2*min{TB[h1(f)], TB[h2(f)]}
        int ans = round(min_cardinality * 2);
        return ans;
    }
}

HLL_Arr::HLL_Arr(uint32_t memory_): memory(memory_), HLL_num(memory * 1024 * 8 / (HLL_size + 8)),
    HLL_raw(HLL_num * HLL_size / 8), reg_sums(HLL_num), hash_table(tab_size){
    cout << "The number of HLLs in layer 2: " << HLL_num << endl;
    for(size_t i = 0;i < HLL_raw.size();i++) HLL_raw[i] = 0;
    for(size_t i = 0;i < reg_sums.size();i++) reg_sums[i] = 0;    
    for(size_t i = 0;i < exp_table.size();i++) exp_table[i] = pow(2.0, 0.0 - i);
    if (register_num == 32) alpha_m = 0.697; 
    else if (register_num == 64) alpha_m = 0.709;
    else if (register_num >= 128) alpha_m = 0.7213/(1 + 1.079/register_num);
    alpha_m_sqm = alpha_m * register_num * register_num; 
    alpha_m_sqm_vhll = 0.7213/(1 + 1.079/(register_num * 2)) * (register_num * 2) * (register_num * 2);
    LC_thresh = 2.5 * register_num; 
    LC_thresh_vhll = 2.5 * (register_num * 2);
}

uint32_t HLL_Arr::get_counter_val(uint32_t HLL_pos,uint32_t bucket_pos){
    uint32_t uint8_pos = HLL_pos * (register_num >> 1) + bucket_pos / 2;
    if(bucket_pos % 2 == 0)
        return HLL_raw[uint8_pos] >> 4;       //high 4 bits
    else
        return HLL_raw[uint8_pos] & 15;       //low 4 bits
}

void HLL_Arr::set_counter_val(uint32_t HLL_pos,uint32_t bucket_pos,uint32_t val_){
    uint32_t uint8_pos = HLL_pos * (register_num >> 1) + bucket_pos / 2;
    if(bucket_pos % 2 == 0){
        HLL_raw[uint8_pos] &= 15;            //keep the low 4 bits unchanged 
        HLL_raw[uint8_pos] |= static_cast<uint8_t>(val_) << 4;      //set the high 4 bits
    } else {
        HLL_raw[uint8_pos] &= 240;            //keep the high 4 bits unchanged 
        HLL_raw[uint8_pos] |= static_cast<uint8_t>(val_);
    }
}

void HLL_Arr::process_packet(string flowid, array<uint64_t,2>& hash_flowid, array<uint64_t,2>& hash_element){
    uint32_t hashres32 = static_cast<uint32_t>(hash_element[0]);
    uint32_t HLL_pos_1, HLL_pos_2;
    HLL_pos_1 = static_cast<uint32_t>(hash_flowid[1] >> 32) % HLL_num;
    HLL_pos_2 = static_cast<uint32_t>(hash_flowid[1]) % HLL_num;
    uint32_t bucket_pos = hashres32 & (register_num - 1); //use the last 4 bits to locate the bucket to update
    uint32_t rou_x = get_leading_zeros(hashres32) + 1;
    uint32_t update_pos;
    if(hash_element[0] >> 63)
        update_pos = HLL_pos_1;
    else
        update_pos = HLL_pos_2;
    rou_x = rou_x <= 15 ? rou_x : 15;
    uint32_t bucket_val = get_counter_val(update_pos, bucket_pos);
    if (bucket_val < rou_x){
        set_counter_val(update_pos, bucket_pos, rou_x);   
        reg_sums[update_pos] += rou_x - bucket_val;       //update RS
        uint16_t min_reg_sum = min(reg_sums[HLL_pos_1], reg_sums[HLL_pos_2]);
        insert_hashtab(flowid, min_reg_sum, hash_flowid[0]);
    }
}

int HLL_Arr::get_cardinality(uint32_t HLL_pos) {
    double res;
    double sum_ = 0;
    uint32_t V_ = 0;
    for(size_t i = 0;i < register_num;i++){
        uint32_t tmpval = get_counter_val(HLL_pos,i);
        sum_ += exp_table[tmpval];
        if(tmpval == 0)
            V_++;
    }
    res = alpha_m_sqm / sum_;
    if(res <= LC_thresh)
        if(V_ > 0)
            res = register_num * log(register_num / (double)V_);
    return round(res);
}

int HLL_Arr::get_cardinality(string flowid, array<uint64_t,2>& hash_flowid, double Gamma) {
    array<uint32_t,2> HLL_pos;
    HLL_pos[0] = static_cast<uint32_t>(hash_flowid[1] >> 32) % HLL_num;
    HLL_pos[1] = static_cast<uint32_t>(hash_flowid[1]) % HLL_num;
    
    if (Gamma > 0.95) {  //use VH_f
        double res;
        double sum_ = 0;
        uint32_t V_ = 0;
        for (size_t k = 0;k < 2;k++) {
            for(size_t i = 0;i < register_num;i++){
                uint32_t tmpval = get_counter_val(HLL_pos[0],i);
                sum_ += exp_table[tmpval];
                if(tmpval == 0)
                    V_++;
            }
        }
        
        res = alpha_m_sqm_vhll / sum_;
        if(res <= LC_thresh_vhll)
            if(V_ > 0)
                res = 2 * register_num * log(2 * register_num / (double)V_);
        return res;
    } else {          // use 2*min{TH[h1(f)], TH[h2(f)]}
        double res_1;
        double sum_ = 0;
        uint32_t V_ = 0;
        for(size_t i = 0;i < register_num;i++){
            uint32_t tmpval = get_counter_val(HLL_pos[0],i);
            sum_ += exp_table[tmpval];
            if(tmpval == 0)
                V_++;
        }
        res_1 = alpha_m_sqm / sum_;
        if(res_1 <= LC_thresh)
            if(V_ > 0)
                res_1 = register_num * log(register_num / (double)V_);
        
        double res_2;
        sum_ = 0;
        V_ = 0;
        for(size_t i = 0;i < register_num;i++){
            uint32_t tmpval = get_counter_val(HLL_pos[1],i);
            sum_ += exp_table[tmpval];
            if(tmpval == 0)
                V_++;
        }
        res_2 = alpha_m_sqm / sum_;
        if(res_2 <= LC_thresh)
            if(V_ > 0)
                res_2 = register_num * log(register_num / (double)V_);
        
        double min_cardinality = min(res_1, res_2);
        int ans = round(min_cardinality * 2);
        return ans;
    }
}

void HLL_Arr::insert_hashtab(string flowid, uint16_t min_reg_sum, uint64_t hahsres64){     // Power of Two
    uint32_t hashres32 = hahsres64 >> 32;         //high 32 bits of initial hash result which is 64 bits
    uint32_t table_pos1 = (hashres32 >> 16) % tab_size;     //high 16 bits
    uint32_t table_pos2 = (hashres32 & MAX_UINT16) % tab_size;  //low 16 bits

    if(hash_table[table_pos1].flowid == "" || hash_table[table_pos1].flowid == flowid){
        hash_table[table_pos1].flowid = flowid;
        hash_table[table_pos1].min_reg_sum = min_reg_sum;
        return;
    }
    else if(hash_table[table_pos2].flowid == "" || hash_table[table_pos2].flowid == flowid){
        hash_table[table_pos2].flowid = flowid;
        hash_table[table_pos2].min_reg_sum = min_reg_sum;
        return;
    }

    uint16_t tmp1 = hash_table[table_pos1].min_reg_sum;
    uint16_t tmp2 = hash_table[table_pos2].min_reg_sum; 
    if(tmp1 > tmp2){
        if(min_reg_sum >= tmp2){
            hash_table[table_pos2].flowid = flowid;
            hash_table[table_pos2].min_reg_sum = min_reg_sum;
        }
    } else {
        if(min_reg_sum >= tmp1){
            hash_table[table_pos1].flowid = flowid;
            hash_table[table_pos1].min_reg_sum = min_reg_sum;
        }
    }
}

void AdaMon::report_superspreaders(vector<IdSpread>& superspreaders){
    superspreaders.clear();
    set<string> checked_flows;
    for(size_t i = 0;i < layer2.tab_size;i++){
        string tmp_flowid = layer2.hash_table[i].flowid;
        if(checked_flows.find(tmp_flowid) != checked_flows.end())
            continue;
        else{
            checked_flows.insert(tmp_flowid);
            //array<uint64_t,2> hash_flowid = str_hash128(tmp_flowid,HASH_SEED_1);
            uint32_t esti_card = get_flow_cardinality(tmp_flowid); 
            superspreaders.push_back( IdSpread(tmp_flowid, esti_card) );
        }
    }
    sort(superspreaders.begin(), superspreaders.end(), IdSpreadComp);
}

uint32_t AdaMon::process_packet(string flowid,string element) {
    array<uint64_t,2> hash_flowid = str_hash128(flowid,HASH_SEED_1);
    array<uint64_t,2> hash_element = str_hash128(flowid + element,HASH_SEED_2);
    bool layer1_full = layer1.process_packet(hash_flowid,hash_element);
    if(!layer1_full){
        #ifdef GLOBAL_HLL
        global_hlls.update_layer1(hash_flowid,hash_element);
        #endif
        return 1;
    }
    layer2.process_packet(flowid,hash_flowid,hash_element);
    #ifdef GLOBAL_HLL
    global_hlls.update_layer2(hash_flowid,hash_element);
    #endif
    return 2;
}

uint32_t get_set_bits(uint32_t bmsize, uint32_t bm){
    uint32_t res = 0;
    for (size_t i = 0;i < bmsize;i++) {
        res += (bm >> i) & 1;
    }
    return res;
} 

void AdaMon::Obtain_Gamma() {
    double load_factor_1, load_factor_2 = 0;
    double n1, n2;
    double L1 = layer1.bitmap_num; 
    double L2 = layer2.HLL_num; 
    // get Gamma_1
    double empty_bm = 0;
    for (size_t i = 0;i < L1;i++) {
        uint32_t tmp_bm = layer1.get_bitmap(i);
        if (tmp_bm == 0) 
            empty_bm++;
    }
    load_factor_1 = (L1 - empty_bm) / L1;
    n1 = 1.0/2.0 * L1 * log(1 / (1 - load_factor_1));
    Gamma_1 = pow(1 - 1/L1, 2*n1 - 2); 

    // get Gamma_2
    double empty_hll = 0;
    for (size_t i = 0;i < L2;i++) {
        bool empty_flag = true;
        for (size_t j = 0;j < layer2.register_num;j++) {
            uint32_t tmp_val = layer2.get_counter_val(i, j);
            if (tmp_val != 0) {
                empty_flag = false;
                break;
            }
        }
        if (empty_flag) {
            empty_hll++;
        }
    }
    load_factor_2 = (L2 - empty_hll) / L2;
    n2 = 1.0/2.0 * L2 * log(1 / (1 - load_factor_2));
    Gamma_2 = pow(1 - 1/L2, 2*n2 - 2); 
    cout << "Gamma_1: " <<Gamma_1 << "  Gamma_2: " << Gamma_2 << endl;
}

uint32_t get_max(int a, int b) {
    return a > b ? a : b;
}

uint32_t AdaMon::get_flow_cardinality(string flowid){
    if (Gamma_1 == -1) {
        Obtain_Gamma();
    }
    array<uint64_t,2> hash_flowid = str_hash128(flowid,HASH_SEED_1);
    int cardinality_layer1 = layer1.get_cardinality(flowid, hash_flowid, 0);  
    int ret;
    if(cardinality_layer1 != BITMAP_FULL_FLAG)
        ret = cardinality_layer1;
    else {
        int cardinality_layer2 = layer2.get_cardinality(flowid, hash_flowid, 0); 
        ret = cardinality_layer2 + layer1.capacity; 
    }
    return ret;
}
