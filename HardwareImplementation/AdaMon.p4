#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/util.p4"
#include "common/headers.p4"

#define ETHERTYPE_DC      0x1234
#define ETHERTYPE_IGEG    0x1235
#define RECYCLE_PORT      0
#define OUTPUT_PORT       0

// Bitmap(LC)
// index width = 32
// table size = 2^19, cell width = 1byte, size = 0.5MB
#define BM_TBL_SIZE       524288
#define BM_CELL_WIDTH     8

// Hyper Log Log
// index width = 32
// estimator cnt = 2^13, register cnt = 2^6, cell width = 1byte, size = 0.5MB
#define HLL_TBL_SIZE      8192  // 8192 estimators
#define HLL_EST_SIZE      64    // 64 registers per estimator
#define HLL_CELL_WIDTH    8     // 8 bits per register, store the cnt of leading 0s
#define HLL_SUM_WIDTH     16    // Partial Sum

// Hash table
#define HASH_TBL_SIZE     1024
#define HASH_CELL1_SIZE   32   // Size of IPv4 addr
#define HASH_CELL2_SIZE   HLL_SUM_WIDTH   

// f: hdr.ipv4.src_addr
// e: hdr.ipv4.dst_addr

typedef bit<32>              INDEX_WIDTH32;
typedef bit<16>              INDEX_WIDTH16;
typedef bit<BM_CELL_WIDTH>   BM_CELL_T;
typedef bit<HLL_CELL_WIDTH>  HLL_CELL_T;
typedef bit<16>              HLL_SUM_T;
typedef bit<HASH_CELL1_SIZE> HASH_CELL1_T;
typedef bit<HASH_CELL2_SIZE> HASH_CELL2_T;

struct metadata_t {
    // Empty
}

Register<BM_CELL_T, INDEX_WIDTH32>(BM_TBL_SIZE) bitmap_LC_table;
Register<HLL_CELL_T, INDEX_WIDTH32>(HLL_TBL_SIZE * HLL_EST_SIZE) hll_table;
Register<HLL_SUM_T, INDEX_WIDTH32>(HLL_TBL_SIZE) hll_sum_table;
// Register<HLL_SUM_T, INDEX_WIDTH32>(BM_TBL_SIZE) hll_sum_table; // Cannot do rshift

Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_bitmap_f_32_1;
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_bitmap_f_32_2;
Hash<bit<8>>(HashAlgorithm_t.CRC8)  hash_bitmap_e_1;
Hash<bit<8>>(HashAlgorithm_t.CRC8)  hash_bitmap_fe_8;
Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_hll_f_16_1;
Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_hll_f_16_2;
Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_hll_f_32;


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_DC   : parse_dc_recycle;
            default : reject;
        }
    }

    state parse_dc_recycle {
        pkt.extract(hdr.recycle);
        transition select (hdr.recycle.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IGEG : parse_igeg;
            default : reject;
        }
    }

    state parse_igeg {
        pkt.extract(hdr.igeg);
        transition select (hdr.igeg.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
    packet_out pkt,
    inout header_t hdr,
    in metadata_t eg_md,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        pkt.emit(hdr);
    }
}


// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // ---------------------------------------------------------------------------[Forward]

    bit<16> vrf;

    action hit(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action miss() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table forward {
        key = {
            vrf : exact;
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
            miss;
        }

        const default_action = miss;
        size = 1024;
    }

    // ---------------------------------------------------------------------------[Variables]

    bit<8>              random_bit;

    bit<1>              bitmap_full_flag = 1w0;
    bit<8>              bitmap_mask_index = 0;
    bit<8>              bitmap_mask = 8w0;
    bit<BM_CELL_WIDTH>  bitmap_check_ret;

    bit<16>             hll_reg_index;
    INDEX_WIDTH32       hll_tbl_idx;
    INDEX_WIDTH32       hll_sum_index;
    bit<32>             hll_rand = 0;
    bit<8>              hll_val = 0;
    bit<HLL_SUM_WIDTH>  hll_sum_delta;
    bit<HLL_CELL_WIDTH> hll_update_ret;

    // ---------------------------------------------------------------------------[Actions]

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, void>(bitmap_LC_table) update_bitmap_LC_table = { // Read bitmap_mask, perform LC update
        void apply (inout BM_CELL_T value) {
            value = value | bitmap_mask;
        }
    };

    RegisterAction<BM_CELL_T, INDEX_WIDTH32, BM_CELL_T>(bitmap_LC_table) read_bitmap_LC_table = { // Read bitmap_mask
        void apply (inout BM_CELL_T value, out BM_CELL_T ret) {
            ret = value;
        }
    };

    RegisterAction<HLL_CELL_T, INDEX_WIDTH32, HLL_CELL_T>(hll_table) update_hll_table = {
        void apply (inout HLL_CELL_T value, out HLL_CELL_T ret) {
            if (hll_val > value) {
                ret = value; // value will never be 0
                value = hll_val;
            } else {
                ret = 0; // a value of 0 indicates that the register is not changed
            }
        }
    };

    RegisterAction<HLL_SUM_T, INDEX_WIDTH32, HLL_SUM_T>(hll_sum_table) update_hll_sum_table = {
        void apply (inout HLL_SUM_T value, out HLL_SUM_T ret) {
            value = value + hll_sum_delta;
            ret = value;
        }
    };

    // ---------------------------------------------------------------------------

    action set_full_flag(bit<1> is_full) {
        bitmap_full_flag = is_full;
    }

    table bitmap_full_lookup {
        key = {
            bitmap_check_ret: exact;
        }

        actions = {
            set_full_flag;
        }

        size = 8; // 8 full conditions

        default_action = set_full_flag(1w0); // Clear bitmap_full_flag if not full
    }

    // ---------------------------------------------------------------------------

    action write_bitmap_mask(bit<8> mask) { // PHV.bitmap_mask_index -> PHV.bitmap_mask
        bitmap_mask = mask;
    }

    table mask_lookup {
        key = {
            bitmap_mask_index: exact;
        }

        actions = {
            write_bitmap_mask;
            NoAction;
        }

        size = 8;

        default_action = NoAction();
    }
    
    // ---------------------------------------------------------------------------
    
    action write_leading_zero(bit<8> cnt) { // PHV.hll_rand -> PHV.hll_val
        hll_val = cnt;
    }

    table leading_zero_lookup {
        key = {
            hll_rand : lpm;
        }

        actions = {
            write_leading_zero;
            NoAction;
        }
        
        size = 33;

        default_action = NoAction();
    }

    // ---------------------------------------------------------------------------

    apply {
        if (hdr.recycle.isValid()) { // Recycled packet, bitmap is not Full
            bitmap_mask_index = hash_bitmap_fe_8.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr},0,8); // h_bm(f,e)
            mask_lookup.apply(); // Use table lookup to calc bitmap_mask = 1 << bitmap_mask_index;
            // Update Bitmap Cell
            update_bitmap_LC_table.execute(hdr.recycle.chosen_idx);
            // Strip dc_recycle header
            hdr.ethernet.ether_type = hdr.recycle.ether_type;
            hdr.recycle.setInvalid();
        } else { // New packet
            random_bit = hash_bitmap_e_1.get({hdr.ipv4.dst_addr},0,2);   // I(e)
            // Check if the bitmap cell is full
            if (random_bit == 0) {
                hdr.recycle.chosen_idx = hash_bitmap_f_32_1.get({hdr.ipv4.src_addr},0,BM_TBL_SIZE); // h_1(f), valid bits [19:0]
            } else {
                hdr.recycle.chosen_idx = hash_bitmap_f_32_2.get({hdr.ipv4.src_addr},0,BM_TBL_SIZE); // h_2(f)
            }
            bitmap_check_ret = read_bitmap_LC_table.execute(hdr.recycle.chosen_idx);
            bitmap_full_lookup.apply(); // Result saved in bitmap_full_flag
            if (bitmap_full_flag == 1w0) { // Bitmap not full, update bitmap in next round
                hdr.recycle.setValid();
                hdr.recycle.ether_type = hdr.ethernet.ether_type;
                hdr.ethernet.ether_type = ETHERTYPE_DC; 
                ig_intr_tm_md.ucast_egress_port = RECYCLE_PORT;
                return;
            }
            // Else, bitmap is full, update HLL and hash table
            hll_rand = hash_hll_f_32.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
            leading_zero_lookup.apply(); // Use table lookup to calc hll_val

            if (random_bit == 0) { // Use idx1
                hll_reg_index = hash_hll_f_16_1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr},0,HLL_EST_SIZE); // h_hll_1(f,e), used to locate reg
            } else {
                hll_reg_index = hash_hll_f_16_2.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr},0,HLL_EST_SIZE); // h_hll_1(f,e), used to locate reg
            }
            hll_tbl_idx = hdr.recycle.chosen_idx[31:6] ++ hll_reg_index[5:0]; // [31:6] from hll_idx_tmp, [5:0] from hll_reg_index
            hll_update_ret = update_hll_table.execute(hll_tbl_idx);
            if (hll_update_ret != 0) { // Value changed
                hdr.igeg.setValid();
                hll_sum_delta = (bit<16>)(hll_val - hll_update_ret);
                hll_sum_index = hdr.recycle.chosen_idx; // >> 6; // Original valid bits are [31:0], becomes [25:0] after >> 6
                hdr.igeg.ps = update_hll_sum_table.execute(hll_sum_index);
                hdr.igeg.ether_type = hdr.ethernet.ether_type;
                hdr.ethernet.ether_type = ETHERTYPE_IGEG;
            }
        }

        vrf = 16w0;
        forward.apply();
    }
}


Register<HASH_CELL1_T, INDEX_WIDTH16>(HASH_TBL_SIZE) hash_table_flow; // Flow id
Register<HASH_CELL2_T, INDEX_WIDTH16>(HASH_TBL_SIZE) hash_table_ps; // Partial sum
Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_light;
// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------
control SwitchEgress(
    inout header_t hdr,
    inout metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    INDEX_WIDTH16 htbl_idx;
    HASH_CELL2_T  htbl_ps_update_ret;

    RegisterAction<HASH_CELL1_T, INDEX_WIDTH16, void>(hash_table_flow) update_hash_table_flow = {
        void apply (inout HASH_CELL1_T value) {
            value = hdr.ipv4.src_addr;
        }
    };

    RegisterAction<HASH_CELL2_T, INDEX_WIDTH16, HASH_CELL2_T>(hash_table_ps) update_hash_table_ps = {
        void apply (inout HASH_CELL2_T value, out HASH_CELL2_T ret) {
            if (hdr.igeg.ps > value) {
                ret = value; // value will never be 0
                value = hdr.igeg.ps;
            } else {
                ret = 0; // a value of 0 indicates that the register is not changed
            }
        }
    };

    apply {
        if (hdr.igeg.isValid()) {
            // Update light part
            htbl_idx = hash_light.get({hdr.ipv4.src_addr},0,HASH_TBL_SIZE); // h_hash(f)
            htbl_ps_update_ret = update_hash_table_ps.execute(htbl_idx);
            if (htbl_ps_update_ret != 0) { // Value changed, update flowID as well
                update_hash_table_flow.execute(htbl_idx);
            }
            // Strip igeg header
            hdr.ethernet.ether_type = hdr.igeg.ether_type;
            hdr.igeg.setInvalid();
        }
    }
}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
