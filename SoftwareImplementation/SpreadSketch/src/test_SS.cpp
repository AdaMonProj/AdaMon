#include "SS.h"
#include "mylibpcap.h"
#include <fstream>
#include <unordered_map>

#define OUTPUT_SUPERSPREADERS 1

int main() {
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t total_mem = 30*1024;
    uint32_t am_mem = 0;    // when am_mem > 0, SS is improved by AdaMon:layer1.
    double am_ratio = (double)am_mem/total_mem;    
    SpreadSketch ss(total_mem, am_ratio);

    // insertion stage
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        ss.update(flowID, elemID);
    }

    // recovery stage
    vector<IdSpread> superspreaders;   
    ss.report_superspreaders(superspreaders);
#ifdef OUTPUT_SUPERSPREADERS
    string ofile_path = "../../SpreadSketch/output/SuperSpreaders";
    write_superspreaders(ofile_path, superspreaders);
#endif
    return 0;
}