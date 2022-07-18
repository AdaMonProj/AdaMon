#include "AdaMon.h"
#include "MurmurHash3.h"
#include "mylibpcap.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <set>
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <unistd.h>
using std::unique_ptr;

#define TEST_PERFLOW_SPREAD 1
#define OUTPUT_SUPERSPREADERS 1

int main() {
    string filename = "MAWI.pcap";
    FILE_HANDLER filehandler(filename);
    uint32_t mem = 1000;
    AdaMon AdaMon(mem, 0.6);
    
    string flowID, elemID;
    while(int status = filehandler.get_item(flowID, elemID)){
        AdaMon.process_packet(flowID, elemID);
        if(filehandler.proc_num()%5000000 == 0)
            cout<<"process packet "<<filehandler.proc_num()<<endl;
    }
#ifdef TEST_PERFLOW_SPREAD
    string flow_query = "192168000001";  //an example
    uint32_t ans = AdaMon.get_flow_cardinality(flow_query);
#endif
#ifdef OUTPUT_SUPERSPREADERS
    vector<IdSpread> superspreaders;
    AdaMon.report_superspreaders(superspreaders);
    string ofile_path = "../../AdaMon/output/SuperSpreaders";
    write_superspreaders(ofile_path, superspreaders);
#endif
    return 0;
}
