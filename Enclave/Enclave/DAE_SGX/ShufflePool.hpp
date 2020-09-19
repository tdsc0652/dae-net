//
// Created by Maxxie Jiang on 6/6/2019.
//

#ifndef ANONYMOUSP2P_SHUFFLEPOOL_HPP
#define ANONYMOUSP2P_SHUFFLEPOOL_HPP


#include "DAENode.hpp"
#include "ConcurrentHeap.hpp"
#include "FuzzingPool.hpp"
#include "orconfig.h"
#include "ConcurrentRandomQueue.hpp"
#include "dae_sgx.hpp"
#include "Enclave.h"
#include "Enclave_t.h"

#include <mbusafecrt.h>
class ChordFinger; 


class ShufflePool: public FuzzingPool {
public:
    std::vector<ConcurrentRandomQueue<std::unique_ptr<AnonymousPacket> > > package_pool;
    ChordFinger *finger_table;
    int m;
    int min_pool;
    double shuffle_P;
    bool debug;

    int debug_total_msg;
    int debug_real_forward_msg;
    int send_dummy;

    struct timespec time_prev;

    void start() override;
    ShufflePool(RandomSocket *_sok, ChordFinger* fingerTable, int _m,int rate, int _min_pool, bool _debug, double _shuffle_P, int send_dummy):
            FuzzingPool(_sok, rate), finger_table(fingerTable), m(_m), min_pool(_min_pool), debug(_debug), shuffle_P(_shuffle_P) {
        package_pool = std::vector<ConcurrentRandomQueue<std::unique_ptr<AnonymousPacket>>>(_m);
        log_err(LOG_WARN, "hi");
        sgx_clock_gettime(CLOCK_REALTIME, &time_prev, sizeof(time_prev));
        debug_total_msg = 0;
        debug_real_forward_msg = 0;
        this->send_dummy = send_dummy;
    }
    ~ShufflePool() {}

    void send_batch();
    void send(std::unique_ptr<AnonymousPacket> packet) override;
};


#endif //ANONYMOUSP2P_SHUFFLEPOOL_HPP
