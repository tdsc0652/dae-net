//
// Created by jianyu on 2/20/19.
//

#ifndef ANONYMOUSP2P_RELAYCONFIG_HPP
#define ANONYMOUSP2P_RELAYCONFIG_HPP
#include <cstdlib>
#include <cstdio>
#include <cstring>

typedef u_int64_t ring_id_t;

typedef struct PeerPair{
    char ip[20] = "10.22.1.16";
    int         port = 3010;
    ring_id_t   relay_id = 0;
    bool        check_usage = true;
} PeerPair;

typedef struct msg_info{
    int first;
    int second;
}msg_info;
//typedef std::tuple<int, int> msg_info;

class RelayConfig {
public:
    char relay_ip[20]    =   "0.0.0.0";
    int         relay_port  =   3010;
    bool        standalone  =   false;
    bool        debug_shuffle = false;
    char shuffle[20]     =   "shuffle";
    PeerPair    init_peers;
    int         ring_bits   =   10;        //1M
    int         daemon      =   0;
    int         debug       =   false;
    bool        is_server   =   false;
    int         msg_rate    =   10;
    int         min_pool    =   10;
    int         bt_time     =   10;

    int         cnt_interval = 1; //s
    double      shuffle_P = 0.8; //s
    int recheck = 10;  //
    int checkwait = 2;  //s
    int d_p2p_time_before = 10; //ms
    int d_p2p_time_after = 1; //s

    int send_dummy = false;
    int check_failure = false;

    ring_id_t   relay_id    =   0;
    ring_id_t   max_relay_id = 0;

    int session = 0;
    char transmission[20];
    int64_t seed;

    static RelayConfig init_from_cmd(int argc, char *argv[]){
        int n = argc;
        auto config = RelayConfig();
        for(int i = 1; i < n; i++){
            printf("%s %s\n", argv[i], argv[i+1]);
            if(strcmp(argv[i], "--ip") == 0){
                strncpy(config.relay_ip, argv[i+1], strlen(argv[i+1]) + 1);
            }else if(strcmp(argv[i], "--port") == 0){
                config.relay_port = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--key") == 0){
                config.relay_id = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--kay_range") == 0){
                config.ring_bits = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--daemon") == 0){
                config.daemon = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--peer_ip") == 0){
                strncpy(config.init_peers.ip, argv[i+1], strlen(argv[i+1]) + 1);
            }else if(strcmp(argv[i], "--peer_port") == 0){
                config.init_peers.port = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--debug") == 0){
                config.debug = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--msg_rate") == 0){
                config.msg_rate = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--pool_size") == 0){
                config.min_pool = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--bt_time") == 0){
                config.bt_time = atoi(argv[i+1]);
            }else if(strcmp(argv[i], "--cnt_time") == 0){
                config.cnt_interval = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--debug_shuffle") == 0){
                config.debug_shuffle = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--shuffle_P") == 0){
                config.shuffle_P = atof(argv[i+1]);
            } else if(strcmp(argv[i], "--recheck") == 0){
                config.recheck = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--checkwait") == 0){
                config.checkwait = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--p2p_time_before") == 0){
                config.d_p2p_time_before = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--p2p_time_after") == 0){
                config.d_p2p_time_after = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--check_failure") == 0){
                config.check_failure = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--send_dummy") == 0){
                config.send_dummy = atoi(argv[i+1]);
            } else if(strcmp(argv[i], "--m") == 0){
                config.ring_bits = atoi(argv[i+1]);
            } else{

            }
            i++;
        }
        config.max_relay_id = (1 << (config.ring_bits));
    }
/*
    // format ./Relay ip:port --list=
    static RelayConfig init_from_cmd(int argc, char** argv) {
        auto relayConfig = RelayConfig();
        CLI::App app{"Relay"};

        int debug_int_relay_id;
        app.add_option("-i,--ip", relayConfig.relay_ip, "ip address");
        app.add_option("-p,--port", relayConfig.relay_port, "ip port");
        app.add_option("-k,--key", debug_int_relay_id, "node key id");
        app.add_option("-m,--key_range", relayConfig.ring_bits, "number of bits for node keys");
        app.add_option("-e,--daemon", relayConfig.daemon, "runs in daemon");
        app.add_option("-l,--peer_ip", relayConfig.init_peers.ip, "init connected peers ip");
        app.add_option("-o,--peer_port", relayConfig.init_peers.port, "init connected peers port");
        app.add_option("-s,--standalone", relayConfig.standalone, "start with standalone");
        app.add_option("-d,--debug", relayConfig.debug, "debugging mode");
        app.add_option("--msg_rate", relayConfig.msg_rate, "message rate");
        app.add_option("--pool_size", relayConfig.min_pool, "minimum shuffle pool size");
        app.add_option("--bt_time", relayConfig.bt_time, "bootstrap time");
        app.add_option("--cnt_time", relayConfig.cnt_interval, "cnt time");
        app.add_option("--debug_shuffle", relayConfig.debug_shuffle, "debug shuffle");
        app.add_option("--shuffle_P", relayConfig.shuffle_P, "shuffle P");
        app.add_option("--recheck", relayConfig.recheck, "re-check times");
        app.add_option("--checkwait", relayConfig.checkwait, "check wait (s)");
        app.add_option("--p2p_time_before", relayConfig.d_p2p_time_before, "p2p time interval before");
        app.add_option("--p2p_time_after", relayConfig.d_p2p_time_after, "p2p time interval after");
        app.add_option("--check_failure", relayConfig.check_failure, "check failure");
        app.add_option("--send_dummy", relayConfig.send_dummy, "send dummy");
        app.parse(argc, argv);

        relayConfig.relay_id = debug_int_relay_id;
        relayConfig.max_relay_id = (1 << (relayConfig.ring_bits));

        return std::move(relayConfig);
    }

    static RelayConfig read_from_file(std::string filename) {
        RelayConfig config;
        std::ifstream config_file(filename);
        std::string key, value;
        while (config_file >> key >>value) {
            if (key == "peer_ip") {
                strncpy(config.init_peers.ip, value.c_str(), value.length()+1);
            } else if (key == "peer_port") {
                config.init_peers.port = std::stoi(value);
            } else if (key == "debug") {
                config.debug = true;
            } else if (key == "key") {
                config.relay_id = std::stoi(value);
            } else if (key == "m") {
                config.ring_bits = std::stoi(value);
            } else if (key == "session") {
                config.session = std::stoi(value);
            } else if (key == "transmission") {
                strncpy(config.transmission, value.c_str(), value.length()+1);
            } else if (key == "seed") {
                config.seed = std::stoi(value);
            } else if (key == "server") {
                config.is_server = true;
            } else if (key == "msg_rate") {
                config.msg_rate = std::stoi(value);
            } else if (key == "pool_size") {
                config.min_pool = std::stoi(value);
            } else if (key == "bt_time") {
                config.bt_time = std::stoi(value);
            } else if (key == "debug_shuffle") {
                config.debug_shuffle = true;
            } else if (key == "shuffle") {
                //config.shuffle = value;
            } else if (key == "cnt_time") {
                config.cnt_interval = std::stoi(value);
            } else if (key == "shuffle_P") {
                config.shuffle_P = std::stod(value);
            } else if (key == "recheck") {
                config.recheck = std::stoi(value);
            } else if (key == "checkwait") {
                config.checkwait = std::stoi(value);
            } else if (key == "p2p_time_before") {
                config.d_p2p_time_before = std::stoi(value);
            } else if (key == "p2p_time_after") {
                config.d_p2p_time_after = std::stoi(value);
            } else if (key == "send_dummy") {
                config.send_dummy = std::stoi(value);
            } else if (key == "check_failure") {
                config.check_failure = std::stoi(value);
            }
//            else if (key == "relay_ip") {
//                config.relay_ip = std::stoi(value);
//            }else if (key == "relay_port") {
//                config.relay_port = std::stoi(value);
//            }
        }
        config.max_relay_id = (1 << (config.ring_bits));
        return config;
    }
    */

    RelayConfig(){}
};


#endif //ANONYMOUSP2P_RELAYCONFIG_HPP
