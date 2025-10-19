#pragma once
#include <netinet/in.h>
#include <sys/time.h>
#include <string>
#include <vector>

// --- Categories possibles pour encoding ---

enum class SizeCat { Small, Medium, Large };
enum class DurCat { Short, Medium, Long };
enum class PeriodicityCat {
    StrongPeriodic,
    WeakPeriodic,
    WeakNonPeriodic,
    StrongNonPeriodic,
    NoData
};

// --- Indicateurs par flux ---

struct flow_metadata {
    size_t total_bytes = 0;
    timeval first_ts{};
    timeval last_ts{};
    bool first_seen = true;
};

// --- Indicateurs par connection ---

struct connection_state {
    std::vector<double> flow_start_times;  
    std::string encoding;                  // stratolgettes - e.g., "a,bC*R"
};

// --- Fonction de categorisation en fonction des metriques de flux/connections ---
// --- La categorisation vise a "discretiser" les metriques ---
// Les metriques de stratoletters sont visibles ici: stratosphereips/StratosphereLinuxIPS/slips_files/core/helpers/symbols_handler.py

// Taille
inline SizeCat categorize_size(size_t bytes) {
    if (bytes < 250) return SizeCat::Small;
    else if (bytes < 1100) return SizeCat::Medium;
    else return SizeCat::Large;
}

// Durée
inline DurCat categorize_duration(double seconds) {
    if (seconds < 0.1) return DurCat::Short;
    else if (seconds < 10.0) return DurCat::Medium;
    else return DurCat::Long;
}

// Périodicité
inline PeriodicityCat categorize_periodicity(double second_order_diff) {
    if (second_order_diff < 1.05) return PeriodicityCat::StrongPeriodic;
    else if (second_order_diff < 1.3) return PeriodicityCat::WeakPeriodic;
    else if (second_order_diff < 5.0) return PeriodicityCat::WeakNonPeriodic;
    else return PeriodicityCat::StrongNonPeriodic;
}

// --- Table d'encodage ---
// Cette table est directement tirée de l'article de S. Garcia decrivant le technology stratoletters ---

inline char encode_symbol(SizeCat size, DurCat dur, PeriodicityCat periodicity) {
    static const char table[5][3][3] = {
        
        // --- Strong Periodicity ---         
        {{'a','b','c'}, {'d','e','f'}, {'g','h','i'}},
        
        // --- Weak Periodicity --- 
        {{'A','B','C'}, {'D','E','F'}, {'G','H','I'}},
        
        // --- Weak Non-Periodicity --- 
        {{'r','s','t'}, {'u','v','w'}, {'x','y','z'}},
        
        // --- Strong Non-Periodicity --- 
        {{'R','S','T'}, {'U','V','W'}, {'X','Y','Z'}},
        
        // --- No Data --- 
        {{'1','2','3'}, {'4','5','6'}, {'7','8','9'}}
    };

    return table[(int)periodicity][(int)size][(int)dur];
}

// --- Table d'encodage pour les symboles de TD ---
// --- La aussi directement tiré du papier de S. garcia ---

inline char encode_timediff_symbol(double seconds) {
    if (seconds < 5.0) return '.';
    else if (seconds < 60.0) return ',';
    else if (seconds < 300.0) return '+';
    else if (seconds < 3600.0) return '*';
    else return '0';
}


// --- Taxonomie Argus pour "Flux" = 7-tuple ---

struct flow {
    unsigned char net_iface;       
    unsigned char tos;             
    unsigned char protocol;
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned short src_port;
    unsigned short dst_port;

    bool operator==(const flow& other) const {
        return net_iface == other.net_iface &&
               tos == other.tos &&
               protocol == other.protocol &&
               src_ip.s_addr == other.src_ip.s_addr &&
               dst_ip.s_addr == other.dst_ip.s_addr &&
               src_port == other.src_port &&
               dst_port == other.dst_port;
    }
};

// --- Fonction de hashage pour chaque flux ---

namespace std {
    template <>
    struct hash<flow> {
        size_t operator()(const flow& f) const {
            return hash<uint32_t>()(f.src_ip.s_addr) ^
                   (hash<uint32_t>()(f.dst_ip.s_addr) << 1) ^
                   (hash<uint16_t>()(f.src_port) << 2) ^
                   (hash<uint16_t>()(f.dst_port) << 3) ^
                   (hash<uint8_t>()(f.tos) << 4) ^
                   (hash<uint8_t>()(f.protocol) << 5) ^
                   (hash<uint8_t>()(f.net_iface) << 6);
        }
    };
}

// --- Issu du papier de S. Garcia: Connection = regroupement des flux en 4-tuple ---

struct connection {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned short dst_port;
    unsigned char protocol;

    bool operator==(const connection& other) const {
        return src_ip.s_addr == other.src_ip.s_addr &&
               dst_ip.s_addr == other.dst_ip.s_addr &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// --- Hashage ---

namespace std {
    template <>
    struct hash<connection> {
        size_t operator()(const connection& c) const {
            return hash<uint32_t>()(c.src_ip.s_addr) ^
                   (hash<uint32_t>()(c.dst_ip.s_addr) << 1) ^
                   (hash<uint16_t>()(c.dst_port) << 2) ^
                   (hash<uint8_t>()(c.protocol) << 3);
        }
    };
}

// --- Header IP ---

struct ip_header {
    unsigned char ihl:4, version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    struct in_addr ip_src, ip_dst;
};

// --- Header TCP ---

struct tcp_header {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset:4, reserved:4;
    unsigned char flags;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

// --- Header UDP ---
struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};
