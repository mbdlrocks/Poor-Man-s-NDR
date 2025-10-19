#include "includes/includes.h"
#include "includes/structs.h"

#define BUF_SIZE 2048 // Buffer pour capture packets

// --- Configuration par défaut de la sonde ---
// Voire notebook d'entrainement du modele pour retrouver les valeurs par defaut

int RNN_MIN_FLOWS = 4;              // Nb. de flows avant trigger possible
double RNN_THRESHOLD = 0.56;        // Seuil de détection RNN
int RNN_NBCONSECUTIVES = 3;         // Nb. trigger consécutifs pour alerte
bool RNN_ISCONSECUTIVES = false;    // Si doit être n*>t consécutif pour trigger
bool CAPTURE_TCP = true;            // Capture le traffic TCP
bool CAPTURE_UDP = true;            // Capture le traffic UDP

// --- Variables globales ---

torch::jit::script::Module rnn_model; // Fichier TorchScript contenant le modèle
std::mutex model_mutex;               // Initialisation mutex

// --- Gestion des lots Flux, Connections --- 

std::unordered_map<flow, size_t> flow_table;                    // Flux
std::unordered_map<connection, size_t> connection_table;        // Connections
std::unordered_map<flow, flow_metadata> flow_meta;              // Flux metadata
std::unordered_map<connection, connection_state> conn_state;    // Pour l'encoding stratoletters 

// --- Buffers pour les panneaux de l'UI ---

std::vector<std::string> ui_flows;              // Panneau 1: Flux
std::vector<std::string> ui_connections;        // Panneau 2: Connections
std::vector<std::string> ui_alerts;             // Panneau 3: Alertes

// --- Nb maximum de ligne par panneau --- 

const size_t UI_MAX_ROWS = 10; // 10 lignes par panneau

// --- Fonction pour l'encodage stratoletters ---

int encode_letter(char ch) 
{
    static const std::string vocabulary = "abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*"; // Symboles possibles
    
    // Correspondance entre les lettres et une int, commencer le decompte à 1
    // Cette fonction doit matcher l'encodage utilisé durant l'entrainement du modèle

    static std::unordered_map<char, int> mapping = [] 
    {
        std::unordered_map<char, int> m;
        for (size_t i = 0; i < vocabulary.size(); ++i) {
            m[vocabulary[i]] = static_cast<int>(i + 1); 
        }
        return m;
    }();

    auto it = mapping.find(ch);
    if (it != mapping.end()) return it->second;

    // Si aucun mapping pour le symbole rencontré -> return 0
    return 0; 
}

// --- Fonction de formatage pour le panneau Flux ---

std::string format_flow_line(const flow &f, size_t packets)
{
    std::ostringstream oss;
    oss << "> "
        << inet_ntoa(f.src_ip) << " -> "
        << inet_ntoa(f.dst_ip) << ":" << f.dst_port
        << "\t| Proto: " << static_cast<int>(f.protocol)
        << " | TOS: " << static_cast<int>(f.tos)
        << "\t| IF: " << static_cast<int>(f.net_iface);
        //<< " | Packets: " << packets;
    return oss.str();
}

// --- Fonction de formatage pour le panneau Connections ---

std::string format_conn_line(const connection &c, size_t packets)
{
    std::ostringstream oss;
    oss << "> " << inet_ntoa(c.src_ip)  
        << " -> " << inet_ntoa(c.dst_ip) << ":" << c.dst_port
        << "\t| Proto: " << static_cast<int>(c.protocol)
        << " | Flows: " << packets;
    return oss.str();
}

// --- Fonction pour le rafraîchissement des trois panneaux ---
void render_ui()
{
    std::cout << "\033[2J\033[H"; // ANSI: clear screen + move cursor to home
    
    // --- Panneau Flux ---

    std::cout << "\n---    FLOWS    ---\n";
    std::cout << "===================\n\n";
    size_t start = (ui_flows.size() > UI_MAX_ROWS) ? ui_flows.size() - UI_MAX_ROWS : 0;
    for (size_t i = start; i < ui_flows.size(); ++i) {
        std::cout << ui_flows[i] << "\n";
    }
    std::cout << "\n";

    // --- Panneau Connections ---

    std::cout << "--- CONNECTIONS ---\n";
    std::cout << "===================\n\n";
    start = (ui_connections.size() > UI_MAX_ROWS) ? ui_connections.size() - UI_MAX_ROWS : 0;
    for (size_t i = start; i < ui_connections.size(); ++i) {
        std::cout << ui_connections[i] << "\n";
    }
    std::cout << "\n";

    // --- Panneau alertes ---

    std::cout << "---   ALERTS    ---\n";
    std::cout << "===================\n\n";
    start = (ui_alerts.size() > UI_MAX_ROWS) ? ui_alerts.size() - UI_MAX_ROWS : 0;
    for (size_t i = start; i < ui_alerts.size(); ++i) {
        std::cout << ui_alerts[i] << "\n";
    }
    std::cout << std::flush;
}

// --- Fonction pour intercepter signal d'arret ---

void handle_sigint(int sig) 
{
    (void)sig;
    render_ui(); // si ctrl+c => refresh l'UI et quitter
    std::cout << "\n[i] Bye !\n";
    exit(0);
}

// --- Fonction principale: Parsing des packets ---

void process_packet(const char* buffer, ssize_t size) 
{
    // Compteur temps
    timeval now{};
    gettimeofday(&now, nullptr);

    // Cast IP header, le struct est defini dans structs.h
    const ip_header* ip = (ip_header*)buffer;

    // Le parser n'accepte (pour l'instant que TCP/UDP)
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return;

    // initialisation ports dst/src
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // parser les ports selon proto en suivant le struct defini
    if (ip->protocol == IPPROTO_TCP) {
        const tcp_header* tcp = (tcp_header*)(buffer + sizeof(ip_header));
        src_port = ntohs(tcp->source_port);
        dst_port = ntohs(tcp->dest_port);
    } else if (ip->protocol == IPPROTO_UDP) {
        const udp_header* udp = (udp_header*)(buffer + sizeof(ip_header));
        src_port = ntohs(udp->source_port);
        dst_port = ntohs(udp->dest_port);
    }

    // --- Instancier les differents objets: flux et connections ---

    // Pour chaque flux, définir les membres suivants

    flow f; 
    f.net_iface = 0;
    f.tos = ip->tos;
    f.protocol = ip->protocol;
    f.src_ip = ip->ip_src;
    f.dst_ip = ip->ip_dst;
    f.src_port = src_port;
    f.dst_port = dst_port;

    // Pour chaque connection...

    connection c;
    c.src_ip = f.src_ip;
    c.dst_ip = f.dst_ip;
    c.dst_port = f.dst_port;
    c.protocol = f.protocol;

    // State = valeur encodée d'une connection en stratoletters

    auto& state = conn_state[c];

    // --- Effectuer les mesures necessaires à l'encodage pour chaque flux ---

    auto& meta = flow_meta[f];      // ID_unique
    meta.total_bytes += size;       // size
    if (meta.first_seen) 
    {
        meta.first_seen = false;    // timing (+/- long)
        meta.first_ts = now;
    }
    meta.last_ts = now;

    // --- Update tables flux et connections ---

    flow_table[f] = flow_table[f] + 1;
    connection_table[c] = connection_table[c] + 1;

    // --- Mesurer la second-order time-difference ---

    double t_now = now.tv_sec + now.tv_usec / 1e6;
    state.flow_start_times.push_back(t_now);

    // 2^TD = Periodicité du signal. 
    // L'encoding se fait selon taille, durée, periodicité

    PeriodicityCat p_cat = PeriodicityCat::NoData;
    if (state.flow_start_times.size() >= 3) {
        size_t n = state.flow_start_times.size();
        double diff1 = state.flow_start_times[n-1] - state.flow_start_times[n-2];
        double diff2 = state.flow_start_times[n-2] - state.flow_start_times[n-3];
        double second_order = fabs(diff1 - diff2);
        p_cat = categorize_periodicity(second_order); // voir structs.h
    }

    SizeCat s_cat = categorize_size(meta.total_bytes);
    double duration = (meta.last_ts.tv_sec - meta.first_ts.tv_sec) + 
                      (meta.last_ts.tv_usec - meta.first_ts.tv_usec) / 1e6;
    DurCat d_cat = categorize_duration(duration); // voir structs.h

    char symbol = encode_symbol(s_cat, d_cat, p_cat); // voir structs.h
    if (state.flow_start_times.size() > 1) {
        double time_gap = state.flow_start_times.back() - state.flow_start_times[state.flow_start_times.size()-2];
        char gap_symbol = encode_timediff_symbol(time_gap); // voir structs.h
        state.encoding.push_back(gap_symbol);
    }
    state.encoding.push_back(symbol);

    // --- Cette partie de la fonction sert a définir les infos a afficher ---

    ui_flows.clear();
    std::vector<std::pair<flow, size_t>> flows_sorted(flow_table.begin(), flow_table.end());
    
    // --- les Flux sont ordonnés par taille ---

    std::sort(flows_sorted.begin(), flows_sorted.end(),
              [](const auto &a, const auto &b){ return a.second > b.second; });
    for (const auto& [flow_key, count] : flows_sorted)
        ui_flows.push_back(format_flow_line(flow_key, count));
    if (ui_flows.size() > UI_MAX_ROWS * 10)
        ui_flows.erase(ui_flows.begin(), ui_flows.begin() + (ui_flows.size() - UI_MAX_ROWS * 10));

    // --- les Connections sont ordonnées par taille ---
    ui_connections.clear();
    std::vector<std::pair<connection, size_t>> conns_sorted(connection_table.begin(), connection_table.end());
    std::sort(conns_sorted.begin(), conns_sorted.end(),
              [](const auto &a, const auto &b){ return a.second > b.second; });
    for (const auto& [conn_key, count] : conns_sorted)
        ui_connections.push_back(format_conn_line(conn_key, count));
    if (ui_connections.size() > UI_MAX_ROWS * 10)
        ui_connections.erase(ui_connections.begin(), ui_connections.begin() + (ui_connections.size() - UI_MAX_ROWS * 10));

    // --- Cette partie de la fonction est responsable de l'inférence RNN ---

    // --- La classification ne se fait que si on a déjà une chaine de caracteres > min size
    if (state.encoding.size() >= RNN_MIN_FLOWS) 
    {
        std::vector<int64_t> indices;
        for (char ch : state.encoding) 
        {
            int id = encode_letter(ch); // On utilise les lettres encodées en int
            if (id > 0)
                indices.push_back(id);
        }

        // --- Recuperer les valeurs du tenseur ---
        
        torch::Tensor input = torch::tensor(indices).unsqueeze(0).to(torch::kLong);

        // --- Pas besoin de calculer le gradient ---
        
        torch::NoGradGuard no_grad;
        std::lock_guard<std::mutex> guard(model_mutex);

        // --- Forward-propagation ---

        auto output = rnn_model.forward({input}).toTensor();

        // --- Proba/Confidence -> sortie de la derniere couche d'activation neuronale ---
        double prob_malicious = output.item<double>(); 


        // --- Decompte du nombre de trigger avec confidence > threshold
        static std::unordered_map<connection, int> packet_counters;
        auto& counter = packet_counters[c]; 

        // --- Implem de la logique de paquets trigger consecutifs ---
        // --- Soit on trigger des que N paquets ont eu une pred > threshold ---
        // --- Soit on considere que ce doit etre N flux DE SUITE ---

        if (RNN_ISCONSECUTIVES) {
            if (prob_malicious > RNN_THRESHOLD)
                counter++;
            else
                counter = 0;
        } else {
            if (prob_malicious > RNN_THRESHOLD)
                counter++;
        }

        // --- Dans les deux cas on parle de N paquets > threshold ---

        if (counter >= RNN_NBCONSECUTIVES) 
        {
            // --- Elements composant l'alerte: dernier score de prediction, nb de flux > threshold ---
            
            struct alert_info 
            {
                double last_confidence;
                int hits;
            };
            
            static std::unordered_map<connection, alert_info> alert_map;
            auto& alert = alert_map[c];
            alert.last_confidence = prob_malicious;
            alert.hits += 1;

            // --- Gestion de l'affichage des alertes ---

            ui_alerts.clear();
            for (const auto& [conn_key, info] : alert_map) 
            {
                std::ostringstream oss;
                oss << "[INFO] C2 Detected: "
                    << inet_ntoa(conn_key.src_ip) << " -> " << inet_ntoa(conn_key.dst_ip)
                    << ":" << conn_key.dst_port 
                    << "\t| Confidence: " << info.last_confidence
                    << "\t| Hits: " << info.hits;
                ui_alerts.push_back(oss.str());
            }

            // --- Comme pour les autres panneaux ---

            if (ui_alerts.size() > UI_MAX_ROWS * 10)
                ui_alerts.erase(ui_alerts.begin(), ui_alerts.begin() + (ui_alerts.size() - UI_MAX_ROWS * 10));

            // --- Reset des compteurs ---

            if (RNN_ISCONSECUTIVES)
                counter = 0; 
            else
                counter -= RNN_NBCONSECUTIVES;
        }
    }

    // --- afficher l'UI dans le terminal ---
    render_ui();
}

// --- Point d'entree ---

int main(int argc, char* argv[]) 
{
    if (argc < 15) {
        std::cerr << "Usage: " << argv[0]
                  << " -i interface -m min_flows -t threshold -n nb_consecutive "
                  << "-c consecutive_flag -T tcp_flag -U udp_flag\n";
        return 1;
    }

    int opt;
    bool tcp_flag_set = false, udp_flag_set = false;
    std::string interface_name;

    // --- Arguments ---

    while ((opt = getopt(argc, argv, "i:m:t:n:c:T:U:")) != -1) 
    {
        switch (opt) {
            case 'i': interface_name = optarg; break;
            case 'm': RNN_MIN_FLOWS = std::stoi(optarg); break;
            case 't': RNN_THRESHOLD = std::stod(optarg); break;
            case 'n': RNN_NBCONSECUTIVES = std::stoi(optarg); break;
            case 'c': RNN_ISCONSECUTIVES = (std::stoi(optarg) != 0); break;
            case 'T': CAPTURE_TCP = (std::stoi(optarg) != 0); tcp_flag_set = true; break;
            case 'U': CAPTURE_UDP = (std::stoi(optarg) != 0); udp_flag_set = true; break;
            default:
                std::cerr << "Usage: " << argv[0]
                          << " -i interface -m min_flows -t threshold -n nb_consecutive "
                          << "-c consecutive_flag -T tcp_flag -U udp_flag\n";
                return 1;
        }
    }

    if (interface_name.empty()) {
        std::cerr << "Error: You must specify a network interface with -i\n";
        return 1;
    }

    if (!tcp_flag_set || !udp_flag_set) {
        std::cerr << "Error: Both -T and -U flags must be provided.\n";
        return 1;
    }

    if (!CAPTURE_TCP && !CAPTURE_UDP) {
        std::cerr << "Error: At least one of TCP (-T 1) or UDP (-U 1) must be enabled.\n";
        return 1;
    }

    std::cout << "[i] Using interface: " << interface_name << "\n";

    // --- Initialisation du RNN ---
    try {
        rnn_model = torch::jit::load("rnn_trace.pt");
        rnn_model.eval();
        std::cout << "[i] RNN model loaded successfully.\n";
    } catch (const c10::Error& e) {
        std::cerr << "Error loading RNN model: " << e.what() << std::endl;
        return 1;
    }

    // --- Initialisation de capture via libpcap ---

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device " << interface_name << ": " << errbuf << "\n";
        return 1;
    }

    // --- Check type liaison => si lo ne pas filtrer ---

    int linktype = pcap_datalink(handle);
    std::cout << "[i] Link-layer type: " << linktype << "\n";
    if (interface_name != "lo" && interface_name != "any") {
        std::string filter_exp;
        if (CAPTURE_TCP && CAPTURE_UDP)
            filter_exp = "tcp or udp";
        else if (CAPTURE_TCP)
            filter_exp = "tcp";
        else
            filter_exp = "udp";

        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << "\n";
            pcap_freecode(&fp);
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
    } else {
        std::cout << "[i] Skipping BPF filter for " << interface_name << "\n";
    }

    signal(SIGINT, handle_sigint);
    std::cout << "[i] Starting packet capture on " << interface_name << "...\n";

    // --- Capture ---
    
    struct pcap_pkthdr* header;
    const u_char* data;
    int res;

    while ((res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue; // timeout

        const u_char* ip_start = data;
        if (linktype == DLT_NULL) {
            ip_start += 4;      
        } else if (linktype == DLT_LINUX_SLL) {
            ip_start += 16;     
        } 
        else if (linktype == DLT_EN10MB) {
            ip_start += 14;
        }

        ssize_t ip_len = header->caplen - (ip_start - data);
        process_packet((const char*)ip_start, ip_len);
    }

    if (res == -1) {
        std::cerr << "Error reading packet: " << pcap_geterr(handle) << "\n";
    }

    pcap_close(handle);
    std::cout << "[i] Bye!\n";
    return 0;
}
