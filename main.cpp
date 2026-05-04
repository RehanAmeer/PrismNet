#include <iostream>
#include <pcap.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <ctime>
#include <map>
#include <iomanip>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

struct packetrec {
    string time;
    string src_ip;
    string dst_ip;
    string prot;
    int src_port;
    int dst_port;
    int p_size;
    string serv_n;
    string hex; 
};

vector<packetrec> capt_pac;
mutex data_mutex;
atomic<bool> iscapt(false);
pcap_t* pcap_handle = nullptr;

string gettime() {
    time_t now = time(0);
    tm* t = localtime(&now);
    char b[10]; 
    strftime(b, sizeof(b), "%H:%M:%S", t);
    return string(b);
}

string getserv(int port_no) {
    if (port_no == 80) return "HTTP";
    else if (port_no == 53) return "DNS";
    else if (port_no == 22) return "SSH";
    else if (port_no == 25) return "SMTP";
    else if (port_no == 21) return "FTP";
    else if (port_no == 3306) return "MySQL";
    else if (port_no == 443) return "HTTPS";
    else if (port_no == 8080) return "HTTPS_Alt";
    else if (port_no == 23) return "Telnet";
    else return "Unknown";
}

string toHexAsciiDump(const unsigned char* data, int len) {
    if (len <= 0) return "No payload data available.";
    ostringstream ss;
    int limit = (len > 48) ? 48 : len; 

    for (int i = 0; i < limit; i += 16) {
        ss << hex << setw(4) << setfill('0') << i << "  ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < limit) {
                ss << hex << setw(2) << setfill('0') << (int)data[i + j] << " ";
            } else {
                ss << "   ";
            }
        }
        ss << " ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < limit) {
                unsigned char ch = data[i + j];
                if (isprint(ch)) ss << ch;
                else ss << ".";
            }
        }
        ss << "\n";
    }
    if (len > 48) {
        ss << "... (" << (len - 48) << " more bytes)";
    }
    return ss.str();
}

string escape_json(const string& s) {
    ostringstream o;
    for (auto c = s.cbegin(); c != s.cend(); c++) {
        switch (*c) {
        case '"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if ('\x00' <= *c && *c <= '\x1f') {
                o << "\\u" << hex << setw(4) << setfill('0') << (int)*c;
            } else {
                o << *c;
            }
        }
    }
    return o.str();
}

string packtojson() {
    lock_guard<mutex> lock(data_mutex);
    string json = "{\"packets\":[";
    int total = capt_pac.size();
    int tcp_count = 0, udp_count = 0, icmp_count = 0;
    long t_size = 0;

    for (int i = 0; i < total; i++) {
        packetrec& p = capt_pac[i];
        if (p.prot == "TCP") tcp_count++;
        else if (p.prot == "UDP") udp_count++;
        else if (p.prot == "ICMP") icmp_count++;
        
        t_size += p.p_size; 

        json += "{";
        json += "\"time\":\"" + escape_json(p.time) + "\",";
        json += "\"src_ip\":\"" + escape_json(p.src_ip) + "\",";
        json += "\"dst_ip\":\"" + escape_json(p.dst_ip) + "\",";
        json += "\"protocol\":\"" + escape_json(p.prot) + "\",";
        json += "\"src_port\":" + to_string(p.src_port) + ",";
        json += "\"dst_port\":" + to_string(p.dst_port) + ",";
        json += "\"service\":\"" + escape_json(p.serv_n) + "\",";
        json += "\"size\":" + to_string(p.p_size) + ",";
        json += "\"hex\":\"" + escape_json(p.hex) + "\"";
        json += "}";
        
        if (i < total - 1) json += ",";
    }
    json += "],";

    double avg = (total > 0) ? (double)t_size / total : 0; 

    json += "\"stats\":{";
    json += "\"total\":" + to_string(total) + ",";
    json += "\"tcp\":" + to_string(tcp_count) + ",";
    json += "\"udp\":" + to_string(udp_count) + ",";
    json += "\"icmp\":" + to_string(icmp_count) + ",";
    json += "\"avg_size\":" + to_string(avg);
    json += "}}";
    
    return json;
}

void pack_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* u_pack) {
    if (!iscapt) return;

    packetrec rec;
    rec.time = gettime();
    rec.p_size = pkthdr->len;
    rec.src_port = 0;
    rec.dst_port = 0;
    rec.serv_n = "Unknown";
    rec.hex = "No payload parsed.";

    struct ether_header* eth_hdr = (struct ether_header*)u_pack;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) return;

    struct ip* ip_hdr = (struct ip*)(u_pack + 14); 
    
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET, &(ip_hdr->ip_src), src_buf, INET_ADDRSTRLEN) == nullptr) return;
    if (inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_buf, INET_ADDRSTRLEN) == nullptr) return; 
    
    rec.src_ip = string(src_buf);
    rec.dst_ip = string(dst_buf);
    
    int ip_len = ip_hdr->ip_hl * 4; 
    const unsigned char* payload = u_pack + 14 + ip_len;
    int payload_len = rec.p_size - (14 + ip_len);
    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        rec.prot = "TCP";
        if (payload_len >= (int)sizeof(struct tcphdr)) {
            struct tcphdr* tcph = (struct tcphdr*)payload; 
            rec.src_port = ntohs(tcph->th_sport);
            rec.dst_port = ntohs(tcph->th_dport);
            rec.serv_n = getserv(rec.dst_port); 
            
            int tcp_len = tcph->th_off * 4;
            if (payload_len >= tcp_len) {
                rec.hex = toHexAsciiDump(payload + tcp_len, payload_len - tcp_len);
            }
        }
    }
    else if (ip_hdr->ip_p == IPPROTO_UDP) {
        rec.prot = "UDP";
        if (payload_len >= (int)sizeof(struct udphdr)) {
            struct udphdr* udph = (struct udphdr*)payload; 
            rec.src_port = ntohs(udph->uh_sport); 
            rec.dst_port = ntohs(udph->uh_dport);
            rec.serv_n = getserv(rec.dst_port); 
            
            if (payload_len >= (int)sizeof(struct udphdr)) {
                rec.hex = toHexAsciiDump(payload + sizeof(struct udphdr), payload_len - sizeof(struct udphdr));
            }
        }
    }
    else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        rec.prot = "ICMP";
        rec.serv_n = "Ping";
        rec.hex = toHexAsciiDump(payload, payload_len);
    }
    
    lock_guard<mutex> lock(data_mutex);
    capt_pac.push_back(rec);
}

void start_capt() {
    if (iscapt) return;
    
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, err) == -1) {
        cout << "Error finding devices: " << err << endl;
        return;
    }
    
    if (alldevs == nullptr) {
        cout << "No device found!" << endl;
        return;
    }
    
    pcap_if_t* selected = nullptr;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        if (!(d->flags & PCAP_IF_LOOPBACK)) { 
            selected = d;
            break;
        }
    }
    if (!selected) selected = alldevs;  
    
    string device_name = selected->name;
    cout << "Using device: " << device_name << endl;
    pcap_freealldevs(alldevs);
        
    pcap_handle = pcap_create(device_name.c_str(), err);
    if (pcap_handle == nullptr) {
        cout << "Create failed: " << err << endl;
        return;
    }

    pcap_set_snaplen(pcap_handle, 65536);
    pcap_set_promisc(pcap_handle, 1);
    pcap_set_timeout(pcap_handle, 10); 
    pcap_set_immediate_mode(pcap_handle, 1); 

    if (pcap_activate(pcap_handle) != 0) {
        cout << "Activation failed." << endl;
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
        return;
    }

    struct bpf_program fp;
    string filter_exp = "ip and (tcp or udp or icmp)";
    if (pcap_compile(pcap_handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Filter compile error" << endl;
    } 
    else {
        pcap_setfilter(pcap_handle, &fp);  
        pcap_freecode(&fp);                  
    }
    
    { 
        lock_guard<mutex> lock(data_mutex);
        capt_pac.clear();
    }
    
    iscapt = true;
    thread capture_thread([]() {
        pcap_loop(pcap_handle, 0, pack_handler, nullptr);
    });
    capture_thread.detach();
}

void stop_capt() {
    if (!iscapt) return;
    
    iscapt = false; 
    if (pcap_handle != nullptr) {
        pcap_breakloop(pcap_handle);
        this_thread::sleep_for(chrono::milliseconds(200));
        pcap_close(pcap_handle);
        pcap_handle = nullptr;
    }
    cout << "Stopped. Packets captured: " << capt_pac.size() << endl;
}

void handleRequest(int client_fd) {
    char buffer[4096] = {0};
    int bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        close(client_fd);
        return;
    }
    
    string request(buffer);
    string method = "", path = "";
    istringstream stream(request);
    stream >> method >> path;
    
    size_t param_pos = path.find("?");
    if (param_pos != string::npos) {
        path = path.substr(0, param_pos);
    }
    
    string body = "";
    string content_type = "text/plain";
    
    if (path == "/" || path == "/index.html") {
        ifstream file("index.html");
        if (file) { 
            ostringstream ss;
            ss << file.rdbuf();
            body = ss.str();
            content_type = "text/html";
        } else {
            body = "Error: index.html not found.";
        }
    }
    else if (path == "/start") {
        start_capt();
        body = "{\"status\":\"started\"}";
        content_type = "application/json";
    }
    else if (path == "/stop") {
        stop_capt();
        body = "{\"status\":\"stopped\"}";
        content_type = "application/json";
    }
    else if (path == "/data") {
        body = packtojson(); 
        content_type = "application/json";
    }
    else if (path == "/pu-logo.png") {
        ifstream file("pu-logo.png", ios::binary);
        if (file) { 
            ostringstream ss;
            ss << file.rdbuf();
            body = ss.str();
            content_type = "image/png";
        } else {
            body = "";
        }
    }
    
    string response = "";
    response += "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: " + content_type + "\r\n";
    response += "Cache-Control: no-cache, no-store, must-revalidate\r\n"; 
    response += "Access-Control-Allow-Origin: *\r\n";
    response += "Content-Length: " + to_string(body.size()) + "\r\n";
    response += "\r\n";
    response += body;
    
    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
}

void start_http_server() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Port binding failed!" << endl;
        return;
    }
    listen(server_fd, 10);
    cout << "Server ready at http://localhost:8080" << endl;
    
    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;
        thread(handleRequest, client_fd).detach();
    }
}

int main() {
    start_http_server();
    return 0;
}
