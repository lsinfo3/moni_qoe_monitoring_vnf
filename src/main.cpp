/**
 *
 * TCP Packet sniffer built using libtins. Is designed to be used to capture HTTP Adaptive Video Streaming traffic
 * Requires libtins <https://github.com/mfontanini/libtins>
 *
 *
 * Note: videoid and iteration are only used for naming purposes
 *
 * IMPORTANT!!!!
 * If you get compile errors regarding regex, use a cmake flag, to force a newer g++ version. See CMakeLists for reference
 * IMPORTANT!!!!
 *
 * @Author: Christian Popp, Lam Dinh-Xuan
 *
 */
#include <sstream>
#include <iostream>
#include <tins/tins.h>
#include <fstream>
#include <sys/stat.h>
#include <regex>
#include <thread>
#include <condition_variable>
#include <map>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
using namespace Tins;

//Variables for packet queue and logfile
std::mutex sender_queue_mtx;
std::deque<Packet> recieved_packets;

// Segment and MPD storage
std::set<std::string> mpd_files = {};
std::map<std::string, double> segment_map;

// Segment info for buffer estimation
std::mutex requested_segments_mtx;
std::deque<std::string> requested_segments; //May be deprecated
//Fancy new stuff
std::map<double, std::string> requested_segments_port;
std::deque<std::string> downloaded_segments;
std::mutex downloaded_segments_mtx;

std::set<std::string> pending_segments;
std::map<std::string, double> video_buffers; //Current video buffers

//DEBUG
std::uint32_t current_packet = 0;


std::string get_payload_string(Packet &packet) {
    try {
        const Tins::RawPDU raw = packet.pdu()->rfind_pdu<RawPDU>();
        const Tins::RawPDU::payload_type payload = raw.payload();
        std::string payload_text(payload.begin(), payload.end());
        return payload_text;
    } catch (Tins::pdu_not_found) {
        return "";
    }
}

std::string get_timestamp(Packet p) {
    std::string timestamp = std::to_string(p.timestamp().seconds());
    timestamp += std::to_string(p.timestamp().microseconds());
    timestamp = timestamp.substr(0, 13);
    return timestamp;
}

std::string get_timestamp_full(Packet p) {
    std::string timestamp = std::to_string(p.timestamp().seconds());
    timestamp += std::to_string(p.timestamp().microseconds());
    return timestamp;
}

/**
 * Returns substring containing the videoid
 * @param segment segment name
 * @return videoid of segment
 */
std::string get_videoid(std::string segment) {
    return segment.substr(0, segment.find('_'));
}


/**
 * Checks if there is already an entry for the video
 * @param segment_name segment of video to be checked
 */
void check_new_video(std::string segment_name) {
    using namespace std;
    cout << "Currently known videos:" << endl;

    if (video_buffers.size() > 0) {
        for (auto const &key : video_buffers) {
            cout << "   " << key.first << " : " << key.second << "s" << endl;
        }
    } else {
        cout << "Currently no known videos" << endl;
    }

    using namespace std;
    string videoid = get_videoid(segment_name);

    if (video_buffers.find(videoid) == video_buffers.end()) {
        cout << "Found new video: " << videoid << endl;
        video_buffers.insert(make_pair(videoid, 0.0));
    }
}

/**
 * Sniffer method. Extracts information from the packets and writes the logfile
 * Two distinct features:
 * 1. Logging of all packets to a logfile
 * 2. Identification of MPD information, storing segments in 'segment_map' and all MPD in 'mpd_files'
 **/
bool process_packet(Packet &packet) {
    current_packet = current_packet + 1;
    using namespace std;

    //Initial variable definition
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t tcp_flag_num = 0;
    uint32_t tcp_ack = 0;
    uint32_t tcp_seq = 0;

    IPv4Address ip_src;
    IPv4Address ip_dst;
    uint16_t packet_length = 0;

    //Assignment of variables. Will later be used to write packet info to file
    //Sometimes, the packet contains no valid MPD. If so, the payload_text length is 0
    string payload_text = get_payload_string(packet);
    if (payload_text.length() == 0) {
        return false;
    }

    //ofstream output;
    //output.open(logdir, ios_base::app);


    TCP *tcp = packet.pdu()->find_pdu<TCP>();
    IP *ip = packet.pdu()->find_pdu<IP>();

    src_port = tcp->sport();
    dst_port = tcp->dport();
    tcp_flag_num = tcp->flags();
    tcp_ack = tcp->ack_seq();
    tcp_seq = tcp->seq();

    ip_src = ip->src_addr();
    ip_dst = ip->dst_addr();
    packet_length = ip->tot_len();

    string timestamp = get_timestamp(packet);
    timestamp = to_string(packet.timestamp().seconds());
    string timestamp_full = get_timestamp_full(packet);

    // Check packet if it cointains any kind of video information (MPG, segments etc.)
    //std::regex m3u8_get("GET.*\\.m3u8");
    std::regex m3u8(".*m3u8");
    std::regex mp4("EXTINF.*\\n.*.mp4");
    std::regex mp4_req("GET.*.mp4");
    std::regex mpd_dl("EXTM3U");
    std::regex http_200("HTTP/1.1 200 OK");
    smatch matched;
    smatch segment_matched;

    if (regex_search(payload_text, matched, mpd_dl)) {

        smatch playlists;
        smatch segments;

        auto m3u8_matches = sregex_iterator(payload_text.begin(), payload_text.end(), m3u8);
        auto m3u8_matches_end = sregex_iterator();

        // Search for all distinct MPD files for different quality levels
        for (sregex_iterator i = m3u8_matches; i != m3u8_matches_end; i++) {
            smatch match = *i;
            string m3u8_string = match.str();
            mpd_files.insert(m3u8_string);
            cout << "MPD file found: " << m3u8_string << endl;
        }

        auto mp4_matches = sregex_iterator(payload_text.begin(), payload_text.end(), mp4);
        auto mp4_matches_end = sregex_iterator();

        // Search MPD files for single segments and their duration
        for (sregex_iterator i = mp4_matches; i != mp4_matches_end; i++) {
            smatch match = *i;
            string mp4_string = match.str();
            double segment_duration = std::stod(mp4_string.substr(7, 5));
            long ln_pos = mp4_string.find(",");
            std::string segment_name = mp4_string.substr(ln_pos + 2, mp4_string.length() - ln_pos);

            check_new_video(segment_name);

            segment_map.insert(make_pair(segment_name, segment_duration));

            //cout << "MPD contains segment with name: " << segment_name << " and duration " << segment_duration
            //     << " seconds." << endl;
        }

        cout << "Segments found so far: " << segment_map.size() << endl;
        cout << "Numer of MPD files (quality levels): " << mpd_files.size() << std::endl;
    }

    if (regex_search(payload_text, segment_matched, mp4_req)) {
        string get_req = segment_matched[0];
        int last_delimiter = (int) get_req.find_last_of('/');

        string segment_name = get_req.substr(last_delimiter + 1, get_req.length() - last_delimiter);

        //Save segment name + request port, to track responses to this port
        requested_segments_port.insert(make_pair(double(src_port), segment_name));

        cout << current_packet << ":" << timestamp_full << ":\t\tGET request for segment: " << segment_name << endl;
    }

    if (regex_search(payload_text, segment_matched, http_200)) {

        if (requested_segments_port.count(double(dst_port)) > 0) {
            //The 200 is a response to a segment GET
            std::string segment_name = requested_segments_port.at(dst_port);
            requested_segments_port.erase(double(dst_port));

            //Save segment to finished segments, so second thread can parse information and add playtime
            downloaded_segments_mtx.lock();
            downloaded_segments.push_front(segment_name);
            downloaded_segments_mtx.unlock();

            cout << current_packet << ":" << timestamp_full << ":\t\tSegment downloaded: " << segment_name << endl;
        }
    }

    // Write all packet information to log
    // [OPTIONAL] It is not necessary for live monitoring, only enable log file in the case of further analysis

    //output << "---payload_start---" << endl;
    //output << "Timestamp: " << timestamp << endl;
    //output << "IP_src: " << ip_src << ":" << src_port << endl;
    //output << "IP_dst: " << ip_dst << ":" << dst_port << endl;
    //output << "TCP_flag: " << tcp_flag_num << endl;
    //output << "TCP_ack: " << tcp_ack << endl;
    //output << "TCP_seq: " << tcp_seq << endl;
    //output << "Packet_length: " << packet_length << endl;
    //output << "---content---" << endl;
    //output << payload_text << endl;
    //output << "---payload_end---" << endl;
    //output << endl;

    //output.close();

    return true;
}

std::string get_segment_number(std::string segment_name) {
    using namespace std;
    int last_0 = (int) segment_name.find_last_of('0');
    return segment_name.substr(last_0 + 1, segment_name.length() - last_0 - 5);
}

/**
 *
 * Checks if any quality level of the given segment has been requested previously
 *
 * @param segment_name name of the segment
 * @return true if any quality level of the segment is in previous_segments, false if not
 */
bool check_quality_levels(std::string segment_name) {
    using namespace std;
    cout << "Currently waiting segment requests: " << endl;
    for (string a : pending_segments) {
        cout << "    " << a << endl;
    }

    regex quality_level("_[0-9]{3}p_");

    string s_240p = regex_replace(segment_name, quality_level, string("_240p_"));
    string s_360p = regex_replace(segment_name, quality_level, string("_360p_"));
    string s_720p = regex_replace(segment_name, quality_level, string("_720p_"));

    return pending_segments.find(s_240p) == pending_segments.end() or
           pending_segments.find(s_360p) == pending_segments.end() or
           pending_segments.find(s_720p) == pending_segments.end();
}

/**
 *
 * Returns the previous segment to the given one
 *
 * @param segment_name
 * @return previous segment
 */
std::string get_previous_segment(std::string segment_name) {
    using namespace std;
    string segment_num = get_segment_number(segment_name);
    if (segment_num.length() == 0) {
        throw new exception_base::runtime_error("No previous segment");
    }
    int segment_number = stoi(segment_num);


    int segment_number_prev = segment_number - 1;
    string segment_num_prev = to_string(segment_number_prev);
    //Check for length. If we check for the previous segment of segment number 10, the previous segment has number 09
    while (segment_num_prev.length() != 7) {
        segment_num_prev = "0" + segment_num_prev;
    }

    string previous_segment = segment_name.substr(0, segment_name.length() - 11) + segment_num_prev + ".mp4";
    return previous_segment;

}

/**
 *
 * Checks if the previous segment to the given one has already been requested
 *
 * @param segment Segment, the predecessor of which is checked for being already requested
 * @return true if the previous segment was already requested, false if not
 **/
bool check_previous_segment(std::string segment_name) {
    using namespace std;

    //Check if the segment number is 0. If so, no previous segment exists
    string segment_num = get_segment_number(segment_name);
    if (segment_num == "") {
        return false;
    }

    string previous_segment = get_previous_segment(segment_name);
    return check_quality_levels(previous_segment);

}

void add_playtime(std::string segment_name) {
    using namespace std;
    string videoid = get_videoid(segment_name);

    double segment_duration = segment_map[segment_name];
    double video_playtime = video_buffers[videoid];

    double new_playtime = video_playtime + segment_duration;

    video_buffers[videoid] = new_playtime;

    cout << "Segment " << segment_name << " downloaded. Old playtime was: " << video_playtime
         << ". Segment duration is " << segment_duration
         << ". New buffer: " << video_buffers[videoid] << endl;
}

void decrement_playtimes() {
    using namespace std;
    if (video_buffers.size() > 0) {
        for (auto &entry : video_buffers) {

            entry.second = entry.second - 0.1;

            if (entry.second <= 0) {
                entry.second = 0;
            } else {
                //cout << entry.first << " : " << entry.second << "s; ";
            }
        }
    }

}

void write_logfile(std::string filename_base) {
    using namespace std::chrono;
    milliseconds ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
    );

    for (auto &entry : video_buffers) {
        std::string filename_complete = filename_base + "_" + entry.first + ".log";
        std::ofstream output;

        output.open(filename_complete, std::ios_base::app);

        output << std::to_string(ms.count()) << ";" << entry.first << ";" << entry.second << ";" << std::endl;

        output.close();
    }
}

std::string get_filename_live(std::string iteration, std::string clients, std::string interface) {
    using namespace std::chrono;
    milliseconds ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
    );

    std::string filename = "rep_" + iteration + "_clients_" + clients + "_interface_" + interface + "_" + std::to_string(ms.count());
    return filename;

}

void estimate_video_buffer(std::string iteration, std::string clients, std::string interface) {
    using namespace std;

    string filename = get_filename_live(iteration, clients, interface);
    string logfile_base = "aws_live_moni/" + filename;

    while (true) {
        downloaded_segments_mtx.lock();
        if (downloaded_segments.size() > 0) {

            string segment_name;
            segment_name = downloaded_segments.back();

            downloaded_segments.pop_back();
            downloaded_segments_mtx.unlock();

            add_playtime(segment_name);

        } else {
            downloaded_segments_mtx.unlock();
        }
        write_logfile(logfile_base);
        decrement_playtimes();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void enqueue(Packet &packet) {
    sender_queue_mtx.lock();
    recieved_packets.push_front(packet);
    sender_queue_mtx.unlock();
}

Packet dequeue() {
    Packet p;
    p = recieved_packets.back();
    recieved_packets.pop_back();
    return p;
}

void process_packets() {
    while (true) {
        Packet p;

        sender_queue_mtx.lock();
        if (!recieved_packets.empty()) {
            p = dequeue();
            sender_queue_mtx.unlock();
            process_packet(p);
        } else {
            sender_queue_mtx.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

/*
 * Simple mkdir on the logdir. Silently fails if the directory exists
 */
void make_logdirs() {
    mkdir("aws_live_moni", 0777);
    mkdir("/tmp/libtins", 0777);

}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        std::cerr
                << "Please enter exactly three arguments: replication, number of clients and network interface"
                << std::endl;
        return 0;
    }

    std::cout << "Started sniffing network interface " << argv[3] << " with parameters: \n Videoid: " << argv[1]
              << "\n Iteration " << argv[2] << "\n Clients: " << argv[2] << std::endl;

    std::string iteration = argv[1];
    std::string clients = argv[2];
    std::string interface = argv[3];

    //Logfile filename etc.
    make_logdirs();

    //Sniffer configuration. Only TCP
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // [OPTIONAL - Configure snapshot length]
    //config.set_snap_len(500);
    // [OPTIONAL - Configure packet buffer size]
    //config.set_buffer_size(50*1024*1024);
    config.set_filter("tcp port 80");
    Sniffer sniffer(interface, config);

    //Thread 1 to capture and decode packets
    std::thread my_thread_1(process_packets);
    //Thread 2 to estimate the video buffer
    std::thread my_thread_2(estimate_video_buffer, argv[1], argv[2], argv[3]);

    sniffer.sniff_loop([&](Packet &packet) {
        enqueue(packet);
        return true;
    });

}

#pragma clang diagnostic pop
