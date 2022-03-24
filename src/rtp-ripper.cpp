#include <iostream>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/foreach.hpp>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>

#include "rtp-ripper.hpp"

#define PT_UNDEFINED (9999)
#define CACHE_SIZE (100)

static char RFC2833_CHARS[] = "0123456789*#ABCDF";



namespace {
  char switch_rfc2833_to_char(int event)
  {
    if (event > -1 && event < (int32_t) sizeof(RFC2833_CHARS)) {
      return RFC2833_CHARS[event];
    }
    return '\0';
  }

  void rtpHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    RtpRipper* ripper = reinterpret_cast<RtpRipper*>( userData );
    ripper->processRtp(pkthdr, packet);
  }

  void generateSilencePacket(RtpRipper::RtpStream& rtpStream, string& packet) {
    void* data = calloc(rtpStream.m_payloadLength, 1);
    switch(rtpStream.m_pt) {
      case 0:
        for (int i = 0; i < rtpStream.m_payloadLength; i += 2) {
          memset((char *)(data) + i, 0xFF, 2);
        }
      break;

      case 8:
        for (int i = 0; i < rtpStream.m_payloadLength; i += 2) {
          memset((char *)(data) + i, 0x55, 2);
        }
        break;

      case 9:
        for (int i = 0; i < rtpStream.m_payloadLength; i += 2) {
          memset((char *)(data) + i, 0xFA, 2);
        }
        break;
    }

    packet.assign(static_cast<char*>(data), rtpStream.m_payloadLength);
  }
}

RtpRipper::RtpRipper(int raw, const string& codecList, u_int callerPort, u_int calleePort, 
    u_int callerTePt, u_int calleeTePt,  FILE* in, FILE* outCaller, FILE* outCallee) :
    m_callerPort(callerPort), m_calleePort(calleePort),
    m_fpInput(in), m_fpCallerOutput(outCaller), m_fpCalleeOutput(outCallee), 
    m_pcap(NULL), m_ripped(false), m_lastWrite(-1),
    m_callerRtpStream(PT_UNDEFINED, callerTePt, "caller", m_fpCallerOutput), 
    m_calleeRtpStream(PT_UNDEFINED, calleeTePt, "callee", m_fpCalleeOutput) {

    m_ethHdrSize = raw ? 0 : sizeof(struct ether_header) ;

    vector<string> vec;
    boost::split(vec, codecList, boost::is_any_of(","));

    BOOST_FOREACH (const string& t, vec) {
      boost::regex e("^(\\d+)\\s*:\\s*(\\w+)", boost::regex::extended);
      boost::smatch mr; ;
      if (boost::regex_search( t, mr, e )) {
        int pt = boost::lexical_cast<int>(mr[1]);
        string codec = mr[2];
        m_mapPt2Codec.insert(mapPt2Codec::value_type(pt, codec)) ;
      }
      else {
        cerr << "failed to parse codec list " << t << endl;
      }
    }
  }

int RtpRipper::rip() {
  assert (!m_ripped) ;
  char errbuf[PCAP_ERRBUF_SIZE];

  m_pcap = pcap_fopen_offline(m_fpInput, errbuf);
  if (!m_pcap) {
    cerr  << "failed opening pcap file: " << errbuf << endl;
    throw std::runtime_error("failed opening pcap file");
  }

  if (pcap_loop(m_pcap, 0, rtpHandler, reinterpret_cast<u_char*>(this)) < 0) {
    cerr << "Error reading pcap file " << pcap_geterr(m_pcap) << endl ;
    throw runtime_error("error reading pcap file");
  }

  pcap_close(m_pcap);

  fflush(m_fpCallerOutput);
  fflush(m_fpCalleeOutput);

  cerr << "caller wrote " << m_callerRtpStream.m_numPackets << endl;
  cerr << "callee wrote " << m_callerRtpStream.m_numPackets << endl;

  cout << "{\"dtmf\": {\"caller\": [";
  bool written = false;
  for (auto it = m_callerRtpStream.m_dequeDtmf.cbegin(); it != m_callerRtpStream.m_dequeDtmf.cend(); ++it) {
    const Dtmf& dtmf = *it;
    if (written) cout << ",";
    cout << "{\"key\":\"" << dtmf.key << "\", \"placement\":" << dtmf.placement << ", \"duration\": " << dtmf.duration << "}";
    written = true;
  }
  cout << "]," << endl;

  written = false;
  cout << "\"callee\": [";
  for (auto it = m_calleeRtpStream.m_dequeDtmf.cbegin(); it != m_calleeRtpStream.m_dequeDtmf.cend(); ++it) {
    const Dtmf& dtmf = *it;
    if (written) cout << ",";
    cout << "{\"key\":\"" << dtmf.key << "\", \"placement\":" << dtmf.placement << ", \"duration\": " << dtmf.duration << "}";
    written = true;
  }
  cout << "]}}" << endl;

  m_ripped = true ;

  // return the payload type discovered for the callee stream
  return m_calleeRtpStream.m_pt;
}

void RtpRipper::processRtp(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ip* ipHeader;
  const struct udphdr* udpHeader;
  u_int sourcePort, destPort;
  u_char *data;
  int dataLength = 0;

  ipHeader = (struct ip*)(packet + m_ethHdrSize);

  if (ipHeader->ip_p == IPPROTO_UDP) {
    udpHeader = (udphdr*)(packet + m_ethHdrSize + sizeof(struct ip));
    sourcePort = ntohs(udpHeader->uh_sport);
    destPort = ntohs(udpHeader->uh_dport);
    data = (u_char*)(packet +  m_ethHdrSize + sizeof(struct ip) + sizeof(struct udphdr));
    dataLength = pkthdr->len - (m_ethHdrSize + sizeof(struct ip) + sizeof(struct udphdr));

    if (destPort == m_callerPort || destPort == m_calleePort) {
      rtp_hdr_t* hdr = (rtp_hdr_t*) data ;
      u_char* payload = data + sizeof(rtp_hdr_t) ;
      int payloadLength = dataLength -  sizeof(rtp_hdr_t);
      int writer = destPort == m_callerPort ? 0 : 1;

      if (hdr->version != 2) {
        cerr << "discarding packet with rtp version " << dec << hdr->version << " with seq " << ntohs(hdr->seq) << endl;
      }

      // lamda function to process the packet for whichever party
      auto _processPacket = [this] (FILE* fp, RtpStream& rtpStream, RtpStream& other, 
        rtp_hdr_t* hdr, u_char* payload, int payloadLength) {

        string codecName;
        u_int32 ts = ntohl(hdr->ts) ;
        u_int16 seq = ntohs(hdr->seq);
        bool marker = hdr->m ;
        int pt = hdr->pt ;
        u_int32 ssrc = ntohl(hdr->ssrc);

        /* handle RFC 2833 and unknown payload types */
        if (pt == rtpStream.m_te_pt) {
          int end = payload[1] & 0x80 ? 1 : 0;
          if (end && ts != rtpStream.m_tsLastDtmf) {
            uint16_t duration = ((payload[2] << 8) + payload[3]) / 8;
            char key = switch_rfc2833_to_char(payload[0]);
            rtpStream.m_tsLastDtmf = ts;

            u_int32 placement = (ts - rtpStream.m_baseTimestamp + rtpStream.m_offset) / 8; 
            Dtmf dtmf(placement, duration, key);
            rtpStream.m_dequeDtmf.push_back(dtmf);
          }
          return;
        }
        else if (PT_UNDEFINED == rtpStream.m_pt) {
          string name;
          if (getCodecFromPt(pt, name)) {
            rtpStream.m_pt = pt;
          }
          else {
            cerr << "unable to find codec for " << pt << endl;
          }
        }
        else if (pt != rtpStream.m_pt) {
          cerr << rtpStream.m_strName << ": unknown payload type " << std::hex << pt << endl;
          return;
        }

        /* check if ssrc changed */
        if (ssrc != rtpStream.m_ssrc) {
          /* new ssrc, which means timestamp can change to a new base */
          if (0 != rtpStream.m_ts) rtpStream.m_offset += (rtpStream.m_ts - rtpStream.m_baseTimestamp);
          rtpStream.m_ssrc = ssrc;
          rtpStream.m_baseTimestamp = ts;
          /*
          cerr << rtpStream.m_strName << ": ssrc changed to 0x" << std::hex << ssrc << ", offset is now " << 
            std::dec << rtpStream.m_offset << ", seq is " << seq << endl;
          */
        }
  
        /* check if timestamp jumped, and if so insert silence */
        if (0 != rtpStream.m_ts && ts - rtpStream.m_ts > 160) {
          int num = (ts - rtpStream.m_ts) / 160 - 1 ;
          //cerr << rtpStream.m_strName <<": ts " <<std::dec<< ts << " - " <<std::dec<< rtpStream.m_ts << " = " <<std::dec<< (ts-rtpStream.m_ts) << endl;
          //cerr << "cur seq = "<< std::dec << seq << "  prev seq = " << std::dec << rtpStream.m_seq << endl;
          //cerr <<"   injecting "<<std::dec <<num<<" silence" << endl;
          if (num > 10000) {
            cerr << rtpStream.m_strName << ": ignore mistemporal packet seq="<< std::dec << seq << ", ts="<< std::dec << ts <<endl;
            return;
          }
          for (int i = 0; i < num; i++) {
            string packet;
            generateSilencePacket(rtpStream, packet);
            fwrite(static_cast<const void *>(packet.data()), packet.length(), 1, rtpStream.m_fp) ;
            rtpStream.m_numPackets++;
          }
          //cerr << rtpStream.m_strName <<  ": generating " << std::dec << num << " silence packets due to timestamp jump" << endl;
        }

        /* insert silence at the beginning for stream that has not started */
        if (0 == other.m_ssrc) {
          string packet;
          generateSilencePacket(other, packet);
          fwrite(static_cast<const void *>(packet.data()), packet.length(), 1, other.m_fp) ;
          other.m_numPackets++;
          other.m_offset += packet.length();
          //cerr << other.m_strName <<  ": generated initial silence packet" << endl;
        }

        else if (0 != rtpStream.m_ts && ts - rtpStream.m_ts != 160) {
          cerr << rtpStream.m_strName <<  ": unexpected ts " << std::dec << ts << " previous was " << rtpStream.m_ts << endl;
        }
        fwrite(payload, payloadLength, 1, rtpStream.m_fp) ;
        rtpStream.m_numPackets++;
        rtpStream.m_ts = ts;
        rtpStream.m_seq = seq;
      } ;
      if (destPort == m_callerPort) {
        _processPacket(m_fpCallerOutput, m_callerRtpStream, m_calleeRtpStream, 
          hdr, payload, payloadLength);
      }
      else if (destPort == m_calleePort) {
        _processPacket(m_fpCalleeOutput, m_calleeRtpStream, m_callerRtpStream,
          hdr, payload, payloadLength);
      }
    }
  }
}
