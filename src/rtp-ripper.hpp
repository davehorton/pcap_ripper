#ifndef __RTP_RIPPER_HPP__
#define __RTP_RIPPER_HPP__

#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <boost/unordered_map.hpp>
#include <deque>

#include "utils.h"
#include "rtp.h"

using namespace std;

#define LAST_WRITER_IS_CALLER (0)
#define LAST_WRITER_IS_CALLEE (1)
#define NO_LAST_WRITER (-1)

struct Dtmf {
  Dtmf(uint32_t p, uint16_t d, char k): placement(p), duration(d), key(k) {}
  uint32_t placement;
  uint16_t duration;
  char key;
};

class RtpRipper {
public:
  RtpRipper(int raw, const string& codec, u_int callerPort, u_int callerPt, u_int calleePort, u_int calleePt, 
   u_int callerTePt, u_int calleeTePt, FILE* in, FILE* outCaller, FILE* outCallee) :
    m_callerPort(callerPort), m_callerPt(callerPt), m_calleePort(calleePort), m_calleePt(calleePt),
    m_fpInput(in), m_fpCallerOutput(outCaller), m_fpCalleeOutput(outCallee), 
    m_pcap(NULL), m_ripped(false), m_lastWrite(-1),
    m_callerRtpStream(callerPt, callerTePt, "caller", outCaller), m_calleeRtpStream(calleePt, calleeTePt, "callee", outCallee) {
      m_ethHdrSize = raw ? 0 : sizeof(struct ether_header) ;
    }
  RtpRipper(int raw, const string& codecList, u_int callerPort, u_int calleePort, 
    u_int callerTePt, u_int calleeTePt, FILE* in, FILE* outCaller, FILE* outCallee) ; 

  ~RtpRipper() {
  }

  class RtpStream {
  public: 
    RtpStream(int pt, int te_pt, const char*szName, FILE* fp) { init(pt, te_pt, szName, fp); }
    void init(int pt, int te_pt, const char* szName, FILE* fp) {
      m_offset = 0;
      m_baseTimestamp = 0;
      m_ts = 0 ;
      m_seq = 0 ;
      m_ssrc = 0;
      m_pt = pt ;
      m_te_pt = te_pt;
      m_numPackets = 0 ;
      m_payloadLength = 160 ;
      m_strName = szName;
      m_tsLastDtmf = 0;
      m_fp = fp;
      m_packetCounter = 0;
    }
    const string& getCodec(void) { return m_strCodecName; }
    void setCodec(const string& name) { m_strCodecName = name; }

    void setCodec(int pt, const string& codecName) {
      m_pt = pt;
      setCodec(codecName); 
    }

    u_int32 getPacketCounter(void) { return m_packetCounter; }
    void resetPacketCounter(void) { m_packetCounter = 0; }
    void incrementPacketCounter(void) { m_packetCounter++; }

    u_int32               m_offset;
    u_int32               m_baseTimestamp;
    u_int32               m_ts ;
    u_int16               m_seq ;
    u_int32               m_ssrc;
    int                   m_pt ;
    int                   m_te_pt;
    u_int32               m_tsLastDtmf ;
    u_int                 m_numPackets ;
    u_int                 m_payloadLength ;

    string                m_strName;
    string                m_strCodecName;

    deque<Dtmf>           m_dequeDtmf;

    FILE*                 m_fp;

    u_int32               m_packetCounter;

  private:
    RtpStream() {}

  } ;

  int rip() ;

  void processRtp(const struct pcap_pkthdr* pkthdr, const u_char* packet) ;

  const string& getCallerCodec(void) { return m_callerRtpStream.getCodec();}
  const string& getCalleeCodec(void) { return m_calleeRtpStream.getCodec();}
  int getCallerPt(void) { return m_callerRtpStream.m_pt;}
  int getCalleePt(void) { return m_calleeRtpStream.m_pt;}

  int getLastWriter(void) { return m_lastWrite;}
  void setLastWriter(int val) { m_lastWrite = val;}

private:

  bool discoverCodecs(void) const { return m_mapPt2Codec.size() > 0;}
  bool getCodecFromPt(int pt, string& name) const {
    mapPt2Codec::const_iterator it = m_mapPt2Codec.find(pt);
    if (m_mapPt2Codec.end() == it) return false ;
    name = it->second;
    return true;
  }

  pcap_t *                  m_pcap;

  bool                      m_ripped ;
  FILE*                     m_fpInput ;
  FILE*                     m_fpCallerOutput ;
  FILE*                     m_fpCalleeOutput ;
  u_int                     m_callerPort ;
  u_int                     m_calleePort ;
  u_int                     m_callerPt ;
  u_int                     m_calleePt ;
  u_int                     m_callerTePt ;
  u_int                     m_calleeTePt ;
  size_t                    m_ethHdrSize ;

  RtpStream                 m_callerRtpStream ;
  RtpStream                 m_calleeRtpStream ;

  int                       m_lastWrite;

  typedef boost::unordered_map<int, string> mapPt2Codec ;
  mapPt2Codec               m_mapPt2Codec;

} ;


#endif
