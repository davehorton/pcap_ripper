#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "rtp-ripper.hpp"

using namespace std ;

const int FILENO_IN         (0);
const int FILENO_OUT_CALLER (3);
const int FILENO_OUT_CALLEE (4);

namespace {
  void usage(int argc, char** argv) {

    cerr << endl;
    cerr << "This is a stream-based utility for ripping rtp packets from a pcap input stream into two output streams containing raw audio." << endl << endl;
    cerr << "Note: this program can NOT be run from the command line: it is intended to be spawned as a child process of a parent process that sets up the pipes that it will use." << endl << endl;
    cerr << "usage: " <<  argv[0] << " [options] filename" << endl ;
    cerr << endl;
    cerr << "options:" << endl ;
    cerr << "---caller-port        UDP port on which caller rtp traffic is received" << endl ;
    cerr << "---caller-pt          caller codec payload type" << endl ;
    cerr << "---caller-te-pt       caller telephony-event payload type" << endl ;
    cerr << "---callee-port        UDP port on which callee rtp traffic is received" << endl ;
    cerr << "---callee-pt          callee codec payload type" << endl ;
    cerr << "---callee-te-pt       caller telephony-event payload type" << endl ;
    cerr << "---codec              codec to be decoded; optional unless codec is OPUS" << endl ;
    cerr << "---codec-list         comma-separated list of possible codecs; e.g. 0:PCMU, 8:PCMA" << endl ;
    cerr << "---no-eth-hdr         if present, recording file does not have an ethernet header (optional: defaults to expecting an eth header to be present)" << endl ;
    cerr << endl ;
    exit(-1);
  }
}
int main(int argc, char** argv) {

  string targetDir, codec, codecList ;
  int raw = 0;
  int c ;
  u_int callerPort=0, calleePort=0, callerPt=UINT_MAX, calleePt=UINT_MAX, callerTePt=UINT_MAX,  calleeTePt=UINT_MAX;

  FILE* fpInput = fdopen(FILENO_IN, "rb");
  if (!fpInput) {
    cerr << "Error opening input pipe: " << strerror(errno) << " (" << errno << ")" << endl ;
    usage(argc, argv);
  }
  FILE* fpCallerOutput = fdopen(FILENO_OUT_CALLER, "wb");
  if (!fpCallerOutput) {
    cerr << "Error opening caller output pipe: " << strerror(errno) << " (" << errno << ")" << endl ;
    usage(argc, argv);
  }
  FILE* fpCalleeOutput = fdopen(FILENO_OUT_CALLEE, "wb");
  if (!fpCalleeOutput) {
    cerr << "Error opening callee output pipe: " << strerror(errno) << " (" << errno << ")" << endl ;
    fclose(fpCallerOutput);
    usage(argc, argv);
  }

  while (1)
  {
    static struct option long_options[] = {
      {"no-eth-hdr",    no_argument, &raw, 1},
      {"caller-port",    required_argument, 0, 'a'},
      {"callee-port",    required_argument, 0, 'b'},
      {"caller-pt",    required_argument, 0, 'x'},
      {"caller-te-pt",    required_argument, 0, 'd'},
      {"callee-pt",    required_argument, 0, 'y'},
      {"callee-te-pt",    required_argument, 0, 'e'},
      {"codec-list",    required_argument, 0, 'l'},
      {"codec",    required_argument, 0, 'c'},
      {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;
    
    c = getopt_long (argc, argv, "a:b:c:x:y:d:e:",
                     long_options, &option_index);
      
    /* Detect the end of the options. */
    if (c == -1)
      break;
    
    switch (c)
    {
      case 0:
        /* If this option set a flag, do nothing else now. */
        if (long_options[option_index].flag != 0)
            break;
        cout << "option " << long_options[option_index].name ;
        if (optarg)
            cout << " with arg " << optarg;
        cout << endl ;
        break;
                              
      case 'a':
        callerPort = boost::lexical_cast<int>(optarg);
        break;
      case 'b':
        calleePort = boost::lexical_cast<int>(optarg);
        break;
      case 'l':
        codecList = boost::to_upper_copy<std::string>(optarg);
        break;
      case 'x':
        callerPt = boost::lexical_cast<int>(optarg);
        break;
      case 'y':
        calleePt = boost::lexical_cast<int>(optarg);
        break;
      case 'd':
        callerTePt = boost::lexical_cast<int>(optarg);
        break;
      case 'e':
        calleeTePt = boost::lexical_cast<int>(optarg);
        break;
      case 'c':
        codec = boost::to_upper_copy<std::string>(optarg);
        break ;
      case '?':
          /* getopt_long already printed an error message. */
          break;
          
      default:
          abort ();
    }
  }
  /* Print any remaining command line arguments (not options). */
  if (optind < argc)
  {
      while (optind < argc)
          cout << argv[optind++] ;
  }

  if (!callerPort || !calleePort /* || UINT_MAX == callerPt || UINT_MAX == calleePt */) {
    usage(argc, argv);
  }

  try {
    int rc = 0;
    if (codecList.empty()) {
      RtpRipper ripper(raw, codec, callerPort, callerPt, calleePort, calleePt, callerTePt, calleeTePt, 
        fpInput, fpCallerOutput, fpCalleeOutput);      
      rc = ripper.rip() ;
    }
    else {
      RtpRipper ripper(raw, codecList, callerPort, calleePort, callerTePt, calleeTePt, 
        fpInput, fpCallerOutput, fpCalleeOutput);      
      rc = ripper.rip() ;
   }
  }
   catch(std::exception const& e)
    {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    exit(0);
}