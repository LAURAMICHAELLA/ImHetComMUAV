#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/external-sync-manager.h"
#include "ns3/mobility-module.h"
#include "ns3/object.h"
#include "ns3/ptr.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/evalvid-client-server-helper.h"


#include "ns3/timer.h"
#include "ns3/nstime.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/config.h"
#include "ns3/global-value.h"

#include "ns3/propagation-loss-model.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/rng-seed-manager.h"
#include "ns3/mobility-helper.h"
#include "ns3/wifi-net-device.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/packet-socket-client.h"
#include "ns3/packet-socket-server.h"
#include "ns3/ht-configuration.h"
#include "ns3/he-configuration.h"
//#include "ns3/wifi-standards.h"

#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/core-module.h"
#include "ns3/config-store-module.h"
#include "ns3/aodv-helper.h"
#include "ns3/olsr-helper.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"


#include <sstream>
#include <stdint.h>
#include <iomanip>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <sys/time.h>

#include "ns3/netanim-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/config-store-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipcs-classifier-record.h"
#include "ns3/service-flow.h"
#include "ns3/ipv4-global-routing-helper.h"

#include "ns3/seq-ts-header.h"
#include "ns3/wave-net-device.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/propagation-module.h"

#include "ns3/log.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/gnuplot.h"
#include "ns3/command-line.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/rng-seed-manager.h"

#define SIM_DST_PORT 12345

using namespace ns3;
using std::cout;
using std::endl;


uint32_t phyTxDropCount=0;
uint32_t phyRxDropCount=0;
uint32_t m_bytesTotal;
// uint32_t BytesReceivedWave;
// uint32_t BytesDropWave;
// uint32_t BytesReceivedWifi;
// uint32_t BytesDropWifi;
// double throughputWave;
// double throughputWifi;


// uint32_t vetBytesReceivedWave[10];
// uint32_t vetBytesReceivedWifi[10];
// double vetBytesDropWave[10];

// double vetBytesDropWifi[10];
// double vet_g_signalDbmAvgWave;
// double vet_g_noiseDbmAvgWave;
// double vet_g_SNRWave;
// double vet_g_signalDbmAvgWifi;
// double vet_g_noiseDbmAvgWifi;
// double vet_g_SNRWifi;

uint32_t packetsReceived; ///< total packets received by all nodes
uint32_t packetsReceived2; ///< total packets received by all nodes
uint32_t totalBytesReceived2=0;
uint32_t totalBytesReceived4=0;
uint32_t totalBytesReceived=0;
uint32_t bytesTotal=0;
double DropBytes=0;

uint32_t pktSize = 1472; //1500
std::ofstream rdTrace;
std::ofstream rdTraced;
uint32_t mbs = 0;
uint32_t totalBytesDropped = 0;
uint32_t totalBytestransmitted = 0;
//uint16_t port = 9;
//std::string CSVfileName = "interfaceManager2.csv";
char tmp_char [30] = "";

// PHY variables


uint32_t BytesReceivedWave;
uint32_t BytesDropWave;

uint32_t BytesReceivedWifi;
uint32_t BytesDropWifi;

uint32_t BytesReceivedAc;
uint32_t BytesDropAc;

uint32_t BytesReceivedAx_2_4;
uint32_t BytesDropAx_2_4;

uint32_t BytesReceivedAx_5;
uint32_t BytesDropAx_5;

double throughputWave [10];
double throughputWifi [10];
double throughputAc [10];

double throughputAx_2_4 [10];
double throughputAx_5 [10];



///Global variables of Interface Manager decision

//802.11p
uint32_t vetBytesReceivedWave[10];
uint32_t vetBytesDropWave[10];
double vet_g_signalDbmAvgWave;
double vet_g_SNRWave;
double vet_g_noiseDbmAvgWave;
double totalBytesReceivedSumWave;

// Settings 802.11p
uint16_t dport = 5001;

//802.11n

uint32_t vetBytesReceivedWifi[10];
uint32_t vetBytesDropWifi[10];
double vet_g_signalDbmAvgWifi;
double vet_g_noiseDbmAvgWifi;
double vet_g_SNRWifi;
double totalBytesReceivedSumWifi;

// Settings 802.11n
uint16_t wdport = 5004;


//802.11ac

uint32_t vetBytesReceivedAc[10];
uint32_t vetBytesDropAc[10];
double vet_g_signalDbmAvgAc[10];
double vet_g_noiseDbmAvgAc [10];
double vet_g_SNRAc [10];
double totalBytesReceivedSumAc;

// Settings 802.11ac

uint16_t acport = 8005;

// Settings 802.11ax 2_4

uint32_t vetBytesReceivedAx_2_4[10];
uint32_t vetBytesDropAx_2_4[10];
double vet_g_signalDbmAvgAx_2_4[10];
double vet_g_noiseDbmAvgAx_2_4 [10];
double vet_g_SNRAx_2_4 [10];
double totalBytesReceivedSumAx_2_4;


uint16_t axport2_4 = 9005; //2_4

// Settings 802.11ax 5

uint32_t vetBytesReceivedAx5[10];
uint32_t vetBytesDropAx5[10];
double vet_g_signalDbmAvgAx5[10];
double vet_g_noiseDbmAvgAx5 [10];
double vet_g_SNRAx5 [10];
double totalBytesReceivedSumAx5;

uint16_t axport5 = 10002; //5

//Evalvid server port

uint16_t port = 9;

// Log Files constructed by me
std::string CSVfileName = "interfaceManager2.csv";
std::string m_CSVfileName = "BytesReceivedWave.output.csv"; ///< CSV file name
std::string m_CSVfileName2 = "BytesReceivedWifi.output.csv"; ///< CSV file name
std::string m_CSVfileName3 = "CheckThroughput.output.csv"; ///< CSV file name
std::string m_CSVfileName4 = "CheckThroughputbyNode_Wave.output.csv"; ///< CSV file name
std::string m_CSVfileName4_1 = "CheckThroughputbyNode_Wifi.output.csv"; ///< CSV file name
std::string m_CSVfileName4_2 = "CheckThroughputbyNode_Ac.output.csv"; ///< CSV file name
std::string m_CSVfileName4_3 = "CheckThroughputbyNode_Ax2_4.output.csv"; ///< CSV file name
std::string m_CSVfileName4_4 = "CheckThroughputbyNode_Ax5.output.csv"; ///< CSV file name
std::string m_CSVfileName5 = "CheckSignalNoiseSNR.output.csv"; ///< CSV file name
std::string m_CSVfileName6 = "BytesReceivedAc.output.csv"; ///< CSV file name
std::string m_CSVfileName7 = "BytesReceivedAx_2_4.output.csv"; ///< CSV file name
std::string m_CSVfileName8 = "BytesReceivedAx_5.output.csv"; ///< CSV file name


std::ofstream out (m_CSVfileName.c_str (), std::ios::app);
std::ofstream out2 (m_CSVfileName2.c_str (), std::ios::app);
std::ofstream out3 (m_CSVfileName3.c_str (), std::ios::app);
std::ofstream out4 (m_CSVfileName4.c_str (), std::ios::app);
std::ofstream out4_1 (m_CSVfileName4_1.c_str (), std::ios::app);
std::ofstream out4_2 (m_CSVfileName4_2.c_str (), std::ios::app);
std::ofstream out4_3 (m_CSVfileName4_3.c_str (), std::ios::app);
std::ofstream out4_4 (m_CSVfileName4_4.c_str (), std::ios::app);
std::ofstream out5 (m_CSVfileName5.c_str (), std::ios::app);
std::ofstream out6 (m_CSVfileName6.c_str (), std::ios::app);
std::ofstream out7 (m_CSVfileName7.c_str (), std::ios::app);
std::ofstream out8 (m_CSVfileName8.c_str (), std::ios::app);






NS_LOG_COMPONENT_DEFINE ("InterfaceManager");


int64_t pktCount_n; //sinalização de pacotes

// Rotinas Gazebo
std::map<Ipv4Address, Ptr<Node>> ip_node_list;



Ipv4Address
GetAddressOfNode(Ptr<Node> node)
{
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1, 0);
  Ipv4Address addri = iaddr.GetLocal();
  return addri;
}

void ForwardMessage(uint32_t sender, int32_t receiver, const std::vector<uint8_t> &payload)
{
  Ptr<Packet> p = Create<Packet>(payload.data(), payload.size());
  Ptr<Node> nodeSender = NodeList::GetNode(sender);
  Ptr<Socket> sock = nodeSender->GetObject<Socket>();
  if (receiver < 0)
  {
    NodeList::GetNode(sender)->GetDevice(0)->Send(p, NodeList::GetNode(sender)->GetDevice(0)->GetBroadcast(), 0);
    //sock->SendTo(p, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), SIM_DST_PORT));
  }
  else
  {
    Ptr<Node> nodeReceiver = NodeList::GetNode(receiver);
    Ipv4Address dstaddr = GetAddressOfNode(nodeReceiver);
    sock->SendTo(p, 0, InetSocketAddress(dstaddr, SIM_DST_PORT));
  }
}

void
ProcessMessage(Ptr<Node> sender, const void* buffer, size_t size)
{
  /*
  Message protocol struct

                  BUFFER
  -------------------------------------
  |             ID_NODE (4)           |  S
  -------------------------------------  I
  |                                   |  Z
  |      PAYLOAD (LENGTH_MESSAGE)     |  E
  |                                   |
  -------------------------------------
  */

  int32_t nodeid;

  memcpy(&nodeid, (((char*)buffer)), sizeof(nodeid));
  std::vector<uint8_t> payload((const char*)buffer + 4, (const char*)buffer + size);

  Simulator::Schedule(MilliSeconds(1), &ForwardMessage, sender->GetId(), nodeid, payload);
}

void SocketReceive(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);
  packet->RemoveAllPacketTags();
  packet->RemoveAllByteTags();

  int32_t idfrom = ip_node_list[InetSocketAddress::ConvertFrom(from).GetIpv4()]->GetId();
  uint8_t buffer[packet->GetSize() + sizeof(idfrom)];
  memcpy(buffer, &idfrom, sizeof(idfrom));
  packet->CopyData(buffer + sizeof(idfrom), packet->GetSize());

  ExternalSyncManager::SendMessage(socket->GetNode(), buffer, packet->GetSize() + sizeof(idfrom));

}

//-------fim Rotinas Gazebo


void ResetDropCounters()
{
    //macTxDropCount = 0;
    phyTxDropCount = 0;
    phyRxDropCount = 0;
}

void ReceivePacket (Ptr<Socket> socket)
{
  while (socket->Recv ())
    {
      NS_LOG_UNCOND ("Received one packet!");
    }
}


void
ReceivedPacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}



static void GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize,
                             uint32_t pktCount, Time pktInterval )
{
  if (pktCount > 0)
    {
      pktCount_n = pktCount;
      socket->Send (Create<Packet> (pktSize));
      Simulator::Schedule (pktInterval, &GenerateTraffic,
                           socket, pktSize,pktCount - 1, pktInterval);
    }
  else
    {
      socket->Close ();
    }
}

// Global variables for use in callbacks.
double g_signalDbmAvg=0;
double g_noiseDbmAvg=0;
uint32_t g_samples=0;
double g_SNR=0;
int counterSamples=1;


void MonitorSniffRx (Ptr<const Packet> packet,
                     uint16_t channelFreqMhz,
                     WifiTxVector txVector,
                     MpduInfo aMpdu,
                     SignalNoiseDbm signalNoise)
{

                      Ptr<Packet> copy2 = packet->Copy ();
                      LlcSnapHeader ppp2;
                      Ipv4Header iph2;
                      copy2->RemoveHeader(ppp2);
                      copy2->RemoveHeader (iph2);
                       g_samples++;
                       g_signalDbmAvg += ((signalNoise.signal - g_signalDbmAvg) / g_samples);
                       g_noiseDbmAvg += ((signalNoise.noise - g_noiseDbmAvg) / g_samples);
                       g_SNR = g_signalDbmAvg/g_noiseDbmAvg;

                       std::cout << "Timer--->" << Simulator::Now().GetSeconds() << "," << "Frequency Mode:" << channelFreqMhz << "," << "Avg Signal (dBm): "  << g_signalDbmAvg << "," << " Avg Noise+Inf(dBm):" << g_noiseDbmAvg << "," << "SNR: " << g_SNR << "," << std::endl;



                       if (iph2.GetDestination()=="192.168.1.1" || iph2.GetDestination()=="192.168.1.2" || iph2.GetDestination()=="192.168.1.3" ||
                         iph2.GetDestination()=="192.168.1.4" || iph2.GetDestination()=="192.168.1.5" || iph2.GetDestination()=="192.168.1.6" ||
                         iph2.GetDestination()=="192.168.1.7" || iph2.GetDestination()=="192.168.1.8" || iph2.GetDestination()=="192.168.1.9" || iph2.GetDestination()=="192.168.1.10") {

                                           vet_g_signalDbmAvgWave= g_signalDbmAvg;
                                           vet_g_noiseDbmAvgWave= g_noiseDbmAvg;
                                           vet_g_SNRWave= g_SNR;

                       } else {
                                         vet_g_signalDbmAvgWave= 0;
                                         vet_g_noiseDbmAvgWave= 0;
                                         vet_g_SNRWave= 0;

                       }

                       if (iph2.GetDestination()=="10.1.1.1" || iph2.GetDestination()=="10.1.1.2" || iph2.GetDestination()=="10.1.1.3" ||
                         iph2.GetDestination()=="10.1.1.4" || iph2.GetDestination()=="10.1.1.5" || iph2.GetDestination()=="10.1.1.6" ||
                         iph2.GetDestination()=="10.1.1.7" || iph2.GetDestination()=="10.1.1.8" || iph2.GetDestination()=="10.1.1.9" || iph2.GetDestination()=="10.1.1.10") {

                                      vet_g_signalDbmAvgWifi= g_signalDbmAvg;
                                      vet_g_noiseDbmAvgWifi= g_noiseDbmAvg;
                                      vet_g_SNRWifi= g_SNR;
                      } else {

                                      vet_g_signalDbmAvgWifi= 0;
                                      vet_g_noiseDbmAvgWifi= 0;
                                      vet_g_SNRWifi= 0;
                      }




                       std::ofstream out5 (m_CSVfileName5.c_str (), std::ios::app);

                       out5 << (Simulator::Now ()).GetSeconds () << ","
                          << counterSamples << ","
                           << iph2.GetDestination() << ","
                           << channelFreqMhz << ","
                           << g_signalDbmAvg << ","
                           << g_noiseDbmAvg << ","
                           << g_SNR << ","

                        //    << mbsWave[i] << ","
                        //    << totalPhyTxBytesWave[i] << ","
                        // //   << totalPhyRxDropWave[i] << ","
                           // << DropBytesWave[i] << ","
                           //<< totalBytesReceivedSumWave <<
                            << std::endl;
                       out5.close ();
                       counterSamples++;
}


/*************************************************************** *
FUNÇÃO QUE CALCULA O PAYLOAD NO RECEPTOR *
***************************************************************/
void PhyRxOkTrace (std::string context, Ptr<const Packet> packet, double snr,WifiMode mode, enum WifiPreamble preamble)
{
  // Received Packets
  Ptr<Packet> m_currentPacket;
  WifiMacHeader hdr;
  m_currentPacket = packet->Copy();
  m_currentPacket->RemoveHeader (hdr);
  if ((hdr.IsData())) {
    m_bytesTotal+= m_currentPacket->GetSize ();
  }

}

/*************************************************************** *
FUNÇÃO QUE CALCULA A QUANTIDADE DE BYTES RECEBIDO PELA REDE *
***************************************************************/
void
SocketRecvStats (std::string context, Ptr<const Packet> p, const Address &addr)
{
      totalBytesReceived2 += p->GetSize ();
      std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Received_1 : " << totalBytesReceived2 << std::endl;
}


void DroppedPacket(std::string context, Ptr <const Packet> p)
{

    std::cout << " TX p: " << *p << std::endl;


    totalBytesDropped += p->GetSize();
  //  totalBytesDropped=0;


    std::cout << "Total Bytes Dropped ="  << totalBytesDropped << "\n" << totalBytesReceived << std::endl;


    //  totalBytesDropped=0;
    // rdTraced << totalBytesDropped <<"\n"<<totalBytesReceived ;


    //NS_LOG_UNCOND ("Total Bytes Dropped =" << totalBytesDropped);
    //cout<< totalBytesDropped<<endl;
//    totalBytesDropped=0;
//    rdTraced << totalBytesDropped <<"\n"<<totalBytesReceived ;

}

/*************************************************************** *
CLASSE QUE CAPTURA PARAMETROS DE REDE
***************************************************************/

class WifiPhyStats : public Object
{
public:
  /**
   * \brief Gets the class TypeId
   * \return the class TypeId
   */
  static TypeId GetTypeId (void);

  /**
   * \brief Constructor
   * \return none
   */
  WifiPhyStats ();

  /**
   * \brief Destructor
   * \return none
   */
  virtual ~WifiPhyStats ();

  /**
   * \brief Returns the number of bytes that have been transmitted
   * (this includes MAC/PHY overhead)
   * \return the number of bytes transmitted
   */
  uint32_t GetTxBytes ();

  /**
   * \brief Callback signiture for Phy/Tx trace
   * \param context this object
   * \param packet packet transmitted

   * \param mode wifi mode
   * \param preamble wifi preamble
   * \param txPower transmission power
   * \return none
   */
  void PhyTxTrace (std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower);

  /**
   * \brief Callback signiture for Phy/TxDrop
   * \param context this object
   * \param packet the tx packet being dropped
   * \return none
   */
  void PhyTxDrop (std::string context, Ptr<const Packet> packet);

  /**
   * \brief Callback signiture for Phy/RxDrop
   * \param context this object
   * \param packet the rx packet being dropped
   * \return none
   */
  void PhyRxDrop (std::string context, Ptr<const Packet> packet);

private:
  uint32_t m_phyTxPkts; ///< phy transmit packets
  uint32_t m_phyTxBytes; ///< phy transmit bytes
};

NS_OBJECT_ENSURE_REGISTERED (WifiPhyStats);

TypeId
WifiPhyStats::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::WifiPhyStats")
    .SetParent<Object> ()
    .AddConstructor<WifiPhyStats> ();
  return tid;
}

WifiPhyStats::WifiPhyStats ()
  : m_phyTxPkts (0),
    m_phyTxBytes (0)
{
}

WifiPhyStats::~WifiPhyStats ()
{
}

void
WifiPhyStats::PhyTxTrace (std::string context, Ptr<const Packet> packet, WifiMode mode, WifiPreamble preamble, uint8_t txPower)
{
  NS_LOG_FUNCTION (this << context << packet << "PHYTX mode=" << mode );
  ++m_phyTxPkts;
  uint32_t pktSize = packet->GetSize ();
  m_phyTxBytes += pktSize;

  NS_LOG_UNCOND ("Received PHY size=" << pktSize);
}

void
WifiPhyStats::PhyTxDrop (std::string context, Ptr<const Packet> packet)
{
  NS_LOG_UNCOND ("PHY Tx Drop");
  phyTxDropCount++;
}

void
WifiPhyStats::PhyRxDrop (std::string context, Ptr<const Packet> packet)
{
  NS_LOG_UNCOND ("PHY Rx Drop");
  phyRxDropCount++;

}

uint32_t
WifiPhyStats::GetTxBytes ()
{
  return m_phyTxBytes;
}

/*************************************************************** *
DropBytes, ReceivesPacket e throughput (minha implementação)
***************************************************************/

void ReceivesPacket(std::string context, Ptr <const Packet> p)
 {
	  //char c= context.at(24);
 	  //int index= c - '0';
 	  //totalBytesReceived[index] += p->GetSize();

   		totalBytesReceived += p->GetSize();
  // 	  std::cout<< "Received (Minha impl) : " << totalBytesReceived << std::endl;
}



void CalculatePhyRxDrop (Ptr<WifiPhyStats> m_wifiPhyStats)
 {
   double totalPhyTxBytes = m_wifiPhyStats->GetTxBytes ();
   double totalPhyRxDrop = m_bytesTotal;
   DropBytes = totalPhyTxBytes - totalPhyRxDrop;
  // std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "\tBytes TX=" << totalPhyTxBytes << "\tBytes RX Drop=" << totalPhyRxDrop << "\tDrop Bytes (Sended-Received):" << DropBytes<< std::endl;
   Simulator::Schedule (MilliSeconds(100), &CalculatePhyRxDrop, m_wifiPhyStats);
}

//-- Callback function is called whenever a packet is received successfully.
//-- This function cumulatively add the size of data packet to totalBytesReceived counter.
//---------------------------------------------------------------------------------------


int cont=0;

void vetorBytesReceived (std::string context, Ptr <const Packet> p)
{
    int cont=0;
    Ptr<Packet> copy = p->Copy ();
    LlcSnapHeader ppp;
    Ipv4Header iph;
    std::string access_class;
    copy->RemoveHeader(ppp);
    copy->RemoveHeader (iph);



  //  PhyRxDrop (context, p);



  if (iph.GetDestination()=="192.168.1.1" || iph.GetDestination()=="192.168.1.2" || iph.GetDestination()=="192.168.1.3" ||
    iph.GetDestination()=="192.168.1.4" || iph.GetDestination()=="192.168.1.5" || iph.GetDestination()=="192.168.1.6" ||
    iph.GetDestination()=="192.168.1.7" || iph.GetDestination()=="192.168.1.8" || iph.GetDestination()=="192.168.1.9" || iph.GetDestination()=="192.168.1.10") {

        // Buffer
         for (uint32_t i=0; i<10; i++){
             vetBytesReceivedWave[i] =p->GetSize();
             vetBytesDropWave[i] = DropBytes;

             //totalBytesReceivedSumWave =totalPhyTxBytesWave[i]+totalBytesReceivedSumWave;
             std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wave:" << "[" << i << "]:" << vetBytesReceivedWave[i] << "Bytes Dropped Wave:" << "[" << i << "]:" << vetBytesDropWave[i] << "," << std::endl;

             //Writing log
             BytesReceivedWave = vetBytesReceivedWave[i] + BytesReceivedWave;
             BytesDropWave = vetBytesDropWave[i] + BytesDropWave;
          }




      //rdTrace << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wave:" << "[" << i << "]:" << BytesReceivedWave[i];


            std::ofstream out (m_CSVfileName.c_str (), std::ios::app);
            out << (Simulator::Now ()).GetSeconds () << ","
               << cont << ","
                << iph.GetSource() << ","
                << iph.GetDestination() << ","
                << BytesReceivedWave << ","
                << BytesDropWave <<

             //    << mbsWave[i] << ","
             //    << totalPhyTxBytesWave[i] << ","
             // //   << totalPhyRxDropWave[i] << ","
                // << DropBytesWave[i] << ","
                //<< totalBytesReceivedSumWave <<
                 std::endl;
            out.close ();
    }


    if (iph.GetDestination()=="10.1.1.1" || iph.GetDestination()=="10.1.1.2" || iph.GetDestination()=="10.1.1.3" ||
       iph.GetDestination()=="10.1.1.4" || iph.GetDestination()=="10.1.1.5" || iph.GetDestination()=="10.1.1.6" ||
       iph.GetDestination()=="10.1.1.7" || iph.GetDestination()=="10.1.1.8" || iph.GetDestination()=="10.1.1.9" || iph.GetDestination()=="10.1.1.10") {

           for (uint32_t i=0; i<10;i++){
               vetBytesReceivedWifi[i] =p->GetSize();
               vetBytesDropWifi[i] = DropBytes;


             //  totalBytesReceivedSumWifi =totalPhyTxBytesWifi[i]+totalBytesReceivedSumWifi;

               //rdTraced << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wifi:" << "[" << i << "]:" << BytesReceivedWave[i];
               std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wifi:" << "[" << i << "]:" << vetBytesReceivedWifi[i] << "Bytes Dropped Wifi:" << "[" << i << "]:" << vetBytesDropWifi[i] << std::endl;

               //Writing log
               BytesReceivedWifi = vetBytesReceivedWifi[i] + BytesReceivedWifi;
               BytesDropWifi = vetBytesDropWifi[i] + BytesDropWifi;
          }




               std::ofstream out2 (m_CSVfileName2.c_str (), std::ios::app);
               out2 << (Simulator::Now ()).GetSeconds () << ","
                    << cont << ","
                    << iph.GetSource() << ","
                    << iph.GetDestination() << ","
                    << BytesReceivedWifi << ","
                    << BytesDropWifi <<

                 //   << mbsWifi[i] << ","
                 //   << totalPhyTxBytesWifi[i] << ","
                 // //  << totalPhyRxDropWifi[i] << ","
                 //   << DropBytesWifi[i] << ","
                   // << totalBytesReceivedSumWifi <<
                    std::endl;
               out2.close ();
    }

    if (iph.GetDestination()=="120.1.1.1" || iph.GetDestination()=="120.1.1.2" || iph.GetDestination()=="120.1.1.3" ||
      iph.GetDestination()=="120.1.1.4" || iph.GetDestination()=="120.1.1.5" || iph.GetDestination()=="120.1.1.6" ||
      iph.GetDestination()=="120.1.1.7" || iph.GetDestination()=="120.1.1.8" || iph.GetDestination()=="120.1.1.9" || iph.GetDestination()=="120.1.1.10") {


            for (uint32_t i=0; i<10;i++){
                vetBytesReceivedAc[i] =p->GetSize();
                vetBytesDropAc[i] = DropBytes;


              //  totalBytesReceivedSumWifi =totalPhyTxBytesWifi[i]+totalBytesReceivedSumWifi;

                //rdTraced << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wifi:" << "[" << i << "]:" << BytesReceivedWave[i];
                std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Ac:" << "[" << i << "]:" << vetBytesReceivedAc[i] << "Bytes Dropped Ac:" << "[" << i << "]:" << vetBytesDropAc[i] << std::endl;



               //Writing log
               BytesReceivedAc = vetBytesReceivedAc[i] + BytesReceivedAc;
               BytesDropAc = vetBytesDropAc[i] + BytesDropAc;
              }

                std::ofstream out6 (m_CSVfileName6.c_str (), std::ios::app);
                out6 << (Simulator::Now ()).GetSeconds () << ","
                     << cont << ","
                     << iph.GetSource() << ","
                     << iph.GetDestination() << ","
                     << BytesReceivedAc << ","
                     << BytesDropAc <<

                  //   << mbsWifi[i] << ","
                  //   << totalPhyTxBytesWifi[i] << ","
                  // //  << totalPhyRxDropWifi[i] << ","
                  //   << DropBytesWifi[i] << ","
                    // << totalBytesReceivedSumWifi <<
                     std::endl;
                out6.close ();

    }

    if (iph.GetDestination()=="160.1.1.1" || iph.GetDestination()=="160.1.1.2" || iph.GetDestination()=="160.1.1.3" ||
      iph.GetDestination()=="160.1.1.4" || iph.GetDestination()=="160.1.1.5" || iph.GetDestination()=="160.1.1.6" ||
      iph.GetDestination()=="160.1.1.7" || iph.GetDestination()=="160.1.1.8" || iph.GetDestination()=="160.1.1.9" || iph.GetDestination()=="160.1.1.10") {


            for (uint32_t i=0; i<10;i++){
                vetBytesReceivedAx_2_4[i] =p->GetSize();
                vetBytesDropAx_2_4[i] = DropBytes;


              //  totalBytesReceivedSumWifi =totalPhyTxBytesWifi[i]+totalBytesReceivedSumWifi;

                //rdTraced << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wifi:" << "[" << i << "]:" << BytesReceivedWave[i];
                std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Ax 2.4GHz:" << "[" << i << "]:" << vetBytesReceivedAx_2_4[i] << "Bytes Dropped Ax 2.4GHz:" << "[" << i << "]:" << vetBytesDropAx_2_4[i] << std::endl;



               //Writing log
               BytesReceivedAx_2_4 = vetBytesReceivedAx_2_4[i] + BytesReceivedAx_2_4;
               BytesDropAx_2_4 = vetBytesDropAx_2_4[i] + BytesDropAx_2_4;
             }


                std::ofstream out7 (m_CSVfileName7.c_str (), std::ios::app);
                out7 << (Simulator::Now ()).GetSeconds () << ","
                     << cont << ","
                     << iph.GetSource() << ","
                     << iph.GetDestination() << ","
                     << BytesReceivedAx_2_4 << ","
                     << BytesDropAx_2_4 <<

                  //   << mbsWifi[i] << ","
                  //   << totalPhyTxBytesWifi[i] << ","
                  // //  << totalPhyRxDropWifi[i] << ","
                  //   << DropBytesWifi[i] << ","
                    // << totalBytesReceivedSumWifi <<
                     std::endl;
                out7.close ();

    }

    if (iph.GetDestination()=="140.1.1.1" || iph.GetDestination()=="140.1.1.2" || iph.GetDestination()=="140.1.1.3" ||
      iph.GetDestination()=="140.1.1.4" || iph.GetDestination()=="140.1.1.5" || iph.GetDestination()=="140.1.1.6" ||
      iph.GetDestination()=="140.1.1.7" || iph.GetDestination()=="140.1.1.8" || iph.GetDestination()=="140.1.1.9" || iph.GetDestination()=="140.1.1.10") {


            for (uint32_t i=0; i<10;i++){
                vetBytesReceivedAx5[i] =p->GetSize();
                vetBytesDropAx5[i] = DropBytes;


              //  totalBytesReceivedSumWifi =totalPhyTxBytesWifi[i]+totalBytesReceivedSumWifi;

                //rdTraced << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Wifi:" << "[" << i << "]:" << BytesReceivedWave[i];
                std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Ax 5GHz:" << "[" << i << "]:" << vetBytesReceivedAx5[i] << "Bytes Dropped Ax 5GHz:" << "[" << i << "]:" << vetBytesDropAx5[i] << std::endl;



               //Writing log
               BytesReceivedAx_5 = vetBytesReceivedAx5[i] + BytesReceivedAx_5;
               BytesDropAx_5 = vetBytesDropAx5[i] + BytesDropAx_5;

              }

                std::ofstream out8 (m_CSVfileName8.c_str (), std::ios::app);
                out8 << (Simulator::Now ()).GetSeconds () << ","
                     << cont << ","
                     << iph.GetSource() << ","
                     << iph.GetDestination() << ","
                     << BytesReceivedAx_5 << ","
                     << BytesDropAx_5 <<

                  //   << mbsWifi[i] << ","
                  //   << totalPhyTxBytesWifi[i] << ","
                  // //  << totalPhyRxDropWifi[i] << ","
                  //   << DropBytesWifi[i] << ","
                    // << totalBytesReceivedSumWifi <<
                     std::endl;
                out8.close ();

                }
        cont++;
        Simulator::Schedule (Seconds (0.1), &vetorBytesReceived, context, p);

}


void
CheckThroughput (Ptr<WifiPhyStats> m_wifiPhyStats)
{


  double totalPhyTxBytes = m_wifiPhyStats->GetTxBytes ();
  double mbs = (m_bytesTotal * 8.0) / 1000000; // 1Mb
  double qtdPackt = packetsReceived;
  m_bytesTotal = 0;
  packetsReceived=0;

  totalBytesReceived =totalPhyTxBytes+totalBytesReceived;


  std::ofstream out3 (m_CSVfileName3.c_str (), std::ios::app);

  out3 << (Simulator::Now ()).GetSeconds () << "," << mbs << "," << "Mbps" << "," << qtdPackt << "," << totalBytesReceived << "," << "Mb" << "" << std::endl;

  out3.close ();
//  packetsReceived = 0;

  Simulator::Schedule (Seconds (0.1), &CheckThroughput, m_wifiPhyStats);
}

void
CheckThroughputbyNode (Ptr<WifiPhyStats> m_wifiPhyStats, Ptr<Node> node)
{
  totalBytesReceived4=0;
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  Ipv4Address addr = ipv4->GetAddress (1, 0).GetLocal ();
  Ipv4Address addr2 = ipv4->GetAddress (2, 0).GetLocal ();
  Ipv4Address addr3 = ipv4->GetAddress (3, 0).GetLocal ();
  Ipv4Address addr4 = ipv4->GetAddress (4, 0).GetLocal ();
  Ipv4Address addr5 = ipv4->GetAddress (5, 0).GetLocal ();

//  double totalPhyTxBytes2 = m_wifiPhyStats->GetTxBytes ();
  double mbs2 = (m_bytesTotal * 8.0) / 1000000;
  m_bytesTotal = 0;



  std::ofstream out4 (m_CSVfileName4.c_str (), std::ios::app);
  std::ofstream out4_1 (m_CSVfileName4_1.c_str (), std::ios::app);
  std::ofstream out4_2 (m_CSVfileName4_2.c_str (), std::ios::app);
  std::ofstream out4_3 (m_CSVfileName4_3.c_str (), std::ios::app);
  std::ofstream out4_4 (m_CSVfileName4_4.c_str (), std::ios::app);

  if (addr=="10.1.1.1" || addr=="10.1.1.2" || addr=="10.1.1.3" ||
    addr=="10.1.1.4" || addr=="10.1.1.5" || addr=="10.1.1.6" ||
    addr=="10.1.1.7" || addr=="10.1.1.8" || addr=="10.1.1.9" || addr=="10.1.1.10") {

      for (uint32_t i=0; i<10;i++){
        throughputWifi [i] = mbs2;
        totalBytesReceivedSumWifi = throughputWifi [i] + totalBytesReceivedSumWifi;
      }


      out4_1 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumWifi << "," << "Mb" << "," << "Ip:" << "," << addr << "," << "Wifi" << "" << std::endl;

  //    totalBytesReceived4=0;

   }

   if (addr2=="192.168.1.1" || addr2=="192.168.1.2" || addr2=="192.168.1.3" ||
       addr2=="192.168.1.4" || addr2=="192.168.1.5" || addr2=="192.168.1.6" ||
       addr2=="192.168.1.7" || addr2=="192.168.1.8" || addr2=="192.168.1.9" || addr2=="192.168.1.10") {

     for (uint32_t i=0; i<10;i++){
       throughputWave[i] = mbs2;
      totalBytesReceivedSumWave = totalBytesReceivedSumWave + throughputWave[i];
     }

   out4 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumWave << "," << "Mb" << "," << "Ip:" << "," << addr2 << "," << "Wave" << "" << std::endl;

      }

   if (addr3=="120.1.1.1" || addr3=="120.1.1.2" || addr3=="120.1.1.3" ||
     addr3=="120.1.1.4" || addr3=="120.1.1.5" || addr3=="120.1.1.6" ||
     addr3=="120.1.1.7" || addr3=="120.1.1.8" || addr3=="120.1.1.9" || addr3=="120.1.1.10") {

       for (uint32_t i=0; i<10;i++){
         throughputAc [i] = mbs2;
         totalBytesReceivedSumAc = throughputAc [i] + totalBytesReceivedSumAc;
       }


       out4_2 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumAc << "," << "Mb" << "," << "Ip:" << "," << addr3 << "," << "Ac" << "" << std::endl;

     }

   if (addr4=="160.1.1.1" || addr4=="160.1.1.2" || addr4=="160.1.1.3" ||
     addr4=="160.1.1.4" || addr4=="160.1.1.5" || addr4=="160.1.1.6" ||
     addr4=="160.1.1.7" || addr4=="160.1.1.8" || addr4=="160.1.1.9" || addr4=="160.1.1.10") {

       for (uint32_t i=0; i<10;i++){
         throughputAx_2_4 [i] = mbs2;
         totalBytesReceivedSumAx_2_4 = throughputAx_2_4 [i] + totalBytesReceivedSumAx_2_4;
       }


       out4_3 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumAx_2_4 << "," << "Mb" << "," << "Ip:" << "," << addr4 << "," << "Ax 2.4GHz" << "" << std::endl;
     }

     if (addr4=="140.1.1.1" || addr4=="140.1.1.2" || addr4=="140.1.1.3" ||
       addr4=="140.1.1.4" || addr4=="140.1.1.5" || addr4=="140.1.1.6" ||
       addr4=="140.1.1.7" || addr4=="140.1.1.8" || addr4=="140.1.1.9" || addr4=="140.1.1.10") {

         for (uint32_t i=0; i<10;i++){
           throughputAx_5 [i] = mbs2;
           totalBytesReceivedSumAx5 = throughputAx_5 [i] + totalBytesReceivedSumAx5;
         }


         out4_4 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumAx5 << "," << "Mb" << "," << "Ip:" << "," << addr5 << "," << "Ax 5GHz" << "" << std::endl;
       }



  out4.close();
  out4_1.close();
  out4_2.close();
  out4_3.close();
  out4_4.close();

//  packetsReceived = 0;
//  totalPhyTxBytes2 = 0;
  Simulator::Schedule (Seconds (0.1), &CheckThroughputbyNode, m_wifiPhyStats, node);
}




static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();
  std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << " " << socket->GetNode ()->GetId () << std::endl;


  if (InetSocketAddress::IsMatchingType (senderAddress))
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress);
      oss << " received one packet from " << addr.GetIpv4 ();
      std::cout << " received one packet from " << addr.GetIpv4 () << std::endl;

    }
  else
    {
      oss << " received one packet!";
      std::cout << " received one packet!" << std::endl;

    }
  return oss.str ();
}

void ReceivePacket2 (Ptr<Socket> socket)
{
    Ptr<Packet> packet;
	  Address senderAddress;
	  socket->SetRecvPktInfo(true);
	  while ((packet = socket->RecvFrom (senderAddress)))
	    {
	      m_bytesTotal += packet->GetSize ();
	      packetsReceived = packetsReceived+1;
	      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
	    }
}


Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node)
{

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr <Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&ReceivePacket2));
  sink->SetRecvPktInfo(true);
  return sink;
}


/*************************************************************** *
Rotinas de Troca de Interface
***************************************************************/



void TearDownLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB)
{
  std::cout << "Setting down Remote Host -> Ue 1" << std::endl;

  std::cout << "source " << nodeA->GetObject<Ipv4>()->GetAddress(interfaceA,0).GetLocal();
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceA,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetDown (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetDown (interfaceA);
}

void TearUpLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB, std::string phyMode2, int j)
{
  std::cout << "Setting UP Remote Host -> Ue "<< j << std::endl;

  std::cout << "source " << nodeA->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal();
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetUp (interfaceB);
  nodeB->GetObject<Ipv4> ()->SetUp (interfaceB);

  //configuration of modulation of this interface
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                  StringValue (phyMode2));
}

void reconfigureUdpClient(UdpClientHelper srcNode, Ptr<Node> dstNode, uint16_t dport){

  std::cout << "Changing Nodos Source app destination" << std::endl;
  Ptr<Ipv4> ipv4 = dstNode->GetObject<Ipv4>();
  std::cout << "Got dst node ipv4 object" << std::endl;
  Ipv4Address ip = ipv4->GetAddress(2,0).GetLocal();
  std::cout << "Destination app Address :: " << ip << std::endl;

  srcNode.SetAttribute("RemotePort", UintegerValue(dport));
  std::cout << "Port Set" << std::endl;
  srcNode.SetAttribute("RemoteAddress", AddressValue(ip));
//  udp->SetRemote(ip, dport);

  //Read and check new destination ip and port values here

  std::cout << "Dest ip/port set in udp client app" << "\nPort:" << dport << "\tIp:" << ip << std::endl;
}

void GetTos (InetSocketAddress sink, Ipv4Address addr, uint32_t portNumber){


          uint8_t tos=sink.GetTos();
          string type;


          switch (tos){
                  case 0x70:
                      type = "AC_BE";
                      break;
                  case 0x28:
                      type = "AC_BK";
                      break;
                  case 0xb8:
                      type = "AC_VI";
                      break;
                  case 0xc0:
                      type = "AC_VO";
                      break;
                  case 0:
                      type = "AC_UNDEF";
                      break;
                      }

          std::cout << "Now:" << Simulator::Now ().GetSeconds () << ", Stablishment with sink COMM with Tos: "<< type << "---sink--- "<< addr << "---port--- " << portNumber << std::endl;



          Simulator::Schedule (MilliSeconds (100), &GetTos, sink, addr, portNumber);
                  }






void experiment(int &numberOfUEs, const std::string phyMode1, const std::string phyMode2, bool verbose, double duration, Ptr<WifiPhyStats> m_wifiPhyStats, int m_mobility, double m_txp, uint32_t m_protocol, int m_numberOfInterfaces)
{

    // 0.Some settings

//    int nodeSpeed = 20; //in m/s UAVs speed
//    int nodePause = 0; //in s UAVs pause

  //  double interPacketInterval = 100;

    std::string m_protocolName; ///< protocol name
    std::string m_mobilityNameSetting; ///< number of Intefaces setting





    // 1. Create nodes
    NodeContainer ueNode;
    ueNode.Create (numberOfUEs);

    std::cout << "Node Containers created, for " << numberOfUEs << "nodes clients!" << std::endl;

    std::cout << "Configuring Routing Protocols!" << std::endl;

    // Routing Protocols
     AodvHelper aodv;
     OlsrHelper olsr;
     DsdvHelper dsdv;
//     DsrHelper dsr;
//     DsrMainHelper dsrMain;
     Ipv4ListRoutingHelper list;
     InternetStackHelper internet;

     Ipv4StaticRoutingHelper staticRouting;

     Ptr<OutputStreamWrapper> routingStreamStart = Create<OutputStreamWrapper> ("routes_start.routes", std::ios::out);

     Ptr<OutputStreamWrapper> routingStreamEnd = Create<OutputStreamWrapper> ("routes_end.routes", std::ios::out);


     // Time rtt = Time (5.0);
     // AsciiTraceHelper ascii;
     // Ptr<OutputStreamWrapper> rtw = ascii.CreateFileStream ("routing_table");

      switch (m_protocol)
       {
       case 0:
         m_protocolName = "NONE";
         break;
       case 1:
           list.Add (staticRouting, 0);
           list.Add (olsr, 10);
           olsr.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
           olsr.PrintRoutingTableAllAt (Seconds (duration), routingStreamEnd);
           m_protocolName = "OLSR";
          break;
       case 2:
           list.Add (aodv, 10);
           aodv.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
           aodv.PrintRoutingTableAllAt (Seconds (duration), routingStreamEnd);
           m_protocolName = "AODV";
         break;
       case 3:
           list.Add (dsdv, 10);
           dsdv.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
           dsdv.PrintRoutingTableAllAt (Seconds (duration), routingStreamEnd);
           m_protocolName = "DSDV";
         break;
       default:
         NS_FATAL_ERROR ("No such protocol:" << m_protocol);
         break;
       }

       internet.SetRoutingHelper (list);
       internet.Install (ueNode);




       NS_LOG_UNCOND ("Routing Setup for " << m_protocolName);


      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");






    // Installing internet stack
  //   InternetStackHelper internet;
  //   //  AodvHelper aodv;
  //     //internet.Install(apNode);
  // //    internet.SetRoutingHelper (aodv);
  //   internet.Install(ueNode);

    // // 3. Create propagation loss matrix
    // Ptr<MatrixPropagationLossModel> lossModel = CreateObject<MatrixPropagationLossModel> ();
    // lossModel->SetDefaultLoss (200); // set default loss to 200 dB (no link)
    // for (size_t i = 0; i < numberOfUEs; ++i)
    // {
    //     lossModel->SetLoss (ueNode.Get (i)-> GetObject<MobilityModel>(), ueNode.Get (i+1)->GetObject<MobilityModel>(), 50); // set symmetric loss i <-> i+1 to 50 dB
    // }

    // 4. Create & setup wifi channel

    // 5. Install PHY and MAC Layer of IEEE 802.11n 5GHz

    Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();
      YansWifiPhyHelper wifiPhy2 =  YansWifiPhyHelper::Default ();

      QosWaveMacHelper wifi80211pMac = QosWaveMacHelper::Default ();

      YansWifiChannelHelper channelWave;
      channelWave.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
      channelWave.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5.9e9));
      channelWave.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");
      wifiPhy2.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);
      Ptr<YansWifiChannel> channel2 = channelWave.Create ();
      wifiPhy2.SetChannel (channel2);



      // wifiPhy2.Set("ChannelNumber", UintegerValue(172));
      //
      // // wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
      // //                                     "DataMode",StringValue (phyMode2),
      // //                                     "ControlMode",StringValue (phyMode2));
      //
      // wifiPhy2.Set ("TxPowerStart",DoubleValue (m_txp));
      // wifiPhy2.Set ("TxPowerEnd", DoubleValue (m_txp));


      NetDeviceContainer waveDevices = wifi80211p.Install (wifiPhy2, wifi80211pMac, ueNode);

      wifiPhy2.EnablePcap ("WAVE_80211p_5_9GHZ", waveDevices);






//Wifi Interface
    AsciiTraceHelper ascii;

    Ipv4AddressHelper address;




    NS_LOG_INFO ("Assign IP WiFi Addresses.");
    address.SetBase ("10.1.1.0", "255.255.255.0");


    Ipv4InterfaceContainer interface;
    interface = address.Assign(waveDevices);



    if (verbose) {
//              wifi.EnableLogComponents ();  // Turn on all Wifi 2.4
              wifi80211p.EnableLogComponents ();  // Turn on all Wave
    //          wifi2.EnableLogComponents ();  // Turn on all Ac 5.0 logging
      //        wifi3.EnableLogComponents ();  // Turn on all Ax 2.4
          //    wifi4.EnableLogComponents ();  // Turn on all Ax 5.0
          }

    //      wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("PacketTxWiFi_intMan.tr"));
          wifiPhy2.EnableAsciiAll (ascii.CreateFileStream ("PacketTxWave_intMan.tr"));
      //    wifiPhy3.EnableAsciiAll (ascii2.CreateFileStream ("PacketTxAc_intMan.tr"));
      //    wifiPhy4.EnableAsciiAll (ascii2.CreateFileStream ("PacketTxAx_2_4_intMan.tr"));
      //    wifiPhy5.EnableAsciiAll (ascii.CreateFileStream ("PacketTxAx_5_intMan.tr"));



    // Tracing
    wifiPhy2.EnablePcap ("wave", waveDevices);



      //only wifi */
       Ptr<Ipv4> ip_wireless[numberOfUEs];
       for (int i = 0; i < numberOfUEs; i++)
       {
           ip_wireless[i] = ueNode.Get(i)->GetObject<Ipv4> ();
       }

       //process of creating of sockets -- for conection with Gazebo

       for (int i = 0; i < numberOfUEs; i++)
         {
           // protocol == 0 means no routing data, WAVE BSM only
           // so do not set up sink

           //
           // Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (i), tid);
           // InetSocketAddress local = InetSocketAddress (interface.GetAddress (i), 80);
           // recvSink->Bind (local);
           // recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));

           ExternalSyncManager::RegisterNode(ueNode.Get(i), MakeCallback(&ProcessMessage));
           Ptr<Socket> srcSocket = Socket::CreateSocket(ueNode.Get(i), TypeId::LookupByName("ns3::UdpSocketFactory"));
           srcSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), SIM_DST_PORT));
           srcSocket->SetRecvCallback(MakeCallback(&SocketReceive));
           srcSocket->SetRecvCallback (MakeCallback (&ReceivePacket));
           srcSocket->SetRecvCallback (MakeCallback (&ReceivePacket2));
           srcSocket->SetAllowBroadcast(true);
           //srcSocket->BindToNetDevice(nodes.Get(i)->GetDevice(1));
           ueNode.Get(i)->AggregateObject(srcSocket);
           ip_node_list.emplace(interface.GetAddress(i), ueNode.Get(i));
           std::cerr << "IP of NODE #" << i << " is " << interface.GetAddress(i) << std::endl;
         }

         std::cout << "Wifi installed!" << std::endl;

         // 2. Place nodes

         if (m_mobility==1){
                   std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet3/mobility.tcl";
                   m_mobilityNameSetting = "Experiment of 3 uavs (mobility nodos) in a 307m of trajectory";

                   // Create Ns2MobilityHelper with the specified trace log file as parameter
                   Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
                   ns2.Install (); // configure movements for each node, while reading trace file

                   NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);

                 } else if (m_mobility==2) {

                       std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet5/mobility.tcl";
                       m_mobilityNameSetting = "Experiment of 5 uavs (mobility nodos) in a area";

                         // Create Ns2MobilityHelper with the specified trace log file as parameter
                         Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
                         ns2.Install (); // configure movements for each node, while reading trace file

                         NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);


                       } else if (m_mobility==3) {

                               std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet8/mobility.tcl";
                               m_mobilityNameSetting = "Experiment of 8 uavs (mobility nodos) in a area";

                                 // Create Ns2MobilityHelper with the specified trace log file as parameter
                                 Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
                                 ns2.Install (); // configure movements for each node, while reading trace file

                                 NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);


                                 } else if (m_mobility==3) {
                                            m_mobilityNameSetting = "Experiment of 3 static nodos [0;0,5;0,10;0]";
                                            MobilityHelper mobility;
                                            Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
                                            positionAlloc->Add (Vector (0.0, 0.0, 0.0));
                                            positionAlloc->Add (Vector (5.0, 0.0, 0.0));
                                            positionAlloc->Add (Vector (10.0, 0.0, 0.0));
                                            mobility.SetPositionAllocator (positionAlloc);

                                            mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
                                            mobility.Install (ueNode);

                                            NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
                                          } else {
                                            // mobility.
                                            m_mobilityNameSetting = "Experiment with mobility defined by Gazebo";
                                            MobilityHelper mobility;
                                            mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
                                            mobility.Install(ueNode);
                                            NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);

                                          }




         std::cout << "Mobility installed" << std::endl;



         sleep(5);






         ApplicationContainer sourceApplications, sinkApplications;
         std::vector<uint8_t> tosValues = {0x70, 0x28, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO

         uint32_t portNumber = 100;




                    //  for (uint32_t index = 1; index < nWifi; ++index)
                    //  {
                        for (uint8_t tosValue : tosValues)
                          {


                                  for (uint32_t u = 0; u < ueNode.GetN (); ++u)
                                  {
                                    auto ipv4 = ueNode.Get (u)->GetObject<Ipv4> ();
                                    const auto address = ipv4->GetAddress (1, 0).GetLocal ();
                                    Ipv4Address addr = ipv4->GetAddress(1,0).GetLocal();

                                    InetSocketAddress sinkSocket (address, portNumber++);


                                    sinkSocket.SetTos (tosValue);


                                    OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
                                    onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
                                    onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
                                    onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
                                    onOffHelper.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
                                //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));

                                    PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), portNumber));
                                    sinkApplications.Add (packetSinkHelper.Install (ueNode.Get (u)));

                                    sourceApplications.Add (onOffHelper.Install (ueNode.Get(u)));



                                    GetTos (sinkSocket, addr, portNumber);

                                    // for (uint32_t i=ueNode.GetN (); i = 0;i--){
                                    //     if (i != u) {
                                    //             sourceApplications.Add (onOffHelper.Install (ueNode.Get (i)));
                                    //             auto ipv4_src = ueNode.Get (i)->GetObject<Ipv4> ();
                                    //             Ipv4Address addr_src = ipv4_src->GetAddress(1,0).GetLocal();
                                    //             std::cout << "Stablishment COMM sink/source with Tos: "<< type << "---sink--- "<< addr << "---sink--- " << addr_src << std::endl;
                                    //               }
                                    //            }




                                }


                            }



                          sinkApplications.Start (Seconds (0.5));
                          sinkApplications.Stop (Seconds (duration/2));
                          sourceApplications.Start (Seconds (1));



                          int i = 1;
                          char id[5] = "rd_a";
                          //char id_sd[5] = "sd_a";
                          char id_server[7] = "server";
                          char novoId[10], novoId_server[10];
                      //  char novoId_sd_a[20];




                          for (uint32_t u = 0; u < ueNode.GetN (); ++u)
                          {
                            auto ipv4 = ueNode.Get (u)->GetObject<Ipv4> ();
                            const auto address = ipv4->GetAddress (1, 0).GetLocal ();
                            Ipv4Address addr = ipv4->GetAddress(1,0).GetLocal();

                            InetSocketAddress sinkSocket (address, port);

                            sinkSocket.SetTos (0xb8); //AC_VI



                            for (int run_ev=1; run_ev < 5; run_ev++){

                             //snprintf (novoId_sd_a, 20, "send:%d-%s-node:%d", run_ev, id_sd, i);
                              snprintf (novoId_server, 10, "%s_%d", id_server, run_ev);
                            //  std::string novoId_sd = novoId_sd_a;



                              EvalvidServerHelper novoId_server (port);
                              novoId_server.SetAttribute ("SenderTraceFilename", StringValue("st_highway_cif.st"));
                              novoId_server.SetAttribute ("SenderDumpFilename", StringValue("sd_a"));
                              novoId_server.SetAttribute ("PacketPayload",UintegerValue(pktSize));


                              ApplicationContainer apps = novoId_server.Install (ueNode.Get(u));
                              apps.Start (Seconds (duration/2+0.1));
                              apps.Stop (Seconds (duration+1.0));


                              snprintf (novoId, 10, "%d_%s_%d", run_ev, id, i);
                              EvalvidClientHelper client (interface.GetAddress (1,0),port);
                              client.SetAttribute ("ReceiverDumpFilename", StringValue(novoId));
                              apps = client.Install (ueNode.Get (u));

                              std::cout << "Now:" << Simulator::Now ().GetSeconds () << ", Qtd of video streaming Sending video: Qtd= " << run_ev <<", node=[" << i << "], from "<< ueNode.Get(u) << "---port--- " << port << ",Tos=" << "AC_VI" << ",Addr=" << addr << ";" << std::endl;

                              apps.Start (Seconds (duration/2+0.5));
                              apps.Stop (Seconds (duration));

                            }





                            i++;
                            //seq++;

                            }

                            std::cout << "CBR traffic to maintain connection " << std::endl;

                            uint32_t payloadSize = 1500; //bytes
                            double interPacketInterval = 250;
                            ApplicationContainer clientApps, serverApps;

                            UdpClientHelper dlClient (interface.GetAddress (1), wdport);
                            dlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
                            // dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
                             dlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
                             dlClient.SetAttribute("StartTime", TimeValue(Seconds(2)));
                             dlClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));


                            // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
                            for (uint32_t i=0; i < ueNode.GetN ();i++){
                                if (i != 0) {
                                        clientApps.Add (dlClient.Install (ueNode.Get(i)));
                                      }
                                }



                          //  UdpServerHelper dlPacketSinkHelper(dport);


                            PacketSinkHelper dlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (interface.GetAddress (1), wdport));



                            for (uint32_t i=0; i < ueNode.GetN ();i++){

                        //            std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;
                            //    std::cout << std::endl;
                              //  std::cout << "wave add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;


                                serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(i)));
                                // clientApps.Add (dlClient.Install (ueNode.Get(i)));

                            }



          // Ipv4StaticRoutingHelper ipv4RoutingHelper;





// if (m_numberOfInterfaces==2) {
//     // 7. Install PHY and MAC Layer of IEEE 802.11p 5GHz
//
//
//
//     Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();
//     YansWifiPhyHelper wifiPhy2 =  YansWifiPhyHelper::Default ();
//
//     NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default ();
//
//     YansWifiChannelHelper channelWave;
//     channelWave.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
//     channelWave.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5.9e9));
//     channelWave.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");
//     wifiPhy2.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);
//     Ptr<YansWifiChannel> channel2 = channelWave.Create ();
//     wifiPhy2.SetChannel (channel2);
//
//
//
//     // wifiPhy2.Set("ChannelNumber", UintegerValue(172));
//     //
//     // // wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
//     // //                                     "DataMode",StringValue (phyMode2),
//     // //                                     "ControlMode",StringValue (phyMode2));
//     //
//     // wifiPhy2.Set ("TxPowerStart",DoubleValue (m_txp));
//     // wifiPhy2.Set ("TxPowerEnd", DoubleValue (m_txp));
//
//
//     NetDeviceContainer waveDevices = wifi80211p.Install (wifiPhy2, wifi80211pMac, ueNode);
//
//     Packet::EnablePrinting ();
//
//     // WiFi Interface
//     Ipv4AddressHelper address;
//
//
//     NS_LOG_INFO ("Assign IP Wave Addresses.");
//
//
//     address.SetBase("192.168.1.0", "255.255.255.0");
//     Ipv4InterfaceContainer interface = address.Assign(waveDevices);
// //    interface.Add(interface2);
//
//     // for (int u = 0; u < numberOfUEs; ++u)
//     // {
//     //     Ptr<Node> node = ueNode.Get (u);
//     //     Ptr<Ipv4StaticRouting> interface2HostStaticRouting = ipv4RoutingHelper.GetStaticRouting (node->GetObject<Ipv4> ());    //Ipv4 static routing helper
//     //     interface2HostStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 2);
//     // }
//
//
//     AsciiTraceHelper ascii2;
//
//     if (verbose){
//       wifi80211p.EnableLogComponents ();
//          }
//
//     // tracing
//
//     wifiPhy2.EnablePcap ("wave-interfaceManager", waveDevices);
//
//     wifiPhy2.EnableAsciiAll (ascii2.CreateFileStream ("PacketTxWave.tr"));
//
//
//
//
//
// //only wifi */
//    Ptr<Ipv4> ip_wireless[numberOfUEs];
//    for (int i = 0; i < numberOfUEs; i++)
//    {
//        ip_wireless[i] = ueNode.Get(i)->GetObject<Ipv4> ();
//    }
//
//
//     for (uint32_t u = 0; u < ueNode.GetN (); ++u)
//     {
//           Ptr<Node> node = ueNode.Get(u);
//           Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
//           Ipv4Address addr = ipv4->GetAddress(0,0).GetLocal();
//           std::cout << std::endl << "Nodo" << u << "\taddress 0: " << addr <<std::endl;
//           addr = ipv4->GetAddress(1,0).GetLocal();
//           std::cout << "Nodo" << u << "\taddress 1: " << addr <<std::endl;
//
//           //only wifi
//           // addr = ipv4->GetAddress(2,0).GetLocal();
//           // std::cout << "Nodo" << u << "\taddress 2: " << addr <<std::endl;
//
//       }
//
//       //process of creating of sockets -- for conection with Gazebo
//
//       for (int i = 0; i < numberOfUEs; i++)
//         {
//           // protocol == 0 means no routing data, WAVE BSM only
//           // so do not set up sink
//
//           //
//           // Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (i), tid);
//           // InetSocketAddress local = InetSocketAddress (interface.GetAddress (i), 80);
//           // recvSink->Bind (local);
//           // recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
//
//           ExternalSyncManager::RegisterNode(ueNode.Get(i), MakeCallback(&ProcessMessage));
//           Ptr<Socket> srcSocket = Socket::CreateSocket(ueNode.Get(i), TypeId::LookupByName("ns3::UdpSocketFactory"));
//           srcSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), SIM_DST_PORT));
//           srcSocket->SetRecvCallback(MakeCallback(&SocketReceive));
//           srcSocket->SetRecvCallback (MakeCallback (&ReceivePacket));
//           srcSocket->SetRecvCallback (MakeCallback (&ReceivePacket2));
//           srcSocket->SetAllowBroadcast(true);
//           //srcSocket->BindToNetDevice(nodes.Get(i)->GetDevice(1));
//           ueNode.Get(i)->AggregateObject(srcSocket);
//           ip_node_list.emplace(interface.GetAddress(i), ueNode.Get(i));
//           std::cerr << "IP of NODE #" << i << " is " << interface.GetAddress(i) << std::endl;
//         }
//
//
//
//               std::cout << "Wave installed!" << std::endl;
//
//
//             //  Ipv4StaticRoutingHelper ipv4RoutingHelper;
//
//     }




    // // 2. Place nodes
    //
    // if (m_mobility==1){
    //           std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet3/mobility.tcl";
    //           m_mobilityNameSetting = "Experiment of 3 uavs (mobility nodos) in a 307m of trajectory";
    //
    //           // Create Ns2MobilityHelper with the specified trace log file as parameter
    //           Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
    //           ns2.Install (); // configure movements for each node, while reading trace file
    //
    //           NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
    //
    //         } else if (m_mobility==2) {
    //
    //               std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet5/mobility.tcl";
    //               m_mobilityNameSetting = "Experiment of 5 uavs (mobility nodos) in a area";
    //
    //                 // Create Ns2MobilityHelper with the specified trace log file as parameter
    //                 Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
    //                 ns2.Install (); // configure movements for each node, while reading trace file
    //
    //                 NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
    //
    //
    //               } else if (m_mobility==3) {
    //
    //                       std::string m_traceFile= "/home/doutorado/sumo/examples/journal2021/fanet8/mobility.tcl";
    //                       m_mobilityNameSetting = "Experiment of 8 uavs (mobility nodos) in a area";
    //
    //                         // Create Ns2MobilityHelper with the specified trace log file as parameter
    //                         Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
    //                         ns2.Install (); // configure movements for each node, while reading trace file
    //
    //                         NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
    //
    //
    //                         } else if (m_mobility==3) {
    //                                    m_mobilityNameSetting = "Experiment of 3 static nodos [0;0,5;0,10;0]";
    //                                    MobilityHelper mobility;
    //                                    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
    //                                    positionAlloc->Add (Vector (0.0, 0.0, 0.0));
    //                                    positionAlloc->Add (Vector (5.0, 0.0, 0.0));
    //                                    positionAlloc->Add (Vector (10.0, 0.0, 0.0));
    //                                    mobility.SetPositionAllocator (positionAlloc);
    //
    //                                    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    //                                    mobility.Install (ueNode);
    //
    //                                    NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
    //                                  } else {
    //                                    // mobility.
    //                                    m_mobilityNameSetting = "Experiment with mobility defined by Gazebo";
    //                                    MobilityHelper mobility;
    //                                    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    //                                    mobility.Install(ueNode);
    //                                    NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
    //
    //                                  }
    //
    //
    //
    //
    // std::cout << "Mobility installed" << std::endl;


    // 9.Install Applications
    //
    // float tempo = 0.01;
    //
    // for (uint32_t i = 0; i < ueNode.GetN (); ++i)
    // {
    //   if (i != 0){
    //     PacketSinkHelper sink ("ns3::UdpSocketFactory", InetSocketAddress (interface.GetAddress(i), 80));
    //     ApplicationContainer sinkApp = sink.Install(ueNode.Get(i));
    //     sinkApp.Start (Seconds(tempo));
    //     sinkApp.Stop (Seconds(duration));
    //   } else {
    //     OnOffHelper onOff ("ns3::UdpSocketFactory", InetSocketAddress(interface.GetAddress(0), 80));
    //     onOff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
    //     onOff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
    //     onOff.SetAttribute ("PacketSize", UintegerValue(pktSize));
    //     onOff.SetAttribute ("Remote", AddressValue(InetSocketAddress(interface.GetAddress(i), 80)));
    //     ApplicationContainer udpApp = onOff.Install(ueNode.Get(0));
    //     udpApp.Start(Seconds(tempo));
    //     udpApp.Stop(Seconds(duration));
    //     tempo+=0.2;
    //
    //   }
    // }

    // // application stuff -- possibility 2
    // uint16_t dport = 5001;
    // uint32_t payloadSize = 1500; //bytes
    // double interPacketInterval = 100;
    // ApplicationContainer clientApps, serverApps;
    //
    // UdpClientHelper dlClient (interface.GetAddress (0), dport);
    // dlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    // dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
    // dlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    // dlClient.SetAttribute("StartTime", TimeValue(MilliSeconds(100)));
    // dlClient.SetAttribute("StopTime", TimeValue(Seconds(10)));
    //
    //
    // // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
    // for (uint32_t i=0; i < ueNode.GetN ();i++){
    //     if (i != 0) {
    //             clientApps.Add (dlClient.Install (ueNode.Get(i)));
    //           }
    //     }
    //
    // UdpServerHelper dlPacketSinkHelper(dport);
    // serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(0)));
    //
    //
    // // Wifi test apps
    // uint16_t wdport = 5004;
    //
    // // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
    // std::cout << std::endl;
    // std::cout << "wifi src add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
    //
    // UdpClientHelper wdlClient (interface2.GetAddress (0), wdport);
    // wdlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    // wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
    // wdlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    // wdlClient.SetAttribute("StartTime", TimeValue(Seconds(10.100)));
    // wdlClient.SetAttribute("StopTime", TimeValue(Seconds(20.100)));
    //
    // for (uint32_t i=0; i < ueNode.GetN ();i++){
    //     if (i != 0) {
    //             std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
    //
    //             clientApps.Add (wdlClient.Install (ueNode.Get(i)));
    //             }
    // }
    //
    // PacketSinkHelper wdlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), wdport));
    //
    // serverApps.Add (wdlPacketSinkHelper.Install (ueNode.Get(0)));

    // // ended application stuff -- possibility 2

    //









    // uint16_t dport = 5001;
    // uint32_t payloadSize = 1500; //bytes
    // ApplicationContainer clientApps, serverApps;
    //
    // UdpClientHelper dlClient (interface.GetAddress (0), dport);
    // dlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    // dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
    // dlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    // dlClient.SetAttribute("StartTime", TimeValue(MilliSeconds(100)));
    // dlClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));
    //
    //
    // // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
    // for (uint32_t i=0; i < ueNode.GetN ();i++){
    //     if (i != 0) {
    //             clientApps.Add (dlClient.Install (ueNode.Get(i)));
    //           }
    //     }
    //
    // UdpServerHelper dlPacketSinkHelper(dport);
    // serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(0)));
    //
    //
    // // Wave test apps
    // uint16_t wdport = 5004;
    //
    // // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
    // std::cout << std::endl;
    // std::cout << "wifi src add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
    //
    // UdpClientHelper wdlClient (interface2.GetAddress (0), wdport);
    // wdlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    // wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
    // wdlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    // wdlClient.SetAttribute("StartTime", TimeValue(Seconds(MilliSeconds(100))));
    // wdlClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));
    //
    // for (uint32_t i=0; i < ueNode.GetN ();i++){
    //     if (i != 0) {
    //             std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
    //
    //             clientApps.Add (wdlClient.Install (ueNode.Get(i)));
    //             }
    // }
    //
    // PacketSinkHelper wdlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), wdport));
    //
    // serverApps.Add (wdlPacketSinkHelper.Install (ueNode.Get(0)));

// if (m_numberOfInterfaces==1) {
//
//
//
//
//     ApplicationContainer sourceApplications, sinkApplications;
//     std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
//     uint32_t portNumber = 10;
//
//     //  for (uint32_t index = 1; index < nWifi; ++index)
//     //  {
//         for (uint8_t tosValue : tosValues)
//           {
//
//             auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
//             const auto address = ipv4->GetAddress (1, 0).GetLocal ();
//
//             InetSocketAddress sinkSocket (address, portNumber++);
//
//
//             sinkSocket.SetTos (tosValue);
//
//
//             OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
//             onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
//             onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
//             onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
//             onOffHelper.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
//         //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
//
//             PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
//             sinkApplications.Add (packetSinkHelper.Install (ueNode.Get (1)));
//
//         for (uint32_t i=0; i < ueNode.GetN ();i++){
//             if (i != 1) {
//                     sourceApplications.Add (onOffHelper.Install (ueNode.Get (i)));
//                   // source
//                       }
//                   }
//           }
//           sinkApplications.Start (Seconds (0.0));
//           sinkApplications.Stop (Seconds (duration));
//           sourceApplications.Start (Seconds (0.1));
//
//         } else if (m_numberOfInterfaces=2) {
//                 ApplicationContainer sourceApplications2, sinkApplications2;
//                 std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
//                 uint32_t portNumber2 = 20;
//
//                 //  for (uint32_t index = 1; index < nWifi; ++index)
//                 //  {
//                     for (uint8_t tosValue : tosValues)
//                       {
//
//                         auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
//                         const auto address2 = ipv4->GetAddress (1, 0).GetLocal ();
//                         InetSocketAddress sinkSocket2 (address2, portNumber2++);
//
//                         sinkSocket2.SetTos (tosValue);
//
//                         OnOffHelper onOffHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
//                         onOffHelper2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
//                         onOffHelper2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
//                         onOffHelper2.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
//                         onOffHelper2.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
//                     //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
//
//                         PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
//                         sinkApplications2.Add (packetSinkHelper2.Install (ueNode.Get (1)));
//
//
//                     for (uint32_t i=0; i < ueNode.GetN ();i++){
//                         if (i !=1) {
//                                 sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (i)));
//                               // source
//                         }
//                     }
//
//                 }
//
//             sinkApplications2.Start (Seconds (0.0));
//             sinkApplications2.Stop (Seconds (duration));
//             sourceApplications2.Start (Seconds (0.1));
//
//           }

    // 11.2 Monitor collisions

     Config::ConnectWithoutContext ("/NodeList/*/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));


    //Config::ConnectWithoutContext ("/NodeList/0/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));

     Config::Connect ("/NodeList/*/$ns3::Node/ApplicationList/*/$ns3::PacketSocketServer/Rx", MakeCallback (&SocketRecvStats));
   // every device will have PHY callback for tracing
   // which is used to determine the total amount of
   // data transmitted, and then used to calculate
   // devices are set up in SetupAdhocDevices(),</Ipv4>
   // the MAC/PHY overhead beyond the app-data
    Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/Tx", MakeCallback (&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
    // TxDrop, RxDrop not working yet.  Not sure what I'm doing wrong.
    Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback (&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
    Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback (&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));



    // 10. Rastreio de Pacotes



    /*Rastreia os pacotes recebidos no terminal escolhido*/
    Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
    // Config::Connect ("/NodeList/2/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
    // Config::Connect ("/NodeList/3/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
    Config::Connect("/NodeList/*/DeviceList/*/Mac/MacRx", MakeCallback(&vetorBytesReceived));




    std::stringstream ST;
    ST<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";

    //ST<<"/NodeList/"<< 0 <<"/ApplicationList/*/$ns3::PacketSink/Rx";                 //

    Config::Connect (ST.str(), MakeCallback(&ReceivesPacket));

    std::stringstream Sd;

    Sd<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRxDrop";                 //
    Config::Connect (Sd.str(), MakeCallback(&DroppedPacket));


    // Interface Manager Routines
  //    CalculatePhyRxDrop (m_wifiPhyStats);

      CheckThroughput (m_wifiPhyStats);
    //  CheckThroughputbyNode (m_wifiPhyStats);


    // 11. monitoring

    Simulator::Schedule(Seconds(0.1), &CalculatePhyRxDrop, m_wifiPhyStats);
  //  Simulator::Schedule(Seconds(0.1), &CalculateThroughput);
  //  Simulator::Schedule(Seconds(0.1), &CalculateThroughput2,m_wifiPhyStats);




    // for (uint32_t j=0; j < ueNode.GetN ();j++){
    //   if (j!=0) {
    //   Simulator::Schedule(Seconds(duration/2), &TearDownLink,ueNode.Get(0), ueNode.Get(j),1,1);
    // //  Simulator::Schedule (Seconds (duration/2), &reconfigureUdpClient, wdlClient, ueNode.Get(j), wdport);
    // //  Simulator::Schedule(Seconds(duration/2+0.1), &TearUpLink,ueNode.Get(0), ueNode.Get(j),2,2, phyMode2, j);
    //     }
    // }





   // 11.1 Enable pcap traces for each node

   // Tracing


   // Tracing

   //11.2 Trace

   // rdTrace.open("bytesreceivedwave.dat", std::ios::out);                                             //
   //   rdTrace << "# Time \t Bytes Received by sample \n";
   //
   //
   //  rdTraced.open("bytesreceivedwifi.dat", std::ios::out);                                             //
   //   rdTraced << "# Time \t Bytes Received by sample \n" ;
   //   Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivedPacket));

   //Packet::EnablePrinting ();

   Ipv4GlobalRoutingHelper::PopulateRoutingTables ();


   // 11.3 Install FlowMonitor on all nodes
   Ptr<FlowMonitor> flowMonitor;
   FlowMonitorHelper flowHelper;
   flowMonitor = flowHelper.InstallAll();


   //Packet::EnablePrinting ();
   ns3::PacketMetadata::Enable ();


   // 13. Print statistics




    //12. Run simulation for "duration" seconds
    Simulator::Stop (Seconds (duration+1));


//    AnimationInterface anim ("interfaceManagerbeta_Anim.xml");
//    anim.EnablePacketMetadata(true);


    Simulator::Run ();






    flowMonitor->CheckForLostPackets();

//     Time runTime;
//     runTime = Seconds(duration);
//
   //   double txPacketsumWifi = 0;
   //   double rxPacketsumWifi = 0;
        double DropPacketsumWifi = 0;
        double LostPacketsumWifi = 0;
   //   //double ThroughputsumWiFi = 0;
   //
   // //double rxDurationWifi=0;
   //  Time DelaysumWifi;
   //  Time JittersumWifi;

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();
    for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i !=stats.end(); ++i)
    {
  	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);




  		  std::cout << std::endl;
  		  std::cout << "Flow : " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Simulation Time: " << Simulator::Now ().GetSeconds() << "\n";
        std::cout << " Tx bytes : " << i->second.txBytes << "\n";
  		  std::cout << " Rx bytes : " << i->second.rxBytes << "\n";
        std::cout << "  First Rx Pkt Time: " << i->second.timeFirstRxPacket.GetSeconds() << "\n";
        std::cout << " First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds() << "\n";
        std::cout << "  Last Tx Pkt Time: " << i->second.timeLastTxPacket.GetSeconds() << "\n";
        std::cout << " Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds() << "\n";
        std::cout << " First packet Delay time : " <<  i->second.timeFirstRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds() << "\n";
        std::cout << " Last packet Delay time : " <<  i->second.timeLastRxPacket.GetSeconds() - i->second.timeLastTxPacket.GetSeconds() << "\n";


        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
        // txPacketsumWifi += i->second.txPackets;
        // rxPacketsumWifi += i->second.rxPackets;
         LostPacketsumWifi += i->second.lostPackets;
         DropPacketsumWifi += i->second.packetsDropped.size();
        // DelaysumWifi += ((i->second.delaySum)/(i->second.rxPackets));               //ns
        // JittersumWifi += ((i->second.jitterSum)/(i->second.rxPackets));
        // std::cout << " Amount of Tx Packets: " << txPacketsumWifi << "\n";
        // std::cout << " Amount of Rx Packets: " << rxPacketsumWifi << "\n";
        std::cout << " Amount of Lost Packets: " << LostPacketsumWifi << "\n";
        std::cout << " Amount of Drop Packets: " << DropPacketsumWifi << "\n";
        // std::cout << " Amount of Delay sum by packet receive sum (D/Rx Pkt): " << DelaysumWifi << "\n";
        // std::cout << " Amount of Jitter sum by packet receive sum (D/Rx Pkt): " << DelaysumWifi << "\n";

        // std::cout << " First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds() << std::endl;
  		  // std::cout << " Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds() << std::endl;

        std::cout << "Throughput Kbps: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps\n";
        //
  		  std::cout << " Throughput : " << i->second.rxBytes *8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n";



        //   NS_LOG_UNCOND("Flow ID " << i->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);*
        //   NS_LOG_UNCOND("Tx Packets = " << i->second.txPackets);
        //   NS_LOG_UNCOND("Rx Packets = " << i->second.rxPackets);
        // NS_LOG_UNCOND("Throughput Kbps: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps");
        // NS_LOG_UNCOND("Throughput Mbps: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024 /1024 << " Mbps");
        // NS_LOG_UNCOND("Delay Sum" << i->second.delaySum);
        // NS_LOG_UNCOND(" First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds());
        // NS_LOG_UNCOND(" Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds());
        // NS_LOG_UNCOND(" WiFi Throughput : " << i->second.rxBytes *8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n");

    }

    // double throughput = 0;
    // for (uint32_t index = 0; index < ueNode.GetN (); ++index)
    //   {
    //     uint64_t totalPacketsThrough = DynamicCast<PacketSink> (ueNode.Get (index))->GetTotalRx ();
    //     throughput += ((totalPacketsThrough * 8) / (duration * 1000000.0)); //Mbit/s
    //   }

    flowMonitor->SerializeToXmlFile("intefaceManager.xml", true, true);


    // for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    // {
    //   Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
    //

    //   std::cout << std::endl;
    //
    //
    //
    //     std::cout << "****** Teste anterior" << "\n";
    //     std::cout << i->second.txPackets << ";" << i->second.rxPackets << ";";
    //     std::cout << i->second.txBytes << ";" << i->second.rxBytes << ";";
    // }
    // // Collisions should be in phyRxDropCount, as Yans wifi set collided frames snr on reception, but it's not possible to differentiate from propagation loss. In this experiment, this is not an issue.
    // std::cout << "Count Phy Tx Drop\t" << "Count Phy Rx Drop" << "\n";
    // std::cout << phyTxDropCount << "\t" << phyRxDropCount << "\n";
    //
    // // Export flowmon data?
    // monitor->SerializeToXmlFile("interfaceManager_beta.xml", true, true);

    // 11. Cleanup
    Simulator::Destroy ();

    // if (throughput > 0)
    //   {
    //     std::cout << "Aggregated throughput: " << throughput << " Mbit/s" << std::endl;
    //
    //   }
    // else
    //   {
    //     NS_LOG_ERROR ("Obtained throughput is 0!");
    //     exit (1);
    //   }


    // ResetDropCounters();
    // m_bytesTotal = 0;
    // totalBytesReceived=0;
    NS_LOG_INFO ("Done.");
}



int main (int argc, char *argv[])
{
    // Defaults
    double duration = 90.0; //seconds
    int numberOfUEs=3; //Default number of UEs attached to each eNodeB
    bool verbose=false;
    uint32_t packetSize = 1472; // bytes
  //  double m_txp=100; ///< distance
    int m_mobility=4;
    double m_txp=20;
    uint32_t m_protocol=1; ///< protocol
    int m_numberOfInterfaces=1;

    //conection Gazebo
      GlobalValue::Bind("SimulatorImplementationType", StringValue("ns3::ExternalSyncSimulatorImpl"));



    // For Wifi Network
    std::string phyMode1 ("HtMcs1");
    //For Wave Network
    std::string phyMode2 ("OfdmRate6MbpsBW10MHz");

    size_t runs = 1;

    LogComponentEnable ("MacLow", LOG_LEVEL_ERROR);
    LogComponentEnable ("AdhocWifiMac", LOG_LEVEL_DEBUG);
    LogComponentEnable ("InterferenceHelper", LOG_LEVEL_ERROR);
    LogComponentEnable ("YansWifiPhy", LOG_LEVEL_ERROR);
    LogComponentEnable ("PropagationLossModel", LOG_LEVEL_INFO);
    LogComponentEnable ("PropagationLossModel", LOG_LEVEL_DEBUG);
    LogComponentEnable ("YansErrorRateModel", LOG_LEVEL_INFO);
    LogComponentEnable ("YansErrorRateModel", LOG_LEVEL_DEBUG);
    LogComponentEnable ("YansWifiChannel", LOG_LEVEL_DEBUG);
    LogComponentEnable ("DsssErrorRateModel", LOG_LEVEL_INFO);
    LogComponentEnable ("DsssErrorRateModel", LOG_LEVEL_DEBUG);
    LogComponentEnable ("Ipv4EndPoint", LOG_LEVEL_DEBUG);
    LogComponentEnable ("Ipv4L3Protocol", LOG_LEVEL_INFO); // uncomment to generate throughput data
    LogComponentEnable ("MacLow", LOG_LEVEL_DEBUG);
    LogComponentEnable ("Ns2MobilityHelper",LOG_LEVEL_DEBUG);


    // Parse command line
    CommandLine cmd;
    cmd.AddValue ("simulationTime", "Simulation time in seconds", duration);
    cmd.AddValue("numberOfNodes", "Amount of nodes. Default: 3", numberOfUEs);
    cmd.AddValue ("verbose", "turn on all WifiNetDevice ans WavwNetDevice log components", verbose);
    cmd.AddValue ("packetSize", "Define size of packets", packetSize);
    cmd.AddValue ("txWiFi", "Define WiFi transmission rate", phyMode1);
    cmd.AddValue ("txWave", "Define Wave transmission rate", phyMode2);
    cmd.AddValue ("mobility", "Define if mobility is based on tracefile or constant position.\n 1-Experiment of 3 uavs (mobility nodos) in a 300 x 400 area \n 2-Experiment of 10 uavs (mobility nodos) in a 600 x 800 area \n 3-Experiment of 3 static nodos", m_mobility);
    cmd.AddValue("runs", "Run count. Default: 1.", runs);
    cmd.AddValue ("protocol", "0=NONE;1=OLSR;2=AODV;3=DSDV", m_protocol);
    cmd.AddValue ("txp", "Transmit power (dB), e.g. txp=7.5", m_txp);
    cmd.AddValue("NumberOfInterfaces", "Define the number of communication interface. \n0-WIFI_PHY_STANDARD_80211n_2_4GHZ //\n 1-WAVE_PHY_STANDARD_80211p_5_9GHZ //. Default: 1.", m_numberOfInterfaces);
    cmd.Parse (argc, argv);


    void ReceivePacket2 (Ptr <Socket> socket);
    void ReceivesPacket (std::string context, Ptr <const Packet> p);
    //void ReceivedPacket (Ptr<const Packet> p, const Address & addr);


    void vetorBytesReceived (std::string context, Ptr <const Packet> p);

    void ReceivedPacket (Ptr<const Packet> p, const Address & addr);

    void CheckThroughput ();


    Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
    m_wifiPhyStats = CreateObject<WifiPhyStats> ();



    void DroppedPacket (std::string context, Ptr<const Packet> p);
  //  void CalculateThroughput2 (Ptr<WifiPhyStats> m_wifiPhyStats);
    Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node );

      // // disable fragmentation for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
      // // turn off RTS/CTS for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("1000"));

      // conection Gazebo
      ExternalSyncManager::SetSimulatorController("127.0.0.1", 7833);
      ExternalSyncManager::SetNodeControllerServerPort(9998);

      Time::SetResolution(Time::NS);
      Time s;


    // Run experiment
    std::cout << "Starting!" << std::endl;
  //  std::cout << "F1 Tx Packets;F1 Rx Packets;F1 Tx Bytes;F1 Rx Bytes;F2 Tx Packets;F2 Rx Packets;F2 Tx Bytes;F2 Rx Bytes;Collisions\n";
    for (size_t i = 0; i < runs; ++i)
    {
        experiment(numberOfUEs, phyMode1, phyMode2, verbose, duration, m_wifiPhyStats, m_mobility, m_txp, m_protocol, m_numberOfInterfaces);

    }


    return 0;

}
