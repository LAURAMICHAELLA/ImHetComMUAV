#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/external-sync-manager.h"
#include "ns3/mobility-module.h"
#include "ns3/object.h"
#include "ns3/ptr.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/timer.h"
#include "ns3/nstime.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/config.h"
#include "ns3/global-value.h"

#include "ns3/timer.h"
#include "ns3/nstime.h"
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/time.h>

// to integrate with HetMUAVNet in 29/09/2020

#define SIM_DST_PORT 12345

#include "string.h"
#include "ns3/propagation-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/core-module.h"
#include "ns3/config-store-module.h"
#include "ns3/aodv-helper.h"
#include "ns3/olsr-helper.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"

#include "ns3/lte-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/network-module.h"

#include "ns3/config-store-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipcs-classifier-record.h"
#include "ns3/service-flow.h"

#include "ns3/point-to-point-module.h"
#include "ns3/lte-module.h"




#include "ns3/core-module.h"
#include "ns3/propagation-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
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


using namespace ns3;
using std::cout;
using std::endl;


// General Variables
uint32_t phyTxDropCount=0;
uint32_t phyRxDropCount=0;
uint32_t m_bytesTotal;
uint32_t m_bytesTotal_all;


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
uint16_t port = 9;
char tmp_char [30] = "";
int numberofexecution;
int old_change;
int numberofchanges;


// PHY variables


uint32_t BytesReceivedWave;
uint32_t BytesDropWave;

uint32_t BytesReceivedWifi;
uint32_t BytesDropWifi;

uint32_t BytesReceivedAc;
uint32_t BytesDropAc;

double throughputWave [10];
double throughputWifi [10];
double throughputAc [10];


///Global variables of Interface Manager decision

//802.11p
uint32_t vetBytesReceivedWave[10];
uint32_t vetBytesDropWave[10];
double vet_g_signalDbmAvgWave[10];
double vet_g_SNRWave [10];
double vet_g_noiseDbmAvgWave [10];
double totalBytesReceivedSumWave;

// Settings 802.11p
uint16_t dport = 5001;


//802.11n

uint32_t vetBytesReceivedWifi[10];
uint32_t vetBytesDropWifi[10];
double vet_g_signalDbmAvgWifi[10];
double vet_g_noiseDbmAvgWifi [10];
double vet_g_SNRWifi [10];
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


// Settings Lte
uint16_t lteport = 5001; //lteport1 = 6001;


// Average of variables

//802.11p
double AvgVetBytesReceivedWave;
double AvgVetBytesDropWave;
double AvgVet_g_signalDbmAvgWave;
double AvgVet_g_noiseDbmAvgWave;
double AvgVet_g_SNRWave;
double AvgTotalBytesReceivedSumWave;
double AvgthroughputWave;


//802.11n
double AvgVetBytesReceivedWifi;
double AvgVetBytesDropWifi;
double AvgVet_g_signalDbmAvgWifi;
double AvgVet_g_SNRWifi;
double AvgVet_g_noiseDbmAvgWifi;
double AvgtotalBytesReceivedSumWifi;
double AvgthroughputWifi;


//802.11ac
double AvgVetBytesReceivedAc;
double AvgVetBytesDropAc;
double AvgVet_g_signalDbmAvgAc;
double AvgVet_g_SNRAc;
double AvgVet_g_noiseDbmAvgAc;
double AvgtotalBytesReceivedSumAc;
double AvgthroughputAc;








// Log Files constructed by me
std::string CSVfileName = "interfaceManager2.csv";
std::string m_CSVfileName = "BytesReceivedWave.output.csv"; ///< CSV file name
std::string m_CSVfileName2 = "BytesReceivedWifi.output.csv"; ///< CSV file name
std::string m_CSVfileName3 = "CheckThroughput.output.csv"; ///< CSV file name
std::string m_CSVfileName4 = "CheckThroughputbyNode.output.csv"; ///< CSV file name
std::string m_CSVfileName5 = "CheckSignalNoiseSNR.output.csv"; ///< CSV file name
std::string m_CSVfileName6 = "BytesReceivedAc.output.csv"; ///< CSV file name

std::ofstream out (m_CSVfileName.c_str (), std::ios::app);
std::ofstream out2 (m_CSVfileName2.c_str (), std::ios::app);
std::ofstream out3 (m_CSVfileName3.c_str (), std::ios::app);
std::ofstream out4 (m_CSVfileName4.c_str (), std::ios::app);
std::ofstream out5 (m_CSVfileName5.c_str (), std::ios::app);
std::ofstream out6 (m_CSVfileName6.c_str (), std::ios::app);






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

//Other global values

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
                     SignalNoiseDbm signalNoise
                    )
{

                      int counterSamples=0;
                      Ptr<Packet> copy2 = packet->Copy ();
                      LlcSnapHeader ppp2;
                      Ipv4Header iph2;
                      copy2->RemoveHeader(ppp2);
                      copy2->RemoveHeader (iph2);

                        g_samples++;
                       g_signalDbmAvg += ((signalNoise.signal - g_signalDbmAvg) / g_samples);
                       g_noiseDbmAvg += ((signalNoise.noise - g_noiseDbmAvg) / g_samples);
                       g_SNR = g_signalDbmAvg/g_noiseDbmAvg;

                       //std::cout << "Interface 2 ---> Source Node:"  << iph2.GetDestination() << "," << "Samples" << g_samples << "Frequency Mode:" << channelFreqMhz << "," << "Avg Signal (dBm): "  << g_signalDbmAvg << "," << " Avg Noise+Inf(dBm):" << g_noiseDbmAvg << "," << "SNR: " << g_SNR << "," << std::endl;


                       for (int i=0;i<10;i++){

                          // 802.11p
                            if (iph2.GetDestination()=="192.168.1.1" || iph2.GetDestination()=="192.168.1.2" || iph2.GetDestination()=="192.168.1.3" ||
                               iph2.GetDestination()=="192.168.1.4" || iph2.GetDestination()=="192.168.1.5" || iph2.GetDestination()=="192.168.1.6" ||
                               iph2.GetDestination()=="192.168.1.7" || iph2.GetDestination()=="192.168.1.8" || iph2.GetDestination()=="192.168.1.9" || iph2.GetDestination()=="192.168.1.10") {

                                           vet_g_signalDbmAvgWave[i]= g_signalDbmAvg;
                                           vet_g_noiseDbmAvgWave[i]= g_noiseDbmAvg;
                                           vet_g_SNRWave[i]= g_SNR;
                                           std::cout << "Dest Node:"  << iph2.GetDestination() << "," << "Samples" << g_samples << "Frequency Mode:" << channelFreqMhz << "," << "Avg Signal (dBm): "  << g_signalDbmAvg << "," << " Avg Noise+Inf(dBm):" << g_noiseDbmAvg << "," << "SNR: " << g_SNR << "," << std::endl;


                              } else {
                                         vet_g_signalDbmAvgWave[i]=0;
                                         vet_g_noiseDbmAvgWave[i]=0;
                                         vet_g_SNRWave[i]=0;

                                       }
                          // 802.11n
                           if (iph2.GetDestination()=="10.1.1.1" || iph2.GetDestination()=="10.1.1.2" || iph2.GetDestination()=="10.1.1.3" ||
                             iph2.GetDestination()=="10.1.1.4" || iph2.GetDestination()=="10.1.1.5" || iph2.GetDestination()=="10.1.1.6" ||
                             iph2.GetDestination()=="10.1.1.7" || iph2.GetDestination()=="10.1.1.8" || iph2.GetDestination()=="10.1.1.9" || iph2.GetDestination()=="10.1.1.10") {

                                          vet_g_signalDbmAvgWifi[i]= g_signalDbmAvg;
                                          vet_g_noiseDbmAvgWifi[i]= g_noiseDbmAvg;
                                          vet_g_SNRWifi[i]= g_SNR;
                                          std::cout << "Dest Node:"  << iph2.GetDestination() << "," << "Samples" << g_samples << "Frequency Mode:" << channelFreqMhz << "," << "Avg Signal (dBm): "  << g_signalDbmAvg << "," << " Avg Noise+Inf(dBm):" << g_noiseDbmAvg << "," << "SNR: " << g_SNR << "," << std::endl;
                          } else {

                                          vet_g_signalDbmAvgWifi[i]= 0;
                                          vet_g_noiseDbmAvgWifi[i]= 0;
                                          vet_g_SNRWifi[i]= 0;
                          }

                          // 802.11ac

                          if (iph2.GetDestination()=="120.1.1.1" || iph2.GetDestination()=="120.1.1.2" || iph2.GetDestination()=="120.1.1.3" ||
                            iph2.GetDestination()=="120.1.1.4" || iph2.GetDestination()=="120.1.1.5" || iph2.GetDestination()=="120.1.1.6" ||
                            iph2.GetDestination()=="120.1.1.7" || iph2.GetDestination()=="120.1.1.8" || iph2.GetDestination()=="120.1.1.9" || iph2.GetDestination()=="120.1.1.10") {

                                         vet_g_signalDbmAvgAc[i]= g_signalDbmAvg;
                                         vet_g_noiseDbmAvgAc[i]= g_noiseDbmAvg;
                                         vet_g_SNRAc[i]= g_SNR;
                                         std::cout << "Dest Node:"  << iph2.GetDestination() << "," << "Samples" << g_samples << "Frequency Mode:" << channelFreqMhz << "," << "Avg Signal (dBm): "  << g_signalDbmAvg << "," << " Avg Noise+Inf(dBm):" << g_noiseDbmAvg << "," << "SNR: " << g_SNR << "," << std::endl;
                         }




                         std::ofstream out5 (m_CSVfileName5.c_str (), std::ios::app);
                         counterSamples++;
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

                     }
          }

/*************************************************************** *
FUNÇÃO QUE EXTRAI O TOS DO PACOTE ENVIADO *
***************************************************************/


// void traceqos (std::string context, Ptr<const Packet> packet)
//     {
//       Ptr<Packet> copy = packet->Copy ();
//       LlcSnapHeader ppp;
//       Ipv4Header iph;
//       std::string access_class;
//       copy->RemoveHeader(ppp);
//       copy->RemoveHeader (iph);
//       //If we are not a QoS AP then we definitely want to use AC_BE to
//       // transmit the packet. A TID of zero will map to AC_BE (through \c
//       // QosUtilsMapTidToAc()), so we use that as our default here.
//       uint8_t tid = QosUtilsGetTidForPacket (packet);
//
//
//       // Any value greater than 7 is invalid and likely indicates that
//       // the packet had no QoS tag, so we revert to zero, which'll
//       // mean that AC_BE is used.
//       if (tid < 8)
//       {
//         switch (tid)
//               {
//                 case 0:
//                 case 3:
//                 access_class = "AC_BE";
//                 break;
//                 case 1:
//                 case 2:
//                 access_class = "AC_BK";
//                 break;
//                 case 4:
//                 case 5:
//                 access_class = "AC_VI";
//                 break;
//                 case 6:
//                 case 7:
//                 break;
//                 access_class = "AC_VO";
//               } }   else {
//                   tid = 0;
//                   access_class = "AC_UNDEF";
//                   NS_ASSERT_MSG (tid < 8, "Tid " << tid << " out of range");
//               }
//       // This enumeration defines the Access Categories as an enumeration with values corresponding to the AC index (ACI) values specified (Table 8-104 "ACI-to-AC coding"; IEEE 802.11-2012).
//       // from qos-utils.h
//
//    std::cout << "Received packet with Tos: "<< int (tid) << " Tos_Tag---> " << access_class << " from "<<iph.GetSource()<<" to "<<iph.GetDestination()<<std::endl;
// }
//

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
//   std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "\tBytes TX=" << totalPhyTxBytes << "\tBytes RX Drop=" << totalPhyRxDrop << "\tDrop Bytes (Sended-Received):" << DropBytes<< std::endl;
   Simulator::Schedule (Seconds(0.1), &CalculatePhyRxDrop, m_wifiPhyStats);
}

//-- Callback function is called whenever a packet is received successfully.
//-- This function cumulatively add the size of data packet to totalBytesReceived counter.
//---------------------------------------------------------------------------------------


int cont=0;

void vetorBytesReceived (std::string context, Ptr <const Packet> p)
{

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
          }

        //Writing log
        BytesReceivedWave =p->GetSize();
        BytesDropWave = DropBytes;


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

          }

          //Writing log
          BytesReceivedWifi =p->GetSize();
          BytesDropWifi = DropBytes;


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
                std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Bytes Received Ac:" << "[" << i << "]:" << vetBytesReceivedAc[i] << "Bytes Dropped Wifi:" << "[" << i << "]:" << vetBytesDropAc[i] << std::endl;



           //Writing log
           BytesReceivedAc =p->GetSize();
           BytesDropAc = DropBytes;


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

//  double totalPhyTxBytes2 = m_wifiPhyStats->GetTxBytes ();
  double mbs2 = (m_bytesTotal * 8.0) / 1000000;
  m_bytesTotal = 0;



  std::ofstream out4 (m_CSVfileName4.c_str (), std::ios::app);

  if (addr=="10.1.1.1" || addr=="10.1.1.2" || addr=="10.1.1.3" ||
    addr=="10.1.1.4" || addr=="10.1.1.5" || addr=="10.1.1.6" ||
    addr=="10.1.1.7" || addr=="10.1.1.8" || addr=="10.1.1.9" || addr=="10.1.1.10") {

      for (uint32_t i=0; i<10;i++){
        throughputWifi [i] = mbs2;
        totalBytesReceivedSumWifi = throughputWifi [i] + totalBytesReceivedSumWifi;
      }


      out4 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumWifi << "," << "Mb" << "," << "Ip:" << "," << addr << "," << "Wifi" << "" << std::endl;

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


       out4 << (Simulator::Now ()).GetSeconds () << "," << mbs2 << "," << "Mbps" << "," << totalBytesReceivedSumAc << "," << "Mb" << "," << "Ip:" << "," << addr3 << "," << "Ac" << "" << std::endl;

   //    totalBytesReceived4=0;

    }
    //  totalBytesReceived4=0;



  out4.close();
//  packetsReceived = 0;
//  totalPhyTxBytes2 = 0;
  Simulator::Schedule (Seconds (0.1), &CheckThroughputbyNode, m_wifiPhyStats, node);
}

/*************************************************************** *
Rotinas de Socket sem Gazebo***************************************************************/

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
	      m_bytesTotal_all += packet->GetSize ();
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
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetDown (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetDown (interfaceB);
}

void TearUpLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB, int j)
{
  std::cout << "Setting UP Remote Host -> Ue "<< j << std::endl;

  std::cout << "source " << nodeA->GetObject<Ipv4>()->GetAddress(interfaceA,0).GetLocal();
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetUp (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetUp (interfaceB);

  // //configuration of modulation of this interface
  // Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
  //                 StringValue (phyMode2));
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

//
/*************************************************************** *
Interface manager - Starts Here
***************************************************************/

void CalculateAvgBuffer(){

// 802.11p
  double SumvetBytesReceivedWave;
  double SumvetBytesDropWave;
  double Sumvet_g_signalDbmAvgWave;
  double Sumvet_g_noiseDbmAvgWave;
  double Sumvet_g_SNRWave;
  double SumthroughputWave;

//802.11n
  double SumvetBytesReceivedWifi;
  double SumvetBytesDropWifi;
  double Sumvet_g_signalDbmAvgWifi;
  double Sumvet_g_noiseDbmAvgWifi;
  double Sumvet_g_SNRWifi;
  double SumthroughputWifi;

//802.11ac
  double SumvetBytesReceivedAc;
  double SumvetBytesDropAc;
  double Sumvet_g_signalDbmAvgAc;
  double Sumvet_g_noiseDbmAvgAc;
  double Sumvet_g_SNRAc;
  double SumthroughputAc;


  int c;

  for (c=0; c<10;c++){

          // 802.11n
          SumvetBytesReceivedWifi = vetBytesReceivedWifi[c] + SumvetBytesReceivedWifi;
          Sumvet_g_signalDbmAvgWifi = vet_g_signalDbmAvgWifi [c] + Sumvet_g_signalDbmAvgWifi;
          SumvetBytesDropWifi = vetBytesDropWifi [c] + SumvetBytesDropWifi;
          Sumvet_g_noiseDbmAvgWifi = vet_g_noiseDbmAvgWifi [c] + Sumvet_g_noiseDbmAvgWifi;
          Sumvet_g_SNRWifi = vet_g_SNRWifi [c] + Sumvet_g_SNRWifi;
          SumthroughputWifi = throughputWifi[c] + SumthroughputWifi;

          // 802.11p

          SumvetBytesReceivedWave = vetBytesReceivedWave[c] + SumvetBytesReceivedWave;
          Sumvet_g_signalDbmAvgWave = vet_g_signalDbmAvgWave [c] + Sumvet_g_signalDbmAvgWave;
          SumvetBytesDropWave = vetBytesDropWave[c] + SumvetBytesDropWave;
          Sumvet_g_noiseDbmAvgWave = vet_g_noiseDbmAvgWave [c] + Sumvet_g_noiseDbmAvgWave;
          Sumvet_g_SNRWave = vet_g_SNRWave [c] + Sumvet_g_SNRWave;
          SumthroughputWave = throughputWave[c] + SumthroughputWave;

          // 802.11ac

          SumvetBytesReceivedAc = vetBytesReceivedAc[c] + SumvetBytesReceivedAc;
          Sumvet_g_signalDbmAvgAc = vet_g_signalDbmAvgAc [c] + Sumvet_g_signalDbmAvgAc;
          SumvetBytesDropAc = vetBytesDropAc[c] + SumvetBytesDropAc;
          Sumvet_g_noiseDbmAvgAc = vet_g_noiseDbmAvgAc [c] + Sumvet_g_noiseDbmAvgAc;
          Sumvet_g_SNRAc = vet_g_SNRAc [c] + Sumvet_g_SNRAc;
          SumthroughputAc = throughputAc[c] + SumthroughputAc;


}

  // 802.11p
  AvgVetBytesReceivedWave= SumvetBytesReceivedWave/10;
  AvgVetBytesDropWave= SumvetBytesDropWave/10;
  AvgVet_g_signalDbmAvgWave= Sumvet_g_signalDbmAvgWave/10;
  AvgVet_g_noiseDbmAvgWave= Sumvet_g_noiseDbmAvgWave/10;
  AvgVet_g_SNRWave= Sumvet_g_SNRWave/10;
  AvgTotalBytesReceivedSumWave=totalBytesReceivedSumWave/10;
  AvgthroughputWave =SumthroughputWave/10;
  // 802.11n
  AvgVetBytesReceivedWifi= SumvetBytesReceivedWifi/10;
  AvgVetBytesDropWifi= SumvetBytesDropWifi/10;
  AvgVet_g_signalDbmAvgWifi= Sumvet_g_signalDbmAvgWifi/10;;
  AvgVet_g_noiseDbmAvgWifi= Sumvet_g_noiseDbmAvgWifi/10;
  AvgVet_g_SNRWifi= Sumvet_g_SNRWifi/10;
  AvgtotalBytesReceivedSumWifi= totalBytesReceivedSumWifi/10;
  AvgthroughputWifi =SumthroughputWifi/10;
  // 802.11ac
  AvgVetBytesReceivedAc= SumvetBytesReceivedAc/10;
  AvgVetBytesDropAc= SumvetBytesDropAc/10;
  AvgVet_g_signalDbmAvgAc= Sumvet_g_signalDbmAvgAc/10;;
  AvgVet_g_noiseDbmAvgAc= Sumvet_g_noiseDbmAvgAc/10;
  AvgVet_g_SNRAc= Sumvet_g_SNRAc/10;
  AvgtotalBytesReceivedSumAc= totalBytesReceivedSumAc/10;
  AvgthroughputAc =SumthroughputAc/10;


  Simulator::Schedule (Seconds (0.1), &CalculateAvgBuffer);

}


//InterMan
void InterfaceManager(NodeContainer ueNode, UdpClientHelper dlClient, UdpClientHelper wdlClient, UdpClientHelper acClient, int numberofexecution){
    //sleep (5);
    int sumPointsIntA=0, sumPointsIntB=0, sumPointsIntC=0 ;// c=0; // A=Wifi 2.4GHz B = Wave 5.9GHz C=802.11ac
    int change;

    //int numberofexecution=0;


  //  int qtd_nodes = AmoutOfNodes();

if (numberofexecution > 5) {
                            //  std::cout << "TimeStamp:" << s.GetSeconds() << ":" << s.GetMilliSeconds() << ":" << s.GetNanoSeconds()<< std::endl;
                    std::cout << "now: " << Simulator::Now ().GetSeconds () << std::endl;

                //if (Simulator::Now ().GetSeconds () > 5000000000) {
                      //payload without headers
                      // std::cout << "vetBytesReceivedWave: " << AvgVetBytesReceivedWave << std::endl;
                      // std::cout << "vetBytesReceivedWifi: " << AvgVetBytesReceivedWifi << std::endl;

                      //bytes received --- c1

                      if (AvgVetBytesReceivedWave > AvgVetBytesReceivedWifi && AvgVetBytesReceivedWave > AvgVetBytesReceivedAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgVetBytesReceivedWifi > AvgVetBytesReceivedWave && AvgVetBytesReceivedWifi > AvgVetBytesReceivedAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgVetBytesReceivedAc > AvgVetBytesReceivedWifi && AvgVetBytesReceivedAc > AvgVetBytesReceivedWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                                  }
                                                  //  else { std::cout << "EOF---AvgVetBytesReceived" << std::endl;

                                              //}


                      // bytes dropped of payload --- c2 loss

                      if (AvgVetBytesDropWave > AvgVetBytesDropWifi && AvgVetBytesDropWave > AvgVetBytesDropAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgVetBytesDropWifi > AvgVetBytesDropWave && AvgVetBytesDropWifi > AvgVetBytesDropAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgVetBytesDropAc > AvgVetBytesDropWifi && AvgVetBytesDropAc > AvgVetBytesDropWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                        }
                                              // else { std::cout << "EOF---AvgVetBytesDrop" << std::endl;
                                              //
                                              // }

                      // bytes throughput --- c3
                      if (AvgthroughputWave > AvgthroughputWifi && AvgthroughputWave > AvgthroughputAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgthroughputWifi > AvgthroughputWave && AvgthroughputWifi > AvgthroughputAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgthroughputAc > AvgthroughputWifi && AvgthroughputAc > AvgthroughputWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                        }
                                              // else { std::cout << "EOF---Avgthroughput" << std::endl;
                                              //
                                              // }

                        // total bytes received --- c4
                        if (AvgTotalBytesReceivedSumWave > AvgtotalBytesReceivedSumWifi && AvgTotalBytesReceivedSumWave > AvgtotalBytesReceivedSumAc){
                                  sumPointsIntB = sumPointsIntB + 1;
                                  std::cout << "sumPointsIntB: " << AvgTotalBytesReceivedSumWave << std::endl;
                                } else if (AvgtotalBytesReceivedSumWifi > AvgTotalBytesReceivedSumWave && AvgtotalBytesReceivedSumWifi > AvgtotalBytesReceivedSumAc) {
                                          sumPointsIntA = sumPointsIntA + 1;
                                          std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                        } else if (AvgtotalBytesReceivedSumAc > AvgtotalBytesReceivedSumWifi && AvgtotalBytesReceivedSumAc > AvgTotalBytesReceivedSumWave) {
                                                    sumPointsIntC = sumPointsIntC + 1;
                                                    std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                          }
                                                // else { std::cout << "EOF---AvgtotalBytesReceived" << std::endl;
                                                //
                                                // }



                      //signal received Dbm --- c5
                      if (AvgVet_g_signalDbmAvgWave > AvgVet_g_signalDbmAvgWifi && AvgVet_g_signalDbmAvgWave > AvgVet_g_signalDbmAvgAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgVet_g_signalDbmAvgWifi > AvgVet_g_signalDbmAvgWave && AvgVet_g_signalDbmAvgWifi > AvgVet_g_signalDbmAvgAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgVet_g_signalDbmAvgAc > AvgVet_g_signalDbmAvgWifi && AvgVet_g_signalDbmAvgAc > AvgVet_g_signalDbmAvgWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                        }
                                              // else { std::cout << "EOF---AvgVet_g_signalDbmAvg" << std::endl;
                                              //
                                              // }


                      //noise Dbm Avg --- c6
                      if (AvgVet_g_noiseDbmAvgWave > AvgVet_g_noiseDbmAvgWifi && AvgVet_g_noiseDbmAvgWave > AvgVet_g_noiseDbmAvgAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgVet_g_noiseDbmAvgWifi > AvgVet_g_noiseDbmAvgWave && AvgVet_g_noiseDbmAvgWifi > AvgVet_g_noiseDbmAvgAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgVet_g_noiseDbmAvgAc > AvgVet_g_noiseDbmAvgWifi && AvgVet_g_noiseDbmAvgAc > AvgVet_g_noiseDbmAvgWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                        }
                                              // else { std::cout << "EOF---AvgVet_g_noiseDbmAvg" << std::endl;
                                              //
                                              // }


                      // g_SNR Avg --- c7
                      if (AvgVet_g_SNRWave > AvgVet_g_SNRWifi && AvgVet_g_SNRWave > AvgVet_g_SNRAc){
                                sumPointsIntB = sumPointsIntB + 1;
                                std::cout << "sumPointsIntB: " << sumPointsIntB << std::endl;
                              } else if (AvgVet_g_SNRWifi > AvgVet_g_SNRWave && AvgVet_g_SNRWifi > AvgVet_g_SNRAc) {
                                        sumPointsIntA = sumPointsIntA + 1;
                                        std::cout << "sumPointsIntA: " << sumPointsIntA << std::endl;
                                      } else if (AvgVet_g_SNRAc > AvgVet_g_SNRWifi && AvgVet_g_SNRAc > AvgVet_g_SNRWave) {
                                                  sumPointsIntC = sumPointsIntC + 1;
                                                  std::cout << "sumPointsIntC: " << sumPointsIntC << std::endl;
                                        }
                                              // else { std::cout << "EOF---AvgVet_g_SNR" << std::endl;
                                              //
                                              // }



                      std::cout << "Number of Points Interface A, " << sumPointsIntA << std::endl;
                      std::cout << "Number of Points Interface B, " << sumPointsIntB << std::endl;
                      std::cout << "Number of Points Interface C, " << sumPointsIntC << std::endl;

                      if (sumPointsIntB > sumPointsIntA && sumPointsIntB > sumPointsIntC ){

                            change=2;

                            for (uint32_t j=0; j < ueNode.GetN();j++){
                                  TearDownLink (ueNode.Get(1), ueNode.Get(j),3,3);
                                  TearDownLink (ueNode.Get(1), ueNode.Get(j),1,1);
                                  std::cout << "Defining interface Wave for communication" << std::endl;
                                  reconfigureUdpClient (wdlClient, ueNode.Get(j), wdport);
                                  TearUpLink (ueNode.Get(1), ueNode.Get(j),2,2,j);

                                }

                              } else if (sumPointsIntA > sumPointsIntB && sumPointsIntA > sumPointsIntC ){

                                    change=1;

                                    for (uint32_t j=0; j < ueNode.GetN();j++){
                                            TearDownLink (ueNode.Get(1), ueNode.Get(j),3,3);
                                            TearDownLink (ueNode.Get(1), ueNode.Get(j),2,2);
                                            std::cout << "Defining interface Wifi for communication" << std::endl;
                                            reconfigureUdpClient (dlClient, ueNode.Get(j), dport);
                                            TearUpLink (ueNode.Get(1), ueNode.Get(j),1,1,j);
                                        }

                                     } else {

                                               change=3;

                                               for (uint32_t j=0; j < ueNode.GetN();j++){
                                                          TearDownLink (ueNode.Get(1), ueNode.Get(j),2,2);
                                                          TearDownLink (ueNode.Get(1), ueNode.Get(j),1,1);
                                                          std::cout << "Defining interface Ac for communication" << std::endl;
                                                          reconfigureUdpClient (acClient, ueNode.Get(j), acport);
                                                          TearUpLink (ueNode.Get(1), ueNode.Get(j),3,3,j);
                                                        }
                                                      }




                      if (old_change != change){
                          numberofchanges=numberofchanges+1;
                          std::cout << "the interface was exchange===" << "Number of times====" << numberofchanges << std::endl;
                      }
                      old_change = change;

                     //memset(old_change,0,sizeof(old_change));
                     //memset(numberofchanges,0,sizeof(numberofchanges));
                     //memset(numberofexecution, 0, sizeof(numberofexecution));
                      // memset(vetBytesReceivedWave, 0, sizeof(vetBytesReceivedWave));
                      // memset(vetBytesReceivedWifi, 0, sizeof(vetBytesReceivedWifi));
                      // memset(throughputWave, 0, sizeof(throughputWave));
                      // memset(throughputWifi, 0, sizeof(throughputWifi));
                      // memset(vet_g_signalDbmAvgWave, 0, sizeof(vet_g_signalDbmAvgWave));
                      // memset(vet_g_signalDbmAvgWifi, 0, sizeof(vet_g_signalDbmAvgWifi));
                      // memset(vet_g_noiseDbmAvgWave, 0, sizeof(vet_g_noiseDbmAvgWave));
                      // memset(vet_g_noiseDbmAvgWifi, 0, sizeof(vet_g_noiseDbmAvgWifi));
                      // memset(vet_g_SNRWave, 0, sizeof(vet_g_SNRWave));
                      // memset(vet_g_SNRWifi, 0, sizeof(vet_g_SNRWifi));


                    //  old_change = change;
                      change=0;
                      sumPointsIntB=0;
                      sumPointsIntA=0;
                      sumPointsIntC=0;


                      // memset(vetBytesDropWave, 0, sizeof(vetBytesDropWave));
                      // memset(vetBytesDropWifi, 0, sizeof(vetBytesDropWifi));
                      // memset(vetBytesReceivedWave, 0, sizeof(vetBytesReceivedWave));
                      // memset(vetBytesReceivedWifi, 0, sizeof(vetBytesReceivedWifi));
                      // memset(throughputWave, 0, sizeof(throughputWave));
                      // memset(throughputWifi, 0, sizeof(throughputWifi));
                      // memset(vet_g_signalDbmAvgWave, 0, sizeof(vet_g_signalDbmAvgWave));
                      // memset(vet_g_signalDbmAvgWifi, 0, sizeof(vet_g_signalDbmAvgWifi));
                      // memset(vet_g_noiseDbmAvgWave, 0, sizeof(vet_g_noiseDbmAvgWave));
                      // memset(vet_g_noiseDbmAvgWifi, 0, sizeof(vet_g_noiseDbmAvgWifi));
                      // memset(vet_g_SNRWave, 0, sizeof(vet_g_SNRWave));
                      // memset(vet_g_SNRWifi, 0, sizeof(vet_g_SNRWifi));
                      totalBytesReceivedSumWave=0;
                      totalBytesReceivedSumWifi=0;
                      totalBytesReceivedSumAc=0;



      }

      numberofexecution=numberofexecution+1;
      std::cout << "IM qtd executions:" << numberofexecution << std::endl;

    Simulator::Schedule (Seconds (1), &InterfaceManager, ueNode, dlClient, wdlClient, acClient, numberofexecution);
  }
//************* End of Interface Manager *******///












void experiment(int &numberOfUEs, const std::string phyMode1, const std::string phyMode2, bool verbose, Ptr<WifiPhyStats> m_wifiPhyStats, int m_mobility, uint32_t m_protocol, double duration, int m_withLte)
{

    // 0.Some settings



//    int nodeSpeed = 20; //in m/s UAVs speed
//    int nodePause = 0; //in s UAVs pause

  //  double interPacketInterval = 100;

    //Time s;
    std::string m_protocolName; ///< protocol name
  //  std::string m_interfaceNameSetting; ///< number of Intefaces setting
    std::string m_mobilityNameSetting; ///< number of Intefaces setting


    void CalculateAvgBuffer();



    // 1. Create nodes
    NodeContainer ueNode;
    ueNode.Create (numberOfUEs);


    //AmoutOfNodes(numberofUes);

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
             internet.SetRoutingHelper (list);
             internet.Install (ueNode);
             olsr.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
             olsr.PrintRoutingTableAllAt (Seconds (146), routingStreamEnd);
             m_protocolName = "OLSR";
            break;
         case 2:
             list.Add (aodv, 10);
             internet.SetRoutingHelper (list);
             internet.Install (ueNode);
             aodv.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
             aodv.PrintRoutingTableAllAt (Seconds (146), routingStreamEnd);
             m_protocolName = "AODV";
           break;
         case 3:
             list.Add (dsdv, 10);
             internet.SetRoutingHelper (list);
             internet.Install (ueNode);
             dsdv.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
             dsdv.PrintRoutingTableAllAt (Seconds (146), routingStreamEnd);
             m_protocolName = "DSDV";
           break;
         default:
           NS_FATAL_ERROR ("No such protocol:" << m_protocol);
           break;
      }


       NS_LOG_UNCOND ("Routing Setup for " << m_protocolName);
       // Ipv4ListRoutingHelper list;

      // OlsrHelper olsr;
      // Ipv4StaticRoutingHelper staticRouting;
      //
      // list.Add (staticRouting, 0);
      // list.Add (olsr, 10);
      //
      // InternetStackHelper internet;
      //   internet.SetRoutingHelper (list); // has effect on the next Install ()
      // internet.Install(ueNode);
      //
      // Ptr<OutputStreamWrapper> routingStreamStart = Create<OutputStreamWrapper> ("olsr_start.routes", std::ios::out);
      // olsr.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);
      //
      // Ptr<OutputStreamWrapper> routingStreamEnd = Create<OutputStreamWrapper> ("olsr_end.routes", std::ios::out);
      // olsr.PrintRoutingTableAllAt (Seconds (duration), routingStreamEnd);







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

    TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");

  //  m_interfaceNameSetting = "Interface Manager";

    YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);
    wifiPhy.SetChannel (channel.Create ());
    wifiPhy.Set ("ChannelNumber", UintegerValue (6));

    channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (2.4e9));
    channel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");

    WifiHelper wifi;
    wifi.SetStandard (WIFI_PHY_STANDARD_80211n_2_4GHZ);
    wifi.SetRemoteStationManager ("ns3::IdealWifiManager");

    WifiMacHelper wifiMac;
    // wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
    //                             "DataMode",StringValue (phyMode1),
    //                             "ControlMode",StringValue (phyMode1));

    // wifiPhy.Set ("TxPowerStart",DoubleValue (m_txp));
    // wifiPhy.Set ("TxPowerEnd", DoubleValue (m_txp));


    wifiMac.SetType ("ns3::AdhocWifiMac");

    NetDeviceContainer wifiDevices = wifi.Install (wifiPhy, wifiMac, ueNode);


    // Tracing
    wifiPhy.EnablePcap("WIFI_80211n_2_4GHZ", wifiDevices);


    // 7. Install PHY and MAC Layer of IEEE 802.11p 5GHz

    Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();
    YansWifiPhyHelper wifiPhy2 =  YansWifiPhyHelper::Default ();

    NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default ();

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

    // 7. Install PHY and MAC Layer of IEEE 802.11ac 5GHz

    std::string wifiManager ("ns3::IdealWifiManager");
    std::string standard ("802.11ac");
    ns3::WifiPhyStandard standard_phy (WIFI_PHY_STANDARD_80211ac);

    WifiHelper wifi2;
    wifi2.SetStandard (standard_phy);
    wifi2.SetRemoteStationManager (wifiManager, "RtsCtsThreshold", UintegerValue (999999));

    YansWifiPhyHelper wifiPhy3 = YansWifiPhyHelper::Default ();
    wifiPhy3.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
    WifiMacHelper wifiMac3;
    wifiMac3.SetType ("ns3::AdhocWifiMac");

    YansWifiChannelHelper helper;
    Ptr<YansWifiChannel> channel3;
    Ptr<LogDistancePropagationLossModel> PropagationLossModel;

    helper.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    // helper.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
    helper.AddPropagationLoss("ns3::FriisPropagationLossModel");
    helper.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
    /* helper.AddPropagationLoss("ns3::RandomWallPropagationLossModel",
    "Walls", DoubleValue(4),
    "Radius", DoubleValue(15),
    "wallLoss", DoubleValue(5)); */

    channel3 = helper.Create();
    wifiPhy3.SetChannel(channel3);



    NetDeviceContainer acDevices = wifi2.Install (wifiPhy3, wifiMac3, ueNode);

  // Tracing
    wifiPhy3.EnablePcap ("AC_80211_5GHZ", acDevices);

    uint16_t nss = 4;
    uint16_t channelWidth = 20;
    uint16_t shortGuardInterval = 800;


    for(uint32_t i=0; i< ueNode.GetN(); ++i) {
            Ptr<NetDevice> nd = acDevices.Get (i);
            Ptr<WifiNetDevice> wnd = nd->GetObject<WifiNetDevice> ();
            Ptr<WifiPhy> wifiPhyPtr = wnd->GetPhy ();
            uint8_t t_Nss = static_cast<uint8_t> (nss);
            wifiPhyPtr->SetNumberOfAntennas (t_Nss);
            wifiPhyPtr->SetMaxSupportedTxSpatialStreams (t_Nss);
            wifiPhyPtr->SetMaxSupportedRxSpatialStreams (t_Nss);

            wifiPhyPtr->SetChannelWidth (channelWidth);
            Ptr<HtConfiguration> HtConfiguration = wnd->GetHtConfiguration ();
            HtConfiguration->SetShortGuardIntervalSupported (shortGuardInterval == 400);
            NS_LOG_DEBUG ("NSS " << wifiPhyPtr->GetMaxSupportedTxSpatialStreams ());
          }



   std::cout << "Wifi+Wave+Ac Intefaces Installed!. Done!" << std::endl;

   //Lte Interfaces

   //if (m_withLte == 1){
         //NetDeviceContainer enbDevs, ueDevs, apDevs;
         NodeContainer enbNode;
         enbNode.Create (1);

         NetDeviceContainer enbDevs; // In Lte we need of ENB
         // For Lte

         //Lte Interfaces
         ConfigStore inputConfig;
         inputConfig.ConfigureDefaults();


         PointToPointHelper p2ph; // We need a point connection with ENB
         std::cout << "P2P helper created!" << std::endl;

         // Installing LTE interface and network configuration
         std::cout << "Configuring LTE!" << std::endl;
         Ptr<LteHelper> lteHelper = CreateObject<LteHelper> ();     //Define LTE
         Ptr<EpcHelper> epcHelper = CreateObject<PointToPointEpcHelper> ();    //Define EPC
         lteHelper->SetEpcHelper (epcHelper);
         lteHelper->SetSchedulerType("ns3::RrFfMacScheduler");
         lteHelper->SetAttribute ("PathlossModel",
                                  StringValue ("ns3::FriisPropagationLossModel"));
         Ptr<Node> pgw = epcHelper->GetPgwNode (); //Define the Packet Data Network Gateway(P-GW)

         //Define the Remote Host (ERB?)
         NodeContainer remoteHostContainer;
         remoteHostContainer.Create (1);
         Ptr<Node> remoteHost = remoteHostContainer.Get (0); //UAV 1 as ERB
         internet.Install (remoteHostContainer);

         //Connect RemoteHost to PGW
         p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("50Mb/s")));
         p2ph.SetDeviceAttribute ("Mtu", UintegerValue (1500));
         p2ph.SetChannelAttribute ("Delay", TimeValue (Seconds (0.010)));

         NetDeviceContainer internetDevices;
         internetDevices = p2ph.Install (pgw, remoteHost);
  //  }
    std::cout << "Starting Internet stack settings on Ue devices!" << std::endl;
    // WiFi Interface
    Ipv4AddressHelper address;
    NS_LOG_INFO ("Assign IP WiFi Addresses.");
    address.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interface;
    interface = address.Assign(wifiDevices);

    // 802.11p
    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interface2 = address.Assign(waveDevices);
    interface.Add(interface2);

    //802.11ac
    address.SetBase("120.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interface3 = address.Assign(acDevices);
    interface.Add(interface3);

    // erb
    //Ipv4AddressHelper address1;
    address.SetBase ("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = address.Assign (internetDevices);      //Ipv4 interfaces
    Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress (1);
    std::cout << "Remote host address : " << remoteHostAddr <<std::endl;

    address.SetBase("2.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer lteInterface = address.Assign(wifiDevices);
    interface.Add(lteInterface);
    std::cout << "Internet stack installed on Ue devices!" << std::endl;


    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting = ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());    //Ipv4 static routing helper
    remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);

    // /* Mobility stuff */
    // MobilityHelper mobility;
    // mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    // mobility.Install(enbNode);
    // std::cout << "Mobility enbNode installed" << std::endl;

    // 2. Place nodes

    if (m_mobility==1){
              std::string m_traceFile= "/home/doutorado/sumo/examples/fanet/different_speed_sumo/mobility_manyspeed.tcl";
              m_mobilityNameSetting = "Experiment of 3 uavs (mobility nodos) in a 300 x 400 area";

              // Create Ns2MobilityHelper with the specified trace log file as parameter
              Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
              ns2.Install (); // configure movements for each node, while reading trace file

              NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);

            } else if (m_mobility==2) {

                  std::string m_traceFile= "/home/doutorado/sumo/examples/fanet10/mobility.tcl";
                  m_mobilityNameSetting = "Experiment of 10 uavs (mobility nodos) in a 300 x 400 area";

                    // Create Ns2MobilityHelper with the specified trace log file as parameter
                    Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
                    ns2.Install (); // configure movements for each node, while reading trace file

                    NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);


                    }  else if (m_mobility==3) {
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
                            mobility.Install(enbNode);

                            NS_LOG_UNCOND ("Experiment Log of ------>" << m_mobilityNameSetting);
                            if (m_withLte == 1){
                              /* Install Lte devices to the nodes */
                                enbDevs = lteHelper->InstallEnbDevice (enbNode);
                                wifiDevices = lteHelper->InstallUeDevice (ueNode);
                                 }


                          }


    std::cout << "Mobility installed" << std::endl;


    /* install internet stack on ues, wifi nodes */
    Ipv4InterfaceContainer iueIpIface;
    iueIpIface = epcHelper->AssignUeIpv4Address (NetDeviceContainer (wifiDevices));
    for (uint32_t u = 0; u < ueNode.GetN (); ++u)
    	{
      Ptr<Node> ueNod = ueNode.Get(u);
      Ptr<Ipv4StaticRouting> ueStaticRouting = ipv4RoutingHelper.GetStaticRouting (ueNod->GetObject<Ipv4> ());
      ueStaticRouting->SetDefaultRoute (epcHelper->GetUeDefaultGatewayAddress (), 1);
    	}
    std::cout << "Internet on Ues installed" << std::endl;


    // Attach all UEs to eNodeB
    for (uint16_t j=0; j < numberOfUEs; j++)
    	{
  	       lteHelper->Attach (wifiDevices.Get(j), enbDevs.Get(0));
    	}



    std::cout << "LTE+EPC+remotehost installed. Done!" << std::endl;


    // 8. Printing interfaces installed to Nodos
    for (uint32_t u = 0; u < ueNode.GetN (); ++u)
    {
          Ptr<Node> node = ueNode.Get(u);
          Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
          Ipv4Address addr = ipv4->GetAddress(0,0).GetLocal();
          std::cout << std::endl << "Node " << u << "\taddress 0: " << addr <<std::endl;
          addr = ipv4->GetAddress(1,0).GetLocal();
          std::cout << "Node " << u << "\taddress 1: " << addr <<std::endl;
          addr = ipv4->GetAddress(2,0).GetLocal();
          std::cout << "Node " << u << "\taddress 2: " << addr <<std::endl;
          addr = ipv4->GetAddress(3,0).GetLocal();
          std::cout << "Node " << u << "\taddress 3: " << addr <<std::endl;
          addr = ipv4->GetAddress(4,0).GetLocal();
          std::cout << "Node " << u << "\taddress 4: " << addr <<std::endl;

  }

        Ptr<Node> node = ueNode.Get(0);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ipv4Address addr = ipv4->GetAddress(0,0).GetLocal();
        ipv4 = pgw->GetObject<Ipv4>();
        addr = ipv4->GetAddress(0,0).GetLocal();
        std::cout << std::endl << "PGW address 0: " << addr <<std::endl;
        addr = ipv4->GetAddress(1,0).GetLocal();
        std::cout << "PGW address 1: " << addr <<std::endl;
        addr = ipv4->GetAddress(2,0).GetLocal();
        std::cout << "PGW address 2: " << addr <<std::endl;

    //process of creating of sockets -- for conection withOUT Gazebo
    // for (int i = 0; i < numberOfUEs; i++)
    //   {
    //     // protocol == 0 means no routing data, WAVE BSM only
    //     // so do not set up sink
    //
    //     Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (i), tid);
    //     InetSocketAddress local = InetSocketAddress (interface.GetAddress (i), 80);
    //     recvSink->Bind (local);
    //     recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
    //
    //
    //   }

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

                // Logs
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

          // Functions
          void ReceivePacket2 (Ptr <Socket> socket);
          void ReceivesPacket (std::string context, Ptr <const Packet> p);
          void vetorBytesReceived (std::string context, Ptr <const Packet> p);
          void ReceivedPacket (Ptr<const Packet> p, const Address & addr);
      //    void CheckThroughput ();
          void DroppedPacket (std::string context, Ptr<const Packet> p);
          //  void CalculateThroughput2 (Ptr<WifiPhyStats> m_wifiPhyStats);
          Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node );

          AsciiTraceHelper ascii, ascii2;


          if (verbose) {
              wifi.EnableLogComponents ();  // Turn on all Wifi logging
              wifi80211p.EnableLogComponents ();  // Turn on all Wifi logging
              wifi2.EnableLogComponents ();  // Turn on all Wifi logging

          }

          wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("PacketTxWiFi_intMan.tr"));
          wifiPhy2.EnableAsciiAll (ascii2.CreateFileStream ("PacketTxWave_intMan.tr"));
          wifiPhy3.EnableAsciiAll (ascii2.CreateFileStream ("PacketTxAc_intMan.tr"));

          std::cout << "Starting the Interface Manager Execution " << std::endl;

          std::cout << "APP traffic with different ToS " << std::endl;



          ApplicationContainer sourceApplications, sinkApplications;
          std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
          uint32_t portNumber = 100;

            //  for (uint32_t index = 1; index < nWifi; ++index)
            //  {
                for (uint8_t tosValue : tosValues)
                  {


                          for (uint32_t u = 0; u < ueNode.GetN (); ++u)
                          {
                            auto ipv4 = ueNode.Get (u)->GetObject<Ipv4> ();
                            const auto address = ipv4->GetAddress (1, 0).GetLocal ();


                            InetSocketAddress sinkSocket (address, portNumber++);
                            sinkSocket.SetTos (tosValue);


                            OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
                            onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
                            onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
                            onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
                            onOffHelper.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
                        //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));

                            PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
                            sinkApplications.Add (packetSinkHelper.Install (ueNode.Get (u)));

                            //sourceApplications.Add (onOffHelper.Install (ueNode.Get (u)));
                            // for (uint32_t i=0; i < ueNode.GetN ();i++){
                            //     if (i != 1) {
                                        sourceApplications.Add (onOffHelper.Install (ueNode.Get (u)));
                                      // source
                                      //     }
                                      // }


                        }
                      }


                  sinkApplications.Start (Seconds (0.0));
                  sinkApplications.Stop (Seconds (duration+5));
                  sourceApplications.Start (Seconds (0.1));

              ApplicationContainer sourceApplications2, sinkApplications2;
              uint32_t portNumber2 = 200;

              //  for (uint32_t index = 1; index < nWifi; ++index)
              //  {
                  for (uint8_t tosValue : tosValues)
                    {
                      for (uint32_t u = 0; u < ueNode.GetN (); ++u)
                      {

                            auto ipv4 = ueNode.Get (u)->GetObject<Ipv4> ();
                            const auto address2 = ipv4->GetAddress (2, 0).GetLocal ();
                            InetSocketAddress sinkSocket2 (address2, portNumber2++);

                            sinkSocket2.SetTos (tosValue);

                            OnOffHelper onOffHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
                            onOffHelper2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
                            onOffHelper2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
                            onOffHelper2.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
                            onOffHelper2.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
                        //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));

                            PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", sinkSocket2);

                            sinkApplications2.Add (packetSinkHelper2.Install (ueNode.Get (u)));

                           sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (u)));

                        // for (uint32_t i=0; i < ueNode.GetN ();i++){
                        //     if (i != 1) {
                        //           sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (i)));
                        //         // source
                        //             }
                        //         }

                        }

                    }

          sinkApplications2.Start (Seconds (0.0));
          sinkApplications2.Stop (Seconds (duration+5));
          sourceApplications2.Start (Seconds (0.1));

          ApplicationContainer sourceApplications3, sinkApplications3;
          uint32_t portNumber3 = 300;

          //  for (uint32_t index = 1; index < nWifi; ++index)
          //  {
              for (uint8_t tosValue : tosValues)
                {

                  for (uint32_t u = 0; u < ueNode.GetN (); ++u)
                  {


                        auto ipv4 = ueNode.Get (u)->GetObject<Ipv4> ();
                        const auto address3 = ipv4->GetAddress (3, 0).GetLocal ();
                        InetSocketAddress sinkSocket3 (address3, portNumber3++);

                        sinkSocket3.SetTos (tosValue);

                        OnOffHelper onOffHelper3 ("ns3::UdpSocketFactory", sinkSocket3);
                        onOffHelper3.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
                        onOffHelper3.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
                        onOffHelper3.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
                        onOffHelper3.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
                    //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));

                        PacketSinkHelper packetSinkHelper3 ("ns3::UdpSocketFactory", sinkSocket3);

                        sinkApplications3.Add (packetSinkHelper3.Install (ueNode.Get (u)));

                        // for (uint32_t i=0; i < ueNode.GetN ();i++){
                        //     if (i != 1) {
                                    sourceApplications3.Add (onOffHelper3.Install (ueNode.Get (u)));
                                  // source
                                  //     }
                                  // }


                      //  sourceApplications3.Add (onOffHelper3.Install (ueNode.Get (u)));


                              // source
                   }

          }

      sinkApplications3.Start (Seconds (0.0));
      sinkApplications3.Stop (Seconds (duration+5));
      sourceApplications3.Start (Seconds (0.1));



    //
    //           //  for (uint32_t index = 1; index < nWifi; ++index)
    //           //  {
    //               for (uint8_t tosValue : tosValues)
    //                 {
    //
    //                   auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
    //
    //
    //                   sinkSocket2.SetTos (tosValue);
    //
    //                   OnOffHelper onOffHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
    //                   onOffHelper2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
    //                   onOffHelper2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
    //                   onOffHelper2.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
    //                   onOffHelper2.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
    //               //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
    //
    //                   PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
    //
    //                   sinkApplications2.Add (packetSinkHelper2.Install (ueNode.Get (1)));
    //
    //               for (uint32_t i=0; i < ueNode.GetN ();i++){
    //                           sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (i)));
    //
    //                         // source
    //               }
    //
    //           }
    //
    //       sinkApplications2.Start (Seconds (0.0));
    //       sinkApplications2.Stop (Seconds (duration+5));
    //       sourceApplications2.Start (Seconds (0.1));
    //
    //       ApplicationContainer sourceApplications3, sinkApplications3;
    // //      std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
    //
    //         //  for (uint32_t index = 1; index < nWifi; ++index)
    //         //  {
    //             for (uint8_t tosValue : tosValues)
    //               {
    //
    //                 auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
    //                 const auto address3 = ipv4->GetAddress (3, 0).GetLocal ();
    //
    //                 InetSocketAddress sinkSocket3 (address3, portNumber3++);
    //
    //
    //                 sinkSocket3.SetTos (tosValue);
    //
    //
    //                 OnOffHelper onOffHelper3 ("ns3::UdpSocketFactory", sinkSocket3);
    //                 onOffHelper3.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
    //                 onOffHelper3.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
    //                 onOffHelper3.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
    //                 onOffHelper3.SetAttribute ("PacketSize", UintegerValue (pktSize)); //bytes
    //             //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
    //
    //                 PacketSinkHelper packetSinkHelper3 ("ns3::UdpSocketFactory", sinkSocket3);
    //                 sinkApplications3.Add (packetSinkHelper3.Install (ueNode.Get (1)));
    //
    //             for (uint32_t i=0; i < ueNode.GetN ();i++){
    //                         sourceApplications3.Add (onOffHelper3.Install (ueNode.Get (i)));
    //                       }
    //               }
    //               sinkApplications3.Start (Seconds (0.0));
    //               sinkApplications3.Stop (Seconds (duration+5));
    //               sourceApplications3.Start (Seconds (0.1));


          std::cout << "CBR traffic to maintain connection " << std::endl;
            //80211p
          uint32_t payloadSize = 1500; //bytes
          double interPacketInterval = 100;
          ApplicationContainer clientApps, serverApps;

          UdpClientHelper dlClient (interface.GetAddress (1), dport);
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


          PacketSinkHelper dlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (interface.GetAddress (1), dport));



          for (uint32_t i=0; i < ueNode.GetN ();i++){

      //            std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;
          //    std::cout << std::endl;
            //  std::cout << "wave add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;


              serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(i)));
              // clientApps.Add (dlClient.Install (ueNode.Get(i)));

          }

          // Wifi test apps 80211n

          // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
          //std::cout << std::endl;
        //  std::cout << "wifi src add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;


          UdpClientHelper wdlClient (interface.GetAddress (2), wdport);
          wdlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
          // wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
          wdlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
          wdlClient.SetAttribute("StartTime", TimeValue(Seconds(1)));
          wdlClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));

          for (uint32_t i=0; i < ueNode.GetN ();i++){
                    //  std::cout << std::endl;
                  //    std::cout << "wifi add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;

                      clientApps.Add (wdlClient.Install (ueNode.Get(i)));
          }

          PacketSinkHelper wdlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (interface.GetAddress (2), wdport));

          for (uint32_t i=0; i < ueNode.GetN ();i++){
                      serverApps.Add (wdlPacketSinkHelper.Install (ueNode.Get(i)));
                      // clientApps.Add (dlClient.Install (ueNode.Get(i)));
              }


//802.11ac

            // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
            // std::cout << std::endl;
            // std::cout << "Ac src add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(3,0).GetLocal() << std::endl;

            UdpClientHelper acClient (interface.GetAddress (3), acport);
            acClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
            // wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
            acClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
            acClient.SetAttribute("StartTime", TimeValue(Seconds(1)));
            acClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));

            for (uint32_t i=0; i < ueNode.GetN ();i++){
                    //    std::cout << std::endl;
                  //      std::cout << "Ac add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(3,0).GetLocal() << std::endl;

      //                        std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(3,0).GetLocal() << std::endl;

                        clientApps.Add (acClient.Install (ueNode.Get(i)));
            }

            PacketSinkHelper acPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (interface.GetAddress (3), acport));

            for (uint32_t i=0; i < ueNode.GetN ();i++){
                        serverApps.Add (acPacketSinkHelper.Install (ueNode.Get(i)));
                        // clientApps.Add (dlClient.Install (ueNode.Get(i)));
                }




        //if (m_withLte == 1){


                  // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
                  UdpClientHelper lteClient (iueIpIface.GetAddress (0), lteport);
                  lteClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
                //  dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
                  lteClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
                  lteClient.SetAttribute("StartTime", TimeValue(Seconds(1)));
                  lteClient.SetAttribute("StopTime", TimeValue(Seconds(duration)));

                  for (uint32_t i=0; i < ueNode.GetN ();i++){
                          //    std::cout << std::endl;
                        //      std::cout << "Ac add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(3,0).GetLocal() << std::endl;

            //                        std::cout << "wifi dest add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(3,0).GetLocal() << std::endl;

                              clientApps.Add (lteClient.Install (ueNode.Get(i)));
                  }
                //  clientApps.Add (dlClient.Install (ueNode.Get(1)));
                  // Downlink (sink) Sink on Ue 0 :: receives data from Remote Host
                //  PacketSinkHelper dlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport));
                  //PacketSinkHelper dlPacketSinkHelper1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport1));

                  UdpServerHelper ltePacketSinkHelper(lteport);
                //  UdpServerHelper dlPacketSinkHelper1(dport1);
                  serverApps.Add (ltePacketSinkHelper.Install (ueNode.Get(0)));
            //      serverApps.Add (dlPacketSinkHelper1.Install (ueNode.Get(0)));


                  // for (uint32_t i=0; i < ueNode.GetN ();i++){
                  //             serverApps.Add (ltePacketSinkHelper.Install (ueNode.Get(i)));
                  //             // clientApps.Add (dlClient.Install (ueNode.Get(i)));
                  //     }

                //      InterfaceManager (ueNode, dlClient, wdlClient, acClient, numberofexecution);


        //}

    //    InterfaceManager (ueNode, dlClient, wdlClient, acClient, numberofexecution);


        // Run experiment
        std::cout << "VERIFYING THE CURRENT TIME!" << std::endl;
        std::cout << "USING SIMULATOR!--->" << Simulator::Now ().GetMilliSeconds() << "s" << std::endl;
  //      std::cout << "USING Timer MilliSeconds!--->" << s.GetNanoSeconds() << "ns" << std::endl;
//        std::cout << "USING Timer Seconds!--->" <<s.GetSeconds() << "s" << std::endl;



         InterfaceManager (ueNode, dlClient, wdlClient, acClient, numberofexecution);







        // 11.2 Monitor collisions

        Config::ConnectWithoutContext ("/NodeList/*/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));

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




        /*Rastreia os pacotes recebidos no terminal escolhido*/
        Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
        // Config::Connect ("/NodeList/2/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
        // Config::Connect ("/NodeList/3/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
  //      Config::Connect("/NodeList/*/DeviceList/*/Mac/MacRx", MakeCallback(&traceqos));
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

        // 11. monitoring

       Simulator::Schedule(Seconds(0.1), &CalculatePhyRxDrop, m_wifiPhyStats);
       Simulator::Schedule(Seconds(0.1), &CalculateAvgBuffer);




     //NS_LOG_UNCOND ("Experiment Log of ------>" << m_interfaceNameSetting);

     Packet::EnablePrinting ();



    // for (int u = 0; u < numberOfUEs; ++u)
    // {
    //     Ptr<Node> node = ueNode.Get (u);
    //     Ptr<Ipv4StaticRouting> interface2HostStaticRouting = ipv4RoutingHelper.GetStaticRouting (node->GetObject<Ipv4> ());    //Ipv4 static routing helper
    //     interface2HostStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 2);
    // }

   Ptr<Ipv4> ip_wireless[numberOfUEs];
   for (int i = 0; i < numberOfUEs; i++)
   {
       ip_wireless[i] = ueNode.Get(i)->GetObject<Ipv4> ();
   }










    // for (int i = 0; i < numberOfUEs; i++)
    //   {
    //     // protocol == 0 means no routing data, WAVE BSM only
    //     // so do not set up sink
    //
    //     Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (i), tid);
    //     InetSocketAddress local = InetSocketAddress (interface.GetAddress (i), 80);
    //     recvSink->Bind (local);
    //     recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
    //
    //
    //   }








//   Simulator::Schedule(Seconds(0.1), &CalculateThroughput);
//   Simulator::Schedule(Seconds(0.1), &CalculateThroughput2,m_wifiPhyStats);

    //Simulator::Schedule (MilliSeconds (300), &vetorBytesReceived);







    // rdTrace.open("throughputmeasurementstesttotalap.dat", std::ios::out);                                             //
    //   rdTrace << "# Time \t Throughput \n";
    //
    //  rdTraced.open("receivedvsdropped.dat", std::ios::out);                                             //
    //   rdTraced << "# Time \t Dropped \n received \n" ;
    // //  Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivedPacket));





   // Tracing

   //11.2 Trace

  // Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivedPacket));

   //Packet::EnablePrinting ();

   Ipv4GlobalRoutingHelper::PopulateRoutingTables ();


   // 11.3 Install FlowMonitor on all nodes
   Ptr<FlowMonitor> flowMonitor;
   FlowMonitorHelper flowHelper;
   flowMonitor = flowHelper.InstallAll();

   FlowMonitorHelper flowmon;
   Ptr<FlowMonitor> monitor = flowmon.InstallAll();
   // Packet::EnablePrinting ();
   // Packet::EnableChecking ();

   for (int i=0; i<numberOfUEs; ++i) {
     Simulator::Schedule (Seconds (0.1), &CheckThroughputbyNode, m_wifiPhyStats, ueNode.Get(i));
   }

   // std::map<std::pair<ns3::Ipv4Address, ns3::Ipv4Address>, std::vector<int>> data;
   //
   // Simulator::Schedule(Seconds(1),&ThroughputMonitor,&flowmon, monitor, data);


   ns3::PacketMetadata::Enable ();




   // 13. Print statistics
   std::map<std::pair<ns3::Ipv4Address, ns3::Ipv4Address>, std::vector<int>> data;




    //12. Run simulation for "duration" seconds
    Simulator::Stop (Seconds (duration+5));

    // for simulation with gazebo
    // animationInterface anim ("interfaceManagerbeta_Anim.xml");
    // anim.EnablePacketMetadata(true);



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

        std::cout << "Throughput Kbps: " << i->second.rxBytes / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps\n";
        //
  		  std::cout << " Throughput : " << i->second.rxBytes / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n";



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
    Simulator::Destroy();

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

  //conection Gazebo
    GlobalValue::Bind("SimulatorImplementationType", StringValue("ns3::ExternalSyncSimulatorImpl"));

    // Defaults
    // if we use mobility from Gazebo the simulationTime is defined by Gazebo simulation
    double duration = 146.0; //seconds if experiment in sumo 90.0 gazebo 140
    int numberOfUEs=3; //Default number of UEs attached to each eNodeB
    bool verbose=false;
    uint32_t packetSize = 1472; // bytes
  //  double m_txp=100; ///< distance



    int m_mobility=4;
    //double m_txp=20;
    uint32_t m_protocol=1; ///< protocol
    int m_withLte=1; ///< protocol

    std::string context;
    Ptr <const Packet> p;


    // For Wifi Network
    std::string phyMode1 ("OfdmRate9Mbps");
    //For Wave Network
    std::string phyMode2 ("OfdmRate6MbpsBW10MHz");

    size_t runs = 1;

    Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
    m_wifiPhyStats = CreateObject<WifiPhyStats> ();

    // Parse command line
    CommandLine cmd;
    // if we use mobility from Gazebo the simulationTime is defined by Gazebo simulation
    cmd.AddValue ("simulationTime", "Simulation time in seconds", duration);
    cmd.AddValue("numberOfNodes", "Amount of nodes. Default: 3", numberOfUEs);
    cmd.AddValue ("verbose", "turn on all WifiNetDevice ans WavwNetDevice log components", verbose);
    cmd.AddValue ("packetSize", "Define size of packets", packetSize);
    cmd.AddValue ("txWiFi", "Define WiFi transmission rate", phyMode1);
    cmd.AddValue ("txWave", "Define Wave transmission rate", phyMode2);
    cmd.AddValue ("mobility", "Define if mobility is based on tracefile or constant position.\n 1-Experiment of 3 uavs (mobility nodos) in a 300 x 400 area \n 2-Experiment of 10 uavs (mobility nodos) in a 300 x 400 area \n 3-Experiment of 3 nodos via Gazebo \n  >=4 -Experiment with Gazebo", m_mobility);
    cmd.AddValue("runs", "Run count. Default: 1.", runs);
    cmd.AddValue("NumberOfInterfaces", "Define the number of communication interface. 0-WITHOUT Lte 1- WITH Lte\n. Default: 0.", m_withLte);
    //cmd.AddValue ("protocol", "0=NONE;1=OLSR;2=AODV;3=DSDV", m_protocol);
//    cmd.AddValue ("txp", "Transmit power (dB), e.g. txp=7.5", m_txp);
    cmd.Parse (argc, argv);





      // // disable fragmentation for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
      // // turn off RTS/CTS for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("1000"));

    // conection Gazebo
    ExternalSyncManager::SetSimulatorController("127.0.0.1", 7833);
    ExternalSyncManager::SetNodeControllerServerPort(9998);


    Time::SetResolution (Time::NS);
    Time s;



    // Run experiment
    std::cout << "Starting!" << std::endl;
    std::cout << "Duration of Experiment NS-3!--->" << duration << "s" << "plus Time of vehicle initialise 5s" << std::endl;


    std::cout << "Time-->" << s << "ns" << std::endl;


        //  std::cout << "F1 Tx Packets;F1 Rx Packets;F1 Tx Bytes;F1 Rx Bytes;F2 Tx Packets;F2 Rx Packets;F2 Tx Bytes;F2 Rx Bytes;Collisions\n";
        for (size_t i = 0; i < runs; ++i)
        {
            experiment(numberOfUEs, phyMode1, phyMode2, verbose,m_wifiPhyStats, m_mobility, m_protocol, duration, m_withLte);


        }



    return 0;

}
