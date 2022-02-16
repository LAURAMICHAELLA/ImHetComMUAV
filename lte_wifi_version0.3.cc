/*
 * lte.cc
 *
 *  Created on: Jul 17, 2019
 *      Author: ubuntu
 * Based on anas version https://groups.google.com/forum/#!searchin/ns-3-users/anas%7Csort:date/ns-3-users/ybKYurgIF98/UNlvKrdECwAJ
 * Version: 0.2 - 2020/03/24 by Laura -
 *
 *
 */


/*
To simulate with logs of internetIpIfaces
./waf --run "scratch/lte_wifi_anas" 2>&1 | tee analyse.txt


*/
#include "ns3/core-module.h"
#include "ns3/config-store-module.h"

#include <sstream>
#include <stdint.h>



#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/applications-module.h"
#include "ns3/lte-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/yans-wifi-helper.h"

#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/wifi-module.h"

#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/internet-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipcs-classifier-record.h"
#include "ns3/service-flow.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/lte-module.h"
#include "ns3/point-to-point-helper.h"
#include <iomanip>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstdio>
#include <sstream>
#include "ns3/yans-wifi-helper.h"
#include "ns3/mobility-helper.h"
#include "ns3/seq-ts-header.h"
#include "ns3/wave-net-device.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/yans-wifi-helper.h"


#include "ns3/propagation-module.h"
NS_LOG_COMPONENT_DEFINE ("LteWifiSimpleExample");

using namespace ns3;
uint32_t totalBytesReceived = 0;

uint32_t totalBytesReceived1=0;
uint32_t totalBytesReceived2=0;
uint32_t totalSumBytesReceived=0;
uint32_t totalSumLteBytesReceived=0;
uint32_t totalSumWaveBytesReceived=0;
uint32_t nNodes=2;
//uint32_t totalPhyTxBytes=0;
std::vector<double> throughputA (100);
std::ofstream rdTrace;
std::ofstream rdTrace2;
std::vector<uint32_t> lteBytesReceived(100);
//uint32_t lteBytesReceived=0;
//uint32_t ltePacketsReceived=0;
uint32_t m_bytesTotal;


std::vector<double> wifiThroughputPerNode (100);
std::vector<uint32_t> wifiPacketsReceived (100);
std::vector<double> wifiPacketsSent (100);
std::ofstream phyTxTraceFile;
std::ofstream macTxTraceFile;
std::ofstream socketRecvTraceFile;
std::vector<uint32_t> ltePacketsReceived(100);
int const sources = 1;
std::vector <uint32_t> totalBytesReceivedNew (sources);
std::vector <double> m_txSafetyRanges; ///< list of ranges
double totalPhyTxBytes=0;
uint32_t macTxDropCount(0), phyTxDropCount(0), phyRxDropCount(0);

uint32_t
ContextToNodeId1 (std::string context)
{
  std::string sub = context.substr (10);  // skip "/NodeList/"
  uint32_t pos = sub.find ("/Device");
  NS_LOG_DEBUG ("Found NodeId " << atoi (sub.substr (0, pos).c_str ()));
  return atoi (sub.substr (0,pos).c_str ());
}

void MacTxDrop(Ptr<const Packet> p)
{
    std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Mac Tx Drop!" << macTxDropCount << std::endl;
    macTxDropCount++;
}

void PhyTxDrop(Ptr<const Packet> p)
{
  std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Phy Tx Drop!" << phyTxDropCount << std::endl;
  phyTxDropCount++;
}

void PhyRxDrop(Ptr<const Packet> p)
{
  std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Phy Rx Drop!" << phyRxDropCount << std::endl;
  phyRxDropCount++;
}

void ResetDropCounters()
{
    macTxDropCount = 0;
    phyTxDropCount = 0;
    phyRxDropCount = 0;
    totalBytesReceived = 0;
    totalSumBytesReceived = 0;
}

int64_t pktCount_n; //sinalização de pacotes

void ReceivePacket (Ptr<Socket> socket)
{
  while (socket->Recv ())
    {
      NS_LOG_UNCOND ("Received one packet!");
      std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "Received one packet!" << std::endl;
    }
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
//
// uint32_t
// ContextToNodeId1 (std::string context)
// {
//   std::string sub = context.substr (10);  // skip "/NodeList/"
//   uint32_t pos = sub.find ("/Device");
//   NS_LOG_DEBUG ("Found NodeId " << atoi (sub.substr (0, pos).c_str ()));
//   return atoi (sub.substr (0,pos).c_str ());
// }

uint32_t pktSize = 1500; //1500

// o que vai dar
void
SocketRecvStats (std::string context, Ptr<const Packet> p, const Address &addr)
{
      totalBytesReceived2 += p->GetSize ();
      std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Received_1 : " << totalBytesReceived2 << std::endl;
}


//



void TearDownLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB)
{
  std::cout << "Setting down Remote Host -> Ue 1" << std::endl;

  std::cout << "source " << nodeA->GetObject<Ipv4>()->GetAddress(interfaceA,0).GetLocal();
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetDown (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetDown (interfaceB);
}

void TearUpLink (Ptr<Node> nodeA, Ptr<Node> nodeB, uint32_t interfaceA, uint32_t interfaceB, std::string phyMode2)
{
  std::cout << "Setting UP Remote Host -> Ue 1" << std::endl;

  std::cout << "source " << nodeA->GetObject<Ipv4>()->GetAddress(interfaceA,0).GetLocal();
  std::cout << " dest " << nodeB->GetObject<Ipv4>()->GetAddress(interfaceB,0).GetLocal() << std::endl;

  nodeA->GetObject<Ipv4> ()->SetUp (interfaceA);
  nodeB->GetObject<Ipv4> ()->SetUp (interfaceB);
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



/////// Extra

// void ReceivePacket (Ptr<Socket> socket)
// {
//   while (socket->Recv ())
//     {
//       NS_LOG_UNCOND ("Received one packet!");
//     }
// }

// /**
//  * \ingroup wave
//  * \brief The WifiPhyStats class collects Wifi MAC/PHY statistics
//  */
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
}

void
WifiPhyStats::PhyRxDrop (std::string context, Ptr<const Packet> packet)
{
  NS_LOG_UNCOND ("PHY Rx Drop");
}

uint32_t
WifiPhyStats::GetTxBytes ()
{
  return m_phyTxBytes;
}

// /* for packet drop  count */



void CalculatePhyRxDrop (Ptr<WifiPhyStats> m_wifiPhyStats)
 {
 double totalPhyTxBytes = m_wifiPhyStats->GetTxBytes ();
 double DropBytes = pktSize - totalPhyTxBytes;

  std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "\tBytes TX=" << totalPhyTxBytes << "\tDrop Bytes (Sended-Received):" << DropBytes<< std::endl;
  ResetDropCounters();
  Simulator::Schedule (MilliSeconds(100), &CalculatePhyRxDrop, m_wifiPhyStats);
}


void CalculateThroughput ()
{

   double mbs2 = ((totalBytesReceived * 8.0)/(1000000*1));

   std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "\tThroughput=" << mbs2 << "\tQtd bytes Received:" << totalBytesReceived<< std::endl;
   totalSumBytesReceived =totalBytesReceived+totalSumBytesReceived;
   std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Total bytes received=\t" << totalSumBytesReceived << std::endl;

   rdTrace << Simulator::Now ().GetSeconds() << "\t" << mbs2 <<"\n";
   std::cout << "\n";
   //ResetDropCounters();


   Simulator::Schedule (MilliSeconds(100), &CalculateThroughput);
}


bool
Receive (Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t mode, const Address &sender)
{
  SeqTsHeader seqTs;
  pkt->PeekHeader (seqTs);
  std::cout << "receive a packet: " << std::endl
            << "  sequence = " << seqTs.GetSeq () << "," << std::endl
            << "  sendTime = " << seqTs.GetTs ().GetSeconds () << "s," << std::endl
            << "  recvTime = " << Now ().GetSeconds () << "s," << std::endl
            << "  protocol = 0x" << std::hex << mode << std::dec  << std::endl;
  return true;
}

void ReceivesPacket(std::string context, Ptr <const Packet> p)
 {
	  //char c= context.at(24);
 	  //int index= c - '0';
 	  //totalBytesReceived[index] += p->GetSize();

   		totalBytesReceived += p->GetSize();
   	  std::cout<< "Received : " << totalBytesReceived << std::endl;
}






int main (int argc, char *argv[])
{
  std::cout << "Starting!" << std::endl;


  //uint32_t packetSize = 1472; // bytes


  //double m_txp=20; ///< distance

  std::string fileDir = "/home/doutorado/ns-allinone-3.30.1/ns-3.30.1/test-output";
  //bool m_tracing = true;
  bool verbose = false;



  uint32_t numberOfUEs=4; //Default number of UEs attached to each eNodeB
//1  uint32_t eNBs=1; //Default number of eNbs in case of LTE interface
  // For Wifi Network
  std::string phyMode1 ("DsssRate1Mbps");
  //For Wave Network
  std::string phyMode2 ("OfdmRate6MbpsBW10MHz");
  double duration = 20; //seconds
  //double monitorInterval = 0.100;
//  std::string rate ("1Mbps");
//  std::string phyMode ("ErpOfdmRate54Mbps");
  void ReceivesPacket (std::string context, Ptr <const Packet> p);
  void CalculateThroughput();

  void MacTxDrop(Ptr<const Packet> p);
  void PhyTxDrop(Ptr<const Packet> p);

  void PhyRxDrop(Ptr<const Packet> p);




  CommandLine cmd;
  cmd.AddValue ("simulationTime", "Simulation time in seconds", duration);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice ans WavwNetDevice log components", verbose);

  cmd.Parse (argc,argv);

  Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
  m_wifiPhyStats = CreateObject<WifiPhyStats> ();
  // m_txSafetyRanges.resize (10, 0);
  // m_txSafetyRanges[0] = 50.0;
  // m_txSafetyRanges[1] = 100.0;
//  void ReceivesPacket (std::string context, Ptr <const Packet> p);





  // Fix non-unicast data rate to be the same as that of unicast
  // Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
  //                 StringValue (phyMode1));
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                  StringValue (phyMode1));

//  Config::SetDefault ("ns3::OnOffApplication::PacketSize", StringValue ("1000"));
//  Config::SetDefault ("ns3::OnOffApplication::DataRate", StringValue (rate));
//  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (phyMode));
//  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2000"));


  // NODES
  // Each node assum a behavior, ue in Lte networks and stas in wifi networks
  // once we have an ad-hoc network apNodes don't exist
  // condidering that in LTE networks we need one enbNode at list
  //NodeContainer ueNode, enbNode, apNode;
  NodeContainer ueNode;
  ueNode.Create (numberOfUEs);
//  enbNode.Create (eNBs);
  //apNode.Create (1);
  std::cout << "Node Containers created, for " << numberOfUEs << "nodes clients!" << std::endl;
  //std::cout << "Node Containers created, for " << eNBs << "eNBs or ERBs in case of LTE interface!" << std::endl;

  //NetDeviceContainer enbDevs, ueDevs, apDevs;
  NetDeviceContainer wifiDevs;



  // Installing Wifi 5.0 GHz Stuff on UEs
  std::cout << "Configuring ad-hoc network interface: WIFI 5 GHz!" << std::endl;

  // the frequency
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211n_5GHZ);
  wifi.EnableLogComponents ();  // Turn on all Wifi logging
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                              "DataMode",StringValue (phyMode1),
                              "ControlMode",StringValue (phyMode1));

  //the MAC
  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");

  // Channel
  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
  channel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5e9));
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  wifiPhy.SetChannel (channel.Create ());
  wifiPhy.Set ("ChannelNumber", UintegerValue (36));

  // Propagation loss models are additive.
  // modelo de perdas
  // channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  // channel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5e9));


  wifiDevs = wifi.Install (wifiPhy, mac, ueNode);


  // Installing internet stack
  InternetStackHelper internet;
  //internet.Install(apNode);
  internet.Install(ueNode);
  std::cout << "Internet stack installed on Ue devices!" << std::endl;

  /* Assign nodes addresses for nodes, one for which interface */

  // WiFi Interface
  Ipv4AddressHelper address;
  NS_LOG_INFO ("Assign IP WiFi Addresses.");
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interface1;
  interface1 = address.Assign(wifiDevs);

  //second Interface
  // ------ > Interface IEEE 802.11p Wave Configurations <------
  // The below set of helpers will help us to put together the wifi NICs we want
  //YansWifiPhyHelper wifiPhy2 =  YansWifiPhyHelper::Default ();


  address.SetBase("192.168.1.0", "255.255.255.0");

  Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();


  NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default ();

  // ns-3 supports generate a pcap trace



  //YansWifiChannelHelper channelWave = YansWifiChannelHelper::Default ();
  YansWifiChannelHelper channelWave = YansWifiChannelHelper::Default ();
  channelWave.AddPropagationLoss("ns3::RangePropagationLossModel","MaxRange",DoubleValue(100));
  channelWave.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);
  wifiPhy.SetChannel (channelWave.Create ());
  wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                      "DataMode",StringValue (phyMode2),
                                      "ControlMode",StringValue (phyMode2));

  wifiPhy.Set("ChannelNumber", UintegerValue(172));





  NetDeviceContainer waveDevices = wifi80211p.Install (wifiPhy, wifi80211pMac, ueNode);




  //Wave Interface
  Ipv4InterfaceContainer interface2 = address.Assign(waveDevices);
  interface1.Add(interface2);



  // Set Tx Power
  // wifiPhy.Set ("TxPowerStart",DoubleValue (m_txp));
  // wifiPhy.Set ("TxPowerEnd", DoubleValue (m_txp));


  Packet::EnablePrinting ();




  //Ipv4StaticRoutingHelper ipv4RoutingHelper;
//  Ptr<Ipv4StaticRouting> remoteHostStaticRouting = ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());    //Ipv4 static routing helper
//  remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);




    std::cout << "Wifi+Wave Intefaces Installed!. Done!" << std::endl;

  if (verbose){
    wifi80211p.EnableLogComponents ();
    wifi.EnableLogComponents ();
    }


  /* Mobility stuff */
  // MobilityHelper mobility;
  // double distance = 5;
  // Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  // positionAlloc->Add (Vector (0.0, 0.0, 0.0));
	// positionAlloc->Add (Vector(distance, 0, 0));
  //
  // mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  // mobility.SetPositionAllocator (positionAlloc);
  // mobility.Install(ueNode);

  // Position of UEs attached to eNB 1
  MobilityHelper ue1mobility;
  ue1mobility.SetPositionAllocator ("ns3::UniformDiscPositionAllocator",
                                    "X", DoubleValue (0.0),
                                    "Y", DoubleValue (0.0),
                                    "rho", DoubleValue (20));
  ue1mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  ue1mobility.Install (ueNode);

//  mobility.Install(apNode);
  std::cout << "Mobility installed" << std::endl;

  /* Install Lte devices to the nodes */
  // enbDevs = lteHelper->InstallEnbDevice (enbNode);
  // ueDevs = lteHelper->InstallUeDevice (ueNode);
  //
  // // Attach all UEs to eNodeB
  // for (uint16_t j=0; j < numberOfUEs; j++)
  // 	{
	//      lteHelper->Attach (ueDevs.Get(j), enbDevs.Get(0));
  // 	}
  //std::cout << "test 4" << std::endl;







   /* install internet stack on ues, wifi nodes */
//   Ipv4InterfaceContainer iueIpIface;
    //Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign (internetDevices);
    //ueInterface = lteHelper->AssignUeIpv4Address (NetDeviceContainer (ueDevs));
//   // for (uint32_t u = 0; u < ueNode.GetN (); ++u)
//   // 	{
//   //     Ptr<Node> ueNod = ueNode.Get(u);
//   //     Ptr<Ipv4StaticRouting> ueStaticRouting = ipv4RoutingHelper.GetStaticRouting (ueNod->GetObject<Ipv4> ());
//   //     ueStaticRouting->SetDefaultRoute (lteHelper->GetUeDefaultGatewayAddress (), 1);
//   // 	}
//   //std::cout << "Internet on Ues installed" << std::endl;


for (uint32_t u = 0; u < ueNode.GetN (); ++u)
{
      Ptr<Node> node = ueNode.Get(u);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
      Ipv4Address addr = ipv4->GetAddress(0,0).GetLocal();
      std::cout << std::endl << "Nodo\t" << u << "address 0: " << addr <<std::endl;
      addr = ipv4->GetAddress(1,0).GetLocal();
      std::cout << "Nodo\t" << u << "address 1: " << addr <<std::endl;
      addr = ipv4->GetAddress(2,0).GetLocal();
      std::cout << "Nodo\t" << u << "address 2: " << addr <<std::endl;

}



  // application stuff
//
//
//   double interPacketInterval = 100;
//   ApplicationContainer clientApps, serverApps;
// //  int nNodes = ueNode.GetN ();
//
//
//   /* Setting applications */
//   uint16_t dport = 5001;// dport1 = 6001;
//
//   // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
//    UdpClientHelper dlClient ((ueNode.Get(1))->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), dport);
//   dlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
//    dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
//   dlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
//   dlClient.SetAttribute("StartTime", TimeValue(MilliSeconds(100)));
//   dlClient.SetAttribute("StopTime", TimeValue(MilliSeconds(10000)));
//   clientApps.Add (dlClient.Install (ueNode.Get(1)));
//   //   // Downlink (sink) Sink on Ue 0 :: receives data from Remote Host
//   // //  PacketSinkHelper dlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport));
//   //   //PacketSinkHelper dlPacketSinkHelper1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport1));
//   //
//   UdpServerHelper dlPacketSinkHelper(dport);
//   // //  UdpServerHelper dlPacketSinkHelper1(dport1);
//   serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(0)));
//   //serverApps.Add (dlPacketSinkHelper1.Install (ueNode.Get(0)));
//
//   // Wifi test apps
//   uint16_t wdport = 5004;
//
//   // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
//   std::cout << std::endl;
//   std::cout << "wave dest add :: " << ueNode.Get(1)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;
//   std::cout << "wave src add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(2,0).GetLocal() << std::endl;
//
//   UdpClientHelper wdlClient ((ueNode.Get(1))->GetObject<Ipv4>()->GetAddress(2,0).GetLocal(), wdport);
//   wdlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
//   wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
//   wdlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
//   clientApps.Add (wdlClient.Install (ueNode.Get(0)));
//   // Downlink (sink) Sink on Ue 1 :: receives data from Ue 0
//   PacketSinkHelper wdlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), wdport));
//   serverApps.Add (wdlPacketSinkHelper.Install (ueNode.Get(1)));


  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");


  for (uint32_t conta_nodos=0;conta_nodos < ueNode.GetN ();conta_nodos++){

  // pegar todos os nodos menos o nó de interesse que irá enviar o  video
    if (conta_nodos != 0) {
      Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (conta_nodos), tid);
      Ptr<Socket> recvSink2 = Socket::CreateSocket (ueNode.Get (conta_nodos), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
      InetSocketAddress local2 = InetSocketAddress (Ipv4Address::GetAny (), 81);
      recvSink->Bind (local);
      recvSink2->Bind (local2);
      recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
      recvSink2->SetRecvCallback (MakeCallback (&ReceivePacket));

    }else{
      //servidor
    Ptr<Socket> source = Socket::CreateSocket (ueNode.Get (conta_nodos), tid);
    Ptr<Socket> source2 = Socket::CreateSocket (ueNode.Get (conta_nodos), tid);
    InetSocketAddress remote1 = InetSocketAddress (interface1.GetAddress (conta_nodos, 0), 80);
    InetSocketAddress remote2 = InetSocketAddress (interface2.GetAddress (conta_nodos, 0), 81);
    source->Connect (remote1);
    source2->Connect (remote2);

    }
  }


  // Setting applications


    // application stuff
    uint16_t dport = 5001, dport1 = 6001;
    uint32_t payloadSize = 1472; //bytes
    double interPacketInterval = 200;
    ApplicationContainer clientApps, serverApps;

    //uint32_t nNodes = ueNode.GetN ();

    UdpClientHelper dlClient (interface1.GetAddress (0), dport);
    dlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    dlClient.SetAttribute ("MaxPackets", UintegerValue(100000000));
    dlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    dlClient.SetAttribute("StartTime", TimeValue(MilliSeconds(100)));
    dlClient.SetAttribute("StopTime", TimeValue(Seconds(10)));


    // Downlink (source) client on Ue1 :: sends data to Ue 0 with LTE
    for (uint32_t i=0; i < ueNode.GetN ();i++){
        if (i != 0) {
                clientApps.Add (dlClient.Install (ueNode.Get(i)));
              }
        }

    // Downlink (sink) Sink on Ue 0 :: receives data from Remote Host
  //  PacketSinkHelper dlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport));
    //PacketSinkHelper dlPacketSinkHelper1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), dport1));

    UdpServerHelper dlPacketSinkHelper(dport);
    UdpServerHelper dlPacketSinkHelper1(dport1);
    serverApps.Add (dlPacketSinkHelper.Install (ueNode.Get(0)));
    serverApps.Add (dlPacketSinkHelper1.Install (ueNode.Get(0)));


    // Wifi test apps
    uint16_t wdport = 5004;

    // Downlink (source) client on Ue 0 :: sends data to Ue 1 with WIFI
    std::cout << std::endl;

    std::cout << "wifi dest add :: " << ueNode.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
    UdpClientHelper wdlClient (interface2.GetAddress (0), wdport);
    wdlClient.SetAttribute ("Interval", TimeValue (MilliSeconds(interPacketInterval)));
    wdlClient.SetAttribute ("MaxPackets", UintegerValue(1000000));
    wdlClient.SetAttribute ("PacketSize", UintegerValue(payloadSize));
    wdlClient.SetAttribute("StartTime", TimeValue(Seconds(10.100)));
    wdlClient.SetAttribute("StopTime", TimeValue(Seconds(20.100)));

    for (uint32_t i=0; i < ueNode.GetN ();i++){
        if (i != 0) {
                std::cout << "wifi src add :: " << ueNode.Get(i)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
                clientApps.Add (wdlClient.Install (ueNode.Get(i)));
                }
    }

    // Downlink (sink) Sink on Ue 1 :: receives data from Ue 0
    PacketSinkHelper wdlPacketSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), wdport));

    serverApps.Add (wdlPacketSinkHelper.Install (ueNode.Get(0)));



    // Log Wifi packet receptions
  //  Config::Connect ("/NodeList/*/$ns3::Node/ApplicationList/*/$ns3::PacketSocketServer/Rx", MakeCallback (&SocketRecvStats));

    // ApplicationContainer sourceApplications, sinkApplications;
    // std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
    // uint32_t portNumber = 10;
    //
    // //  for (uint32_t index = 1; index < nWifi; ++index)
    // //  {
    //     for (uint8_t tosValue : tosValues)
    //       {
    //
    //         auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
    //         const auto address = ipv4->GetAddress (1, 0).GetLocal ();
    //
    //         InetSocketAddress sinkSocket (address, portNumber++);
    //
    //
    //         sinkSocket.SetTos (tosValue);
    //
    //
    //         OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
    //         onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
    //         onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
    //         onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
    //         onOffHelper.SetAttribute ("PacketSize", UintegerValue (packetSize)); //bytes
    //     //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
    //
    //         PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
    //         sinkApplications.Add (packetSinkHelper.Install (ueNode.Get (1)));
    //
    //     for (uint32_t i=0; i < ueNode.GetN ();i++){
    //         if (i != 1) {
    //                 sourceApplications.Add (onOffHelper.Install (ueNode.Get (i)));
    //               // source
    //         }
    //     }
    //
    // }

    std::stringstream ST;
    ST<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";


  //ST<<"/NodeList/"<< 0 <<"/ApplicationList/*/$ns3::PacketSink/Rx";                 //

    Config::Connect (ST.str(), MakeCallback(&ReceivesPacket));


    // sinkApplications.Start (Seconds (0.0));
    // sinkApplications.Stop (Seconds (duration/2));
    // sourceApplications.Start (Seconds (1.0));              //  }
    //


  // ApplicationContainer sourceApplications2, sinkApplications2;
  // uint32_t portNumber2 = 20;
  //
  // //  for (uint32_t index = 1; index < nWifi; ++index)
  // //  {
  //     for (uint8_t tosValue : tosValues)
  //       {
  //
  //         auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
  //         const auto address2 = ipv4->GetAddress (2, 0).GetLocal ();
  //         InetSocketAddress sinkSocket2 (address2, portNumber2++);
  //
  //         sinkSocket2.SetTos (tosValue);
  //
  //         OnOffHelper onOffHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
  //         onOffHelper2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  //         onOffHelper2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  //         onOffHelper2.SetAttribute ("DataRate", DataRateValue (50000000 / numberOfUEs));
  //         onOffHelper2.SetAttribute ("PacketSize", UintegerValue (packetSize)); //bytes
  //     //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
  //
  //         PacketSinkHelper packetSinkHelper2 ("ns3::UdpSocketFactory", sinkSocket2);
  //         sinkApplications2.Add (packetSinkHelper2.Install (ueNode.Get (1)));
  //
  //
  //     for (uint32_t i=0; i < ueNode.GetN ();i++){
  //         if (i != 1) {
  //                 sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (i)));
  //               // source
  //         }
  //     }
  //
  // }
  //
  // sinkApplications2.Start (Seconds (duration/2 + 1));
  // sinkApplications2.Stop (Seconds (duration + 1));
  // sourceApplications.Start (Seconds (duration/2 + 1.1));



  // Log Wifi packet receptions
  Config::Connect ("/NodeList/*/$ns3::Node/ApplicationList/*/$ns3::PacketSocketServer/Rx", MakeCallback (&SocketRecvStats));



  // fix random number streams
  //m_streamIndex += m_waveBsmHelper.AssignStreams (ueNode, m_streamIndex);

  /*Hablita a criação do arquivos de ratreamento do pacotes*/

  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream ("teste11.tr");
  wifiPhy.EnableAsciiAll (osw);

  // called by ConfigureChannels()

  // every device will have PHY callback for tracing
  // which is used to determine the total amount of
  // data transmitted, and then used to calculate
  // devices are set up in SetupAdhocDevices(),</Ipv4>
  // the MAC/PHY overhead beyond the app-data
   Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/Tx", MakeCallback (&WifiPhyStats::PhyTxTrace, m_wifiPhyStats));
   // TxDrop, RxDrop not working yet.  Not sure what I'm doing wrong.
   Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback (&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
   Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback (&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));

 // Channel width must be set *after* installation because the attribute is overwritten by the ConfigureStandard method ()
   //Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (20));
   // Channel width must be set *after* installation because the attribute is overwritten by the ConfigureStandard method ()
  // Config::Set ("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/Phy/State/Tx", UintegerValue (10));


  //
  //



   // Connect MacRx event at MAC layer of sink node to ReceivePacket function for throughput calculation
   /*Rastreia os pacotes recebidos no terminal escolhido*/
  // Config::Connect ("/NodeList/*/DeviceList/*/Phy/State/RxOk", MakeCallback(&WifiPhyStats::PhyRxOkTrace, m_wifiPhyStats));

    // std::stringstream ss;
    // ss << "/NodeList/" << i << "/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";
    // ss << "/NodeList/12/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";
    // Config::Connect (ss.str(), MakeCallback(&ReceivePacket));

   //Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (20));

   // Set guard interval
   //Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/HtConfiguration/ShortGuardIntervalSupported", BooleanValue (true));

   // TxDrop, RxDrop not working yet.  Not sure what I'm doing wrong.
  Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback (&WifiPhyStats::PhyTxDrop, m_wifiPhyStats));
  Config::Connect ("/NodeList/*/DeviceList/*/ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback (&WifiPhyStats::PhyRxDrop, m_wifiPhyStats));






 // Connect MacRx event at MAC layer of sink node to ReceivePacket function for throughput calculation

    //node = ueNode.Get(0);
  //Simulator::Schedule(Seconds(6), &TearDownLink, remoteHost, pgw, 1, 2);
  //Simulator::Schedule (Seconds (1), &CalculateThroughput);
    // uint32_t apNum = 0;
    Simulator::Schedule(Seconds(0.1), &CalculatePhyRxDrop, m_wifiPhyStats);
    Simulator::Schedule(Seconds(0.1), &CalculateThroughput);
    for (uint32_t j=0; j < ueNode.GetN ();j++){
      if (j!=0) {
      Simulator::Schedule(Seconds(10), &TearDownLink,ueNode.Get(0), ueNode.Get(j),1,1);
      Simulator::Schedule (Seconds (10), &reconfigureUdpClient, wdlClient, ueNode.Get(j), wdport);
      Simulator::Schedule(Seconds(10.1), &TearUpLink,ueNode.Get(0), ueNode.Get(j),2,2, phyMode2);
        }
    }




    // Simulator::Schedule(Seconds(10.1), &CalculateThroughput);

    // Tracing
    wifiPhy.EnablePcap ("wifi-simple-adhoc", wifiDevs);
    // Tracing
    wifiPhy.EnablePcap ("wave-simple-80211p", waveDevices);


//-------------------------------------




  // Monitor verifications

  // Flow Monitor
  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();


  NS_LOG_INFO ("Starting simulation.....");
  Simulator::Stop(Seconds(duration+1));


  AnimationInterface anim ("lte+wifi.xml");


//   anim.SetConstantPosition(ueNode.Get(0), 40.0, 100.0);
//   anim.SetConstantPosition(ueNode.Get(1), 60.0, 100.0);
// //  anim.SetConstantPosition(apNode.Get(0), 50.0, 80.0);
//   anim.SetConstantPosition(enbNode.Get(0), 80.0, 80.0);
//   anim.SetConstantPosition(pgw, 80.0, 60.0);
//   anim.SetConstantPosition(remoteHostContainer.Get(0), 80.0, 40.0);
  anim.EnablePacketMetadata (true);
  // Uncomment to enable PCAP tracing




  Simulator::Run ();



  /* Show results */
  flowMonitor->CheckForLostPackets();




  Time runTime;
  runTime = Seconds(duration);

  int txPacketsumWifi = 0;
  //int txPacketsumWave = 0;
  int rxPacketsumWifi = 0;
  //int rxPacketsumWave = 0;
  int DropPacketsumWifi = 0;
  //int DropPacketsumWave = 0;
  int LostPacketsumWifi = 0;
  //int LostPacketsumWave = 0;
  //double ThroughputsumWave = 0;
  double ThroughputsumWiFi = 0;
  //double rxDurationWave=0;

  double rxDurationWifi=0;
  Time DelaysumWifi;
  //Time DelaysumWave;
  Time JittersumWifi;
  //Time JittersumWave;


  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();

  for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i !=stats.end(); ++i)
  {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);

        txPacketsumWifi += i->second.txPackets;
        rxPacketsumWifi += i->second.rxPackets;
        LostPacketsumWifi += i->second.lostPackets;
        DropPacketsumWifi += i->second.packetsDropped.size();
        DelaysumWifi += ((i->second.delaySum)/(i->second.rxPackets));               //ns
        JittersumWifi += ((i->second.jitterSum)/(i->second.rxPackets));

        std::cout << std::endl;
        std::cout << "\nFlow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Simulation Time: " << Simulator::Now ().GetSeconds() << "\n";
        std::cout << "  First Time: " << i->second.timeFirstRxPacket.GetSeconds() << "\n";
        std::cout << " First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds() << std::endl;
        std::cout << " Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds() << std::endl;
        std::cout << "  Last Tx Pkt Time: " << i->second.timeLastTxPacket.GetSeconds() << "\n";
        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
        std::cout << " Rx bytes : " << i->second.rxBytes << "\n";

        std::cout << "  Lost Packets:   " << i->second.lostPackets << "\n";
        rxDurationWifi = i->second.timeLastRxPacket.GetSeconds () - i->second.timeFirstRxPacket.GetSeconds ();
        ThroughputsumWiFi += (i->second.rxBytes * 8.0 / rxDurationWifi / 1000 / 1000);  //Mbps
          if (i->second.rxPackets > 1)
          {
              std::cout << "  Delay:   " << ((i->second.delaySum)/(i->second.rxPackets))/1000000 << " milliseconds\n";         //ms
              std::cout << "  Jitter:   " << ((i->second.jitterSum)/(i->second.rxPackets)) << " nanoseconds\n";       //ns
          }
          std::cout << "  Throughput Wifi: " << i->second.rxBytes * 8.0 / rxDurationWifi / 1000 / 1000 << " Mbps\n";
          std::cout << " Wifi Reception Throughput : " << i->second.rxBytes *8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n";

          std::cout << "******" << "\n";
  }
  std::cout << (macTxDropCount + phyTxDropCount + phyRxDropCount) << "\n";
    // Collisions should be in phyRxDropCount, as Yans wifi set collided frames snr on reception, but it's not possible to differentiate from propagation loss. In this experiment, this is not an issue
  flowMonitor->SerializeToXmlFile("sbrc_0.3.xml", true, true);

//   std::cout << "::TEST INTERFACE MANAGER::" << "\n";
//   std::cout << "Total time: " <<  duration << "\n";
//   std::cout << "Number of nodes: " << numberOfUEs << "\n";
//   //std::cout << "Number of sources: " << m_numSources << "\n";
//   //std::cout << "Inter-node distance: " << m_distNodes << "\n";
//   std::cout << "CCA mode1 threshold: NOT USED \n";
//   std::cout << "Packet size: " << payloadSize << "\n";
// //  std::cout << "Short guard enabled: " << m_shortGuardEnabled << "\n";
// //  std::cout << "MCS index: " << m_mcsIndex << "\n";
// //  std::cout << "Channel width: " << m_channelWidth << "\n";
//   std::cout << "Application rate Wave: " << phyMode2 << "\n";
//   std::cout << "Application rate Wifi: " << phyMode1 << "\n";
// //  std::cout << "Error model type: " << m_errorModelType << "\n";
// //  std::cout << "Tracing enabled: " << m_tracing << "\n";
//
//   std::cout << "Tx packet sum Wave: " << txPacketsumWave << "\n";
//   std::cout << "Tx packet sum Wifi: " << txPacketsumWifi << "\n";
//   std::cout << "Rx packet sum Wave: " << rxPacketsumWave << "\n";
//   std::cout << "Rx packet sum Wifi: " << rxPacketsumWifi << "\n";
//   std::cout << "Lost packet sum Wave: " << LostPacketsumWave << "\n";
//   std::cout << "Lost packet sum Wifi: " << LostPacketsumWifi << "\n";
//   std::cout << "Drop packet sum Wave: " << DropPacketsumWave << "\n";
//   std::cout << "Drop packet sum Wifi: " << DropPacketsumWifi << "\n";
//   std::cout << "Throughput sum Wave: " << ThroughputsumWave << "\n";
//   std::cout << "Throughput sum Wifi: " << ThroughputsumWiFi << "\n";
//   std::cout << "Delay sum Wave: " << DelaysumWave.As (Time::MS) << " milliseconds\n";
//   std::cout << "Delay sum Wifi: " << DelaysumWifi.As (Time::MS) << " milliseconds\n";
//   std::cout << "Jitter sum Wave: " << JittersumWave.As (Time::MS) << " milliseconds\n";
//   std::cout << "Jitter sum Wifi: " << JittersumWifi.As (Time::MS) << " milliseconds\n";
//   std::cout << "Avg throughput Wave: " << ThroughputsumWave/numberOfUEs << "\n";
//   std::cout << "Avg throughput Wifi: " << ThroughputsumWiFi/numberOfUEs << "\n";
//   std::cout << "Packets delivery ratio Wave: " << ((rxPacketsumWave *100) / txPacketsumWave) << "%" << "\n";
//   std::cout << "Packets lost ratio Wifi: " << ((LostPacketsumWifi *100) / txPacketsumWifi) << "%" << "\n";
//
//   std::cout << "******" << "\n";


  Simulator::Destroy ();
  ResetDropCounters();

  NS_LOG_INFO ("Done.");

  return 0;
}
