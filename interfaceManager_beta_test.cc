#include "string.h"
#include "ns3/core-module.h"
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
uint32_t phyTxDropCount(0), phyRxDropCount(0);
uint32_t m_bytesTotal;
uint32_t packetsReceived; ///< total packets received by all nodes
uint32_t totalBytesReceived2=0;
uint32_t totalBytesReceived=0;
uint32_t totalBytesReceivedSum=0;
uint32_t bytesTotal=0;

uint32_t pktSize = 1472; //1500
std::ofstream rdTrace;
    std::ofstream rdTraced;
uint32_t mbs = 0;
uint32_t totalBytesDropped = 0;
uint32_t totalBytestransmitted = 0;
uint16_t port = 9;
std::string CSVfileName = "interfaceManager2.csv";
char tmp_char [30] = "";




NS_LOG_COMPONENT_DEFINE ("InterfaceManager");


int64_t pktCount_n; //sinalização de pacotes


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


static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (InetSocketAddress::IsMatchingType (senderAddress))
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress);
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
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
	      packetsReceived += 1;
	      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
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

// Global variables for use in callbacks.
double g_signalDbmAvg;
double g_noiseDbmAvg;
uint32_t g_samples;

void MonitorSniffRx (Ptr<const Packet> packet,
                     uint16_t channelFreqMhz,
                     WifiTxVector txVector,
                     MpduInfo aMpdu,
                     SignalNoiseDbm signalNoise)
{
                       g_samples++;
                       g_signalDbmAvg += ((signalNoise.signal - g_signalDbmAvg) / g_samples);
                       g_noiseDbmAvg += ((signalNoise.noise - g_noiseDbmAvg) / g_samples);
}


/*************************************************************** *
FUNÇÃO QUE CALCULA O PAYLOAD NO RECEPTOR *
***************************************************************/
void PhyRxOkTrace (std::string context, Ptr<const Packet> packet, double snr,WifiMode mode, enum WifiPreamble preamble)
{
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

void DroppedPacket(std::string context, Ptr <const Packet> p)
{

    std::cout << " TX p: " << *p << std::endl;

    //totalBytesDropped += p->GetSize();
    //cout<< totalBytesDropped<<endl;
    totalBytesDropped=0;
    rdTraced << totalBytesDropped <<"\n"<<totalBytesReceived ;

}

void ReceivedPacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
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



void CalculatePhyRxDrop (Ptr<WifiPhyStats> m_wifiPhyStats)
 {
   double totalPhyTxBytes = m_wifiPhyStats->GetTxBytes ();
   double totalPhyRxDrop = phyRxDropCount;
   double DropBytes = totalPhyTxBytes - totalPhyRxDrop;
   std::cout << "[" << Simulator::Now ().GetSeconds() << "]\t" << "\tBytes TX=" << totalPhyTxBytes << "\tBytes RX Drop=" << totalPhyRxDrop << "\tDrop Bytes (Sended-Received):" << DropBytes<< std::endl;
   Simulator::Schedule (MilliSeconds(100), &CalculatePhyRxDrop, m_wifiPhyStats);
}

//-- Callback function is called whenever a packet is received successfully.
//-- This function cumulatively add the size of data packet to totalBytesReceived counter.
//---------------------------------------------------------------------------------------

void ReceivesPacket(std::string context, Ptr <const Packet> p)
 {
	  //char c= context.at(24);
 	  //int index= c - '0';
 	  //totalBytesReceived[index] += p->GetSize();

   		totalBytesReceived += p->GetSize();
   	  std::cout<< "Received (Minha impl) : " << totalBytesReceived << std::endl;
}


void CalculateThroughput2 (Ptr<WifiPhyStats> m_wifiPhyStats)
{
//   //for (int f=0; f<TN; f++)
//  //{
//   double TotalThroughput2=0;
  double totalPhyTxBytes = m_wifiPhyStats->GetTxBytes ();
  double mbs2 = ((totalPhyTxBytes*8.0)/(1000000*1));
  totalBytesReceivedSum =totalPhyTxBytes+totalBytesReceivedSum;

  //    //mbs[f] = ((totalBytesReceived[f]*8.0)/(1000000*1));
//    //cout<<"size of vector is  "<< totalBytesReceived.size()<< endl;
  //  TotalThroughput2+=mbs2+TotalThroughput2;
 std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Throughput Wifi network  : \t" << mbs2 << "\tQtd bytes Received:" << totalPhyTxBytes <<  std::endl;
 std::cout<< "Sum of total bytes received Wifi up to " <<  "[" << Simulator::Now ().GetSeconds() << "s]\t=" << totalBytesReceivedSum << std::endl;


  //  //rdTrace << Simulator::Now ().GetSeconds() << "\t"<< f << "\t" << mbs[f] <<"\n";
 //rdTrace2 << Simulator::Now ().GetSeconds() << "\t" << mbs2 <<"\n"<< "\nTotal bytes Received:" << totalBytesReceived1 << std::endl;
 Simulator::Schedule (MilliSeconds (100), &CalculateThroughput2,m_wifiPhyStats);
}

void
CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out (CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << "," << kbs << "," << packetsReceived << "," << "" << std::endl;

  out.close ();
  packetsReceived = 0;

  Simulator::Schedule (Seconds (1.0), &CheckThroughput);
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


void experiment(int &numberOfUEs, const std::string phyMode1, const std::string phyMode2, bool verbose, double duration, Ptr<WifiPhyStats> m_wifiPhyStats, int m_mobility, double m_txp)
{

    // 0.Some settings

//    int nodeSpeed = 20; //in m/s UAVs speed
//    int nodePause = 0; //in s UAVs pause

//    double interPacketInterval = 100;



    // 1. Create nodes
    NodeContainer ueNode;
    ueNode.Create (numberOfUEs);

    std::cout << "Node Containers created, for " << numberOfUEs << "nodes clients!" << std::endl;

    OlsrHelper olsr;
    Ipv4StaticRoutingHelper staticRouting;

    Ipv4ListRoutingHelper list;
    list.Add (staticRouting, 0);
    list.Add (olsr, 10);

    InternetStackHelper internet;
      internet.SetRoutingHelper (list); // has effect on the next Install ()
    internet.Install(ueNode);

    Ptr<OutputStreamWrapper> routingStreamStart = Create<OutputStreamWrapper> ("olsr_start.routes", std::ios::out);
    olsr.PrintRoutingTableAllAt (Seconds (1.0), routingStreamStart);

    Ptr<OutputStreamWrapper> routingStreamEnd = Create<OutputStreamWrapper> ("olsr_end.routes", std::ios::out);
    olsr.PrintRoutingTableAllAt (Seconds (duration), routingStreamEnd);

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

    //
    // YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    // YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    // wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);

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
    //
    // wifiPhy.Set ("TxPowerStart",DoubleValue (m_txp));
    // wifiPhy.Set ("TxPowerEnd", DoubleValue (m_txp));


    wifiMac.SetType ("ns3::AdhocWifiMac");

    NetDeviceContainer wifiDevices = wifi.Install (wifiPhy, wifiMac, ueNode);



    if (verbose) {
        wifi.EnableLogComponents ();  // Turn on all Wifi logging
    }


    // Tracing
    wifiPhy.EnablePcap ("wifi-intefaceManager", wifiDevices);

  //6. Atribui pilha de protocolos Internet aos Nodos




    // Ipv4StaticRoutingHelper ipv4RoutingHelper;



    std::cout << "Internet stack installed on Ue devices!" << std::endl;


  //  Ipv4StaticRoutingHelper ipv4RoutingHelper;






    // 7. Install PHY and MAC Layer of IEEE 802.11n 5GHz



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



    //wifiPhy2.Set("ChannelNumber", UintegerValue(172));

    // wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
    //                                     "DataMode",StringValue (phyMode2),
    //                                     "ControlMode",StringValue (phyMode2));

    // wifiPhy2.Set ("TxPowerStart",DoubleValue (m_txp));
    // wifiPhy2.Set ("TxPowerEnd", DoubleValue (m_txp));


    NetDeviceContainer waveDevices = wifi80211p.Install (wifiPhy2, wifi80211pMac, ueNode);

    Packet::EnablePrinting ();

    // WiFi Interface
    Ipv4AddressHelper address;
    NS_LOG_INFO ("Assign IP WiFi Addresses.");
    address.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interface;
    interface = address.Assign(wifiDevices);

    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interface2 = address.Assign(waveDevices);
    interface.Add(interface2);

    // for (int u = 0; u < numberOfUEs; ++u)
    // {
    //     Ptr<Node> node = ueNode.Get (u);
    //     Ptr<Ipv4StaticRouting> interface2HostStaticRouting = ipv4RoutingHelper.GetStaticRouting (node->GetObject<Ipv4> ());    //Ipv4 static routing helper
    //     interface2HostStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"), 2);
    // }


    if (verbose){
      wifi80211p.EnableLogComponents ();
         }

    std::cout << "Wifi+Wave Intefaces Installed!. Done!" << std::endl;


   Ptr<Ipv4> ip_wireless[numberOfUEs];
   for (int i = 0; i < numberOfUEs; i++)
   {
       ip_wireless[i] = ueNode.Get(i)->GetObject<Ipv4> ();
   }

   // //Ipv4StaticRoutingHelper ipv4RoutingHelper;
   // Ptr<Ipv4StaticRouting> staticRouting[numberOfUEs];
   // for (int i = 0; i < numberOfUEs; i++)
   // {
   //     staticRouting[i] = ipv4RoutingHelper.GetStaticRouting (ip_wireless[i]);
   // }
   //
   // //Flow 0: 0--->6--->12
   // staticRouting[0]->AddHostRouteTo (Ipv4Address ("10.1.1.1"), Ipv4Address ("10.1.1.2"), 1);
   // staticRouting[0]->AddHostRouteTo (Ipv4Address ("10.1.1.1"), Ipv4Address ("10.1.1.3"), 1);
   //
   // staticRouting[0]->AddHostRouteTo (Ipv4Address ("192.168.1.1"), Ipv4Address ("192.168.1.2"), 2);
   // staticRouting[0]->AddHostRouteTo (Ipv4Address ("192.168.1.1"), Ipv4Address ("192.168.1.3"), 2);
   //
   // staticRouting[1]->AddHostRouteTo (Ipv4Address ("10.1.1.2"), Ipv4Address ("10.1.1.1"), 1);
   // staticRouting[1]->AddHostRouteTo (Ipv4Address ("10.1.1.2"), Ipv4Address ("10.1.1.3"), 1);
   //
   // staticRouting[1]->AddHostRouteTo (Ipv4Address ("192.168.1.2"), Ipv4Address ("192.168.1.1"), 2);
   // staticRouting[1]->AddHostRouteTo (Ipv4Address ("192.168.1.2"), Ipv4Address ("192.168.1.3"), 2);
   //
   // staticRouting[2]->AddHostRouteTo (Ipv4Address ("10.1.1.3"), Ipv4Address ("10.1.1.1"), 1);
   // staticRouting[2]->AddHostRouteTo (Ipv4Address ("10.1.1.3"), Ipv4Address ("10.1.1.2"), 1);
   //
   // staticRouting[2]->AddHostRouteTo (Ipv4Address ("192.168.1.3"), Ipv4Address ("192.168.1.1"), 2);
   // staticRouting[2]->AddHostRouteTo (Ipv4Address ("192.168.1.3"), Ipv4Address ("192.168.1.2"), 2);

    // 8. Printing interfaces installed to Nodos
    for (uint32_t u = 0; u < ueNode.GetN (); ++u)
    {
          Ptr<Node> node = ueNode.Get(u);
          Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
          Ipv4Address addr = ipv4->GetAddress(0,0).GetLocal();
          std::cout << std::endl << "Nodo" << u << "\taddress 0: " << addr <<std::endl;
          addr = ipv4->GetAddress(1,0).GetLocal();
          std::cout << "Nodo" << u << "\taddress 1: " << addr <<std::endl;
          addr = ipv4->GetAddress(2,0).GetLocal();
          std::cout << "Nodo" << u << "\taddress 2: " << addr <<std::endl;

    }

    // 2. Place nodes

    if (m_mobility==1){
                //std::string m_traceFile= "/home/doutorado/sumo/examples/fanet10/mobility.tcl";
                std::string m_traceFile= "/home/doutorado/sumo/examples/fanet/different_speed_sumo/mobility_manyspeed.tcl";

                  // Create Ns2MobilityHelper with the specified trace log file as parameter
                  Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
                  ns2.Install (); // configure movements for each node, while reading trace file
                //  mobility.Install (ueNode);
            } else {
            MobilityHelper mobility;
            Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
            positionAlloc->Add (Vector (0.0, 0.0, 0.0));
            positionAlloc->Add (Vector (5.0, 0.0, 0.0));
            positionAlloc->Add (Vector (10.0, 0.0, 0.0));
            mobility.SetPositionAllocator (positionAlloc);

            mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
            mobility.Install (ueNode);
    }

  //   MobilityHelper mobilityUAVs;
  //   int64_t streamIndex = 0; // used to get consistent mobility across scenarios
  //
  //   ObjectFactory pos;
  //   pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
  //   pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=100.0]"));
  //   pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=100.0]"));
  //
  //   Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  //   streamIndex += taPositionAlloc->AssignStreams (streamIndex);
  //
  //   std::stringstream ssSpeed;
  //   ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
  //   std::stringstream ssPause;
  //   ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
  //   mobilityUAVs.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
  //                                   "Speed", StringValue (ssSpeed.str ()),
  //                                   "Pause", StringValue (ssPause.str ()),
  //                                   "PositionAllocator", PointerValue (taPositionAlloc));
  //   mobilityUAVs.SetPositionAllocator (taPositionAlloc);
  //   mobilityUAVs.Install (ueNode);
  //   streamIndex += mobilityUAVs.AssignStreams (ueNode, streamIndex);
  //   NS_UNUSED (streamIndex); // From this point, streamIndex is unused
  // // End Uavs mobility configurations



    std::cout << "Mobility installed" << std::endl;

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

    TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");




    for (int i = 0; i < numberOfUEs; i++)
      {
        // protocol == 0 means no routing data, WAVE BSM only
        // so do not set up sink

        Ptr<Socket> recvSink = Socket::CreateSocket (ueNode.Get (i), tid);
        InetSocketAddress local = InetSocketAddress (interface.GetAddress (i), 80);
        recvSink->Bind (local);
        recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));


      }



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
    // dlClient.SetAttribute("StopTime", TimeValue(Seconds(duration/2)));
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
    // wdlClient.SetAttribute("StartTime", TimeValue(Seconds(duration/2+100)));
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

    ApplicationContainer sourceApplications, sinkApplications;
    std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
    uint32_t portNumber = 10;

    //  for (uint32_t index = 1; index < nWifi; ++index)
    //  {
        for (uint8_t tosValue : tosValues)
          {

            auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
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
            sinkApplications.Add (packetSinkHelper.Install (ueNode.Get (1)));

        for (uint32_t i=0; i < ueNode.GetN ();i++){
            if (i != 1) {
                    sourceApplications.Add (onOffHelper.Install (ueNode.Get (i)));
                  // source
                      }
                  }
          }
          sinkApplications.Start (Seconds (0.0));
          sinkApplications.Stop (Seconds (duration/2));
          sourceApplications.Start (Seconds (0.1));


        ApplicationContainer sourceApplications2, sinkApplications2;
        uint32_t portNumber2 = 20;

        //  for (uint32_t index = 1; index < nWifi; ++index)
        //  {
            for (uint8_t tosValue : tosValues)
              {

                auto ipv4 = ueNode.Get (1)->GetObject<Ipv4> ();
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
                sinkApplications2.Add (packetSinkHelper2.Install (ueNode.Get (1)));


            for (uint32_t i=0; i < ueNode.GetN ();i++){
                if (i !=1) {
                        sourceApplications2.Add (onOffHelper2.Install (ueNode.Get (i)));
                      // source
                }
            }

        }

    sinkApplications2.Start (Seconds (duration/2 + 0.1));
    sinkApplications2.Stop (Seconds (duration + 1));
    sourceApplications2.Start (Seconds (duration/2 + 0.1));



    // 11.2 Monitor collisions

    Config::ConnectWithoutContext ("/NodeList/0/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));

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


    AsciiTraceHelper ascii;
    wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("interfaceManager_beta.tr"));
    wifiPhy2.EnableAsciiAll (ascii.CreateFileStream ("interfaceManager_beta2.tr"));

    /*Rastreia os pacotes recebidos no terminal escolhido*/
    Config::Connect ("/NodeList/1/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
    Config::Connect ("/NodeList/2/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));
    Config::Connect ("/NodeList/3/DeviceList/*/Phy/State/RxOk", MakeCallback(&PhyRxOkTrace));

    std::stringstream ST;
    ST<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";
    Config::Connect (ST.str(), MakeCallback(&ReceivesPacket));




    // 11. monitoring

    Simulator::Schedule(Seconds(0.1), &CalculatePhyRxDrop, m_wifiPhyStats);
  //  Simulator::Schedule(Seconds(0.1), &CalculateThroughput);
    Simulator::Schedule(Seconds(0.1), &CalculateThroughput2,m_wifiPhyStats);




    // for (uint32_t j=0; j < ueNode.GetN ();j++){
    //   if (j!=0) {
    //   Simulator::Schedule(Seconds(10), &TearDownLink,ueNode.Get(0), ueNode.Get(j),1,1);
    //   //Simulator::Schedule (Seconds (10), &reconfigureUdpClient, wdlClient, ueNode.Get(j), wdport);
    //   Simulator::Schedule(Seconds(10.1), &TearUpLink,ueNode.Get(0), ueNode.Get(j),2,2, phyMode2, j);
    //     }
    // }





   // 11.1 Enable pcap traces for each node

   // Tracing

   wifiPhy.EnablePcapAll (std::string ("intMan-node"));

   // Tracing

   //11.2 Trace

   rdTrace.open("throughputmeasurementstesttotalap.dat", std::ios::out);                                             //
     rdTrace << "# Time \t Throughput \n";

    rdTraced.open("receivedvsdropped.dat", std::ios::out);                                             //
     rdTraced << "# Time \t Dropped \n received \n" ;
     Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivedPacket));

   //Packet::EnablePrinting ();

   Ipv4GlobalRoutingHelper::PopulateRoutingTables ();


   // 11.3 Install FlowMonitor on all nodes
   Ptr<FlowMonitor> flowMonitor;
   FlowMonitorHelper flowHelper;
   flowMonitor = flowHelper.InstallAll();


   //Packet::EnablePrinting ();
   ns3::PacketMetadata::Enable ();


   // 13. Print statistics

   //AnimationInterface anim ("interfaceManagerbeta_Anim.xml");
   //anim.EnablePacketMetadata(true);


    //12. Run simulation for "duration" seconds
    Simulator::Stop (Seconds (duration+1));


    Simulator::Run ();





    flowMonitor->CheckForLostPackets();

//     Time runTime;
//     runTime = Seconds(duration);
//
//     int txPacketsumWifi = 0;
//     int rxPacketsumWifi = 0;
//     int DropPacketsumWifi = 0;
//     int LostPacketsumWifi = 0;
// //    double ThroughputsumWiFi = 0;
//
//   //  double rxDurationWifi=0;
//     Time DelaysumWifi;
//     Time JittersumWifi;

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();
    for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i !=stats.end(); ++i)
    {
  	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);

        // txPacketsumWifi += i->second.txPackets;
        // rxPacketsumWifi += i->second.rxPackets;
        // LostPacketsumWifi += i->second.lostPackets;
        // DropPacketsumWifi += i->second.packetsDropped.size();
        // DelaysumWifi += ((i->second.delaySum)/(i->second.rxPackets));               //ns
        // JittersumWifi += ((i->second.jitterSum)/(i->second.rxPackets));


  		  std::cout << std::endl;
  		  std::cout << "Flow : " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Simulation Time: " << Simulator::Now ().GetSeconds() << "\n";
        std::cout << " Tx bytes : " << i->second.txBytes << "\n";
  		  std::cout << " Rx bytes : " << i->second.rxBytes << "\n";
        std::cout << "  First Time: " << i->second.timeFirstRxPacket.GetSeconds() << "\n";
        std::cout << " First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds() << "\n";
        std::cout << " Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds() << "\n";
        std::cout << "  Last Tx Pkt Time: " << i->second.timeLastTxPacket.GetSeconds() << "\n";
        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";

        // std::cout << " First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds() << std::endl;
  		  // std::cout << " Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds() << std::endl;
        //
  		  std::cout << " WiFi Throughput : " << i->second.rxBytes *8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n";



        NS_LOG_UNCOND("Flow ID " << i->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);
        NS_LOG_UNCOND("Tx Packets = " << i->second.txPackets);
        NS_LOG_UNCOND("Rx Packets = " << i->second.rxPackets);
        NS_LOG_UNCOND("Throughput Kbps: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps");
        NS_LOG_UNCOND("Throughput Mbps: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024 /1024 << " Mbps");
        NS_LOG_UNCOND("Delay Sum" << i->second.delaySum);
        NS_LOG_UNCOND(" First Tx Pkt time : " << i->second.timeFirstTxPacket.GetSeconds());
        NS_LOG_UNCOND(" Last Rx Pkt time : " << i->second.timeLastRxPacket.GetSeconds());
        NS_LOG_UNCOND(" WiFi Throughput : " << i->second.rxBytes *8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024 << " Mbps\n");

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
    double duration = 5; //seconds
    int numberOfUEs=3; //Default number of UEs attached to each eNodeB
    bool verbose=false;
    uint32_t packetSize = 1472; // bytes
  //  double m_txp=100; ///< distance
    int m_mobility=1;
    double m_txp=20;



    // For Wifi Network
    std::string phyMode1 ("OfdmRate9Mbps");
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
    cmd.AddValue ("mobility", "Define if mobility is based on tracefile or constant position", m_mobility);
    cmd.AddValue("runs", "Run count. Default: 1.", runs);
    cmd.AddValue ("txp", "Transmit power (dB), e.g. txp=7.5", m_txp);
    cmd.Parse (argc, argv);


    void ReceivePacket2 (Ptr <Socket> socket);
    void ReceivesPacket (std::string context, Ptr <const Packet> p);
    void ReceivedPacket (Ptr<const Packet> p, const Address & addr);

    void CheckThroughput ();


    Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
    m_wifiPhyStats = CreateObject<WifiPhyStats> ();



    void DroppedPacket (std::string context, Ptr<const Packet> p);
    void CalculateThroughput2 (Ptr<WifiPhyStats> m_wifiPhyStats);
    Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node );

      // // disable fragmentation for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
      // // turn off RTS/CTS for frames below 2200 bytes
      // Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("1000"));




    // Run experiment
    std::cout << "Starting!" << std::endl;
  //  std::cout << "F1 Tx Packets;F1 Rx Packets;F1 Tx Bytes;F1 Rx Bytes;F2 Tx Packets;F2 Rx Packets;F2 Tx Bytes;F2 Rx Bytes;Collisions\n";
    for (size_t i = 0; i < runs; ++i)
    {
        experiment(numberOfUEs, phyMode1, phyMode2, verbose, duration, m_wifiPhyStats, m_mobility, m_txp);

    }


    return 0;

}
