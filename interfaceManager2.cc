/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Sebastien Deronne <sebastien.deronne@gmail.com>
 */

 //
//  I changed this code to include Throughput Calculate at each 100ms during runtime simulation for Wifi Networks
// I did this because i need to get some parameters as throughput, RSSI, jitter, packet loss at runtime to apply an algorithm that change the interface communication during simulation
// by Laura Michaella -- 25/03/2020 --<laura.michaella@gmail.com>

#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/mobility-helper.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/yans-wifi-channel.h"

// This is a simple example in order to show how to configure an IEEE 802.11n Wi-Fi network
// with multiple TOS. It outputs the aggregated UDP throughput, which depends on the number of
// stations, the HT MCS value (0 to 7), the channel width (20 or 40 MHz) and the guard interval
// (long or short). The user can also specify the distance between the access point and the
// stations (in meters), and can specify whether RTS/CTS is used or not.

using namespace ns3;
uint32_t phyTxDropCount(0), phyRxDropCount(0);
uint32_t totalBytesReceived = 0;
uint32_t totalBytesReceivedSum = 0;
uint32_t totalBytesDropped = 0;
uint32_t bytesTotal; ///< total bytes received by all nodes
uint32_t packetsReceived; ///< total packets received by all nodes
uint16_t port = 10;
std::string CSVfileName = "interfaceManager2.csv";
std::ofstream rdTraced;

uint64_t pktCount_n; //sinalização de pacotes

void ReceivePacket (Ptr<Socket> socket)
{
  while (socket->Recv ())
    {
      NS_LOG_UNCOND ("Received one packet!");
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
//  NS_LOG_FUNCTION (this << context << packet << "PHYTX mode=" << mode );
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



//-----Functions to get throughput at runtime simulation showing in the cmd

void ReceivesPacket(std::string context, Ptr <const Packet> p)
 {
   //char c= context.at(24);
     //int index= c - '0';
     //totalBytesReceived[index] += p->GetSize();
// It's workking
       totalBytesReceived += p->GetSize();
//      std::cout<< "[" << Simulator::Now ().G etSeconds() << "]\t" << "Received : " << totalBytesReceived << std::endl;
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

// void
// ReceivePacket (Ptr <Socket> socket)
// {
// 	Ptr<Packet> packet;
// 	  Address senderAddress;
// 	  socket->SetRecvPktInfo(true);
// 	  while ((packet = socket->RecvFrom (senderAddress)))
// 	    {
// 	      bytesTotal += packet->GetSize ();
// 	      packetsReceived += 1;
// 	      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
// 	    }
// }


void CalculateThroughput2 ()
{
//   //for (int f=0; f<TN; f++)
//  //{
//   double TotalThroughput2=0;
  double mbs2 = ((totalBytesReceived*8.0)/(1000000*1));
  totalBytesReceivedSum =totalBytesReceived+totalBytesReceivedSum;

  //    //mbs[f] = ((totalBytesReceived[f]*8.0)/(1000000*1));
//    //cout<<"size of vector is  "<< totalBytesReceived.size()<< endl;
  //  TotalThroughput2+=mbs2+TotalThroughput2;
 std::cout<< "[" << Simulator::Now ().GetSeconds() << "]\t" << "Throughput Wifi network  : \t" << mbs2 << "\tQtd bytes Received:" << totalBytesReceived <<  std::endl;
 std::cout<< "Sum of total bytes received Wifi up to " <<  "[" << Simulator::Now ().GetSeconds() << "s]\t=" << totalBytesReceivedSum << std::endl;


  //  //rdTrace << Simulator::Now ().GetSeconds() << "\t"<< f << "\t" << mbs[f] <<"\n";
 //rdTrace2 << Simulator::Now ().GetSeconds() << "\t" << mbs2 <<"\n"<< "\nTotal bytes Received:" << totalBytesReceived1 << std::endl;
 Simulator::Schedule (MilliSeconds (100), &CalculateThroughput2);
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

// void ReceivedPacket(Ptr<const Packet> p, const Address & addr)
// {
// 	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
//
// }


void DroppedPacket(std::string context, Ptr <const Packet> p)
{

    std::cout << " TX p: " << *p << std::endl;

    totalBytesDropped += p->GetSize();
    //cout<< totalBytesDropped<<endl;
  //  rdTraced << totalBytesDropped <<"\n"<<totalBytesReceived ;

    std::cout << Simulator::Now ().GetSeconds() << "\t" << "Total Bytes Dropped:" << totalBytesDropped <<"\n"<< "Total Bytes Received:" << totalBytesReceived << std::endl;
    totalBytesDropped=0;
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
   totalPhyTxBytes=0;
   totalPhyRxDrop=0;
   DropBytes=0;
   Simulator::Schedule (MilliSeconds(100), &CalculatePhyRxDrop, m_wifiPhyStats);
}



//-----End of functions
NS_LOG_COMPONENT_DEFINE ("WifiMultiTos");

int main (int argc, char *argv[])
{
  uint32_t nWifi = 20;
  double simulationTime = 5; //seconds
  double distance = 20.0; //meters
  uint16_t mcs = 7;
  uint8_t channelWidth = 20; //MHz
  bool useShortGuardInterval = false;
  bool useRts = false;
  



  CommandLine cmd;
  cmd.AddValue ("nWifi", "Number of stations", nWifi);
  cmd.AddValue ("distance", "Distance in meters between the stations and the access point", distance);
  cmd.AddValue ("simulationTime", "Simulation time in seconds", simulationTime);
  cmd.AddValue ("useRts", "Enable/disable RTS/CTS", useRts);
  cmd.AddValue ("mcs", "MCS value (0 - 7)", mcs);
  cmd.AddValue ("channelWidth", "Channel width in MHz", channelWidth);
  cmd.AddValue ("useShortGuardInterval", "Enable/disable short guard interval", useShortGuardInterval);
  cmd.Parse (argc,argv);

  std::ofstream out (CSVfileName.c_str ());
  out << "SimulationSecond," <<
  "ReceiveRate," <<
  "PacketsReceived," <<
  std::endl;
  out.close ();

  Ptr<WifiPhyStats> m_wifiPhyStats; ///< wifi phy statistics
  m_wifiPhyStats = CreateObject<WifiPhyStats> ();
  //void ReceivedPacket (Ptr<const Packet> p, const Address & addr);
  Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node );
  void ReceivePacket (Ptr <Socket> socket); //Setup packet receivers ->  \param addr the receiving IPv4 address , \param node the receiving node -> \returns the communication socket
  /// Check network throughput
  void CheckThroughput ();
  void DroppedPacket (std::string context, Ptr<const Packet> p);

  // instanciamento de métodos


  NodeContainer wifiStaNodes;
  wifiStaNodes.Create (nWifi);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
  phy.SetChannel (channel.Create ());

  WifiMacHelper mac;
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211n_5GHZ);

  std::ostringstream oss;
  oss << "HtMcs" << mcs;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (oss.str ()),
                                "ControlMode", StringValue (oss.str ()),
                                "RtsCtsThreshold", UintegerValue (useRts ? 0 : 999999));

  Ssid ssid = Ssid ("ns3-80211n");

  mac.SetType ("ns3::StaWifiMac",
               "Ssid", SsidValue (ssid));

  NetDeviceContainer staDevices;
  staDevices = wifi.Install (phy, mac, wifiStaNodes);

  // mac.SetType ("ns3::ApWifiMac",
  //              "Ssid", SsidValue (ssid));

  // NetDeviceContainer apDevice;
  // apDevice = wifi.Install (phy, mac, wifiApNode);

  // Set channel width
  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));

  // Set guard interval
  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/HtConfiguration/ShortGuardIntervalSupported", BooleanValue (useShortGuardInterval));

  // mobility
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  for (uint32_t i = 0; i < nWifi; i++)
    {
      positionAlloc->Add (Vector (distance, 0.0, 0.0));
    }
  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  //mobility.Install (wifiApNode);
  mobility.Install (wifiStaNodes);

  // Internet stack
  InternetStackHelper stack;
//  stack.Install (wifiApNode);
  stack.Install (wifiStaNodes);
  Ipv4AddressHelper address;

  address.SetBase ("192.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer staNodeInterfaces;

  staNodeInterfaces = address.Assign (staDevices);
  //apNodeInterface = address.Assign (apDevice);

  //Setting Socket parameters

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");


  for (int conta_nodos=0;conta_nodos<=2;conta_nodos++){

  // pegar todos os nodos menos o nó de interesse que irá enviar o  video
    if (conta_nodos != 1) {
      Ptr<Socket> recvSink = Socket::CreateSocket (wifiStaNodes.Get (conta_nodos), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
      recvSink->Bind (local);
      recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));

    }else{
      //servidor
    Ptr<Socket> source = Socket::CreateSocket (wifiStaNodes.Get (conta_nodos), tid);
    InetSocketAddress remote = InetSocketAddress (staNodeInterfaces.GetAddress (conta_nodos, 0), 80);
    source->Connect (remote);

    }
  }


  // Setting applications
  ApplicationContainer sourceApplications, sinkApplications;
  std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
  uint32_t portNumber = 9;
  for (uint32_t index = 0; index < nWifi; ++index)
    {
      for (uint8_t tosValue : tosValues)
        {
          auto ipv4 = wifiStaNodes.Get (1)->GetObject<Ipv4> ();
          const auto address = ipv4->GetAddress (1, 0).GetLocal ();
          InetSocketAddress sinkSocket (address, portNumber++);
          sinkSocket.SetTos (tosValue);
          OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
          onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
          onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
          onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / nWifi));
          onOffHelper.SetAttribute ("PacketSize", UintegerValue (1472)); //bytes
          sourceApplications.Add (onOffHelper.Install (wifiStaNodes.Get (index)));
          PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
          sinkApplications.Add (packetSinkHelper.Install (wifiStaNodes.Get (1)));
        }
    }

//callbacks


  sinkApplications.Start (Seconds (0.0));
  sinkApplications.Stop (Seconds (simulationTime + 1));
  sourceApplications.Start (Seconds (1.0));
  sourceApplications.Stop (Seconds (simulationTime + 1));


  LogComponentEnable ("YansWifiChannel",LOG_LEVEL_DEBUG);

  phy.EnablePcap ("interfaceManager2-sta", staDevices);

  Packet::EnablePrinting ();


  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();



// calculate throughput network
  std::stringstream ST;
  ST<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";

  //ST<<"/NodeList/"<< 0 <<"/ApplicationList/*/$ns3::PacketSink/Rx";                 //

  Config::Connect (ST.str(), MakeCallback(&ReceivesPacket));

  Simulator::Schedule(Seconds(0.1), &CalculateThroughput2);

// calculate dropped packet

  std::stringstream Sd;

  Sd<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRxDrop";                 //
  Config::Connect (Sd.str(), MakeCallback(&DroppedPacket));


  Simulator::Schedule(Seconds(0.1), &CalculatePhyRxDrop,m_wifiPhyStats);



  // rdTraced.open("receivedvsdropped.dat", std::ios::out);                                             //
  // rdTraced << "# Time \t Dropped \n received \n" ;
  // Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivedPacket));



  Simulator::Stop (Seconds (simulationTime + 1));
  Simulator::Run ();

  double throughput = 0;
  for (uint32_t index = 0; index < sinkApplications.GetN (); ++index)
    {
      uint64_t totalPacketsThrough = DynamicCast<PacketSink> (sinkApplications.Get (index))->GetTotalRx ();
      throughput += ((totalPacketsThrough * 8) / (simulationTime * 1000000.0)); //Mbit/s
    }

  Simulator::Destroy ();

  if (throughput > 0)
    {
      std::cout << "Aggregated throughput: " << throughput << " Mbit/s" << std::endl;

    }
  else
    {
      NS_LOG_ERROR ("Obtained throughput is 0!");
      exit (1);
    }

  return 0;
}
