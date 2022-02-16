/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 *
 * Net topology
 *
 * With a 3x3 mesh grid (size can vary):
 *
 *               n2   n3   n4
 *
 *
 * n0----n1 )))  n5   n6   n7
 *
 *
 *               n8   n9   n10
 *
 *
 *
 *  n0: internet node.
 *  n1: access node (a static mesh node with a P2P link).
 *  n2-n10: mesh nodes.
 *
 *  n0 has ip 1.1.1.1 to emulate internet access.
 *  n1 is always at the middle of the mesh, horizontal distance to the mesh can be set.
 *
 *  There are traffic generators in each node but n1 (no need)
 *  so they can emulate uploads and downloads to internet.
 *
 *  A IPv4 ping app is enable to check conectivity and keep track of
 *  simulation as it runs. It pings "internet" (AKA 1.1.1.1) from the last node every 1 sec.
 *
 *  In this scenario, AODV routes are used as L3 routing protocol for everyone.
 *  This solves L2 routing as well inside the mesh.
 *
 *  Performance is measured with Flowmon. Every node (but n1) has sink for packets.
 *  Flows are output in a .CSV file, using tabs as separators
 *
 *  Author: Carlos Cordero
 *  Email: carlos.cordero.0@gmail.com
 *
 */

#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/v4ping-helper.h"
#include "ns3/aodv-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/flow-monitor.h"
#include "ns3/animation-interface.h"
//----------------------------
#include "ns3/wifi-phy.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <stdlib.h>
#include <iomanip>

//---------------------------------
//added lib
#include "ns3/gnuplot.h"
#include "ns3/flow-monitor-module.h"
#include <ns3/flow-monitor-helper.h>

#include "ns3/energy-module.h"
//#include <gnuplot.h>
//---------------------
uint32_t packetsReceived;
uint32_t bytesTotal;

using namespace ns3;
//-----------------------------------------------
//void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon,Gnuplot2dDataset DataSet);
void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon,Gnuplot2dDataset DataSet);

//------------------------------------------------

// Trace function for remaining energy at node.
void
RemainingEnergy (double oldValue, double remainingEnergy)
{
  NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                 << "s Current remaining energy = " << remainingEnergy << "J");
}

/// Trace function for total energy consumption at node.
void
TotalEnergy (double oldValue, double totalEnergy)
{
  NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                 << "s Total energy consumed by radio = " << totalEnergy << "J");
}

/// --- some callbacks ----///

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

// Global variables for use in callbacks.
double g_signalDbmAvg;
double g_noiseDbmAvg;
uint32_t g_samples;
uint8_t m_tos;


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
// extract edca
void traceqos (std::string context, Ptr<const Packet> packet)
        {
          Ptr<Packet> copy = packet->Copy ();
          LlcSnapHeader ppp;
          Ipv4Header iph;
          std::string access_class;
          copy->RemoveHeader(ppp);
          copy->RemoveHeader (iph);
          //If we are not a QoS AP then we definitely want to use AC_BE to
          // transmit the packet. A TID of zero will map to AC_BE (through \c
          // QosUtilsMapTidToAc()), so we use that as our default here.
          uint8_t tid = QosUtilsGetTidForPacket (packet);


          // Any value greater than 7 is invalid and likely indicates that
          // the packet had no QoS tag, so we revert to zero, which'll
          // mean that AC_BE is used.
          if (tid < 8)
          {
            switch (tid)
                  {
                    case 0:
                    case 3:
                    access_class = "AC_BE";
                    break;
                    case 1:
                    case 2:
                    access_class = "AC_BK";
                    break;
                    case 4:
                    case 5:
                    access_class = "AC_VI";
                    break;
                    case 6:
                    case 7:
                    break;
                    access_class = "AC_VO";
                  } }   else {
                      tid = 0;
                      access_class = "AC_UNDEF";
                      NS_ASSERT_MSG (tid < 8, "Tid " << tid << " out of range");
                  }
          // This enumeration defines the Access Categories as an enumeration with values corresponding to the AC index (ACI) values specified (Table 8-104 "ACI-to-AC coding"; IEEE 802.11-2012).
          // from qos-utils.h


          std::cout<< "[" << Simulator::Now ().GetSeconds() << "]" <<"<--->" << "Send packet from "<<iph.GetSource()<<" to "<<iph.GetDestination()<<std::endl;
          }



///-----------------------------------------------------////

int main (int argc, char *argv[])
{
  ns3::PacketMetadata::Enable ();
  NS_LOG_COMPONENT_DEFINE ("TesisBase");
//---------------------------------------
 // LogComponentEnable ("Time", LOG_LEVEL_ALL);
  //LogComponentEnableAll (LOG_LEVEL_DEBUG);
// LogComponentEnable ("aodvRoutingProtocol", LOG_LEVEL_ALL);
 //LogComponentEnable ("PacketSink", LOG_LEVEL_DEBUG);
//-----------------------------------------------
  LogComponentEnable ("V4Ping", LOG_LEVEL_DEBUG);


// Variable definition (all generic variables starts with "m_")
  int m_xNodes = 3; // Mesh width in number of nodes
  int m_yNodes = 2; // Mesh heigth in number of nodes
  int m_numberUavMdc = 5;
  int m_distNodes = 100; // Distance between nodes (mts)
  int m_distNodes_2 = 100; // Distance between nodes (mts)
  int m_distAP = 50; // Distance between access nodes and mesh (mts)
  int m_totalTime = 90; // Time to simulate (segs)
  int m_packetSize = 512; // Packet size for tests
  double m_rss = 88; //86 minimum for 100mts range 11a, 88 for 11g
  bool m_mobile = false; // Mesh nodes are mobile
  bool m_newFlowFile = false; // Clear flow .csv file
  bool m_drawAnim = false; // Enable netanim .xls output
  int nodeSpeed = 20; //in m/s UAVs speed
  int nodePause = 0; //in s UAVs pause
  uint8_t channelWidth = 20; //MHz

  std::string m_txAppRate = "128kbps"; // Transmision speed for apps
  std::string m_txInternetRate = "1Mbps"; // Transmision speed to n0 <-> n1 link
  std::string m_animFile = "resultados/basev4-aodv.xml"; // File for .xml
  std::string m_routeFile = "resultados/basev4-aodv-route.xml"; // File for .xml routing
  std::string m_statsFile = "resultados/basev4-aodv-3x3"; // Prefix for statistics output files
  std::string m_flowmonFile = "resultados/basev4-aodv.flowmon"; // File for flowmon output
  int tmp_x;
  char tmp_char [30] = "";
  Ptr<Socket> SetupPacketReceive (Ipv4Address addr, Ptr<Node> node);
  void ReceivePacket (Ptr<Socket> socket);



// Command line options
  CommandLine cmd;
  cmd.AddValue ("mesh-width", "Number of node in mesh width", m_xNodes);
  cmd.AddValue ("mesh-height", "Number of node in mesh height", m_yNodes);
  cmd.AddValue ("node-distance", "Distance between nodes (horizontally / vertically)", m_distNodes);
  cmd.AddValue ("ap-distance", "Distance between access nodes and mesh (horizontally)", m_distAP);
  cmd.AddValue ("time", "Total time to simulate", m_totalTime);
  cmd.AddValue ("mobile", "Set movement to mesh nodes", m_mobile);
  cmd.AddValue ("app-packet-size", "Set packet size to tx from apps", m_packetSize);
  cmd.AddValue ("app-tx-rate", "Set speed of traffic generation", m_txAppRate);
  cmd.AddValue ("link-speed", "Transmision speed over P2P link", m_txInternetRate);
  cmd.AddValue ("enable-anim", "Enable output for .xml animation", m_drawAnim);
  cmd.AddValue ("anim-file", "Set output name for .xml animation file", m_animFile);
  cmd.AddValue ("route-file", "Set output name for route file", m_routeFile);
  cmd.AddValue ("stats-file", "Set output prefix for .csv flows results file", m_statsFile);
  cmd.AddValue ("new-flow-file", "Clear .csv flows results file", m_newFlowFile);
  cmd.AddValue ("flow-file", "Set output name for flow monitor .flowmon file", m_flowmonFile);
  cmd.Parse (argc, argv);

// Node container creation (all node containers starts with "nc_")
  NodeContainer nc_all; // Contains every node (starting with internet node, access nodes and then mesh nodes
  NodeContainer nc_mesh; // Contains only mesh nodes (x*y nodes)
  NodeContainer nc_wireless; // Contains access and mesh nodes
  NodeContainer nc_internet; // Contains internet nodes
  NodeContainer nc_destiny; // Contains nodes with sink for apps (internet and mesh nodes)
  NodeContainer nc_uav; // contains uavs
  nc_mesh.Create (m_xNodes * m_yNodes);
  nc_all.Create (2);
  nc_uav.Create (m_numberUavMdc);
  nc_all.Add (nc_mesh);
  nc_all.Add (nc_uav);
  nc_wireless.Add (nc_all.Get (1));
  nc_wireless.Add (nc_mesh);
  nc_internet.Add (nc_all.Get (0));
  nc_internet.Add (nc_all.Get (1));
  nc_destiny.Add (nc_all.Get (0));
  nc_destiny.Add (nc_mesh);
  nc_destiny.Add (nc_uav);



// Create P2P links between n0 <-> n1 (all devices starts with "de_")
  PointToPointHelper p2pinternet;
  p2pinternet.SetDeviceAttribute ("DataRate", StringValue (m_txInternetRate));
  p2pinternet.SetChannelAttribute ("Delay", StringValue ("10ms"));
  NetDeviceContainer de_internet;
  de_internet = p2pinternet.Install (nc_internet);

// Set YansWifiChannel
  WifiHelper wifi;
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  WifiMacHelper wifiMac;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211g);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue ("ErpOfdmRate6Mbps"));
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  wifiPhy.Set ("RxGain", DoubleValue (m_rss));
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");

  wifiMac.SetType ("ns3::AdhocWifiMac");
  wifiPhy.SetChannel (wifiChannel.Create ());
  NetDeviceContainer de_wireless = wifi.Install (wifiPhy, wifiMac, nc_wireless);

// Configurating uav communications

  // setting up wifi phy and channel using helpers
  WifiHelper wifi_uav;
  wifi_uav.SetStandard (WIFI_PHY_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy_uav =  YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel_uav;
  wifiChannel_uav.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel_uav.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy_uav.SetChannel (wifiChannel_uav.Create ());

  // Add a mac and disable rate control
  WifiMacHelper wifiMac_uav;
  wifi_uav.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue ("DsssRate11Mbps"),
                                "ControlMode",StringValue ("DsssRate11Mbps"));

  wifiPhy_uav.Set ("TxPowerStart",DoubleValue (7.5));
  wifiPhy_uav.Set ("TxPowerEnd", DoubleValue (7.5));

  wifiMac_uav.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer de_uav = wifi_uav.Install (wifiPhy_uav, wifiMac_uav, nc_uav);

//  wifi.EnableLogComponents ();
//  wifi_uav.EnableLogComponents ();

// Set startup positions for nodes
  MobilityHelper mobilityMesh; //Position mesh nodes
  mobilityMesh.SetPositionAllocator ("ns3::GridPositionAllocator",
                                    "MinX", DoubleValue (m_distAP),
                                    "MinY", DoubleValue (0.0),
                                    "DeltaX", DoubleValue (m_distNodes),
                                    "DeltaY", DoubleValue (m_distNodes_2),
                                    "GridWidth", UintegerValue (m_xNodes),
                                    "LayoutType", StringValue ("RowFirst"));

  if (m_mobile) // Set mobility for mesh
  { //if walking nodes
    int t1 = m_distAP / 2;
    int t2 = m_distAP + ((m_xNodes - 1) * m_distNodes) + (m_distAP / 2);
    int t3 = m_distAP / -2;
    int t4 = (m_yNodes * m_distNodes) + (m_distAP / 2);
    sprintf (tmp_char, "%d|%d|%d|%d", t1, t2, t3, t4);
    mobilityMesh.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                                  "Mode", StringValue ("Time"),
                                  "Time", StringValue ("2s"),
                                  "Bounds", StringValue (tmp_char));
  }
  else
  { //if standing nodes
    mobilityMesh.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  }
  mobilityMesh.Install (nc_mesh);

  MobilityHelper mobilityInternet; //Position internet and access node
  mobilityInternet.SetPositionAllocator ("ns3::GridPositionAllocator",
                                    "MinX", DoubleValue (m_distAP * -1),
                                    "MinY", DoubleValue ((m_distNodes * (m_yNodes - 1)) / 2),
                                    "DeltaX", DoubleValue (m_distAP),
                                    "DeltaY", DoubleValue (0.0),
                                    "GridWidth", UintegerValue (2),
                                    "LayoutType", StringValue ("RowFirst"));
  mobilityInternet.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobilityInternet.Install (nc_internet);

  // Uavs Mobility --------

  MobilityHelper mobilityUAVs;
  int64_t streamIndex = 0; // used to get consistent mobility across scenarios

  ObjectFactory pos;
  pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
  pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
  pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=200.0]"));

  Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  streamIndex += taPositionAlloc->AssignStreams (streamIndex);

  std::stringstream ssSpeed;
  ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
  std::stringstream ssPause;
  ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
  mobilityUAVs.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                  "Speed", StringValue (ssSpeed.str ()),
                                  "Pause", StringValue (ssPause.str ()),
                                  "PositionAllocator", PointerValue (taPositionAlloc));
  mobilityUAVs.SetPositionAllocator (taPositionAlloc);
  mobilityUAVs.Install (nc_uav);
  streamIndex += mobilityUAVs.AssignStreams (nc_uav, streamIndex);
  NS_UNUSED (streamIndex); // From this point, streamIndex is unused
// End Uavs mobility configurations


// Set Internet stack and config IPs for interfaces (all interfaces starts with "if_")
  InternetStackHelper internetStack;
  AodvHelper aodv;
  internetStack.SetRoutingHelper (aodv);
  internetStack.Install (nc_all);

  Ipv4AddressHelper addrMesh;
  addrMesh.SetBase ("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer if_mesh = addrMesh.Assign (de_wireless);


  Ipv4AddressHelper addrInternet;
  addrInternet.SetBase ("1.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if_internet = addrInternet.Assign (de_internet);


  Ipv4AddressHelper addressUAV;
  addressUAV.SetBase ("192.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if_uav = addressUAV.Assign (de_uav);
  //if_mesh.Add(if_uav);

  // 
  // Ptr<Ipv4> ip_wireless[m_numberUavMdc];
  // {
  //   for (int cont = 0; cont < m_numberUavMdc; cont++)
  //     ip_wireless[cont] = nc_uav.Get(cont)->GetObject<Ipv4> ();
  // }
  //
  // Ipv4StaticRoutingHelper ipv4RoutingHelper;
  // Ptr<Ipv4StaticRouting> staticRouting[m_numberUavMdc];
  // for (int i = 0; i < m_numberUavMdc; i++)
  // {
  //     staticRouting[i] = ipv4RoutingHelper.GetStaticRouting (ip_wireless[i]);
  // }
  //
  //
  // //Flow 0: 0--->6--->12
  // staticRouting[0]->AddHostRouteTo (Ipv4Address ("192.168.1.1"), Ipv4Address ("10.1.1.1"), 1);
  // staticRouting[1]->AddHostRouteTo (Ipv4Address ("192.168.1.2"), Ipv4Address ("10.1.1.2"), 1);
  // staticRouting[2]->AddHostRouteTo (Ipv4Address ("192.168.1.3"), Ipv4Address ("10.1.1.2"), 1);
  // staticRouting[3]->AddHostRouteTo (Ipv4Address ("192.168.1.4"), Ipv4Address ("10.1.1.2"), 1);
  // staticRouting[4]->AddHostRouteTo (Ipv4Address ("192.168.1.5"), Ipv4Address ("10.1.1.2"), 1);



// Install applications
// Set sinks for receiving data
  PacketSinkHelper sinkTcp ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer ac_sinkTcp = sinkTcp.Install (nc_destiny);
  ac_sinkTcp.Start (Seconds (10.0));
  ac_sinkTcp.Stop (Seconds (m_totalTime - 1));

// Set traffic generator apps
  Config::SetDefault ("ns3::OnOffApplication::PacketSize", UintegerValue (m_packetSize));
  Config::SetDefault ("ns3::OnOffApplication::DataRate", StringValue (m_txAppRate));
  std::ostringstream oss_crv;
  oss_crv << "ns3::ConstantRandomVariable[Constant=" << std::rand () % 10 << "]";
  Config::SetDefault ("ns3::OnOffApplication::OnTime", StringValue (oss_crv.str ()));
  oss_crv << "ns3::ConstantRandomVariable[Constant=" << std::rand () % 10 << "]";
  Config::SetDefault ("ns3::OnOffApplication::OffTime", StringValue (oss_crv.str ()));
//------------------------------
  //Config::SetDefault ("ns3::OnOffApplication::OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=10.0]"));
 // Config::SetDefault ("ns3::OnOffApplication::OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]"));
//-------------------------------------
  ApplicationContainer ac_onoffMesh; // Creates 1 OnOff App in each mesh node TO internet
  OnOffHelper onoffMesh ("ns3::TcpSocketFactory", Address (InetSocketAddress (if_internet.GetAddress (0), 9)));

  ApplicationContainer ac_onoffMesh_UAV; // Creates 1 OnOff App in each uav node TO mesh
  OnOffHelper onoffMesh_UAV ("ns3::TcpSocketFactory", Address (InetSocketAddress (if_mesh.GetAddress (0), 9)));

// //----------------------------------
  //onoffMesh.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=3.0]"));
 // onoffMesh.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=5.0]"));
//---------------------------------------------
  ac_onoffMesh = onoffMesh.Install (nc_mesh);
  ac_onoffMesh.Start (Seconds (30));
  ac_onoffMesh.Stop (Seconds (m_totalTime - 10));

  ac_onoffMesh_UAV = onoffMesh_UAV.Install (nc_uav);
  ac_onoffMesh_UAV.Start (Seconds (m_totalTime/2));
  ac_onoffMesh_UAV.Stop (Seconds (m_totalTime + 1));

  ApplicationContainer ac_onoffInternet [m_xNodes * m_yNodes]; // Creates 1 OnOff App for each mesh node FROM internet
  ApplicationContainer ac_onoffUAV [m_numberUavMdc]; // Creates 1 OnOff App for each uav node FROM mesh node
  // applications between UAV and mesh routers (UAV is source nodes and mesh are the sink nodes)
  // ApplicationContainer sourceApplications, sinkApplications;
  // std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
  // uint32_t portNumber = 9;
  for (tmp_x = 0; tmp_x < m_xNodes * m_yNodes; tmp_x++)
  {
    OnOffHelper onoffInternet ("ns3::TcpSocketFactory", Address (InetSocketAddress (if_mesh.GetAddress (tmp_x), 9)));
    ac_onoffInternet [tmp_x] = onoffInternet.Install (nc_all.Get (0));
    ac_onoffInternet [tmp_x].Start (Seconds (30));
    ac_onoffInternet [tmp_x].Stop (Seconds (m_totalTime - 5));
  }
  for (tmp_x = 0; tmp_x < m_xNodes * m_yNodes; tmp_x++)
  {
      for (int tmp_uav = 0; tmp_uav < m_numberUavMdc; tmp_uav++)
      {
        OnOffHelper onoffMesh_UAV ("ns3::TcpSocketFactory", Address (InetSocketAddress (if_uav.GetAddress (tmp_uav), 9)));
        ac_onoffUAV [tmp_uav] = onoffMesh_UAV .Install (nc_mesh.Get (tmp_x));
        ac_onoffUAV [tmp_uav].Start (Seconds (m_totalTime/2));
        ac_onoffUAV [tmp_uav].Stop (Seconds (m_totalTime +1));
      }
  }
  // for (tmp_x = 0; tmp_x < m_xNodes * m_yNodes; tmp_x++)
  // {
  // // Setting UAV applications
  //   for (uint32_t index = 0; index < m_numberUavMdc; ++index)
  //     {
  //       for (uint8_t tosValue : tosValues)
  //         {
  //           auto ipv4 = nc_uav.Get (index)->GetObject<Ipv4> ();
  //           const auto address = ipv4->GetAddress (1, 0).GetLocal ();
  //           InetSocketAddress sinkSocket (address, portNumber++);
  //           sinkSocket.SetTos (tosValue);
  //           OnOffHelper onOffHelper ("ns3::UdpSocketFactory", sinkSocket);
  //           onOffHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  //           onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  //           onOffHelper.SetAttribute ("DataRate", DataRateValue (50000000 / m_numberUavMdc));
  //           onOffHelper.SetAttribute ("PacketSize", UintegerValue (1472)); //bytes
  //           sourceApplications.Add (onOffHelper.Install (nc_mesh.Get (tmp_x)));
  //           PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
  //           sinkApplications.Add (packetSinkHelper.Install (nc_uav.Get (index)));
  //         }
  //     }
  // }
  //
  //
  // sinkApplications.Start (Seconds (m_totalTime/2));
  // sinkApplications.Stop (Seconds (m_totalTime + 1));
  // sourceApplications.Start (Seconds (m_totalTime/2 + 1));
  // sourceApplications.Stop (Seconds (m_totalTime + 1));




/////PING FOR  TESTS
        V4PingHelper ping1 (if_internet.GetAddress (0));
        ping1.SetAttribute ("Verbose", BooleanValue (true));
        ping1.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
         ApplicationContainer appPingInternet1 = ping1.Install (nc_all.Get(m_xNodes * m_yNodes + 1));
        appPingInternet1.Start (Seconds (0));
        appPingInternet1.Stop (Seconds (m_totalTime - 1));

        V4PingHelper ping2 (if_mesh.GetAddress (0));
        ping2.SetAttribute ("Verbose", BooleanValue (true));
         ping2.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
        ApplicationContainer appPingInternet2 = ping2.Install (nc_all.Get(m_xNodes * m_yNodes + 1));
        appPingInternet2.Start (Seconds (0));
         appPingInternet2.Stop (Seconds (m_totalTime - 1));

         V4PingHelper ping3 (if_uav.GetAddress (0));
         ping3.SetAttribute ("Verbose", BooleanValue (true));
          ping3.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
         ApplicationContainer appPingInternet3 = ping3.Install (nc_all.Get(m_xNodes * m_yNodes + 1));
         appPingInternet3.Start (Seconds (0));
          appPingInternet3.Stop (Seconds (m_totalTime - 1));

//----starting callbacks ----//

// Set channel width
Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));
Config::ConnectWithoutContext ("/NodeList/0/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));
// make able to verify mac_Rx
Config::Connect("/NodeList/*/DeviceList/*/Mac/MacRx", MakeCallback(&traceqos));

//----------------------------start of Energy Model--------------------------//
  /** Energy Model **/
  /***************************************************************************/
  /* energy source */
  //BasicEnergySourceHelper basicSourceHelper;
  // configure energy source
  //basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (0.1));
  // install source
 // EnergySourceContainer sources = basicSourceHelper.Install (nc_internet);
  /* device energy model */
 // WifiRadioEnergyModelHelper radioEnergyHelper;
  // configure radio energy model
 // radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0174));
  // install device model
  //DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (de_wireless,sources);//
  /***************************************************************************/




  /** connect trace sources **/
  /***************************************************************************/

  // energy source
 //Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource> (sources.Get (1));
// basicSourcePtr->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergy));
  // device energy model
 //Ptr<DeviceEnergyModel> basicRadioModelPtr =
  // basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
 ///NS_ASSERT (basicRadioModelPtr != NULL);
  //basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption", MakeCallback (&TotalEnergy));
/***************************************************************************/


///-------------------------------end of energy model-----------------------//


/////END PING FOR TESTS

//----------------------------------------------------------
//// Sets animation configs and create .xml file for NetAnim
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  Simulator::Stop (Seconds (m_totalTime));

 for (tmp_x = 2; tmp_x < m_xNodes * m_yNodes + 2; tmp_x++)
 {
  sprintf (tmp_char, "%d-STA", tmp_x);
 AnimationInterface animation ("m_animFile.xml");
   animation.UpdateNodeDescription (nc_all.Get (tmp_x), tmp_char);

  }

   AnimationInterface animation1 ("m_animFile1.xml");
 animation1.UpdateNodeDescription (nc_all.Get (0), "0-Internet");
 animation1.UpdateNodeDescription (nc_all.Get (1), "1-AP");
 //animation1.UpdateNodeDescription (nc_uav.GetN (), "UAV");

// animation1.UpdateNodeColor(nc_mesh.Get(m_xNodes * m_yNodes), 0, 255, 0);

 animation1.UpdateNodeColor (nc_internet.Get (0), 255, 0, 0);

 animation1.UpdateNodeColor (nc_internet.Get (1), 0, 0, 255);

 if (m_drawAnim)
  {
   AnimationInterface animation ("m_animFile2.xml");
   animation.EnablePacketMetadata(true);
    animation.EnableIpv4RouteTracking (m_routeFile, Seconds (0), Seconds (m_totalTime), Seconds (0.25));
 }
//------------------------GNU plot start------------------------------------------



 //Gnuplot parameters

    std::string fileNameWithNoExtension1 = "FlowVSThroughput_UAV";
    std::string graphicsFileName_uav        = fileNameWithNoExtension1 + ".png";
    std::string plotFileName_uav            = fileNameWithNoExtension1 + ".plt";
    std::string plotTitle_uav               = "Flow vs Throughput";
    std::string dataTitle_uav               = "Throughput UAV";

    std::string fileNameWithNoExtension = "FlowVSThroughput_";
    std::string graphicsFileName        = fileNameWithNoExtension + ".png";
    std::string plotFileName            = fileNameWithNoExtension + ".plt";
    std::string plotTitle               = "Flow vs Throughput";
    std::string dataTitle               = "Throughput";

    // Instantiate the plot and set its title.
    Gnuplot gnuplot (graphicsFileName);
    gnuplot.SetTitle (plotTitle);

    Gnuplot gnuplot2 (graphicsFileName_uav);
    gnuplot.SetTitle (plotTitle_uav);


    // Make the graphics file, which the plot file will be when it
    // is used with Gnuplot, be a PNG file.
    gnuplot.SetTerminal ("png");
    gnuplot2.SetTerminal ("png");


    // Set the labels for each axis.
    gnuplot.SetLegend ("Flow", "Throughput");
    gnuplot2.SetLegend ("Flow", "Throughput");



   Gnuplot2dDataset dataset, dataset2;
   dataset.SetTitle (dataTitle_uav);
   dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);
   dataset2.SetTitle (dataTitle);
   dataset2.SetStyle (Gnuplot2dDataset::LINES_POINTS);



  //flowMonitor declaration
  FlowMonitorHelper fmHelper;
  Ptr<FlowMonitor> allMon = fmHelper.InstallAll();
  // call the flow monitor function
  allMon->CheckForLostPackets();
  ThroughputMonitor(&fmHelper, allMon, dataset);
  ThroughputMonitor(&fmHelper, allMon, dataset2);


  //Simulator::Schedule (Seconds (m_totalTime));//, &MeshTest::Report, this);
  Simulator::Stop (Seconds (m_totalTime));
  Simulator::Run ();

  //Gnuplot ...continued
  gnuplot.AddDataset (dataset);
  gnuplot.AddDataset (dataset2);
  // Open the plot file.
  std::ofstream plotFile (plotFileName.c_str());
  std::ofstream plotFile2 (plotFileName_uav.c_str());

  // Write the plot file.
  gnuplot.GenerateOutput (plotFile);
  gnuplot.GenerateOutput (plotFile2);

  // Close the plot file.
  plotFile.close ();
  plotFile2.close ();


Simulator::Destroy ();
  return 0;

}


// void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon,Gnuplot2dDataset DataSet)
// 	{
//     double localThrou=0;
// //    double localThrou2=0;
//
// 		std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats();
//
//
//
//     int txPacketsumWifi = 0;
//     int rxPacketsumWifi = 0;
//     int DropPacketsumWifi = 0;
//     int LostPacketsumWifi = 0;
//     double ThroughputsumWiFi = 0;
//     double rxDurationWifi=0;
//     Time DelaysumWifi;
//     Time JittersumWifi;
//
//
// 		Ptr<Ipv4FlowClassifier> classing = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier());
// 		for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
// 		{
// 			Ipv4FlowClassifier::FiveTuple fiveTuple = classing->FindFlow (stats->first);
//
//       // if((fiveTuple.sourceAddress == "192.168.1.1" && fiveTuple.destinationAddress == "10.1.1.1") || (fiveTuple.sourceAddress == "192.168.1.2" && fiveTuple.destinationAddress == "10.1.1.2")
//       //  || (fiveTuple.sourceAddress == "192.168.1.3" && fiveTuple.destinationAddress == "10.1.1.3") || (fiveTuple.sourceAddress == "192.168.1.4" && fiveTuple.destinationAddress == "10.1.1.4")
//       //  || (fiveTuple.sourceAddress == "192.168.1.5" && fiveTuple.destinationAddress == "10.1.1.5"))
//       //  {
//          txPacketsumWifi += stats->second.txPackets;
//          rxPacketsumWifi += stats->second.rxPackets;
//          LostPacketsumWifi += stats->second.lostPackets;
//          DropPacketsumWifi += stats->second.packetsDropped.size();
//          DelaysumWifi += ((stats->second.delaySum)/(stats->second.rxPackets));               //ns
//          JittersumWifi += ((stats->second.jitterSum)/(stats->second.rxPackets));
//
//          rxDurationWifi = stats->second.timeLastRxPacket.GetSeconds () - stats->second.timeFirstRxPacket.GetSeconds ();
//          ThroughputsumWiFi += (stats->second.rxBytes * 8.0 / rxDurationWifi / 1000 / 1000);  //Mbps
//
//          std::cout<<"\nFlow ID			: " << stats->first <<" ; "<< fiveTuple.sourceAddress <<" -----> "<<fiveTuple.destinationAddress<<std::endl;
//          std::cout << "  Simulation Time: " << Simulator::Now().GetSeconds() << "\n";
//          std::cout << "  First Time: " << stats->second.timeFirstRxPacket.GetSeconds() << "\n";
//          std::cout << "  Last Time: " << stats->second.timeLastTxPacket.GetSeconds() << "\n";
//          std::cout<<"Duration		: "<<(stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())<<std::endl;
//          std::cout<<"Last Received Packet	: "<< stats->second.timeLastRxPacket.GetSeconds()<<" Seconds"<<std::endl;
//          std::cout << "  Tx Packets: " << stats->second.txPackets << "\n";
//          std::cout << "  Tx Bytes:   " << stats->second.txBytes << "\n";
//          std::cout << "  Rx Packets: " << stats->second.rxPackets << "\n";
//          std::cout << "  Rx Bytes:   " << stats->second.rxBytes << "\n";
//          std::cout << "  Lost Packets:   " << stats->second.lostPackets << "\n";
//            if (stats->second.rxPackets > 1)
//            {
//                std::cout << "  Delay:   " << ((stats->second.delaySum)/(stats->second.rxPackets))/1000000 << " milliseconds\n";         //ms
//                std::cout << "  Jitter:   " << ((stats->second.jitterSum)/(stats->second.rxPackets)) << " nanoseconds\n";       //ns
//            }
//       	std::cout<<"Throughput: " << stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps"<<std::endl;
//         localThrou=(stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024);
//   			 //updata gnuplot data
//               DataSet.Add((double)Simulator::Now().GetSeconds(),(double) localThrou);
//   			std::cout<<"---------------------------------------------------------------------------"<<std::endl;
//
//   		}
//
//       Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, flowMon,DataSet);
//       {
//       flowMon->SerializeToXmlFile ("ThroughputMonitor_uav.xml", true, true);
//     }
//      // if((fiveTuple.sourceAddress == "10.1.1.1" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.1" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.2" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.2" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.3" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.3" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.4" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.4" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.5" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.5" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.6" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.6" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.7" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.7" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.8" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.8" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.9" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.9" && fiveTuple.destinationAddress == "1.1.1.2")
//      //  || (fiveTuple.sourceAddress == "10.1.1.10" && fiveTuple.destinationAddress == "1.1.1.1") || (fiveTuple.sourceAddress == "10.1.1.10" && fiveTuple.destinationAddress == "1.1.1.2"))
//      //
//      //  {
//      //    txPacketsumWifi += stats->second.txPackets;
//      //    rxPacketsumWifi += stats->second.rxPackets;
//      //    LostPacketsumWifi += stats->second.lostPackets;
//      //    DropPacketsumWifi += stats->second.packetsDropped.size();
//      //    DelaysumWifi += ((stats->second.delaySum)/(stats->second.rxPackets));               //ns
//      //    JittersumWifi += ((stats->second.jitterSum)/(stats->second.rxPackets));
//      //
//      //    rxDurationWifi = stats->second.timeLastRxPacket.GetSeconds () - stats->second.timeFirstRxPacket.GetSeconds ();
//      //    ThroughputsumWiFi += (stats->second.rxBytes * 8.0 / rxDurationWifi / 1000 / 1000);  //Mbps
//      //
//      //    std::cout<<"\nFlow ID			: " << stats->first <<" ; "<< fiveTuple.sourceAddress <<" -----> "<<fiveTuple.destinationAddress<<std::endl;
//      //    std::cout << "  Simulation Time: " << Simulator::Now().GetSeconds() << "\n";
//      //    std::cout << "  First Time: " << stats->second.timeFirstRxPacket.GetSeconds() << "\n";
//      //    std::cout << "  Last Time: " << stats->second.timeLastTxPacket.GetSeconds() << "\n";
//      //    std::cout<<"Duration		: "<<(stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())<<std::endl;
//      //    std::cout<<"Last Received Packet	: "<< stats->second.timeLastRxPacket.GetSeconds()<<" Seconds"<<std::endl;
//      //    std::cout << "  Tx Packets: " << stats->second.txPackets << "\n";
//      //    std::cout << "  Tx Bytes:   " << stats->second.txBytes << "\n";
//      //    std::cout << "  Rx Packets: " << stats->second.rxPackets << "\n";
//      //    std::cout << "  Rx Bytes:   " << stats->second.rxBytes << "\n";
//      //    std::cout << "  Lost Packets:   " << stats->second.lostPackets << "\n";
//      //      if (stats->second.rxPackets > 1)
//      //      {
//      //          std::cout << "  Delay:   " << ((stats->second.delaySum)/(stats->second.rxPackets))/1000000 << " milliseconds\n";         //ms
//      //          std::cout << "  Jitter:   " << ((stats->second.jitterSum)/(stats->second.rxPackets)) << " nanoseconds\n";       //ns
//      //      }
//      //   std::cout<<"Throughput: " << stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps"<<std::endl;
//      //   localThrou2=(stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024);
//      //    //updata gnuplot data
//      //         DataSet.Add((double)Simulator::Now().GetSeconds(),(double) localThrou2);
//      //   std::cout<<"---------------------------------------------------------------------------"<<std::endl;
//      //   Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, flowMon,DataSet);
//      //  flowMon->SerializeToXmlFile ("ThroughputMonitor_mesh_access.xml", true, true);
//      // }
// 	// }
//
// }

void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon,Gnuplot2dDataset DataSet)
	{
        double localThrou=0;
		std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats();
		Ptr<Ipv4FlowClassifier> classing = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier());
		for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
		{
			Ipv4FlowClassifier::FiveTuple fiveTuple = classing->FindFlow (stats->first);
			std::cout<<"Flow ID			: " << stats->first <<" ; "<< fiveTuple.sourceAddress <<" -----> "<<fiveTuple.destinationAddress<<std::endl;
			std::cout<<"Tx Packets = " << stats->second.txPackets<<std::endl;
			std::cout<<"Rx Packets = " << stats->second.rxPackets<<std::endl;
            std::cout<<"Duration		: "<<(stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())<<std::endl;
			std::cout<<"Last Received Packet	: "<< stats->second.timeLastRxPacket.GetSeconds()<<" Seconds"<<std::endl;
			std::cout<<"Throughput: " << stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps"<<std::endl;
            localThrou=(stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024);
			 //updata gnuplot data
            DataSet.Add((double)Simulator::Now().GetSeconds(),(double) localThrou);
			std::cout<<"---------------------------------------------------------------------------"<<std::endl;
		}
			Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, flowMon,DataSet);

{
	flowMon->SerializeToXmlFile ("ThroughputMonitor.xml", true, true);
      }

	}

///----------------------end of the code---------------------------------------------------


//////////// Log data

// If requested, clean the flow file for a new use
  //if (m_newFlowFile)
  //{
  //  std::ostringstream os_clear;
   // os_clear << m_statsFile << "_flows.csv";
   // std::ofstream of_clear (os_clear.str().c_str(), std::ios::out | std::ios::trunc);
   // of_clear << """Src IP""\t""Dest IP""\t";
   // of_clear << """Src Port""\t""Dest Port""\t";
   // of_clear << """First Tx Pkt""\t""Last Tx Pkt""\t";
   // of_clear << """First Rx Pkt""\t""Last Rx Pkt""\t";
   // of_clear << """Total Tx Bytes""\t""Total Rx Bytes""\t";
   // of_clear << """Total Tx Packets""\t""Total Rx Packets""\n";
   // of_clear.close ();
  //}
//void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon,Gnuplot2dDataset DataSet);
// Open file to append new data
  //std::ostringstream os;
  //os << m_statsFile << "_flows.csv";
  //std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
//Print per flow statistics
        //monitor->CheckForLostPackets ();

        //std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
        //std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats();
        //Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
       // Ptr<Ipv4FlowClassifier> classing = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier());

  //for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
  //for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
  //{
        //Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
        //Ipv4FlowClassifier::FiveTuple fiveTuple = classing->FindFlow (stats->first);

      //  std::cout<<"Flow ID			: " << stats->first <<" ; "<< fiveTuple.sourceAddress <<" -----> "<<fiveTuple.destinationAddress<<std::endl;
	//std::cout<<"Tx Packets = " << stats->second.txPackets<<std::endl;
	//std::cout<<"Rx Packets = " << stats->second.rxPackets<<std::endl;
       // std::cout<<"Duration		: "<<(stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())<<std::endl;
	//std::cout<<"Last Received Packet	: "<< stats->second.timeLastRxPacket.GetSeconds()<<" Seconds"<<std::endl;
	//std::cout<<"Throughput: " << stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps"<<std::endl;
       // localThrou=(stats->second.rxBytes * 8.0 / (stats->second.timeLastRxPacket.GetSeconds()-stats->second.timeFirstTxPacket.GetSeconds())/1024/1024);
			// updata gnuplot data
       // DataSet.Add((double)Simulator::Now().GetSeconds(),(double) localThrou);
	//std::cout<<"---------------------------------------------------------------------------"<<std::endl;
	//	}

        //Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, flowMon,DataSet);

//{
	//flowMon->SerializeToXmlFile ("ThroughputMonitor.xml", true, true);
    // }

	//}
//
//}


//------------------------------------------------------------
          //NS_LOG_UNCOND("Flow ID: " << i->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);//3
    	  //NS_LOG_UNCOND("Tx Packets = " << i->second.txPackets);//4
    	 // NS_LOG_UNCOND("Rx Packets = " << i->second.rxPackets);//5
    	 // NS_LOG_UNCOND("Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps");//6

 //------------------------------------------------------------
    //of << t.sourceAddress << "\t" << t.destinationAddress << "\t";
   //of << t.sourcePort << "\t" << t.destinationPort << "\t";
  // of << i->second.timeFirstTxPacket.GetSeconds() << "\t" << i->second.timeLastTxPacket.GetSeconds() << "\t";
  // of << i->second.timeFirstRxPacket.GetSeconds() << "\t" << i->second.timeLastTxPacket.GetSeconds() << "\t";
  // of << i->second.txBytes << "\t" << i->second.rxBytes << "\t";
   // of << i->second.txPackets << "\t" << i->second.rxPackets << "\n";

 //}
//-----------------------------------------------------

  //of << """AODV""\t" << m_xNodes << "x" << m_yNodes <<"\n";
  //of.close ();
