/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* Copyright (c) 2016 University of Washington
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
* Authors: Tom Henderson <tomhend@u.washington.edu>
*          Matías Richart <mrichart@fing.edu.uy>
*          Sébastien Deronne <sebastien.deronne@gmail.com>
*/

#include "ns3/log.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/gnuplot.h"
#include "ns3/command-line.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/wifi-phy.h"
#include "ns3/ssid.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/rng-seed-manager.h"
#include "ns3/mobility-helper.h"
#include "ns3/waypoint-mobility-model.h"
#include "ns3/wifi-net-device.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/packet-socket-client.h"
#include "ns3/packet-socket-server.h"
#include "ns3/ht-configuration.h"
#include "ns3/he-configuration.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/olsr-helper.h"
#include "ns3/aodv-module.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiManagerExample");

/*
* Function used to dump the mobility of the node on stdout.
*/

void MobilityPrint (Ptr<Node> node) {
  Ptr<MobilityModel> mobility = node->GetObject<MobilityModel> ();
  Vector pos = mobility->GetPosition ();
  Vector vel = mobility->GetVelocity ();

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  Ipv4Address addr = ipv4->GetAddress (1, 0).GetLocal ();


  std::cout << "position," << Simulator::Now ().GetSeconds () << "," << addr << "," << pos << "," << vel << "\n";
  Simulator::Schedule (Seconds (0.1), &MobilityPrint, node);
}

void configureChannel(YansWifiPhyHelper *wifiPhy) {
  YansWifiChannelHelper helper;
  Ptr<YansWifiChannel> channel;
  Ptr<LogDistancePropagationLossModel> PropagationLossModel;

  helper.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  // helper.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  helper.AddPropagationLoss("ns3::FriisPropagationLossModel");
  helper.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
  /* helper.AddPropagationLoss("ns3::RandomWallPropagationLossModel",
  "Walls", DoubleValue(4),
  "Radius", DoubleValue(15),
  "wallLoss", DoubleValue(5)); */

  channel = helper.Create();
  wifiPhy->SetChannel(channel);
}

YansWifiPhyHelper configurePhy() {
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  configureChannel(&wifiPhy);
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  return wifiPhy;
}

WifiMacHelper configureMac() {
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");
  return wifiMac;
}



void ThroughputMonitor (FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon, std::map<std::pair<ns3::Ipv4Address, ns3::Ipv4Address>, std::vector<int>> previousData) {
  std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats();
  flowMon->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier());
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
  {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (stats->first);
    std::vector<int> now{(int) stats->second.txPackets, (int) stats->second.txBytes, (int) stats->second.rxPackets, (int) stats->second.rxBytes, (int) Simulator::Now ().GetSeconds ()};
    std::pair<ns3::Ipv4Address, ns3::Ipv4Address> key = std::make_pair(t.sourceAddress, t.destinationAddress);
    std::vector<int> new_;
    new_.insert(new_.end(), {now[0], now[1], now[2], now[3], now[4]});
    if (previousData.count(key)) {
      std::vector<int> previous = previousData[key];
      std::cout << "summary," << now[4] << "," << t.sourceAddress << "," << t.destinationAddress << "," << now[0]-previous[0] << ","
      << now[1]-previous[1] << "," <<  (now[1]-previous[1]) * 8.0 / (now[4]-previous[4]) / 1000 / 1000  << ","
      << now[2]-previous[2] << "," << now[3]-previous[3]  << "," << (now[3]-previous[3]) * 8.0 / (now[4]-previous[4]) / 1000 / 1000 << "\n";
    } else {
      std::cout << "summary," << now[4] << "," << t.sourceAddress << "," << t.destinationAddress << "," << now[0]<< ","
      << now[1]  << "," << now[1] * 8.0 / (now[4]-1.0) / 1000 / 1000 << ","
      << new_[2] << "," << new_[3]  << "," << new_[3] * 8.0 / (now[4]-1.0) / 1000 / 1000 << "\n";
    }
    previousData[std::make_pair (t.sourceAddress, t.destinationAddress)] = new_;
  }
  Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, flowMon, previousData);
}

int main (int argc, char *argv[])
{
  uint32_t rtsThreshold = 999999;  // disabled even for large A-MPDU
  uint32_t maxAmpduSize = 65535;
  uint32_t packetSize = 1024; // bytes
  bool broadcast = 0;
  uint16_t nss = 2;
  uint16_t shortGuardInterval = 800;
  uint16_t channelWidth = 20;
  std::string wifiManager ("ns3::IdealWifiManager");
  std::string standard ("802.11ac");
  ns3::WifiPhyStandard standard_phy (WIFI_PHY_STANDARD_80211ac);
  uint32_t maxSlrc = 7;
  uint32_t maxSsrc = 7;
  std::string dataRate = "100Mb/s";

  int distance = 1000;
  int position = 0;
  int altitude = 10;
  float speed = 10;
  float flightDuration = ((altitude * 2) + distance)/speed;
  float duration = flightDuration + 2;

  CommandLine cmd;
  cmd.AddValue ("maxSsrc","The maximum number of retransmission attempts for a RTS packet", maxSsrc);
  cmd.AddValue ("distance","Distance between the fixed nodes", distance);
  cmd.AddValue ("position","Starting position of the middle node", position);
  cmd.AddValue ("maxSlrc","The maximum number of retransmission attempts for a DATA packet", maxSlrc);
  cmd.AddValue ("rtsThreshold","RTS threshold", rtsThreshold);
  cmd.AddValue ("maxAmpduSize","Max A-MPDU size", maxAmpduSize);
  cmd.AddValue ("broadcast","Send broadcast instead of unicast", broadcast);
  cmd.AddValue ("channelWidth","Set channel width of the client (valid only for 802.11n or ac)", channelWidth);
  cmd.AddValue ("nss","Set nss of the client (valid only for 802.11n or ac)", nss);
  cmd.AddValue ("shortGuardInterval","Set short guard interval of the client (802.11n/ac/ax) in nanoseconds", shortGuardInterval);
  cmd.AddValue ("standard","Set standard (802.11a, 802.11b, 802.11g, 802.11n-5GHz, 802.11n-2.4GHz, 802.11ac, 802.11-holland, 802.11-10MHz, 802.11-5MHz, 802.11ax-5GHz, 802.11ax-2.4GHz)", standard);
  cmd.AddValue ("wifiManager","Set wifi rate manager (Aarf, Aarfcd, Amrr, Arf, Cara, Ideal, Minstrel, MinstrelHt, Onoe, Rraa)", wifiManager);
  cmd.Parse (argc,argv);

  if (standard == "802.11ac")
  {
    NS_ABORT_MSG_IF (channelWidth != 20 && channelWidth != 40 && channelWidth != 80 && channelWidth != 160, "Invalid channel width for standard " << standard);
    NS_ABORT_MSG_IF (nss == 0 || nss > 4, "Invalid nss " << nss << " for standard " << standard);
  }
  else if (standard == "802.11ax-5GHz" || standard == "802.11ax-2.4GHz")
  {
    NS_ABORT_MSG_IF (channelWidth != 20 && channelWidth != 40 && channelWidth != 80 && channelWidth != 160, "Invalid channel width for standard " << standard);
    NS_ABORT_MSG_IF (nss == 0 || nss > 4, "Invalid nss " << nss << " for standard " << standard);
  }

  Config::SetDefault ("ns3::WifiRemoteStationManager::MaxSlrc", UintegerValue (maxSlrc));
  Config::SetDefault ("ns3::WifiRemoteStationManager::MaxSsrc", UintegerValue (maxSsrc));



  WifiHelper wifi;
  wifi.SetStandard (standard_phy);
  wifi.SetRemoteStationManager (wifiManager, "RtsCtsThreshold", UintegerValue (rtsThreshold));
  YansWifiPhyHelper wifiPhy = configurePhy();
  WifiMacHelper wifiMac = configureMac();

  int n = 3;

  NodeContainer Nodes;
  Nodes.Create(n);

  NetDeviceContainer Devices;
  for(int i=0; i<n; ++i) {
    Devices.Add(wifi.Install (wifiPhy, wifiMac, Nodes.Get(i)));
  }

  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/BE_MaxAmpduSize", UintegerValue (maxAmpduSize));

  // Configure the mobility of the stations
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();

  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  positionAlloc->Add (Vector (distance, 0.0, 0.0));

  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

  mobility.Install (Nodes.Get(0));
  mobility.Install (Nodes.Get(n-1));

  // Configure the mobility of the SetShortGuardIntervalSupported
  std::deque<Waypoint> waypoints;

    Waypoint startWaypoint (Seconds (0.0), Vector (0.0, 0.0, 0.0));
    Waypoint firstIntermediateWaypoint (Seconds (altitude/speed), Vector(0.0, 0.0, altitude));
    Waypoint secondIntermediateWaypoint (Seconds ((altitude+distance)/speed), Vector(distance, 0.0, altitude));
    Waypoint endWaypoint (Seconds ((2*altitude+distance)/speed), Vector(distance, 0.0, 0.0));
    waypoints.push_back(startWaypoint);
    waypoints.push_back(firstIntermediateWaypoint);
    waypoints.push_back(secondIntermediateWaypoint);
    waypoints.push_back(endWaypoint);

  for (int i = 1; i<n-1; ++i) {
    MobilityHelper uavMobility;
    uavMobility.SetMobilityModel ("ns3::WaypointMobilityModel");
    uavMobility.Install (Nodes.Get(i));
  }


  for (int i = 1; i<n-1; ++i) {
    Ptr<WaypointMobilityModel> mob = Nodes.Get(i)->GetObject<WaypointMobilityModel>();
    for ( std::deque<Waypoint>::iterator w = waypoints.begin (); w != waypoints.end (); ++w )
    {
      mob->AddWaypoint (*w);
    }
  }

  // Perform post-install configuration from defaults for channel width,
  // guard interval, and nss, if necessary
  // Obtain pointer to the WifiPhy

  for(int i=0; i<n; ++i) {
    Ptr<NetDevice> nd = Devices.Get (i);
    Ptr<WifiNetDevice> wnd = nd->GetObject<WifiNetDevice> ();
    Ptr<WifiPhy> wifiPhyPtr = wnd->GetPhy ();
    uint8_t t_Nss = static_cast<uint8_t> (nss);
    wifiPhyPtr->SetNumberOfAntennas (t_Nss);
    wifiPhyPtr->SetMaxSupportedTxSpatialStreams (t_Nss);
    wifiPhyPtr->SetMaxSupportedRxSpatialStreams (t_Nss);

    // Only set the channel width and guard interval for HT and VHT modes
    if (standard == "802.11ac")
    {
      wifiPhyPtr->SetChannelWidth (channelWidth);
      Ptr<HtConfiguration> HtConfiguration = wnd->GetHtConfiguration ();
      HtConfiguration->SetShortGuardIntervalSupported (shortGuardInterval == 400);
    }
    else if (standard == "802.11ax-5GHz"
    || standard == "802.11ax-2.4GHz")
    {
      wifiPhyPtr->SetChannelWidth (channelWidth);
      wnd->GetHeConfiguration ()->SetGuardInterval (NanoSeconds (shortGuardInterval));
    }
    NS_LOG_DEBUG ("NSS " << wifiPhyPtr->GetMaxSupportedTxSpatialStreams ());
  }


  /*
  * Point to point between the first and last nodes.
  */

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("500Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer pointToPointDevices;
  pointToPointDevices = pointToPoint.Install(Nodes.Get(0), Nodes.Get(n-1));

  /*
  * Internet stack
  */
  OlsrHelper olsr;
  Ipv4StaticRoutingHelper staticRouting;

  Ipv4ListRoutingHelper list;
  list.Add (staticRouting, 0);
  list.Add (olsr, 10);

  InternetStackHelper internet;
  internet.SetRoutingHelper (list); // has effect on the next Install ()
  internet.Install(Nodes);

  Ptr<OutputStreamWrapper> routingStreamStart = Create<OutputStreamWrapper> ("olsr_start.routes", std::ios::out);
  olsr.PrintRoutingTableAllAt (Seconds (3.0), routingStreamStart);

  Ptr<OutputStreamWrapper> routingStreamEnd = Create<OutputStreamWrapper> ("olsr_end.routes", std::ios::out);
  olsr.PrintRoutingTableAllAt (Seconds (20.0), routingStreamEnd);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0","255.255.255.0");

  Ipv4InterfaceContainer Interfaces;

  for(int i=0; i<n; ++i) {
    Interfaces.Add(address.Assign (Devices.Get(i)));
  }

  address.SetBase ("192.168.1.0","255.255.255.0");
  Interfaces.Add(address.Assign (pointToPointDevices.Get(0)));
  Interfaces.Add(address.Assign (pointToPointDevices.Get(1)));



  //Ptr<Ipv4> ipv4Left = Nodes.Get(0)->GetObject<Ipv4> ();
  //Ptr<Ipv4> ipv4Right = Nodes.Get(2)->GetObject<Ipv4> ();
  //Ptr<Ipv4StaticRouting> staticRoutingLeft = staticRouting.GetStaticRouting (ipv4Left);
  // The ifIndex for this outbound route is 1; the first p2p link added
  //staticRoutingLeft->AddHostRouteTo (Ipv4Address ("10.0.0.3"), Ipv4Address ("192.168.1.2"), 2);

  //Ptr<Ipv4StaticRouting> staticRoutingRight = staticRouting.GetStaticRouting (ipv4Right);
  // The ifIndex we want on node B is 2; 0 corresponds to loopback, and 1 to the first point to point link
  //staticRoutingRight->AddHostRouteTo (Ipv4Address ("10.0.0.1"), Ipv4Address ("192.168.1.1"), 2);

  uint16_t port = 9;

  /*
  * Configure the CBR generator
  * The address is the address of the sink.
  */

  int src = 1;
  int dst = 0;

  PacketSinkHelper sink1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer apps_sink1 = sink1.Install (Nodes.Get(dst));

  OnOffHelper onoff ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address ("192.168.1.1"), port));
  onoff.SetConstantRate (DataRate (dataRate), packetSize);
  onoff.SetAttribute ("StartTime", TimeValue (Seconds (1.000000)));
  ApplicationContainer clientApp = onoff.Install (Nodes.Get(src));

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  apps_sink1.Start (Seconds (0.5));
  apps_sink1.Stop (Seconds (duration));


  //wifiPhy.EnablePcap("dump", Nodes);

  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();
  Packet::EnablePrinting ();
  Packet::EnableChecking ();

  for (int i=0; i<n; ++i) {
    Simulator::Schedule (Seconds (0), &MobilityPrint, Nodes.Get(i));
  }

  std::map<std::pair<ns3::Ipv4Address, ns3::Ipv4Address>, std::vector<int>> data;

  Simulator::Schedule(Seconds(2.0),&ThroughputMonitor,&flowmon, monitor, data);


  Simulator::Stop (Seconds (duration));

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
