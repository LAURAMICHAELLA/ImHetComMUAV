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
// for program test
 //./waf --run "scratch/wifi-multi-tos-test -nWifi=2 --distance=50.0 --simulationTime=90.0 --verbose=false" 2>&1 | tee 80211nqos_2.txt
 #include <sstream>
#include <fstream>
#include <iostream>
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
#include "ns3/command-line.h"
#include "ns3/pointer.h"
#include "ns3/udp-client-server-helper.h"

#include "ns3/wifi-net-device.h"
#include "ns3/qos-txop.h"
#include "ns3/qos-utils.h"

#include "ns3/wifi-mac.h"
#include "ns3/edca-parameter-set.h"
 #include "ns3/packet.h"
#include "ns3/llc-snap-header.h"
#include "ns3/ipv4-header.h"

//#include "uan-cw-example.h"
#include "ns3/core-module.h"

#include "ns3/mobility-module.h"
#include "ns3/stats-module.h"
#include "ns3/applications-module.h"

#include "ns3/itu-r-1411-los-propagation-loss-model.h"
#include "ns3/network-module.h"
#include "ns3/stats-module.h"
#include "ns3/uan-module.h"
#include "ns3/callback.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h" // biblioteca pra simulação
#include "ns3/uan-mac.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/wifi-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/wifi-mac-queue.h"


// This is a simple example in order to show how to configure an IEEE 802.11n Wi-Fi network
// with multiple TOS. It outputs the aggregated UDP throughput, which depends on the number of
// stations, the HT MCS value (0 to 7), the channel width (20 or 40 MHz) and the guard interval
// (long or short). The user can also specify the distance between the access point and the
// stations (in meters), and can specify whether RTS/CTS is used or not.

/*Enumerator
AC_BE 	, 0 and 3 , Best Effort.

AC_BK , 1 and 2 Background.

AC_VI, 4 and 5 , Video.

AC_VO, 6 and 7, Voice.

AC_BE_NQOS 	total number of ACs.
Total number of ACs.

AC_UNDEF
*/

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiMultiTos");

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
          uint8_t tid = 0;
          tid = QosUtilsGetTidForPacket (packet);
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


          std::cout << "Received packet with Tos: "<< int (tid) << " Tos_Tag---> " << access_class << " from "<<iph.GetSource()<<" to "<<iph.GetDestination()<<std::endl;
          }


int main (int argc, char *argv[])
{
  uint32_t nWifi = 4;
  double simulationTime = 10; //seconds
  double distance = 1.0; //meters
  uint16_t mcs = 7;
  uint8_t channelWidth = 20; //MHz
  bool useShortGuardInterval = false;
  bool useRts = false;
  bool verbose = false;

  CommandLine cmd;
  cmd.AddValue ("nWifi", "Number of stations", nWifi);
  cmd.AddValue ("distance", "Distance in meters between the stations and the access point", distance);
  cmd.AddValue ("simulationTime", "Simulation time in seconds", simulationTime);
  cmd.AddValue ("useRts", "Enable/disable RTS/CTS", useRts);
  cmd.AddValue ("mcs", "MCS value (0 - 7)", mcs);
  cmd.AddValue ("channelWidth", "Channel width in MHz", channelWidth);
  cmd.AddValue ("useShortGuardInterval", "Enable/disable short guard interval", useShortGuardInterval);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.Parse (argc,argv);

  NodeContainer wifiStaNodes;
  wifiStaNodes.Create (nWifi);
  NodeContainer wifiApNode;
  wifiApNode.Create (1);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
  phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  phy.SetChannel (channel.Create ());

  // Set guard interval
  phy.Set ("ShortGuardEnabled", BooleanValue (useShortGuardInterval));

  WifiMacHelper mac;
  WifiHelper wifi;

  // ns-3 supports generate a pcap trace



  wifi.SetStandard (WIFI_PHY_STANDARD_80211n_5GHZ);


  if (verbose)
  {
    wifi.EnableLogComponents ();  // Turn on all Wifi logging
  }

  std::ostringstream oss;
  oss << "HtMcs" << mcs;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (oss.str ()),
                                "ControlMode", StringValue (oss.str ()),
                                "RtsCtsThreshold", UintegerValue (useRts ? 0 : 999999));

  Ssid ssid = Ssid ("ns3-80211n");

  /*EdcaParameterSet edca;
  uint8_t aifsn = edca.GetBeAifsn();
  uint8_t qosInfo = edca.GetQosInfo();
  uint8_t qosSup = edca.IsQosSupported(); */




  mac.SetType ("ns3::StaWifiMac",
               "Ssid", SsidValue (ssid));

  NetDeviceContainer staDevices;
  staDevices = wifi.Install (phy, mac, wifiStaNodes);

  mac.SetType ("ns3::ApWifiMac",
               "Ssid", SsidValue (ssid));

  NetDeviceContainer apDevice;
  apDevice = wifi.Install (phy, mac, wifiApNode);



  // Set channel width
  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));
  Config::ConnectWithoutContext ("/NodeList/0/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));
  // make able to verify mac_Rx
  Config::Connect("/NodeList/*/DeviceList/*/Mac/MacRx", MakeCallback(&traceqos));





/*Modify EDCA configuration (TXOP limit) for AC_BE
  Ptr<NetDevice> dev = wifiApNode.Get (1)->GetDevice (0);
  Ptr<WifiNetDevice> wifi_dev = DynamicCast<WifiNetDevice> (dev);
  Ptr<WifiMac> wifi_mac = wifi_dev->GetMac ();
  PointerValue ptr, ptr2;
  Ptr<QosTxop> edca_ptr, edca_ptr2;
  wifi_mac->GetAttribute ("BE_Txop", ptr);
  edca_ptr = ptr.Get<QosTxop> ();
  edca_ptr2 = ptr2.QosUtilsGetTidForPacket<QosTxop>();
  Ptr<EdcaTxopN> edca3 = ptr.Get<EdcaTxopN>();

  edca_ptr->SetTxopLimit (MicroSeconds (3008));

  uint8_t tid = 8;
  tid = QosUtilsGetTidForPacket<WifiMac>;

  if (tid > 7)
          {
            tid = 0;
          }
*/
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
  mobility.Install (wifiApNode);
  mobility.Install (wifiStaNodes);

  // Internet stack
  InternetStackHelper stack;
  stack.Install (wifiApNode);
  stack.Install (wifiStaNodes);
  Ipv4AddressHelper address;

  address.SetBase ("192.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer staNodeInterfaces, apNodeInterface;

  staNodeInterfaces = address.Assign (staDevices);
  apNodeInterface = address.Assign (apDevice);

  // Setting applications
  ApplicationContainer sourceApplications, sinkApplications;
  std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
  uint32_t portNumber = 9;
  for (uint32_t index = 0; index < nWifi; ++index)
    {
      for (uint8_t tosValue : tosValues)
        {
          auto ipv4 = wifiApNode.Get (0)->GetObject<Ipv4> ();
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
          sinkApplications.Add (packetSinkHelper.Install (wifiApNode.Get (0)));

                }
    }


  sinkApplications.Start (Seconds (0.0));
  sinkApplications.Stop (Seconds (simulationTime + 1));
  sourceApplications.Start (Seconds (1.0));
  sourceApplications.Stop (Seconds (simulationTime + 1));

  LogComponentEnable ("Ns2MobilityHelper",LOG_LEVEL_DEBUG);

  phy.EnablePcap ("wifi-multi-tos-pcap-ap", apDevice);
  phy.EnablePcap ("wifi-multi-tos-pcap-sta", staDevices);

  Packet::EnablePrinting ();

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    Ptr<FlowMonitor> flowmon;
    FlowMonitorHelper flowmonHelper;
    flowmon = flowmonHelper.InstallAll ();

    AnimationInterface anim ("animation-80211QoS.xml");



  Simulator::Stop (Seconds (simulationTime + 1));
  Simulator::Run ();


  // Rotina para imprimir estatisticas por fluxo

  flowmon -> CheckForLostPackets();




  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmonHelper.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
  {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);
       NS_LOG_UNCOND("Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);
       NS_LOG_UNCOND("Tx Packets = " << iter->second.txPackets);
       NS_LOG_UNCOND("Rx Packets = " << iter->second.rxPackets);
       NS_LOG_UNCOND("Throughput: " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps");
       NS_LOG_UNCOND("Throughput: " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1024 /1024 << " Mbps");
       NS_LOG_UNCOND("Signal (dBm): " << g_signalDbmAvg << " dBm");
       NS_LOG_UNCOND("Noi+Inf(dBm)" << g_noiseDbmAvg << " dBm");
       NS_LOG_UNCOND("SNR (dB)" << (g_signalDbmAvg - g_noiseDbmAvg) << " dBm");
  //     NS_LOG_UNCOND("BE?" << edca_ptr << "...");
//       NS_LOG_UNCOND("QoSInfo?" << edca_ptr2 << "...");
//       NS_LOG_UNCOND("QosSupported?" << tid << "...");
//       NS_LOG_UNCOND("QosSupported?" << edca3 << "...")
  }


  double throughput=0;
  for (uint32_t index = 0; index < sinkApplications.GetN (); ++index)
    {
      uint64_t totalPacketsThrough = DynamicCast<PacketSink> (sinkApplications.Get (index))->GetTotalRx ();
      throughput += ((totalPacketsThrough * 8) / (simulationTime * 1000000.0)); //Mbit/s

      }

/*    dev = wifiApNode.Get (1)->GetDevice (0);
    wifi_dev = DynamicCast<WifiNetDevice> (dev);
    wifi_mac = wifi_dev->GetMac ();
    wifi_mac->GetAttribute ("VI_Txop", ptr);
    edca = ptr.Get<QosTxop> ();
    edca->SetTxopLimit (MicroSeconds (3008));
*/
  flowmon->SerializeToXmlFile ("wifi-multi-tos-test_QOS.xml", true, true);
  Simulator::Destroy ();

  if (throughput > 0)
    {
  //    std::cout << "Aggregated throughput: " << throughput << " Mbit/s" << aifsn << "m_acBE & 0x0f" <<
  //    qosInfo << "ac?" << qosSup << "support?" << std::endl;
  std::cout << "Aggregated throughput: " << throughput << " Mbit/s" << std::endl;
          }

  else
    {
      NS_LOG_ERROR ("Obtained throughput is 0!");
      exit (1);
    }

  return 0;
}
