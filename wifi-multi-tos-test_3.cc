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

#include "ns3/vector.h"
#include "ns3/socket.h"
#include "ns3/position-allocator.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/double.h"
#include "ns3/string.h"
#include "ns3/log.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/mobility-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/mobility-model.h"
#include "ns3/internet-stack-helper.h"

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

// bibliotecas video
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-helper.h"
#include "ns3/evalvid-client-server-helper.h"
#include "ns3/socket.h"
#include "ns3/qos-txop.h"


#include "ns3/ocb-wifi-mac.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/wifi-mac-header.h"


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
Example of execution
./waf --run "scratch/wifi-multi-tos-test_2 --80211Mode=1" 2>&1 | tee 802.11n_EDCA_WiFi.txt

*/

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiMultiTos");

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


          std::cout << "Received packet with Tos: "<< int (tid) << " Tos_Tag---> " << access_class << " from "<<iph.GetSource()<<" to "<<iph.GetDestination()<<std::endl;
          }


int main (int argc, char *argv[])
{
  uint32_t nWifi = 3;
  uint32_t m_mobility=1; ///< mobility
  double simulationTime = 90.0; //seconds that is the time total of mobility from one complete trajectory
  double interval = 0.1; // seconds
//  double distance = 1.0; //meters
//  uint32_t numPackets = 1;
  uint16_t mcs = 1;
  uint32_t m_fading=1; ///< fading
  uint8_t channelWidth = 20; //MHz
  uint32_t packetSize = 1472; // bytes
  uint32_t m_80211mode = 1;
  bool useShortGuardInterval = false;
  bool useRts = false;
  bool verbose = false;


  std::string m_traceFile= "/home/doutorado/sumo/examples/fanet_old/different_speed_sumo/mobility_manyspeed.tcl";
  std::string m_lossModelName;
  std::string phyModeWave ("OfdmRate6MbpsBW10MHz");

  LogComponentEnable ("EvalvidClient", LOG_LEVEL_INFO);
  LogComponentEnable ("EvalvidServer", LOG_LEVEL_INFO);

  CommandLine cmd;
  cmd.AddValue ("mobility", "1=trace;2=twoNodes", m_mobility);
  cmd.AddValue ("80211Mode", "1=802.11n_EDCA (WiFi); 2=802.11n_DCF (WiFi); 3=802.11p(Wave); 4=802.11n_DCF_5GHz; ", m_80211mode);
  cmd.AddValue ("nWifi", "Number of stations", nWifi);
//  cmd.AddValue ("distance", "Distance in meters between the stations and the access point", distance);
  cmd.AddValue ("simulationTime", "Simulation time in seconds", simulationTime);
  cmd.AddValue ("interval", "interval (seconds) between packets", interval);
  cmd.AddValue ("useRts", "Enable/disable RTS/CTS", useRts);
  cmd.AddValue ("mcs", "MCS value (0 - 7)", mcs);
  cmd.AddValue ("fading", "0=None;1=Nakagami;(buildings=1 overrides)", m_fading);
  cmd.AddValue ("channelWidth", "Channel width in MHz", channelWidth);
  cmd.AddValue ("useShortGuardInterval", "Enable/disable short guard interval", useShortGuardInterval);
  cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
//  cmd.AddValue ("numPackets", "number of packets generated", numPackets);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.Parse (argc,argv);

  Time interPacketInterval = Seconds (interval);


  NodeContainer wifiStaNodes;
  wifiStaNodes.Create (nWifi);

  YansWifiChannelHelper channel;
  channel= YansWifiChannelHelper::Default ();
  YansWifiPhyHelper phy = YansWifiPhyHelper::Default ();
  phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);


  // the channel
  //WaveHelper waveHelper = WaveHelper::Default ();
  //YansWifiChannelHelper wavePhy =  YansWavePhyHelper::Default ();
  Ptr<YansWifiChannel> channelWave = channel.Create ();
  phy.SetChannel (channel.Create ());
  // Set channel width
    Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));
    Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));
//  wifiPhy.SetChannel (channel);
//  wavePhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11);

// Wave
double freq = 0.0;

if ((m_80211mode == 3))
  {
    // 802.11p 5.9 GHz
    freq = 5.9e9;
  }
else if ((m_80211mode == 4))
    { // set channel from 802.11n
        freq = 5.180e9;
  }else
  {
    // 802.11n 2.4 GHz
    freq = 2.4e9;
  }



  // Propagation loss models are additive.
  // modelo de perdas
   m_lossModelName = "ns3::FriisPropagationLossModel";
   channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
   channel.AddPropagationLoss (m_lossModelName, "Frequency", DoubleValue (freq));

   // Propagation loss models are additive.
     if (m_fading != 0)
       {
         // if no obstacle model, then use Nakagami fading if requested
         channel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");
       }


  // Set guard interval
  //phy.Set ("HtConfiguration", BooleanValue (useShortGuardInterval));

  WifiMacHelper mac;
  WifiHelper wifi;

  // ns-3 supports generate a pcap trace
  //Set Non-unicastMode rate to unicast mode
  std::ostringstream oss;
  oss << "HtMcs" << mcs;

  NetDeviceContainer staDevices;


if (m_80211mode == 1) //802.11n 2.4 GHz with EDCA
    {
      mac.SetType ("ns3::AdhocWifiMac","QosSupported", BooleanValue (true));
      Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (oss.str ()));
      wifi.SetStandard (WIFI_PHY_STANDARD_80211n_2_4GHZ);
      wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                    "DataMode", StringValue (oss.str ()),
                                    "ControlMode", StringValue (oss.str ()),
                                    "RtsCtsThreshold", UintegerValue (useRts ? 0 : 999999));

      staDevices = wifi.Install (phy, mac, wifiStaNodes);


  } else if (m_80211mode == 2) // 802.11n 2.4 GHz without EDCA
  {
    mac.SetType ("ns3::AdhocWifiMac");
    Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (oss.str ()));
    wifi.SetStandard (WIFI_PHY_STANDARD_80211n_2_4GHZ);
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode", StringValue (oss.str ()),
                                  "ControlMode", StringValue (oss.str ()),
                                  "RtsCtsThreshold", UintegerValue (useRts ? 0 : 999999));
  staDevices = wifi.Install (phy, mac, wifiStaNodes);

  }
  else if (m_80211mode == 3)  // 802.11p 5.9 GHz default
    {
      phy.SetChannel (channelWave);
      NqosWaveMacHelper wifi80211pMac = NqosWaveMacHelper::Default ();
      Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default ();
      wifi80211p.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                          "DataMode",StringValue (phyModeWave),
                                          "ControlMode",StringValue (phyModeWave));
      staDevices = wifi80211p.Install (phy, wifi80211pMac, wifiStaNodes);

      if (verbose)
          {
          wifi80211p.EnableLogComponents ();  // Turn on all Wifi logging
          }


    } else if (m_80211mode == 4) // 802.11n 5GHz without EDCA
        {
            mac.SetType ("ns3::AdhocWifiMac");
            Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (oss.str ()));
            wifi.SetStandard (WIFI_PHY_STANDARD_80211n_5GHZ);
            wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (oss.str ()),
                                "ControlMode", StringValue (oss.str ()),
                                "RtsCtsThreshold", UintegerValue (useRts ? 0 : 999999));
          staDevices = wifi.Install (phy, mac, wifiStaNodes);
        } else{
              wifi.SetRemoteStationManager ("ns3::IdealWifiManager");
              mac.SetType ("ns3::AdhocWifiMac",
                           "QosSupported", BooleanValue (true));
              staDevices = wifi.Install (phy, mac, wifiStaNodes);

              //Modify EDCA configuration (TXOP limit) for AC_BE
              Ptr<NetDevice> dev = wifiStaNodes.Get (1)->GetDevice (0);
              Ptr<WifiNetDevice> wifi_dev = DynamicCast<WifiNetDevice> (dev);
              Ptr<WifiMac> wifi_mac = wifi_dev->GetMac ();
              PointerValue ptr;
              Ptr<QosTxop> edca;
              wifi_mac->GetAttribute ("VI_Txop", ptr);
              edca = ptr.Get<QosTxop> ();
              edca->SetTxopLimit (MicroSeconds (3008));


        }



          // Set guard interval
          Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/HtConfiguration/ShortGuardIntervalSupported", BooleanValue (useShortGuardInterval));
  //else {

    /*      phy.SetChannel (channelWave);
          WaveHelper waveHelper = WaveHelper::Default ();
          QosWaveMacHelper waveMac = QosWaveMacHelper::Default ();
          waveMac.SetType ("ns3::OcbWifiMac", "QosSupported", BooleanValue (true));
          waveHelper.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                              "DataMode",StringValue (phyModeWave),
                                              "ControlMode",StringValue (phyModeWave),
                                              "NonUnicastMode", StringValue (phyModeWave));
          channel.AddPropagationLoss ("ns3::FriisPropagationLossModel", "Frequency", DoubleValue (5.9e9));
          staDevices = waveHelper.Install (phy, waveMac, wifiStaNodes);



          if (verbose)
              {
              wifi80211p.EnableLogComponents ();  // Turn on all Wifi logging
              }

        } */

// 802.11n
if ((m_80211mode == 1) | (m_80211mode == 2) | (m_80211mode == 4)) {

  if (verbose)
  {
    wifi.EnableLogComponents ();  // Turn on all Wifi logging
  }
}


if (m_80211mode == 1) {
   //Modify EDCA configuration (TXOP limit) for AC_VI
   Ptr<NetDevice> dev = wifiStaNodes.Get (1)->GetDevice (0);
   Ptr<WifiNetDevice> wifi_dev = DynamicCast<WifiNetDevice> (dev);
   Ptr<WifiMac> wifi_mac = wifi_dev->GetMac ();
   PointerValue ptr;
   Ptr<QosTxop> edca;
   wifi_mac->GetAttribute ("VI_Txop", ptr);
   edca = ptr.Get<QosTxop> ();
   edca->SetTxopLimit (MicroSeconds (3008));
}


  //Ssid ssid = Ssid ("ns3-80211n");

  /*EdcaParameterSet edca;
  uint8_t aifsn = edca.GetBeAifsn();
  uint8_t qosInfo = edca.GetQosInfo();
  uint8_t qosSup = edca.IsQosSupported(); */



    // mobility
  // Create Ns2MobilityHelper with the specified trace log file as parameter
  if (m_mobility == 1)
    {
      // Create Ns2MobilityHelper with the specified trace log file as parameter
      Ns2MobilityHelper ns2 = Ns2MobilityHelper (m_traceFile);
      ns2.Install (); // configure movements for each node, while reading trace file
      // initially assume all nodes packet not moving
      if (m_80211mode == 3) {
        WaveBsmHelper::GetNodesMoving ().resize (nWifi, 0);
      }
    } else if (m_mobility == 2){
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
    positionAlloc->Add (Vector (0.0, 0.0, 0.0));
    positionAlloc->Add (Vector (5.0, 0.0, 0.0));
    mobility.SetPositionAllocator (positionAlloc);
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (wifiStaNodes);
}


  // Internet stack
  InternetStackHelper stack;
  stack.Install (wifiStaNodes);
  Ipv4AddressHelper address;

  address.SetBase ("192.168.1.0", "255.255.255.0");
  Ipv4InterfaceContainer staNodeInterfaces;
  staNodeInterfaces = address.Assign (staDevices);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  uint16_t port = 4000;

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
    // Create one EvalvidClient application -server

    EvalvidServerHelper server (port);
    server.SetAttribute ("SenderTraceFilename", StringValue("st_highway_cif.st"));
    server.SetAttribute ("SenderDumpFilename", StringValue("sd_a01"));
    server.SetAttribute ("PacketPayload",UintegerValue(packetSize));
    ApplicationContainer appsSink = server.Install (wifiStaNodes.Get(1));

    if ((m_80211mode == 5) | (m_80211mode == 1)) {
      InetSocketAddress destC (staNodeInterfaces.GetAddress (1), port);
      destC.SetTos (0xb8); //AC_VI
    }

      // Create one EvalvidClient application -client

    EvalvidClientHelper client (staNodeInterfaces.GetAddress (1),port);
    client.SetAttribute ("ReceiverDumpFilename", StringValue("rd_a01"));
  ApplicationContainer  appsClient = client.Install (wifiStaNodes.Get (0));


 // Setting applications
  ApplicationContainer sourceApplications, sinkApplications;
  std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; //AC_BE, AC_BK, AC_VI, AC_VO
  uint32_t portNumber = 9;

//  for (uint32_t index = 1; index < nWifi; ++index)
  //  {
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
          onOffHelper.SetAttribute ("PacketSize", UintegerValue (packetSize)); //bytes
      //    onOffHelper.SetAttribute ("MaxBytes", UintegerValue (1000000));
          sourceApplications.Add (onOffHelper.Install (wifiStaNodes.Get (2)));
          PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", sinkSocket);
          // source
          sinkApplications.Add (packetSinkHelper.Install (wifiStaNodes.Get (1)));

        }              //  }

  appsSink.Start (Seconds (0.0));
  appsSink.Stop (Seconds (simulationTime+1.0));
  appsClient.Start (Seconds (1.0));
  appsClient.Stop (Seconds (simulationTime+1.0));

  sinkApplications.Start (Seconds (0.0));
  sinkApplications.Stop (Seconds (simulationTime + 1));
  sourceApplications.Start (Seconds (1.0));
  sourceApplications.Stop (Seconds (simulationTime + 1));


  LogComponentEnable ("Ns2MobilityHelper",LOG_LEVEL_DEBUG);

  //phy.EnablePcap ("wifi-multi-tos-pcap-ap", apDevice);
  // Tracing
      phy.EnablePcap ("wifi-multi-tos-pcap-sta", staDevices);



  Packet::EnablePrinting ();

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    Ptr<FlowMonitor> flowmon;
    FlowMonitorHelper flowmonHelper;
    flowmon = flowmonHelper.InstallAll ();

    AnimationInterface anim ("animation-80211QoS.xml");

//    Simulator::Schedule (Seconds (simulationTime + 3.0), &GenerateTraffic,
//                         source, packetSize, interPacketInterval);

// Set channel width
Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (channelWidth));
Config::ConnectWithoutContext ("/NodeList/0/DeviceList/*/Phy/MonitorSnifferRx", MakeCallback (&MonitorSniffRx));
// make able to verify mac_Rx
Config::Connect("/NodeList/*/DeviceList/*/Mac/MacRx", MakeCallback(&traceqos));

  Simulator::Stop (Seconds (simulationTime + 3.0));
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
       NS_LOG_UNCOND("Delay Sum" << iter->second.delaySum);

  //     NS_LOG_UNCOND("BE?" << edca_ptr << "...");
//       NS_LOG_UNCOND("QoSInfo?" << edca_ptr2 << "...");
//       NS_LOG_UNCOND("QosSupported?" << tid << "...");
//       NS_LOG_UNCOND("QosSupported?" << edca3 << "...")
    if (t.sourceAddress == Ipv4Address("192.168.1.2") && t.destinationAddress == Ipv4Address("192.168.1.1"))
       {
       NS_LOG_UNCOND("---Sending Video---");
       NS_LOG_UNCOND("Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);
       NS_LOG_UNCOND("Tx Packets = " << iter->second.txPackets);
       NS_LOG_UNCOND("Rx Packets = " << iter->second.rxPackets);
       NS_LOG_UNCOND("Throughput Video: " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1024  << " Kbps");
       NS_LOG_UNCOND("Delay Sum" << iter->second.delaySum);

       }
  }

  double throughput=0;
  for (uint32_t index = 0; index < sinkApplications.GetN (); ++index)
    {
      uint64_t totalPacketsThrough = DynamicCast<PacketSink> (sinkApplications.Get (index))->GetTotalRx ();
      throughput += ((totalPacketsThrough * 8) / (simulationTime * 1000000.0)); //Mbit/s

    }

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
