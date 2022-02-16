/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 University of Washington
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FIsourcesESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/flow-monitor.h"
#include "ns3/spectrum-helper.h"
#include "ns3/spectrum-wifi-phy.h"
#include "ns3/spectrum-wifi-helper.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/multi-model-spectrum-channel.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/csma-helper.h"
#include "ns3/olsr-helper.h"
#include "ns3/nstime.h"
#include "ns3/stats-module.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("test");

int const sources = 3;
std::vector <uint32_t> totalBytesReceived (sources);

void ReceivePacket(std::string context, Ptr <const Packet> p)
{
	//char c = context.at(10);
    char c = context.at(24);
	int index = c - '0';
	totalBytesReceived[index] += p->GetSize();
}

void CalculateThroughput ()
{
    std::vector <double> throughput(sources);
    for (int i = 0; i < sources; i++)
	{
        throughput[i] = ((totalBytesReceived[i] * 8.0) / 1000000);
        std::cout << Simulator::Now ().GetSeconds() << "\t" << i << "\t" << throughput[i] << "\n";
    }
    std::cout << "\n";
    Simulator::Schedule (MilliSeconds (100), &CalculateThroughput);
}



//---------------------------Methods to generate TCP traces---------------------------------

static void CwndTracer (Ptr<OutputStreamWrapper> stream, uint32_t oldval, uint32_t newval)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
}

static void SsThreshTracer (Ptr<OutputStreamWrapper> stream, uint32_t oldval, uint32_t newval)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
}

static void RttTracer (Ptr<OutputStreamWrapper> stream, Time oldval, Time newval)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void RtoTracer (Ptr<OutputStreamWrapper> stream, Time oldval, Time newval)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void NextTxTracer (Ptr<OutputStreamWrapper> stream, SequenceNumber32 old, SequenceNumber32 nextTx)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << nextTx << std::endl;
}

static void InFlightTracer (Ptr<OutputStreamWrapper> stream, uint32_t old, uint32_t inFlight)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << inFlight << std::endl;
}

static void NextRxTracer (Ptr<OutputStreamWrapper> stream, SequenceNumber32 old, SequenceNumber32 nextRx)
{
    *stream->GetStream () << Simulator::Now ().GetSeconds () << " " << nextRx << std::endl;
}


static void TraceCwnd (std::string cwnd_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> cWndStream = ascii.CreateFileStream (cwnd_tr_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/CongestionWindow";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&CwndTracer,cWndStream));
}

static void TraceSsThresh (std::string ssthresh_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> ssThreshStream = ascii.CreateFileStream (ssthresh_tr_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/SlowStartThreshold";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&SsThreshTracer, ssThreshStream));
}
static void TraceRtt (std::string rtt_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> rttStream = ascii.CreateFileStream (rtt_tr_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/RTT";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&RttTracer, rttStream));
}

static void TraceRto (std::string rto_tr_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> rtoStream = ascii.CreateFileStream (rto_tr_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/RTO";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&RtoTracer, rtoStream));
}

static void TraceNextTx (std::string &next_tx_seq_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> nextTxStream = ascii.CreateFileStream (next_tx_seq_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/NextTxSequence";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&NextTxTracer, nextTxStream));
}

static void TraceInFlight (std::string &in_flight_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> inFlightStream = ascii.CreateFileStream (in_flight_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/BytesInFlight";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&InFlightTracer, inFlightStream));
}

static void TraceNextRx (std::string &next_rx_seq_file_name, uint32_t nodeId)
{
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> nextRxStream = ascii.CreateFileStream (next_rx_seq_file_name.c_str ());
    std::ostringstream oss;
    oss << "/NodeList/" << nodeId << "/$ns3::TcpL4Protocol/SocketList/*/RxBuffer/NextRxSequence";
    Config::ConnectWithoutContext (oss.str (), MakeBoundCallback (&NextRxTracer, nextRxStream));
}



static void ScheduleAllTraces(std::string prefix_file_name, std::string file_dir, NodeContainer srcNodes, NodeContainer sinkNodes) // in Mbps calculated every 2s
{
    for (uint16_t i = 0; i < srcNodes.GetN (); i++)
    {
        uint32_t nodeId = srcNodes.Get(i)->GetId();

        std::ostringstream oss1;
        oss1 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-cwnd.data";
        Simulator::Schedule (Seconds (1.0), &TraceCwnd, oss1.str(), nodeId);

        std::ostringstream oss2;
        oss2 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-ssth.data";
        Simulator::Schedule (Seconds (1.0), &TraceSsThresh, oss2.str(), nodeId);

        std::ostringstream oss3;
        oss3 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-rto.data";
        Simulator::Schedule (Seconds (1.0), &TraceRto, oss3.str(), nodeId);

        std::ostringstream oss4;
        oss4 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-next-tx.data";
        Simulator::Schedule (Seconds (1.0), &TraceNextTx, oss4.str(), nodeId);

        std::ostringstream oss5;
        oss5 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-inflight.data";
        Simulator::Schedule (Seconds (1.0), &TraceInFlight, oss5.str(), nodeId);

        std::ostringstream oss6;
        oss6 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-rtt.data";
        Simulator::Schedule (Seconds (1.0), &TraceRtt, oss6.str(), nodeId);

    }
    for (uint16_t i = 0; i < sinkNodes.GetN (); i++)
    {
        uint32_t nodeId = sinkNodes.Get(i)->GetId();

        std::ostringstream oss7;
        oss7 << file_dir << "/" << prefix_file_name << "-" << nodeId << "-next-rx.data";
        Simulator::Schedule (Seconds (1.0), &TraceNextRx, oss7.str(),nodeId);

    }
}



int main (int argc, char *argv[])
{
  double m_totalTime = 4;
  double m_distNodes = 10;
  double m_ccaMode1Threshold = 0;
  int m_packetSize = 1448;
//  int m_shortGuardEnabled = 1;
  int m_mcsIndex = 1;
  int m_channelWidth = 40;
  int m_numNodes = 25;
  int m_numSources = 3;
  std::string m_txAppRate = "30Mbps";
  std::string m_errorModelType = "ns3::YansErrorRateModel";
  std::string tcpType = "NewReno";
  std::string probeType = "ns3::Ipv4PacketProbe";
  std::string tracePath = "/NodeList/*/$ns3::Ipv4L3Protocol/Tx";
  std::string prefixFileName = "test";
  std::string fileDir = "/home/mahesh/ns3/ns-allinone-3.26/ns-3.26/test-output";
  bool m_tracing = true;

  CommandLine cmd;
  cmd.AddValue ("m_totalTime", "Total simulation time in seconds", m_totalTime);
  cmd.AddValue ("m_distNodes", "Distance between the nodes in meters", m_distNodes);
  cmd.AddValue ("m_ccaMode1Threshold", "CCA mode1 threshold", m_ccaMode1Threshold);
  cmd.AddValue ("m_packetSize", "Size of application packet in bytes", m_packetSize);
//  cmd.AddValue ("m_shortGuardEnabled", "Whether short guard is enabled or not", m_shortGuardEnabled);
  cmd.AddValue ("m_mcsIndex", "MCS index of 802.11ac transmission", m_mcsIndex);
  cmd.AddValue ("m_channelWidth", "Channel width of 802.11ac transmission", m_channelWidth);
  cmd.AddValue ("m_numNodes", "Number of nodes", m_numNodes);
  cmd.AddValue ("m_numSources", "Number of sources", m_numSources);
  cmd.AddValue ("m_txAppRate", "Set speed of traffic generation", m_txAppRate);
  cmd.AddValue ("m_errorModelType", "Type of error model used", m_errorModelType);
  cmd.AddValue ("m_tracing", "Turn on routing table tracing", m_tracing);
  cmd.Parse (argc, argv);

  // 4 MB of TCP buffer
  //Config::SetDefault ("ns3::TcpSocket::RcvBufSize", UintegerValue (1 << 21));
  //Config::SetDefault ("ns3::TcpSocket::SndBufSize", UintegerValue (1 << 21));
  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (1448));
  Config::SetDefault ("ns3::TcpSocket::InitialCwnd", UintegerValue (1));
  Config::SetDefault ("ns3::TcpSocket::InitialSlowStartThreshold", UintegerValue (442572)); //441640
  Config::SetDefault("ns3::TcpL4Protocol::SocketType",TypeIdValue(TypeId::LookupByName("ns3::Tcp" + tcpType)));
  //Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));   // disable fragmentation for frames below 2200 bytes

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  NodeContainer nc_wireless;
  nc_wireless.Create (m_numNodes);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  SpectrumWifiPhyHelper phyHelper = SpectrumWifiPhyHelper::Default ();
  phyHelper.SetPcapDataLinkType (SpectrumWifiPhyHelper::DLT_IEEE802_11_RADIO);
  //Config::SetDefault ("ns3::WifiPhy::CcaMode1Threshold", DoubleValue (m_ccaMode1Threshold));

  Ptr<MultiModelSpectrumChannel> spectrumChannel = CreateObject<MultiModelSpectrumChannel> ();

  Ptr<FriisPropagationLossModel> lossModel = CreateObject<FriisPropagationLossModel> ();
  spectrumChannel->AddPropagationLossModel (lossModel);

  Ptr<ConstantSpeedPropagationDelayModel> delayModel = CreateObject<ConstantSpeedPropagationDelayModel> ();
  spectrumChannel->SetPropagationDelayModel (delayModel);

  phyHelper.SetErrorRateModel (m_errorModelType);
  phyHelper.Set ("TxPowerStart", DoubleValue (25));
  phyHelper.Set ("TxPowerEnd", DoubleValue (25));
//  phyHelper.Set ("ShortGuardEnabled", BooleanValue (m_shortGuardEnabled));
  phyHelper.SetChannel (spectrumChannel);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  WifiHelper wifi;

  WifiMacHelper wifiMac;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211ac);
  std::ostringstream oss;
  oss << "VhtMcs" << m_mcsIndex;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (oss.str ()),
                                "ControlMode", StringValue (oss.str ()));

  wifiMac.SetType ("ns3::AdhocWifiMac");

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  MobilityHelper mobilityWireless;
  Ptr<ListPositionAllocator> wirelessAlloc = CreateObject<ListPositionAllocator> ();

  for (int i = 0; i < 5; i++)
  {
      for (int j = 0; j < 5; j++)
      {
          wirelessAlloc->Add(Vector (j*m_distNodes, i*m_distNodes, 0.0));
      }
  }

  mobilityWireless.SetPositionAllocator (wirelessAlloc);
  mobilityWireless.Install (nc_wireless);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  Ptr<MobilityModel> mob[m_numNodes];
  Vector pos[m_numNodes];

  for (int i = 0; i < m_numNodes; i++)
  {
      mob[i] = nc_wireless.Get(i)->GetObject<MobilityModel>();         // Node i
      pos[i] = mob[i]->GetPosition ();
  }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  NetDeviceContainer de_wireless;                 //Channel numbers - 38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159

  //Flow 0: 0--->6--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (38));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(0)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 1: 1--->6--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (46));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(1)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 2: 2--->7--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (54));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(2)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(7)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(7)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 3: 3--->7--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (62));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(3)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(7)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(7)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 4: 4--->8--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (102));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(4)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(8)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(8)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 5: 5--->6--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (110));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(5)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 6: 6--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (118));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(6)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 7: 7--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (126));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(7)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 8: 8--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (134));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(8)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 9: 9--->8--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (142));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(9)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(8)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(8)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 10: 10--->11--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (151));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(10)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(11)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(11)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 11: 11--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (159));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(11)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 13: 13--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (38));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(13)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 14: 14--->13--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (46));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(14)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(13)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(13)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 15: 15--->11--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (54));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(15)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(11)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(11)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 16: 16--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (62));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(16)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 17: 17--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (102));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(17)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 18: 18--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (110));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(18)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 19: 19--->13--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (118));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(19)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(13)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(13)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 20: 20--->16--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (126));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(20)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(16)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(16)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 21: 21--->16--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (134));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(21)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(16)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(16)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 22: 22--->17--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (142));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(22)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(17)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(17)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 23: 23--->18--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (151));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(23)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(18)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(18)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));


  //Flow 24: 24--->18--->12
  phyHelper.Set ("ChannelNumber", UintegerValue (159));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(24)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(18)));

  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(18)));
  de_wireless.Add (wifi.Install (phyHelper, wifiMac, nc_wireless.Get(12)));

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Channel width must be set *after* installation because the attribute is overwritten by the ConfigureStandard method ()
  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (m_channelWidth));

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  InternetStackHelper internet;
  internet.Install (nc_wireless);

  Ipv4AddressHelper addrWireless;
  addrWireless.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if_wireless = addrWireless.Assign (de_wireless);

  Ptr<Ipv4> ip_wireless[m_numNodes];
  for (int i = 0; i < m_numNodes; i++)
  {
      ip_wireless[i] = nc_wireless.Get(i)->GetObject<Ipv4> ();
  }

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> staticRouting[m_numNodes];
  for (int i = 0; i < m_numNodes; i++)
  {
      staticRouting[i] = ipv4RoutingHelper.GetStaticRouting (ip_wireless[i]);
  }


  //Flow 0: 0--->6--->12
  staticRouting[0]->AddHostRouteTo (Ipv4Address ("10.1.1.4"), Ipv4Address ("10.1.1.2"), 1);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.4"), Ipv4Address ("10.1.1.4"), 2);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.1"), Ipv4Address ("10.1.1.3"), 1);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.1"), Ipv4Address ("10.1.1.1"), 1);


  //Flow 1: 1--->6--->12
  staticRouting[1]->AddHostRouteTo (Ipv4Address ("10.1.1.8"), Ipv4Address ("10.1.1.6"), 1);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.8"), Ipv4Address ("10.1.1.8"), 4);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.5"), Ipv4Address ("10.1.1.7"), 2);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.5"), Ipv4Address ("10.1.1.5"), 3);


  //Flow 2: 2--->7--->12
  staticRouting[2]->AddHostRouteTo (Ipv4Address ("10.1.1.12"), Ipv4Address ("10.1.1.10"), 1);
  staticRouting[7]->AddHostRouteTo (Ipv4Address ("10.1.1.12"), Ipv4Address ("10.1.1.12"), 2);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.9"), Ipv4Address ("10.1.1.11"), 3);
  staticRouting[7]->AddHostRouteTo (Ipv4Address ("10.1.1.9"), Ipv4Address ("10.1.1.9"), 1);


  //Flow 3: 3--->7--->12
  staticRouting[3]->AddHostRouteTo (Ipv4Address ("10.1.1.16"), Ipv4Address ("10.1.1.14"), 1);
  staticRouting[7]->AddHostRouteTo (Ipv4Address ("10.1.1.16"), Ipv4Address ("10.1.1.16"), 4);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.13"), Ipv4Address ("10.1.1.15"), 4);
  staticRouting[7]->AddHostRouteTo (Ipv4Address ("10.1.1.13"), Ipv4Address ("10.1.1.13"), 3);


  //Flow 4: 4--->8--->12
  staticRouting[4]->AddHostRouteTo (Ipv4Address ("10.1.1.20"), Ipv4Address ("10.1.1.18"), 1);
  staticRouting[8]->AddHostRouteTo (Ipv4Address ("10.1.1.20"), Ipv4Address ("10.1.1.20"), 2);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.17"), Ipv4Address ("10.1.1.19"), 5);
  staticRouting[8]->AddHostRouteTo (Ipv4Address ("10.1.1.17"), Ipv4Address ("10.1.1.17"), 1);


  //Flow 5: 5--->6--->12
  staticRouting[5]->AddHostRouteTo (Ipv4Address ("10.1.1.24"), Ipv4Address ("10.1.1.22"), 1);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.24"), Ipv4Address ("10.1.1.24"), 6);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.21"), Ipv4Address ("10.1.1.23"), 6);
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.21"), Ipv4Address ("10.1.1.21"), 5);


  //Flow 6: 6--->12
  staticRouting[6]->AddHostRouteTo (Ipv4Address ("10.1.1.26"), Ipv4Address ("10.1.1.26"), 7);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.25"), Ipv4Address ("10.1.1.25"), 7);


  //Flow 7: 7--->12
  staticRouting[7]->AddHostRouteTo (Ipv4Address ("10.1.1.28"), Ipv4Address ("10.1.1.28"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.27"), Ipv4Address ("10.1.1.27"), 8);


  //Flow 8: 8--->12
  staticRouting[8]->AddHostRouteTo (Ipv4Address ("10.1.1.30"), Ipv4Address ("10.1.1.30"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.29"), Ipv4Address ("10.1.1.29"), 9);


  //Flow 9: 9--->8--->12
  staticRouting[9]->AddHostRouteTo (Ipv4Address ("10.1.1.34"), Ipv4Address ("10.1.1.32"), 1);
  staticRouting[8]->AddHostRouteTo (Ipv4Address ("10.1.1.34"), Ipv4Address ("10.1.1.34"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.31"), Ipv4Address ("10.1.1.33"), 10);
  staticRouting[8]->AddHostRouteTo (Ipv4Address ("10.1.1.31"), Ipv4Address ("10.1.1.31"), 4);


  //Flow 10: 10--->11--->12
  staticRouting[10]->AddHostRouteTo (Ipv4Address ("10.1.1.38"), Ipv4Address ("10.1.1.37"), 1);
  staticRouting[11]->AddHostRouteTo (Ipv4Address ("10.1.1.38"), Ipv4Address ("10.1.1.38"), 2);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.35"), Ipv4Address ("10.1.1.36"), 11);
  staticRouting[11]->AddHostRouteTo (Ipv4Address ("10.1.1.35"), Ipv4Address ("10.1.1.35"), 1);

  //Flow 11: 11--->12
  staticRouting[11]->AddHostRouteTo (Ipv4Address ("10.1.1.40"), Ipv4Address ("10.1.1.40"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.39"), Ipv4Address ("10.1.1.39"), 12);


  //Flow 13: 13--->12
  staticRouting[13]->AddHostRouteTo (Ipv4Address ("10.1.1.42"), Ipv4Address ("10.1.1.42"), 1);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.41"), Ipv4Address ("10.1.1.41"), 13);


  //Flow 14: 14--->13--->12
  staticRouting[14]->AddHostRouteTo (Ipv4Address ("10.1.1.46"), Ipv4Address ("10.1.1.44"), 1);
  staticRouting[13]->AddHostRouteTo (Ipv4Address ("10.1.1.46"), Ipv4Address ("10.1.1.46"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.43"), Ipv4Address ("10.1.1.45"), 14);
  staticRouting[13]->AddHostRouteTo (Ipv4Address ("10.1.1.43"), Ipv4Address ("10.1.1.43"), 2);


  //Flow 15: 15--->11--->12
  staticRouting[15]->AddHostRouteTo (Ipv4Address ("10.1.1.50"), Ipv4Address ("10.1.1.48"), 1);
  staticRouting[11]->AddHostRouteTo (Ipv4Address ("10.1.1.50"), Ipv4Address ("10.1.1.50"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.47"), Ipv4Address ("10.1.1.49"), 15);
  staticRouting[11]->AddHostRouteTo (Ipv4Address ("10.1.1.47"), Ipv4Address ("10.1.1.47"), 4);


  //Flow 16: 16--->12
  staticRouting[16]->AddHostRouteTo (Ipv4Address ("10.1.1.52"), Ipv4Address ("10.1.1.52"), 1);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.51"), Ipv4Address ("10.1.1.51"), 16);


  //Flow 17: 17--->12
  staticRouting[17]->AddHostRouteTo (Ipv4Address ("10.1.1.54"), Ipv4Address ("10.1.1.54"), 1);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.53"), Ipv4Address ("10.1.1.53"), 17);


  //Flow 18: 18--->12
  staticRouting[18]->AddHostRouteTo (Ipv4Address ("10.1.1.56"), Ipv4Address ("10.1.1.56"), 1);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.55"), Ipv4Address ("10.1.1.55"), 18);


  //Flow 19: 19--->13--->12
  staticRouting[19]->AddHostRouteTo (Ipv4Address ("10.1.1.60"), Ipv4Address ("10.1.1.58"), 1);
  staticRouting[13]->AddHostRouteTo (Ipv4Address ("10.1.1.60"), Ipv4Address ("10.1.1.60"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.57"), Ipv4Address ("10.1.1.59"), 19);
  staticRouting[13]->AddHostRouteTo (Ipv4Address ("10.1.1.57"), Ipv4Address ("10.1.1.57"), 4);


  //Flow 20: 20--->16--->12
  staticRouting[20]->AddHostRouteTo (Ipv4Address ("10.1.1.64"), Ipv4Address ("10.1.1.62"), 1);
  staticRouting[16]->AddHostRouteTo (Ipv4Address ("10.1.1.64"), Ipv4Address ("10.1.1.64"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.61"), Ipv4Address ("10.1.1.63"), 20);
  staticRouting[16]->AddHostRouteTo (Ipv4Address ("10.1.1.61"), Ipv4Address ("10.1.1.61"), 2);


  //Flow 21: 21--->16--->12
  staticRouting[21]->AddHostRouteTo (Ipv4Address ("10.1.1.68"), Ipv4Address ("10.1.1.66"), 1);
  staticRouting[16]->AddHostRouteTo (Ipv4Address ("10.1.1.68"), Ipv4Address ("10.1.1.68"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.65"), Ipv4Address ("10.1.1.66"), 21);
  staticRouting[16]->AddHostRouteTo (Ipv4Address ("10.1.1.65"), Ipv4Address ("10.1.1.65"), 4);


  //Flow 22: 22--->17--->12
  staticRouting[22]->AddHostRouteTo (Ipv4Address ("10.1.1.72"), Ipv4Address ("10.1.1.70"), 1);
  staticRouting[17]->AddHostRouteTo (Ipv4Address ("10.1.1.72"), Ipv4Address ("10.1.1.72"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.69"), Ipv4Address ("10.1.1.71"), 22);
  staticRouting[17]->AddHostRouteTo (Ipv4Address ("10.1.1.69"), Ipv4Address ("10.1.1.69"), 2);


  //Flow 23: 23--->18--->12
  staticRouting[23]->AddHostRouteTo (Ipv4Address ("10.1.1.76"), Ipv4Address ("10.1.1.78"), 1);
  staticRouting[18]->AddHostRouteTo (Ipv4Address ("10.1.1.76"), Ipv4Address ("10.1.1.76"), 3);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.73"), Ipv4Address ("10.1.1.75"), 23);
  staticRouting[18]->AddHostRouteTo (Ipv4Address ("10.1.1.73"), Ipv4Address ("10.1.1.73"), 2);


  //Flow 24: 24--->18--->12
  staticRouting[24]->AddHostRouteTo (Ipv4Address ("10.1.1.80"), Ipv4Address ("10.1.1.78"), 1);
  staticRouting[18]->AddHostRouteTo (Ipv4Address ("10.1.1.80"), Ipv4Address ("10.1.1.80"), 5);

  staticRouting[12]->AddHostRouteTo (Ipv4Address ("10.1.1.77"), Ipv4Address ("10.1.1.79"), 24);
  staticRouting[18]->AddHostRouteTo (Ipv4Address ("10.1.1.77"), Ipv4Address ("10.1.1.77"), 4);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////



  //------------------Starting Applications-------------------------------
    uint16_t port = 50000;
    Address sinkLocalAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
    PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", sinkLocalAddress);
    ApplicationContainer sourceApplicationsWiFi, sinkApplicationsWiFi;

    NodeContainer srcNodes;
    for (int i = 0; i < m_numSources; i++)
    {
        srcNodes.Add(nc_wireless.Get(i));
    }

    NodeContainer sinkNodes;
    sinkNodes.Add(nc_wireless.Get(12));

    int dest_interfaces[m_numSources] = {3, 7, 11};//, 15, 19, 23};//, 25, 27, 29};//, 33, 37, 39};//, 41, 45, 49};//, 51, 53, 55};//, 59, 63, 67};//, 71, 75, 79};

    for (uint16_t i = 0; i < m_numSources; i++)
    {
        OnOffHelper sourceHelper ("ns3::TcpSocketFactory", Address (InetSocketAddress (if_wireless.GetAddress (dest_interfaces[i], 0), port)));
        sourceHelper.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
        sourceHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
        sourceHelper.SetAttribute ("DataRate", DataRateValue (m_txAppRate)); //bit/s
        sourceHelper.SetAttribute ("PacketSize", UintegerValue(m_packetSize));

        ApplicationContainer sourceApp = sourceHelper.Install (nc_wireless.Get(i));
        sourceApplicationsWiFi.Add(sourceApp);
        sourceApp.Start (Seconds (0.5 + i * 0.1));
        sourceApp.Stop (Seconds (m_totalTime));

        sinkHelper.SetAttribute ("Protocol", TypeIdValue (TcpSocketFactory::GetTypeId ()));
        ApplicationContainer sinkApp = sinkHelper.Install (nc_wireless.Get(12));
        sinkApplicationsWiFi.Add(sinkApp);
        sinkApp.Start (Seconds (0.1 + i * 0.1));
        sinkApp.Stop (Seconds (m_totalTime));

        std::stringstream ss;
        //ss << "/NodeList/" << i << "/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";
        ss << "/NodeList/12/DeviceList/" << i << "/$ns3::WifiNetDevice/Mac/MacRx";
        Config::Connect (ss.str(), MakeCallback(&ReceivePacket) );              // Connect MacRx event at MAC layer of sink node to ReceivePacket function for throughput calculation
    }

    if (m_tracing)
    {
        std::cout << "Tracing activated" << std::endl;
        ScheduleAllTraces(prefixFileName, fileDir, srcNodes, sinkNodes);
    }

    Simulator::Schedule (Seconds (1.0), &CalculateThroughput);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  Simulator::Stop (Seconds (m_totalTime));
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();
  Simulator::Run ();

  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();

  Time runTime;
  runTime = Seconds(m_totalTime);

  int txPacketsum = 0;
  int rxPacketsum = 0;
  int DropPacketsum = 0;
  int LostPacketsum = 0;
  double Throughputsum = 0;
  double rxDuration;
  Time Delaysum;
  Time Jittersum;

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end(); ++i)
  {
    if (i->first > 0) // flow number
      {
        Ipv4FlowClassifier::FiveTuple t=classifier->FindFlow (i->first);

        if ((t.destinationAddress == Ipv4Address("10.1.1.4")) || (t.destinationAddress == Ipv4Address("10.1.1.8")) || (t.destinationAddress == Ipv4Address("10.1.1.12")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.16")) || (t.destinationAddress == Ipv4Address("10.1.1.20")) || (t.destinationAddress == Ipv4Address("10.1.1.24")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.26")) || (t.destinationAddress == Ipv4Address("10.1.1.28")) || (t.destinationAddress == Ipv4Address("10.1.1.30")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.34")) || (t.destinationAddress == Ipv4Address("10.1.1.38")) || (t.destinationAddress == Ipv4Address("10.1.1.40")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.42")) || (t.destinationAddress == Ipv4Address("10.1.1.46")) || (t.destinationAddress == Ipv4Address("10.1.1.50")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.52")) || (t.destinationAddress == Ipv4Address("10.1.1.56")) || (t.destinationAddress == Ipv4Address("10.1.1.60")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.64")) || (t.destinationAddress == Ipv4Address("10.1.1.68")) || (t.destinationAddress == Ipv4Address("10.1.1.72")) ||
            (t.destinationAddress == Ipv4Address("10.1.1.76")) || (t.destinationAddress == Ipv4Address("10.1.1.80")))
        {
            txPacketsum += i->second.txPackets;
            rxPacketsum += i->second.rxPackets;
            LostPacketsum += i->second.lostPackets;
            DropPacketsum += i->second.packetsDropped.size();
            Delaysum += ((i->second.delaySum)/(i->second.rxPackets));               //ns
            Jittersum += ((i->second.jitterSum)/(i->second.rxPackets));             //ns

            rxDuration = i->second.timeLastRxPacket.GetSeconds () - i->second.timeFirstRxPacket.GetSeconds ();
            Throughputsum += (i->second.rxBytes * 8.0 / rxDuration / 1000 / 1000);  //Mbps
        }
        std::cout << "\nFlow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Simulation Time: " << m_totalTime << "\n";
        std::cout << "  First Time: " << i->second.timeFirstRxPacket.GetSeconds() << "\n";
        std::cout << "  Last Time: " << i->second.timeLastTxPacket.GetSeconds() << "\n";
        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
        std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        std::cout << "  Lost Packets:   " << i->second.lostPackets << "\n";
        if (i->second.rxPackets > 1)
        {
            std::cout << "  Delay:   " << ((i->second.delaySum)/(i->second.rxPackets))/1000000 << " milliseconds\n";         //ms
            std::cout << "  Jitter:   " << ((i->second.jitterSum)/(i->second.rxPackets)) << " nanoseconds\n";       //ns
        }
        std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / rxDuration / 1000 / 1000 << " Mbps\n";
        std::cout << "******" << "\n";
      }
  }

  std::cout << "::TEST WIFI 25 NODES::" << "\n";
  std::cout << "Total time: " << m_totalTime << "\n";
  std::cout << "Number of nodes: " << m_numNodes << "\n";
  std::cout << "Number of sources: " << m_numSources << "\n";
  std::cout << "Inter-node distance: " << m_distNodes << "\n";
  std::cout << "CCA mode1 threshold: NOT USED \n";
  std::cout << "Packet size: " << m_packetSize << "\n";
//  std::cout << "Short guard enabled: " << m_shortGuardEnabled << "\n";
  std::cout << "MCS index: " << m_mcsIndex << "\n";
  std::cout << "Channel width: " << m_channelWidth << "\n";
  std::cout << "Application rate: " << m_txAppRate << "\n";
  std::cout << "Error model type: " << m_errorModelType << "\n";
  std::cout << "Tracing enabled: " << m_tracing << "\n";

  std::cout << "Tx packet sum: " << txPacketsum << "\n";
  std::cout << "Rx packet sum: " << rxPacketsum << "\n";
  std::cout << "Lost packet sum: " << LostPacketsum << "\n";
  std::cout << "Drop packet sum: " << DropPacketsum << "\n";
  std::cout << "Throughput sum: " << Throughputsum << "\n";
  std::cout << "Delay sum: " << Delaysum.As (Time::MS) << " milliseconds\n";
  std::cout << "Jitter sum: " << Jittersum.As (Time::MS) << " milliseconds\n";
  std::cout << "Avg throughput: " << Throughputsum/m_numSources << "\n";
  std::cout << "Packets delivery ratio: " << ((rxPacketsum *100) / txPacketsum) << "%" << "\n";
  std::cout << "Packets lost ratio: " << ((LostPacketsum *100) / txPacketsum) << "%" << "\n";

  std::cout << "******" << "\n";

  Simulator::Destroy ();

  return 0;
}
