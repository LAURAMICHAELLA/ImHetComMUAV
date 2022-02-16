#include "string.h"
#include "ns3/core-module.h"
#include "ns3/propagation-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;
uint32_t macTxDropCount(0), phyTxDropCount(0), phyRxDropCount(0);

void MacTxDrop(Ptr<const Packet> p)
{
    macTxDropCount++;
}

void PhyTxDrop(Ptr<const Packet> p)
{
    phyTxDropCount++;
}

void PhyRxDrop(Ptr<const Packet> p)
{
    phyRxDropCount++;
}
void ResetDropCounters()
{
    macTxDropCount = 0;
    phyTxDropCount = 0;
    phyRxDropCount = 0;
}

void experiment(const std::string &datarate)
{
    // 1. Create 3 nodes
    NodeContainer nodes;
    nodes.Create (4);

    // 2. Place nodes
    for (size_t i = 0; i < 4; ++i)
    {
        nodes.Get(i)-> AggregateObject (CreateObject<ConstantPositionMobilityModel> ());
    }

    // 3. Create propagation loss matrix
    Ptr<MatrixPropagationLossModel> lossModel = CreateObject<MatrixPropagationLossModel> ();
    lossModel->SetDefaultLoss (200); // set default loss to 200 dB (no link)
    for (size_t i = 0; i < 3; ++i)
    {
        lossModel->SetLoss (nodes.Get (i)-> GetObject<MobilityModel>(), nodes.Get (i+1)->GetObject<MobilityModel>(), 50); // set symmetric loss i <-> i+1 to 50 dB
    }

    // 4. Create & setup wifi channel
    Ptr<YansWifiChannel> wifiChannel = CreateObject <YansWifiChannel> ();
    wifiChannel->SetPropagationLossModel (lossModel);
    wifiChannel->SetPropagationDelayModel (CreateObject <ConstantSpeedPropagationDelayModel> ());

    // 5. Install wireless devices
    WifiHelper wifi;
    wifi.SetStandard (WIFI_PHY_STANDARD_80211b);
    Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",StringValue ("DsssRate11Mbps"));
    YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
    wifiPhy.SetChannel (wifiChannel);
    WifiMacHelper wifiMac;
    wifiMac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

    //// Enable pcap?
    ////wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
    ////wifiPhy.EnablePcap ("exposed-terminal", nodes);

    // 6. Install TCP/IP stack & assign IP addresses
    InternetStackHelper internet;
    internet.Install (nodes);
    Ipv4AddressHelper ipv4;
    ipv4.SetBase ("10.0.0.0", "255.0.0.0");
    ipv4.Assign (devices);

    // 7.1 Install applications: two CBR streams
    ApplicationContainer cbrApps;
    OnOffHelper onOffHelper ("ns3::UdpSocketFactory", Address());
    onOffHelper.SetAttribute ("PacketSize", UintegerValue (500));
    onOffHelper.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
    onOffHelper.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
    onOffHelper.SetAttribute ("DataRate", StringValue (datarate));

    //// flow 1:  node 1 -> node 0
    onOffHelper.SetAttribute ("StartTime", TimeValue (Seconds (1.0)));
    onOffHelper.SetAttribute ("Remote", AddressValue(InetSocketAddress (Ipv4Address ("10.0.0.1"),9000)));
    cbrApps.Add (onOffHelper.Install (nodes.Get (1)));

    //// flow 2:  node 2 -> node 3
    onOffHelper.SetAttribute ("StartTime", TimeValue (Seconds (1.0)));
    onOffHelper.SetAttribute ("Remote", AddressValue(InetSocketAddress (Ipv4Address ("10.0.0.4"),9000)));
    cbrApps.Add (onOffHelper.Install (nodes.Get (2)));

    // 7.2 Install applications: two UDP sinks
    ApplicationContainer sinkApps;
    PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9000));
    sinkApps.Add (packetSinkHelper.Install (nodes.Get (0)));
    sinkApps.Add (packetSinkHelper.Install (nodes.Get (3)));

    // 8.1 Install FlowMonitor on all nodes
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

    // 8.2 Monitor collisions
//    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTxDrop", MakeCallback(&MacTxDrop));
//    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxDrop", MakeCallback(&PhyRxDrop));
//    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxDrop", MakeCallback(&PhyTxDrop));

    // 9. Run simulation for 150 seconds
    Simulator::Stop (Seconds (150));
    Simulator::Run ();

    // 10. Print statistics
    monitor->CheckForLostPackets ();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
        std::cout << i->second.txPackets << ";" << i->second.rxPackets << ";";
        std::cout << i->second.txBytes << ";" << i->second.rxBytes << ";";
    }
    std::cout << (macTxDropCount + phyTxDropCount + phyRxDropCount) << "\n";
    // Collisions should be in phyRxDropCount, as Yans wifi set collided frames snr on reception, but it's not possible to differentiate from propagation loss. In this experiment, this is not an issue.

    //// Export flowmon data?
    ////monitor->SerializeToXmlFile("exposed-terminal.flowmon", true, true);

    // 11. Cleanup
    Simulator::Destroy ();
    ResetDropCounters();
}

int main (int argc, char *argv[])
{
    // Defaults
    std::string datarate = "1Mbps";
    size_t runs = 10;

    // Parse command line
    CommandLine cmd;
    cmd.AddValue("datarate", "Simulation transmission data rate. Default: 2Mbps.", datarate);
    cmd.AddValue("runs", "Run count. Default: 10.", runs);
    cmd.Parse (argc, argv);

    // Run experiment
    std::cout << "F1 Tx Packets;F1 Rx Packets;F1 Tx Bytes;F1 Rx Bytes;F2 Tx Packets;F2 Rx Packets;F2 Tx Bytes;F2 Rx Bytes;Collisions\n";
    for (size_t i = 0; i < runs; ++i)
    {
        experiment(datarate);
    }
    return 0;
}
