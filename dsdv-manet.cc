/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Hemanth Narra
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
 * Author: Hemanth Narra <hemanth@ittc.ku.com>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/dsdv-helper.h"
#include "ns3/wifi-phy.h"
#include "ns3/dsdv-packet.h"
#include "ns3/netanim-module.h"
#include "ns3/wifi-tx-vector.h"
#include "ns3/energy-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <fstream>
#include "ns3/gnuplot.h"




using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DsdvManetExample");
uint16_t port = 9;
std::ofstream rdTrace;
    std::ofstream rdTraced;
    int const TN= 4;
/**
 * \ingroup dsdv
 * \ingroup dsdv-examples
 * \ingroup examples
 *
 * \brief DSDV Manet example
 */
class DsdvManetExample
{
public:
  DsdvManetExample ();
  /**
   * Run function
   * \param nWifis The total number of nodes
   * \param nSinks The total number of receivers
   * \param txpLvls Transmission Power Levels
   * \param appTypeFlag Application Type Flag
   * \param totalTime The total simulation time
   * \param rate The network speed
   * \param phyMode The physical mode
   * \param nodeSpeed The node speed
   * \param periodicUpdateInterval The routing update interval
   * \param settlingTime The routing update settling time
   * \param dataStart The data transmission start time
   * \param printRoutes print the routes if true
   * \param CSVfileName The CSV file name
   */
  void CaseRun (uint32_t nWifis,
                uint32_t nSinks,
			//	uint16_t txpLvls,
				uint16_t appTypeFlag,
				double totalTime,
                std::string rate,
                std::string phyMode,
                uint32_t nodeSpeed,
                uint32_t periodicUpdateInterval,
                uint32_t settlingTime,
                double dataStart,
                bool printRoutes,
                std::string CSVfileName);

private:
  uint32_t m_nWifis; ///< total number of nodes
  uint32_t m_nSinks; ///< number of receiver nodes
//  uint16_t m_txpLvls; /// < Transmission Power Levels
  uint16_t m_appTypeFlag; /// < Application Type Flag
  double m_totalTime; ///< total simulation time (in seconds)
  std::string m_rate; ///< network bandwidth
  std::string m_phyMode; ///< remote station manager data mode
  uint32_t m_nodeSpeed; ///< mobility speed
  uint32_t m_periodicUpdateInterval; ///< routing update interval
  uint32_t m_settlingTime; ///< routing setting time
  double m_dataStart; ///< time to start data transmissions (seconds)
  uint32_t bytesTotal; ///< total bytes received by all nodes
  uint32_t packetsReceived; ///< total packets received by all nodes
  bool m_printRoutes; ///< print routing table
  std::string m_CSVfileName; ///< CSV file name
  NodeContainer nodes; ///< the collection of nodes
  NetDeviceContainer devices; ///< the collection of devices
  Ipv4InterfaceContainer interfaces; ///< the collection of interfaces
  double initialEnergy = 0.5786930; // joule
  double voltage = 6.0; // volts
  double idleCurrent = 0.0273; // Ampere
  double txCurrent = 0.0174; // Ampere


  uint32_t totalBytesReceived = 0;
  uint32_t mbs = 0;

    uint32_t totalBytesDropped = 0;
    uint32_t totalBytestransmitted = 0;

private:
  /// Create and initialize all nodes
  void CreateNodes ();
  /**
   * Create and initialize all devices
   * \param tr_name The trace file name
   */
  void CreateDevices (std::string tr_name);
  /**
   * Create network
   * \param tr_name The trace file name
   */
  void InstallInternetStack (std::string tr_name);
  /// Create data sinks and sources
  void InstallApplications ();
  /// Setup mobility model
  void SetupMobility ();
  /**
   * Packet receive function
   * \param socket The communication socket
   */
  void ReceivePacket (Ptr <Socket> socket);
  /**
   * Setup packet receivers
   * \param addr the receiving IPv4 address
   * \param node the receiving node
   * \returns the communication socket
   */
  Ptr <Socket> SetupPacketReceive (Ipv4Address addr, Ptr <Node> node );
  /// Check network throughput
  void CheckThroughput ();
  /// Install Energy Sources
  void InstallEnergySources();
  void ReceivedPacket (Ptr<const Packet> p, const Address & addr);
  void ReceivesPacket (std::string context, Ptr <const Packet> p);
  void DroppedPacket (std::string context, Ptr<const Packet> p);
  void TraceNetDevTxWifi (std::string context, Ptr<const Packet> p);
  void CalculateThroughput();
  //void Create2DPlotFile();

};

template <int node>
void RemainingEnergyTrace (double oldValue, double newValue)
{
  std::stringstream ss;
  ss << "energy_" << node << ".log";

  static std::fstream f (ss.str ().c_str (), std::ios::out);

  f << Simulator::Now ().GetSeconds () << "    remaining energy=" << newValue << std::endl;
}

template <int node>
void PhyStateTrace (std::string context, Time start, Time duration, WifiPhyState state)
{
  std::stringstream ss;
  ss << "state_" << node << ".log";

  static std::fstream f (ss.str ().c_str (), std::ios::out);

  f << Simulator::Now ().GetSeconds () << "    state=" << state << " start=" << start << " duration=" << duration << std::endl;
}

void
DsdvManetExample::ReceivedPacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}



int main (int argc, char **argv)
{
  DsdvManetExample test;
  uint32_t nWifis = 10;
  uint32_t nSinks = 9;
//  uint16_t txpLvls = 3;
  uint16_t appTypeFlag = 3;
  double totalTime = 100;
  std::string rate ("1Mbps");
  std::string phyMode ("ErpOfdmRate54Mbps");
  uint32_t nodeSpeed = 1; // in m/s
  std::string appl = "all";
  uint32_t periodicUpdateInterval = 15;
  //uint32_t periodicUpdateInterval = 5;

  uint32_t settlingTime = 6;
  double dataStart = 5.0;
  bool printRoutingTable = true;
  std::string CSVfileName = "DsdvManetExample.csv";

  CommandLine cmd;
  cmd.AddValue ("nWifis", "Number of wifi nodes[Default:30]", nWifis);
  cmd.AddValue ("nSinks", "Number of wifi sink nodes[Default:10]", nSinks);
//  cmd.AddValue ("txpLvls", "Transmission Power Levels[Default:3]", txpLvls);
//  cmd.AddValue ("appTypeFlag", "Application Type Flag[Default:0]", appTypeFlag);
  cmd.AddValue ("totalTime", "Total Simulation time[Default:100]", totalTime);
  cmd.AddValue ("phyMode", "Wifi Phy mode[Default:DsssRate11Mbps]", phyMode);
  cmd.AddValue ("rate", "CBR traffic rate[Default:8kbps]", rate);
  cmd.AddValue ("nodeSpeed", "Node speed in RandomWayPoint model[Default:10]", nodeSpeed);
  cmd.AddValue ("periodicUpdateInterval", "Periodic Interval Time[Default=15]", periodicUpdateInterval);
  cmd.AddValue ("settlingTime", "Settling Time before sending out an update for changed metric[Default=6]", settlingTime);
  cmd.AddValue ("dataStart", "Time at which nodes start to transmit data[Default=50.0]", dataStart);
  cmd.AddValue ("printRoutingTable", "print routing table for nodes[Default:1]", printRoutingTable);
  cmd.AddValue ("CSVfileName", "The name of the CSV output file name[Default:DsdvManetExample.csv]", CSVfileName);
  cmd.Parse (argc, argv);

  std::ofstream out (CSVfileName.c_str ());
  out << "SimulationSecond," <<
  "ReceiveRate," <<
  "PacketsReceived," <<
  "NumberOfSinks," <<
  std::endl;
  out.close ();

  SeedManager::SetSeed (12345);

  Config::SetDefault ("ns3::OnOffApplication::PacketSize", StringValue ("1000"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate", StringValue (rate));
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (phyMode));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2000"));

  test = DsdvManetExample ();
  //test.CaseRun (nWifis, nSinks, txpLvls, appTypeFlag, totalTime, rate, phyMode, nodeSpeed, periodicUpdateInterval, settlingTime, dataStart, printRoutingTable, CSVfileName);
  test.CaseRun (nWifis, nSinks, appTypeFlag, totalTime, rate, phyMode, nodeSpeed, periodicUpdateInterval, settlingTime, dataStart, printRoutingTable, CSVfileName);

  return 0;
}

DsdvManetExample::DsdvManetExample ()
  : bytesTotal (0),
    packetsReceived (0)
{
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

void
DsdvManetExample::ReceivePacket (Ptr <Socket> socket)
{
	Ptr<Packet> packet;
	  Address senderAddress;
	  socket->SetRecvPktInfo(true);
	  while ((packet = socket->RecvFrom (senderAddress)))
	    {
	      bytesTotal += packet->GetSize ();
	      packetsReceived += 1;
	      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
	    }
}

void
DsdvManetExample::CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 1000;
  bytesTotal = 0;

  std::ofstream out (m_CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << "," << kbs << "," << packetsReceived << "," << m_nSinks << ","  << "" << std::endl;

  out.close ();
  packetsReceived = 0;

  Simulator::Schedule (Seconds (1.0), &DsdvManetExample::CheckThroughput, this);
}


Ptr <Socket>
DsdvManetExample::SetupPacketReceive (Ipv4Address addr, Ptr <Node> node)
{

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr <Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback ( &DsdvManetExample::ReceivePacket, this));
  sink->SetRecvPktInfo(true);
  return sink;
}




//-- Callback function is called whenever a packet is received successfully.
//-- This function cumulatively add the size of data packet to totalBytesReceived counter.
//---------------------------------------------------------------------------------------
	void
	DsdvManetExample::ReceivesPacket(std::string context, Ptr <const Packet> p)
	{

		//char c= context.at(10);
		//int index= c - '0';
	  // totalBytesReceived[index] += p->GetSize();

		totalBytesReceived += p->GetSize();
	  //cout<< "Received : " << totalBytesReceived << endl;
	}

	void DsdvManetExample::TraceNetDevTxWifi (std::string context, Ptr <const Packet> p)
	{

				totalBytestransmitted += p->GetSize();
				//cout<<"transmitted : "<<totalBytestransmitted<<endl;
	}



		void
	DsdvManetExample::DroppedPacket(std::string context, Ptr <const Packet> p)
	{

	std::cout << " TX p: " << *p << std::endl;

		//totalBytesDropped += p->GetSize();
		//cout<< totalBytesDropped<<endl;
		totalBytesDropped=0;
	rdTraced << totalBytesDropped <<"\n"<<totalBytesReceived ;


	}
/*
void calculate()
{
	    rdTraced << Simulator::Now ().GetSeconds() << "\t" << totalBytesDropped <<"\n"<<totalBytesReceived ;
		    Simulator::Schedule (Seconds (1.0), &calculate);
}
*/

void
DsdvManetExample::CalculateThroughput()
{

  //for (int f=0; f<TN; f++)
	//{
  double mbs = ((totalBytesReceived*8.0)/(1000000*1));
   //mbs[f] = ((totalBytesReceived[f]*8.0)/(1000000*1));
   //cout<<"size of vector is  "<< totalBytesReceived.size()<< endl;
  totalBytesReceived =0;
 //rdTrace << Simulator::Now ().GetSeconds() << "\t"<< f << "\t" << mbs[f] <<"\n";
    rdTrace << Simulator::Now ().GetSeconds() << "\t" << mbs <<"\n";

		//}
  //fill(totalBytesReceived.begin(), totalBytesReceived.end(), 0);

    Simulator::Schedule (Seconds (1.0), &DsdvManetExample::CalculateThroughput,this);

}


//Gnuplot parameters
//void Create2DPlotFile()
//{
// std::string fileNameWithNoExtension = "FlowVSThroughput";
//      std::string graphicsFileName        = fileNameWithNoExtension + ".png";
//      std::string plotFileName            = fileNameWithNoExtension + ".plt";
//      std::string plotTitle               = "Flow vs Throughput";
//      std::string dataTitle               = "Throughput";
//
//      // Instantiate the plot and set its title.
//      Gnuplot plot (graphicsFileName);
//      plot.SetTitle (plotTitle);
//
//      // Make the graphics file, which the plot file will be when it
//      // is used with Gnuplot, be a PNG file.
//      plot.SetTerminal ("png");
//
//      // Set the labels for each axis.
//      plot.SetLegend ("Flow", "Throughput");
//
//
//      Gnuplot2dDataset dataset;
//      dataset.SetTitle (dataTitle);
//      dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);
//double x;
//  double y;
//
//  // Create the 2-D dataset.
//  for (x = -5.0; x <= +5.0; x += 1.0)
//    {
//      // Calculate the 2-D curve
//      //
//      //            2
//      //     y  =  x   .
//      //
//      y = x * x;
//
//      // Add this point.
//      dataset.Add (x, y);
//    }
//
//  // Add the dataset to the plot.
//  plot.AddDataset (dataset);
//
//  // Open the plot file.
//  std::ofstream plotFile (plotFileName.c_str());
//
//  // Write the plot file.
//  plot.GenerateOutput (plotFile);
//
//  // Close the plot file.
//  plotFile.close ();
//}

void
DsdvManetExample::CaseRun (uint32_t nWifis, uint32_t nSinks, uint16_t appTypeFlag, double totalTime, std::string rate,
                           std::string phyMode, uint32_t nodeSpeed, uint32_t periodicUpdateInterval, uint32_t settlingTime,
                           double dataStart, bool printRoutes, std::string CSVfileName)
{
  m_nWifis = nWifis;
  m_nSinks = nSinks;
  //m_txpLvls = txpLvls;
  m_appTypeFlag = appTypeFlag;
  m_totalTime = totalTime;
  m_rate = rate;
  m_phyMode = phyMode;
  m_nodeSpeed = nodeSpeed;
  m_periodicUpdateInterval = periodicUpdateInterval;
  m_settlingTime = settlingTime;
  m_dataStart = dataStart;
  m_printRoutes = printRoutes;
  m_CSVfileName = CSVfileName;

  std::stringstream ss;
  ss << m_nWifis;
  std::string t_nodes = ss.str ();

  std::stringstream ss3;
  ss3 << m_totalTime;
  std::string sTotalTime = ss3.str ();

  std::string tr_name = "Dsdv_Manet_" + t_nodes + "Nodes_" + sTotalTime + "SimTime";
  std::cout << "Trace file generated is " << tr_name << ".tr\n";

  CreateNodes ();
  CreateDevices (tr_name);
  SetupMobility ();
  InstallInternetStack (tr_name);
  InstallApplications ();
  InstallEnergySources();
//  Create2DPlotFile();

  std::cout << "\nStarting simulation for " << m_totalTime << " s ...\n";

  //CheckThroughput ();
  Config::Set ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelWidth", UintegerValue (40));
  std::stringstream ST;
  ST<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRx";

  //ST<<"/NodeList/"<< 0 <<"/ApplicationList/*/$ns3::PacketSink/Rx";                 //

  Config::Connect (ST.str(), MakeCallback(&DsdvManetExample::ReceivesPacket,this));

  std::stringstream Sd;

  Sd<<"/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacRxDrop";                 //
  Config::Connect (Sd.str(), MakeCallback(&DsdvManetExample::DroppedPacket,this));


  Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTx", MakeCallback(&DsdvManetExample::TraceNetDevTxWifi,this));


  AnimationInterface anim("anim.xml");
  anim.EnableIpv4L3ProtocolCounters(Seconds(1.0),Seconds(m_totalTime));
  anim.EnableIpv4RouteTracking("routeTracking",Seconds(1.0),Seconds(m_totalTime));
  anim.EnablePacketMetadata(true);
  rdTrace.open("throughputmeasurementstesttotalap.dat", std::ios::out);                                             //
    rdTrace << "# Time \t Throughput \n";

     rdTraced.open("receivedvsdropped.dat", std::ios::out);                                             //
    rdTraced << "# Time \t Dropped \n received \n" ;
  Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&DsdvManetExample::ReceivedPacket, this));
//  uint32_t txPacketsum = 0;
//    uint32_t rxPacketsum = 0;
//    uint32_t DropPacketsum = 0;
//    uint32_t LostPacketsum = 0;
//    double Delaysum = 0;
  Ptr<FlowMonitor> flowMonitor;
     FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (m_totalTime));
  Simulator::Run ();
  NS_LOG_UNCOND("Flow monitor statistics: ");

  //flowMonitor->SerializeToXmlFile ("results.xml" , true, true );
    // Print per flow statistics
  flowMonitor->CheckForLostPackets ();
      Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier ());

      std::map< FlowId, FlowMonitor::FlowStats > stats = flowMonitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
        {
//	  if (i->first)
//	     {
	            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
	            std::cout << "Flow " << i->first - 2 << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
	            std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
	            std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
	            std::cout << "  TxOffered:  " << i->second.txBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
	            std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
	            std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
	            std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
	     }
//        }
//  txPacketsum += iter->second.txPackets;
//  rxPacketsum += iter->second.rxPackets;
//  LostPacketsum += iter->second.lostPackets;
//  DropPacketsum += iter->second.packetsDropped.size();
//  Delaysum += iter->second.delaySum.GetSeconds();
//  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);
//  NS_LOG_UNCOND("Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress);
//  NS_LOG_UNCOND("Tx Packets = " << iter->second.txPackets);
//  NS_LOG_UNCOND("Rx Packets = " << iter->second.rxPackets);
//  NS_LOG_UNCOND("Throughput="<<iter->second.rxBytes * 8.0 /(iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds())/ 1024<<"Kbps");
//  std::cout << "\n";
//   std::cout << "\n";
//   std::cout << "  All Tx Packets: " << txPacketsum << "\n";
//   std::cout << "  All Rx Packets: " << rxPacketsum << "\n";
//   std::cout << "  All Delay: " << Delaysum / txPacketsum << "\n";
//   std::cout << "  All Lost Packets: " << LostPacketsum << "\n";
//   std::cout << "  All Drop Packets: " << DropPacketsum << "\n";
//   std::cout << "  Packets Delivery Ratio: " << ((rxPacketsum * 100) /txPacketsum) << "%" << "\n";
//   std::cout << "  Packets Lost Ratio: " << ((LostPacketsum * 100) /txPacketsum) << "%" << "\n";
//        }


  flowMonitor->SerializeToXmlFile("dsdvFlow.xml", true, true);
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}

void
DsdvManetExample::CreateNodes ()
{
  std::cout << "Creating " << (unsigned) m_nWifis << " nodes.\n";
  nodes.Create (m_nWifis);
  NS_ASSERT_MSG (m_nWifis >= m_nSinks, "Sinks must be less or equal to the number of nodes in network");
}

void
DsdvManetExample::SetupMobility ()
{
  MobilityHelper mobility;
//  ObjectFactory pos;
//  pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
//  pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
//  pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
//
//  std::ostringstream speedConstantRandomVariableStream;
//  speedConstantRandomVariableStream << "ns3::ConstantRandomVariable[Constant="
//                                    << m_nodeSpeed
//                                    << "]";
//
//  Ptr <PositionAllocator> taPositionAlloc = pos.Create ()->GetObject <PositionAllocator> ();
//  mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel", "Speed", StringValue (speedConstantRandomVariableStream.str ()),
//                             "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]"), "PositionAllocator", PointerValue (taPositionAlloc));
//  mobility.SetPositionAllocator (taPositionAlloc);
//  mobility.Install (nodes);

  Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();

//  	positionAlloc ->Add(Vector(0, 0, 0));	//node0		10.1.1.1
//    positionAlloc ->Add(Vector(40, 0, 0));	//node1		10.1.1.2
//    positionAlloc ->Add(Vector(80, 0, 0));	//node2		10.1.1.3
//    positionAlloc ->Add(Vector(120, 0, 0));	//node3		10.1.1.4
//    positionAlloc ->Add(Vector(160, 0, 0));	//node4		10.1.1.5
//    positionAlloc ->Add(Vector(200, 0, 0));	//node5		10.1.1.6
//    positionAlloc ->Add(Vector(240, 0, 0)); 	//node6		10.1.1.7
//    positionAlloc ->Add(Vector(280, 0, 0)); 	//node7		10.1.1.8
//    positionAlloc ->Add(Vector(320, 0, 0)); 	//node8		10.1.1.9
//    positionAlloc ->Add(Vector(360, 0, 0)); 	//node9		10.1.1.10

  positionAlloc ->Add(Vector(15, 0, 0));	//node0		10.1.1.1
  positionAlloc ->Add(Vector(40, 0, 0));	//node1		10.1.1.2
  positionAlloc ->Add(Vector(0, 20, 0));	//node2		10.1.1.3
  positionAlloc ->Add(Vector(25, 20, 0));	//node3		10.1.1.4
  positionAlloc ->Add(Vector(50, 20, 0));	//node4		10.1.1.5
  positionAlloc ->Add(Vector(0, 40, 0));	//node5		10.1.1.6
  positionAlloc ->Add(Vector(25, 40, 0)); 	//node6		10.1.1.7
  positionAlloc ->Add(Vector(50, 40, 0)); 	//node7		10.1.1.8
  positionAlloc ->Add(Vector(20, 60, 0)); 	//node8		10.1.1.9
  positionAlloc ->Add(Vector(40, 60, 0)); 	//node9		10.1.1.10
//  positionAlloc ->Add(Vector(292, 10, 0)); 	//node10	10.1.1.11
//  positionAlloc ->Add(Vector(230, 20, 0)); 	//node11	10.1.1.12
//  positionAlloc ->Add(Vector(265, 20, 0)); 	//node12	10.1.1.13
//  positionAlloc ->Add(Vector(200, 45, 0));  //node13	10.1.1.14
//  positionAlloc ->Add(Vector(230, 40, 0));  //node14	10.1.1.15
//  positionAlloc ->Add(Vector(249, 33, 0));  //node15 	10.1.1.16
//  positionAlloc ->Add(Vector(291, 50, 0));  //node16	10.1.1.17
//  positionAlloc ->Add(Vector(270, 45, 0));  //node17	10.1.1.18
//  positionAlloc ->Add(Vector(257, 0, 0));	//node18	10.1.1.19
//  positionAlloc ->Add(Vector(225, 0, 0));	//node19	10.1.1.20
//  positionAlloc ->Add(Vector(0, 210, 0));	//node20	10.1.1.21
//  positionAlloc ->Add(Vector(30, 210, 0)); 	//node21	10.1.1.22
//  positionAlloc ->Add(Vector(60, 210, 0));	//node22	10.1.1.23
//  positionAlloc ->Add(Vector(0, 250, 0));	//node23	10.1.1.24
//  positionAlloc ->Add(Vector(30, 250, 0));	//node24	10.1.1.25
//  positionAlloc ->Add(Vector(60, 250, 0));	//node25	10.1.1.26
//  positionAlloc ->Add(Vector(90, 250, 0));  //node26	10.1.1.27
//  positionAlloc ->Add(Vector(0, 290, 0)); 	//node27	10.1.1.28
//  positionAlloc ->Add(Vector(30, 290, 0)); 	//node28	10.1.1.29
//  positionAlloc ->Add(Vector(60, 290, 0));	//node29	10.1.1.30
//  positionAlloc ->Add(Vector(360, 292, 0)); //node30	10.1.1.31
//  positionAlloc ->Add(Vector(315, 225, 0)); //node31	10.1.1.32
//  positionAlloc ->Add(Vector(360, 200, 0)); //node32	10.1.1.33
//  positionAlloc ->Add(Vector(405, 225, 0)); //node33	10.1.1.34
//  positionAlloc ->Add(Vector(315, 315, 0));	//node34	10.1.1.35
//  positionAlloc ->Add(Vector(360, 338, 0));	//node35	10.1.1.36
//  positionAlloc ->Add(Vector(292, 270, 0)); //node36	10.1.1.37
//  positionAlloc ->Add(Vector(360, 247, 0)); //node37	10.1.1.38
//  positionAlloc ->Add(Vector(427, 270, 0));	//node38	10.1.1.39
//  positionAlloc ->Add(Vector(405, 315, 0)); //node39	10.1.1.40
//  positionAlloc ->Add(Vector(5, 400, 0));	//node40	10.1.1.41
//  positionAlloc ->Add(Vector(25, 425, 0)); 	//node41	10.1.1.42
//  positionAlloc ->Add(Vector(45, 453, 0)); 	//node42	10.1.1.43
//  positionAlloc ->Add(Vector(50, 425, 0)); 	//node43	10.1.1.44
//  positionAlloc ->Add(Vector(45, 405, 0)); 	//node44	10.1.1.45
//  positionAlloc ->Add(Vector(25, 440, 0));	//node45	10.1.1.46
//  positionAlloc ->Add(Vector(25, 410, 0));	//node46	10.1.1.47
//  positionAlloc ->Add(Vector(7, 450, 0)); 	//node47	10.1.1.48
//  positionAlloc ->Add(Vector(4, 425, 0)); 	//node48	10.1.1.49
//  positionAlloc ->Add(Vector(100, 430, 0)); //node49	10.1.1.50


  mobility.SetPositionAllocator(positionAlloc);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes);

}

void
DsdvManetExample::InstallEnergySources()
{

	double txPowerStart = 10.8792;
	// Energy sources
	  EnergySourceContainer eSources;
	  //BasicEnergySourceHelper basicSourceHelper;
	  LiIonEnergySourceHelper liIonSourceHelper;
	  WifiRadioEnergyModelHelper radioEnergyHelper;

	  double initEnergy = initialEnergy*1000.000000;
	  liIonSourceHelper.Set ("LiIonEnergySourceInitialEnergyJ", DoubleValue (initEnergy));
	  liIonSourceHelper.Set ("InitialCellVoltage", DoubleValue (voltage));

	  radioEnergyHelper.Set ("IdleCurrentA", DoubleValue (idleCurrent));
	  radioEnergyHelper.Set ("TxCurrentA", DoubleValue (txCurrent));

	  // compute the efficiency of the power amplifier (eta) assuming that the provided value for tx current
	  // corresponds to the minimum tx power level
	  double eta = DbmToW (txPowerStart) / ((txCurrent - idleCurrent) * voltage);


	  radioEnergyHelper.SetTxCurrentModel ("ns3::LinearWifiTxCurrentModel",
	                                       "Voltage", DoubleValue (voltage),
	                                       "IdleCurrent", DoubleValue (idleCurrent),
	                                       "Eta", DoubleValue (eta));

	  // install an energy source on each node
	  for (NodeContainer::Iterator n = nodes.Begin (); n != nodes.End (); n++)
	    {
	      eSources.Add (liIonSourceHelper.Install (*n));

	      Ptr<WifiNetDevice> wnd;

	      for (uint32_t i = 0; i < (*n)->GetNDevices (); ++i)
	        {
	          wnd = (*n)->GetDevice (i)->GetObject<WifiNetDevice> ();
	          // if it is a WifiNetDevice
	          if (wnd != 0)
	            {
	              // this device draws power from the last created energy source
	              radioEnergyHelper.Install (wnd, eSources.Get (eSources.GetN () - 1));
	            }
	        }
	    }

	  	  	  	eSources.Get (0)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<0>));
	    		eSources.Get (1)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<1>));
	    		eSources.Get (2)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<2>));
	    		eSources.Get (3)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<3>));
	    		eSources.Get (4)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<4>));
	    		eSources.Get (5)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<5>));
	    		eSources.Get (6)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<6>));
	    		eSources.Get (7)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<7>));
	    		eSources.Get (8)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<8>));
	    		eSources.Get (9)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<9>));
//	    		eSources.Get (10)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<10>));
//	    		eSources.Get (11)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<11>));
//	    		eSources.Get (12)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<12>));
//	    		eSources.Get (13)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<13>));
//	    		eSources.Get (14)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<14>));
//	    		eSources.Get (15)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<15>));
//	    		eSources.Get (16)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<16>));
//	    		eSources.Get (17)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<17>));
//	    		eSources.Get (18)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<18>));
//	    		eSources.Get (19)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<19>));
//	    		eSources.Get (20)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<20>));
//	    		eSources.Get (21)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<21>));
//	    		eSources.Get (22)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<22>));
//	    		eSources.Get (23)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<23>));
//	    		eSources.Get (24)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<24>));
//	    		eSources.Get (25)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<25>));
//	    		eSources.Get (26)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<26>));
//	    		eSources.Get (27)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<27>));
//	    		eSources.Get (28)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<28>));
//	    		eSources.Get (29)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<29>));
//	    		eSources.Get (30)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<30>));
//	    		eSources.Get (31)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<31>));
//	    		eSources.Get (32)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<32>));
//	    		eSources.Get (33)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<33>));
//	    		eSources.Get (34)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<34>));
//	    		eSources.Get (35)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<35>));
//	    		eSources.Get (36)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<36>));
//	    		eSources.Get (37)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<37>));
//	    		eSources.Get (38)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<38>));
//	    		eSources.Get (39)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<39>));
//	    		eSources.Get (40)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<40>));
//	    		eSources.Get (41)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<41>));
//	    		eSources.Get (42)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<42>));
//	    		eSources.Get (43)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<43>));
//	    		eSources.Get (44)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<44>));
//	    		eSources.Get (45)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<45>));
//	    		eSources.Get (46)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<46>));
//	    		eSources.Get (47)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<47>));
//	    		eSources.Get (48)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<48>));
//	    		eSources.Get (49)->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergyTrace<49>));


	    		Config::Connect ("/NodeList/0/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<0>));
	    		Config::Connect ("/NodeList/1/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<1>));
	    		Config::Connect ("/NodeList/2/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<2>));
	    		Config::Connect ("/NodeList/3/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<3>));
	    		Config::Connect ("/NodeList/4/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<4>));
	    		Config::Connect ("/NodeList/5/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<5>));
	    		Config::Connect ("/NodeList/6/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<6>));
	    		Config::Connect ("/NodeList/7/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<7>));
	    		Config::Connect ("/NodeList/8/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<8>));
	    		Config::Connect ("/NodeList/9/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<9>));
//		    	Config::Connect ("/NodeList/10/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<10>));
//	    		Config::Connect ("/NodeList/11/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<11>));
//	    		Config::Connect ("/NodeList/12/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<12>));
//	    		Config::Connect ("/NodeList/13/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<13>));
//	    		Config::Connect ("/NodeList/14/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<14>));
//	    		Config::Connect ("/NodeList/15/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<15>));
//	    		Config::Connect ("/NodeList/16/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<16>));
//	    		Config::Connect ("/NodeList/17/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<17>));
//	    		Config::Connect ("/NodeList/18/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<18>));
//	    		Config::Connect ("/NodeList/19/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<19>));
//	    		Config::Connect ("/NodeList/20/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<20>));
//	    		Config::Connect ("/NodeList/21/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<21>));
//	    		Config::Connect ("/NodeList/22/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<22>));
//	    		Config::Connect ("/NodeList/23/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<23>));
//	    		Config::Connect ("/NodeList/24/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<24>));
//	    		Config::Connect ("/NodeList/25/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<25>));
//	    		Config::Connect ("/NodeList/26/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<26>));
//	    		Config::Connect ("/NodeList/27/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<27>));
//	    		Config::Connect ("/NodeList/28/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<28>));
//	    		Config::Connect ("/NodeList/29/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<29>));
//	    		Config::Connect ("/NodeList/30/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<30>));
//	    		Config::Connect ("/NodeList/31/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<31>));
//	    		Config::Connect ("/NodeList/32/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<32>));
//	    		Config::Connect ("/NodeList/33/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<33>));
//	    		Config::Connect ("/NodeList/34/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<34>));
//	    		Config::Connect ("/NodeList/35/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<35>));
//	    		Config::Connect ("/NodeList/36/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<36>));
//	    		Config::Connect ("/NodeList/37/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<37>));
//	    		Config::Connect ("/NodeList/38/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<38>));
//	    		Config::Connect ("/NodeList/39/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<39>));
//	    		Config::Connect ("/NodeList/40/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<40>));
//	    		Config::Connect ("/NodeList/41/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<41>));
//	    		Config::Connect ("/NodeList/42/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<42>));
//	    		Config::Connect ("/NodeList/43/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<43>));
//	    		Config::Connect ("/NodeList/44/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<44>));
//	    		Config::Connect ("/NodeList/45/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<45>));
//	    		Config::Connect ("/NodeList/46/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<46>));
//	    		Config::Connect ("/NodeList/47/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<47>));
//	    		Config::Connect ("/NodeList/48/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<48>));
//	    		Config::Connect ("/NodeList/49/DeviceList/*/Phy/State/State", MakeCallback (&PhyStateTrace<49>));
}

void
DsdvManetExample::CreateDevices (std::string tr_name)
{
	double maxPower = 20.2729;		// TxPowerEnd in dbm
	double minPower = 10.8792;		// TxPowerStart in dbm
//	double maxPower = 30.0964;
//	double minPower = 16.9897;
//	uint32_t rtsThreshold = 2346;
	//uint32_t rtsThreshold = 2000;
	//std::string manager = "ns3::ParfWifiManager";
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  //wifiPhy.Set ("TxPowerLevels", UintegerValue(m_txpLvls));
  wifiPhy.Set ("TxPowerStart", DoubleValue(minPower));
  wifiPhy.Set ("TxPowerEnd", DoubleValue(maxPower));
  wifiPhy.Set ("ShortGuardEnabled", BooleanValue(true));
 // wifiPhy.Set ("AppTypeFlag", UintegerValue(m_appTypeFlag));

//  wifiPhy.Set ("TxGain", DoubleValue(0) );
//  wifiPhy.Set ("RxGain", DoubleValue (0) );
  //The energy of a received signal should be higher than this threshold (dbm) to allow the PHY layer to detect the signal
 // wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue(-51.0));		// Energy detection threshold value in dbm
  //The energy of a received signal should be higher than this threshold (dbm) to allow the PHY layer to declare CCA BUSY state.
 // wifiPhy.Set ("CcaMode1Threshold", DoubleValue(-55.0));	//CCA Mode 1 Threshold value in dbm
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.Set("GreenfieldEnabled", BooleanValue(true));
  wifiPhy.SetChannel (wifiChannel.Create ());

  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211n_2_4GHZ);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue (m_phyMode), "ControlMode",StringValue (m_phyMode));
 // wifi.SetRemoteStationManager (manager, "DefaultTxPowerLevel", UintegerValue (m_txpLvls), "RtsCtsThreshold", UintegerValue (rtsThreshold));
  devices = wifi.Install (wifiPhy, wifiMac, nodes);

  AsciiTraceHelper ascii;
  wifiPhy.EnableAscii (ascii.CreateFileStream (tr_name + ".tr"), nodes);
  wifiPhy.EnablePcap (tr_name,nodes);

}

void
DsdvManetExample::InstallInternetStack (std::string tr_name)
{

  DsdvHelper dsdv;
  dsdv.Set ("PeriodicUpdateInterval", TimeValue (Seconds (m_periodicUpdateInterval)));
  dsdv.Set ("SettlingTime", TimeValue (Seconds (m_settlingTime)));
//  dsdv.Set ("TxpLevel", UintegerValue(m_txpLvls));
  dsdv.Set ("Nodes", UintegerValue(m_nWifis));
  dsdv.Set ("AppTypeFlag", UintegerValue(m_appTypeFlag));
//  dsdv.Set ("EnableRouteAggregation",BooleanValue(true));
  InternetStackHelper stack; //

  stack.SetRoutingHelper (dsdv); // has effect on the next Install ()
  stack.Install (nodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  interfaces = address.Assign (devices);
  if (m_printRoutes)
    {
//	  for(uint16_t i = 0; i < m_totalTime ; i += 19)
//	  {
      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ((tr_name +".routes"), std::ios::out);
      dsdv.PrintRoutingTableAllAt(Seconds (99), routingStream) ;//(Seconds (399), routingStream);
	//  }+ std::to_string(i)
	  }
}

void
DsdvManetExample::InstallApplications ()
{

  for (uint32_t i = 0; i <= m_nSinks - 1; i++ )
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Ipv4Address nodeAddress = node->GetObject<Ipv4> ()->GetAddress (1, 0).GetLocal ();
      Ptr<Socket> sink = SetupPacketReceive (nodeAddress, node);
    }

  for (uint32_t clientNode = 0; clientNode <= m_nWifis - 1; clientNode++ )
    {
      for (uint32_t j = 0; j <= m_nSinks - 1; j++ )
        {
          OnOffHelper onoff1 ("ns3::UdpSocketFactory", Address (InetSocketAddress (interfaces .GetAddress (j), port)));
          onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
          onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

          if (j != clientNode)
            {
              ApplicationContainer apps1 = onoff1.Install (nodes.Get (clientNode));
              Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
              apps1.Start (Seconds (var->GetValue (m_dataStart, m_dataStart + 1)));
              apps1.Stop (Seconds (m_totalTime));
            }
        }
    }
}
