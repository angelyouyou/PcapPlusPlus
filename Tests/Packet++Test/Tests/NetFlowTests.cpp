#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "IpAddress.h"
#include "SystemUtils.h"
#include "GeneralUtils.h"
#include "NetFlowLayer.h"

/**
 * 1.Read netflow file to packet;
 * 2.*/
PTF_TEST_CASE(NetFlowRecordParsingTest)
{
	timeval time = {0};
	gettimeofday(&time, nullptr);

    /** 1.Read netflow file to packet */
    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/NetFlow-V1.dat");
    READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/NetFlow-V5.dat");

    pcpp::Packet netFlowV1Packet(&rawPacket1);
    pcpp::Packet netFlowV5Packet(&rawPacket5);

    /** 2.Check the information of NetFlow v1 */
    PTF_ASSERT_TRUE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow_v1))
    PTF_ASSERT_TRUE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow))
    PTF_ASSERT_FALSE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow_v5))
    pcpp::NetFlowV1Layer* netFlowV1Layer = netFlowV1Packet.getLayerOfType<pcpp::NetFlowV1Layer>();
    PTF_ASSERT_NOT_NULL(netFlowV1Layer)
    PTF_ASSERT_EQUAL(netFlowV1Layer->NetFlowLayer::toString(), "NetFlow Version 1 Layer", string)

    /** 3.Check the information of NetFlow v5 */
    PTF_ASSERT_TRUE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow_v5))
    PTF_ASSERT_TRUE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow))
    PTF_ASSERT_FALSE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow_v1))
    pcpp::NetFlowV5Layer* netFlowV5Layer = netFlowV5Packet.getLayerOfType<pcpp::NetFlowV5Layer>();
    PTF_ASSERT_NOT_NULL(netFlowV5Layer)
    PTF_ASSERT_EQUAL(netFlowV5Layer->NetFlowLayer::toString(), "NetFlow Version 5 Layer", string)
}

PTF_TEST_CASE(NetFlowV1CreateAndEditTest)
{
    /** 1.Build ethernet/IP/UDP header */
    pcpp::EthLayer ethLayer(pcpp::MacAddress("ca:01:33:92:00:08"), pcpp::MacAddress("00:50:79:66:68:00"));

    pcpp::IPv4Address srcIp("192.168.10.100");
    pcpp::IPv4Address dstIp("192.168.10.254");
    pcpp::IPv4Layer ipLayer(srcIp, dstIp);
    ipLayer.getIPv4Header()->ipId = htobe16(0xdde);
    ipLayer.getIPv4Header()->timeToLive = 255;

    pcpp::UdpLayer udpLayer(61985, 9996);

    /** 2.Build NetFlow header */
    pcpp::NetFlowV1Header v1Header;
    memset(&v1Header, 0, sizeof(v1Header));
    v1Header.version = pcpp::hostToNet16(NetFlow_Version_1);
    v1Header.count = pcpp::hostToNet16(0);
    v1Header.sysUptime = pcpp::hostToNet16(0xdac8);
    v1Header.unix_secs = pcpp::hostToNet32(0x60b4e857);
    v1Header.unix_nsecs = pcpp::hostToNet32(0x039335be);

    pcpp::NetFlowV1Layer netFlowV1Layer;
    netFlowV1Layer.setNetFlowHeader((uint8_t*)&v1Header);
    PTF_ASSERT_NOT_NULL(&netFlowV1Layer)
    PTF_ASSERT_EQUAL(netFlowV1Layer.getVersionByData(), 1, int)

    /** 3.Build NetFlow record */
    pcpp::NetFlowV1Record v1Record1;
    memset(&v1Record1, 0, sizeof(v1Record1));
    v1Record1.dPkts = pcpp::hostToNet32(1);
    v1Record1.dOctets = pcpp::hostToNet32(80);
    v1Record1.first = pcpp::hostToNet32(80);
    v1Record1.last = pcpp::hostToNet32(0x76ec);
    v1Record1.input = pcpp::hostToNet32(0x76ec);
    pcpp::IPv4Address ipv4SrcAddress1("10.1.12.2");
    uint32_t ipv4SrcAddressInt1 = pcpp::hostToNet32(ipv4SrcAddress1.toInt());
    v1Record1.srcaddr = ipv4SrcAddressInt1;
    pcpp::IPv4Address ipv4DstAddress1("10.1.12.1");
    uint32_t ipv4DstAddressInt1 = pcpp::hostToNet32(ipv4DstAddress1.toInt());
    v1Record1.dstaddr = ipv4DstAddressInt1;
    v1Record1.proto = 89;
    v1Record1.tos = 0xc0;
    v1Record1.tcp_flags = 0x10;

    uint8_t* record1 = netFlowV1Layer.addRecordAtLast((uint8_t*)&v1Record1);
    PTF_ASSERT_NOT_NULL(record1)

    /** 4.Build all layers */
    pcpp::Packet netflowV1Packet;
    PTF_ASSERT_TRUE(netflowV1Packet.addLayer(&ethLayer))
    PTF_ASSERT_TRUE(netflowV1Packet.addLayer(&ipLayer))
    PTF_ASSERT_TRUE(netflowV1Packet.addLayer(&udpLayer))
    PTF_ASSERT_TRUE(netflowV1Packet.addLayer(&netFlowV1Layer))

    /** 5.Remove and add netflow record */
    PTF_ASSERT_TRUE(netFlowV1Layer.removeRecordAtIndex(0));

    netFlowV1Layer.addRecordAtLast((uint8_t*)&v1Record1);
    PTF_ASSERT_NOT_NULL(record1)

    pcpp::LoggerPP::getInstance().suppressErrors();
    PTF_ASSERT_FALSE(netFlowV1Layer.removeRecordAtIndex(4));
    (netFlowV1Layer.getNetFlowHeader())->countOrLen = htobe16(100);
    PTF_ASSERT_FALSE(netFlowV1Layer.removeRecordAtIndex(4));
    pcpp::LoggerPP::getInstance().enableErrors();

    /** 6.Read netflow file to buffer */
    READ_FILE_INTO_BUFFER(1, "PacketExamples/NetFlow-V1.dat")

    /** 7.Compare the packet content with the buffer of file */
    PTF_ASSERT_EQUAL(netflowV1Packet.getRawPacket()->getRawDataLen(), FILE_INTO_BUFFER_LENGTH(1), int);
    PTF_ASSERT_BUF_COMPARE(netflowV1Packet.getRawPacket()->getRawData(), FILE_INTO_BUFFER(1), netflowV1Packet.getRawPacket()->getRawDataLen());

    FREE_FILE_INTO_BUFFER(1);
    std::string hexStr = pcpp::byteArrayToHexDumpString(netflowV1Packet.getRawPacket()->getRawData(),
                                                        netflowV1Packet.getRawPacket()->getRawDataLen());
    LOG_ERROR("%s", hexStr.c_str());
}