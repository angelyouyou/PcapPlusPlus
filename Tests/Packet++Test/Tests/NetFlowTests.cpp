#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "NetFlowLayer.h"

PTF_TEST_CASE(NetFlowRecordParsingTest)
{
	timeval time = {0};
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/NetFlow-V1.dat");
    READ_FILE_AND_CREATE_PACKET(5, "PacketExamples/NetFlow-V5.dat");

	pcpp::Packet netFlowV1Packet(&rawPacket1);
    pcpp::Packet netFlowV5Packet(&rawPacket5);

	PTF_ASSERT_TRUE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow_v1))
	PTF_ASSERT_TRUE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow))
	PTF_ASSERT_FALSE(netFlowV1Packet.isPacketOfType(pcpp::NetFlow_v5))
	auto* netFlowV1Layer = netFlowV1Packet.getLayerOfType<pcpp::NetFlowV1Layer>();
	PTF_ASSERT_NOT_NULL(netFlowV1Layer)
    PTF_ASSERT_EQUAL(netFlowV1Layer->toString(), "NetFlow V1 Layer", string)

    PTF_ASSERT_TRUE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow_v5))
    PTF_ASSERT_TRUE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow))
    PTF_ASSERT_FALSE(netFlowV5Packet.isPacketOfType(pcpp::NetFlow_v1))
    auto* netFlowV5Layer = netFlowV5Packet.getLayerOfType<pcpp::NetFlowV5Layer>();
    PTF_ASSERT_NOT_NULL(netFlowV5Layer)
    PTF_ASSERT_EQUAL(netFlowV5Layer->toString(), "NetFlow V5 Layer", string)
}

PTF_TEST_CASE(NetFlowV1CreateAndEditTest)
{
    pcpp::EthLayer ethLayer(pcpp::MacAddress("00:01:01:00:00:02"), pcpp::MacAddress("01:00:5e:00:00:16"));

    pcpp::IPv4Address srcIp("1.1.1.1");
    pcpp::IPv4Address dstIp("1.1.1.2");
    pcpp::IPv4Layer ipLayer(srcIp, dstIp);

    ipLayer.getIPv4Header()->ipId = htobe16(3941);
    ipLayer.getIPv4Header()->timeToLive = 255;

    pcpp::NetFlowV1Layer netFlowV1Layer;

    uint8_t* record = netFlowV1Layer.addRecordAtIndex(1);
    PTF_ASSERT_NOT_NULL(record)

    record = netFlowV1Layer.addRecord();
    PTF_ASSERT_NOT_NULL(record)

    record = netFlowV1Layer.addRecordAtIndex(3);
    PTF_ASSERT_NOT_NULL(record)

    pcpp::LoggerPP::getInstance().suppressErrors();
    PTF_ASSERT_NULL(netFlowV1Layer.addRecordAtIndex(4))
    PTF_ASSERT_NULL(netFlowV1Layer.addRecordAtIndex(4))
    PTF_ASSERT_NULL(netFlowV1Layer.addRecordAtIndex(4))
    pcpp::LoggerPP::getInstance().enableErrors();

    record = netFlowV1Layer.addRecordAtIndex(4);
    PTF_ASSERT_NOT_NULL(record)
    record = netFlowV1Layer.addRecordAtIndex(5);
    PTF_ASSERT_NOT_NULL(record)

    pcpp::Packet netFlowV5Layer;
    PTF_ASSERT_TRUE(netFlowV5Layer.addLayer(&ethLayer))
    PTF_ASSERT_TRUE(netFlowV5Layer.addLayer(&ipLayer))
    PTF_ASSERT_TRUE(netFlowV5Layer.addLayer(&netFlowV1Layer))

    READ_FILE_INTO_BUFFER(1, "PacketExamples/NetFlow-V5.dat")

    PTF_ASSERT_EQUAL(netFlowV5Layer.getRawPacket()->getRawDataLen(), bufferLength1, int)
    PTF_ASSERT_BUF_COMPARE(netFlowV5Layer.getRawPacket()->getRawData(), buffer1, netFlowV5Layer.getRawPacket()->getRawDataLen())

    delete[] buffer1;
}