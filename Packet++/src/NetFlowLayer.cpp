#define LOG_MODULE PacketLogModuleNetFlowLayer

#include "NetFlowLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <cstring>
#include "EndianPortable.h"
#include "SystemUtils.h"

namespace pcpp
{
    NetFlowLayer* NetFlowLayer::parseNetFlowLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
    {
        if (!isNetFlowLayerValid(data, dataLen, packet)) {
            return nullptr;
        }

        auto *netflowHeader = (NetFlowHeader*)data;
        uint16_t version = netToHost16(netflowHeader->version);
        switch (version)
        {
            case NetFlow_Version_1:
                return new NetFlowV1Layer(data, dataLen, prevLayer, packet);
            case NetFlow_Version_5:
                return new NetFlowV5Layer(data, dataLen, prevLayer, packet);
//            case NetFlow_Version_7:
//                return new NetFlowV7Layer(data, dataLen, prevLayer, packet);
//            case NetFlow_Version_9:
//                return new NetFlowV9Layer(data, dataLen, prevLayer, packet);
//            case NetFlow_Version_IPFIX:
//                return new NetFlowIPFIXLayer(data, dataLen, prevLayer, packet);
            default:
                return nullptr;
        }
    }

    bool NetFlowLayer::isNetFlowLayerValid(uint8_t* data, size_t dataLen, Packet* packet)
    {
        if ((dataLen <= NETFLOW_MIN_HEADER_LEN) || (data == nullptr)) {
            return false;
        }

        auto *netflowHeader = (NetFlowHeader*)data;
        uint16_t version = netToHost16(netflowHeader->version);
        switch (version)
        {
            case NetFlow_Version_1:
                return (dataLen >= (NETFLOW_V1_HEADER_LEN + NETFLOW_V1_RECORD_LEN));
            case NetFlow_Version_5:
                return (dataLen >= (NETFLOW_V5_HEADER_LEN + NETFLOW_V5_RECORD_LEN));
            case NetFlow_Version_7:
                return (dataLen >= (NETFLOW_V7_HEADER_LEN + NETFLOW_V7_RECORD_LEN));
//            case NetFlow_Version_9:
//                return (dataLen >= (NETFLOW_V7_HEADER_LEN + NETFLOW_V7_RECORD_LEN));
//            case NetFlow_Version_IPFIX:
//                return (dataLen >= (NETFLOW_V7_HEADER_LEN + NETFLOW_V7_RECORD_LEN));
            default:
                return false;
        }
    }

    /*************
     * NetFlowLayer
    *************/
    NetFlowLayer::NetFlowLayer(ProtocolType NetFlowVer)
    {
        m_DataLen = getHeaderSizeByVersion(NetFlowVer);
        m_Data = new uint8_t[m_DataLen];
        memset(m_Data, 0, m_DataLen);
        m_Protocol = NetFlowVer;
    }

    size_t NetFlowLayer::getHeaderSizeByVersion(ProtocolType NetFlowVer)
    {
        int headerSize = 0;
        switch (NetFlowVer) {
            case NetFlow_v1: {
                headerSize = sizeof(NetFlowV1Header);
                break;
            }
            case NetFlow_v5: {
                headerSize = sizeof(NetFlowV5Header);
                break;
            }
            case NetFlow_v7:{
                headerSize = sizeof(NetFlowV7Header);
                break;
            }
            case NetFlow_v9:{
                headerSize = sizeof(NetFlowV9Header);
                break;
            }
            case NetFlow_IPFIX:{
                headerSize = sizeof(NetFlowIPFIXHeader);
                break;
            }
            default:{
                break;
            }
        }

        return headerSize;
    }

    size_t NetFlowLayer::getRecordSizeByVersion(ProtocolType NetFlowVer)
    {
        int recordSize = 0;
        switch (NetFlowVer) {
            case NetFlow_v1: {
                recordSize = sizeof(NetFlowV1Record);
                break;
            }
            case NetFlow_v5: {
                recordSize = sizeof(NetFlowV5Record);
                break;
            }
            case NetFlow_v7:{
                recordSize = sizeof(NetFlowV7Record);
                break;
            }
            default:{
                break;
            }
        }

        return recordSize;
    }

    std::string NetFlowLayer::toString() const
    {
        std::string NetFlowVer;
        switch (getProtocol())
        {
            case NetFlow_v1:
                NetFlowVer = "1";
                break;
            case NetFlow_v5:
                NetFlowVer = "5";
                break;
            case NetFlow_v7:
                NetFlowVer = "7";
                break;
            case NetFlow_v9:
                NetFlowVer = "9";
                break;
            default:
                NetFlowVer = "5";
        }

        std::string msgType;

        std::string result = "NetFlow V" + NetFlowVer + " Layer";
        return result;
    }

    /*----------------------------*/
    u_int16_t NetFlowLayer::getRecordCountOrLength() const
    {
        return be16toh(getNetFlowHeader()->countOrLen);
    }

    uint8_t* NetFlowLayer::getFirstRecord() const
    {
        size_t headerLen = getHeaderSizeByVersion(m_Protocol);
        // check if there are records at all
        if (getHeaderLen() <= headerLen)
            return nullptr;

        return (m_Data + headerLen);
    }

    uint8_t* NetFlowLayer::getNextRecord(uint8_t* record) const
    {
        if (record == nullptr)
            return nullptr;

        // prev record was the last record
        if ((uint8_t*)record + getRecordSizeByVersion(m_Protocol) - m_Data >= (int)getHeaderSizeByVersion(m_Protocol))
            return nullptr;

        auto* nextRecord = (uint8_t*)((uint8_t*)record + getRecordSizeByVersion(m_Protocol));

        return nextRecord;
    }

    uint8_t* NetFlowLayer::addRecordAt(int offset)
    {
        if (offset > (int)getHeaderSizeByVersion(m_Protocol))
        {
            LOG_ERROR("Cannot add record, offset is out of layer bounds");
            return nullptr;
        }

        size_t recordSize = getRecordSizeByVersion(m_Protocol);
        if (!extendLayer(offset, recordSize))
        {
            LOG_ERROR("Cannot add record, cannot extend layer");
            return nullptr;
        }

        auto* recordBuffer = new uint8_t[recordSize];
        memset(recordBuffer, 0, recordSize);

        memcpy(m_Data + offset, recordBuffer, recordSize);

        delete[] recordBuffer;

        getNetFlowHeader()->countOrLen = htobe16(getRecordCountOrLength() + 1);

        return (uint8_t*)(m_Data + offset);
    }

    uint8_t* NetFlowLayer::addRecord()
    {
        return addRecordAt((int)getHeaderLen());
    }

    uint8_t* NetFlowLayer::addRecordAtIndex(int index)
    {
        int recordCnt = (int)getRecordCountOrLength();

        if (index < 0 || index > recordCnt)
        {
            LOG_ERROR("Cannot add record, index %d out of bounds", index);
            return nullptr;
        }

        size_t offset = getHeaderSizeByVersion(m_Protocol);

        uint8_t* curRecord = getFirstRecord();
        for (int i = 0; i < index; i++)
        {
            if (curRecord == nullptr)
            {
                LOG_ERROR("Cannot add record, cannot find record at index %d", i);
                return nullptr;
            }

            offset += getRecordSizeByVersion(m_Protocol);
            curRecord = getNextRecord(curRecord);
        }

        return addRecordAt((int)offset);
    }

    bool NetFlowLayer::removeRecordAtIndex(int index)
    {
        int recordCount = (int)getRecordCountOrLength();

        if (index < 0 || index >= recordCount)
        {
            LOG_ERROR("Cannot remove record, index %d is out of bounds", index);
            return false;
        }

        size_t offset = getHeaderSizeByVersion(m_Protocol);

        uint8_t* curRecord = getFirstRecord();
        for (int i = 0; i < index; i++)
        {
            if (curRecord == nullptr)
            {
                LOG_ERROR("Cannot remove record at index %d, cannot find record at index %d", index, i);
                return false;
            }

            offset += getRecordSizeByVersion(m_Protocol);
            curRecord = getNextRecord(curRecord);
        }

        if (!shortenLayer((int)offset, getRecordSizeByVersion(m_Protocol)))
        {
            LOG_ERROR("Cannot remove record at index %d, cannot shorted layer", index);
            return false;
        }

        getNetFlowHeader()->countOrLen = htobe16(recordCount - 1);

        return true;
    }

    bool NetFlowLayer::removeAllRecords()
    {
        int offset = (int)sizeof(getHeaderSizeByVersion(m_Protocol));

        if (!shortenLayer(offset, getHeaderLen()-offset))
        {
            LOG_ERROR("Cannot remove all records, cannot shorted layer");
            return false;
        }

        getNetFlowHeader()->countOrLen = 0;

        return true;
    }
    /*---------------------------------------*/

    /*************
     * NetFlowV1Layer
     *************/

    void NetFlowV1Layer::setNetFlowV1Header(netflow_v1_header* header) const
    {
        netflow_v1_header* netflowV1Header = getNetFlowV1Header();
        memcpy(netflowV1Header, header, sizeof(netflow_v1_header));
    }

    netflow_v1_record* NetFlowV1Layer::getNetFlowV1Record()
    {
        return (netflow_v1_record*)(m_Data + sizeof(netflow_v1_header));
    }

    void NetFlowV1Layer::setNetFlowV1Record(netflow_v1_record* record)
    {
        netflow_v1_record* netflowV1Record = getNetFlowV1Record();
        memcpy(netflowV1Record, record, sizeof(netflow_v1_record));
    }

    /*************
     * NetFlowV5Layer
     *************/

    void NetFlowV5Layer::setNetFlowV5Header(netflow_v5_header* header) const
    {
        netflow_v5_header* netflowV5Header = getNetFlowV5Header();
        memcpy(netflowV5Header, header, sizeof(netflow_v5_header));
    }

    netflow_v5_record* NetFlowV5Layer::getNetFlowV5Record()
    {
        return (netflow_v5_record*)(m_Data + sizeof(netflow_v5_header));
    }

    void NetFlowV5Layer::setNetFlowV5Record(netflow_v5_record* record)
    {
        netflow_v5_record* netflowV5Record = getNetFlowV5Record();
        memcpy(netflowV5Record, record, sizeof(netflow_v5_record));
    }
}
