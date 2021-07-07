#define LOG_MODULE PacketLogModuleNetFlowLayer

#include "NetFlowLayer.h"
#include "PacketUtils.h"
#include "IpAddress.h"
#include "Logger.h"
#include <cstring>
#include "EndianPortable.h"
#include "SystemUtils.h"

namespace pcpp
{
    /***************************************************************************************************************
     *                                               NetFlowLayer static functions
    ****************************************************************************************************************/
    NetFlowLayer* NetFlowLayer::parseNetFlowLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
    {
        if (!isNetFlowLayerValid(data, dataLen)) {
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
            default:
                return nullptr;
        }
    }

    bool NetFlowLayer::isNetFlowLayerValid(uint8_t* data, size_t dataLen)
    {
        if ((dataLen <= NETFLOW_MIN_HEADER_LEN) || (data == nullptr)) {
            return false;
        }

        NetFlowHeader *netflowHeader = (NetFlowHeader*)data;
        uint16_t version = netToHost16(netflowHeader->version);
        uint16_t countOrLen = netToHost16(netflowHeader->countOrLen);
        switch (version)
        {
            case NetFlow_Version_1:
                return (dataLen >= NETFLOW_V1_TOTAL_LEN(countOrLen));
            case NetFlow_Version_5:
                return (dataLen >= NETFLOW_V5_TOTAL_LEN(countOrLen));
            case NetFlow_Version_7:
            default:
                return false;
        }
    }

    bool NetFlowLayer::isValidNetFlowVersion(uint16_t version) {
        bool valid = false;
        switch (version) {
            case NetFlow_Version_1:
            case NetFlow_Version_5:
            case NetFlow_Version_7:
            case NetFlow_Version_9:
            case NetFlow_Version_IPFIX: {
                valid = true;
                break;
            }
            default:{
                break;
            }
        }

        return valid;
    }

    ProtocolType NetFlowLayer::getProtocolTypeByVersion(u_int16_t version)  {
        ProtocolType protocolType = UnknownProtocol;
        switch (version) {
            case NetFlow_Version_1: {
                protocolType = NetFlow_v1;
                break;
            }
            case NetFlow_Version_5: {
                protocolType = NetFlow_v5;
                break;
            }
            case NetFlow_Version_7:{
                protocolType = NetFlow_v7;
                break;
            }
            case NetFlow_Version_9:{
                protocolType = NetFlow_v9;
                break;
            }
            case NetFlow_Version_IPFIX:{
                protocolType = NetFlow_IPFIX;
                break;
            }
            default:{
                break;
            }
        }

        return protocolType;
    }

    size_t NetFlowLayer::getHeaderSizeByVersion(uint16_t version)
    {
        int headerSize = 0;
        switch (version) {
            case NetFlow_Version_1: {
                headerSize = sizeof(NetFlowV1Header);
                break;
            }
            case NetFlow_Version_5: {
                headerSize = sizeof(NetFlowV5Header);
                break;
            }
            case NetFlow_Version_7:{
                headerSize = sizeof(NetFlowV7Header);
                break;
            }
            case NetFlow_Version_9:{
                headerSize = sizeof(NetFlowV9Header);
                break;
            }
            case NetFlow_Version_IPFIX:{
                headerSize = sizeof(NetFlowIPFIXHeader);
                break;
            }
            default:{
                LOG_ERROR("Get NetFlow header by version failed, for version is invalid.");
                break;
            }
        }

        return headerSize;
    }

    size_t NetFlowLayer::getHeaderSizeByProtocol(ProtocolType protocolType)
    {
        return getHeaderSizeByVersion(getVersionByProtocol(protocolType));
    }

    uint16_t NetFlowLayer::getVersionByProtocol(ProtocolType protocolType)
    {
        if (protocolType == NetFlow_v1) {
            return NetFlow_Version_1;
        } else if (protocolType == NetFlow_v5) {
            return NetFlow_Version_5;
        } else if (protocolType == NetFlow_v7) {
            return NetFlow_Version_7;
        } else if (protocolType == NetFlow_v9) {
            return NetFlow_Version_9;
        } else if (protocolType == NetFlow_IPFIX) {
            return NetFlow_Version_IPFIX;
        } else {
            LOG_ERROR("Get NetFlow version by protocol failed, for protocol is invalid.");
            return NetFlow_Version_INVALID;
        }
    }

    std::string& NetFlowLayer::appendNetHeaderTitle(std::string &result, const std::string& title) {
        result += "\n";
        result += title;

        return result;
    }

    std::string& NetFlowLayer::appendNetFlowFieldString(std::string &result, const std::string& fieldName, u_int32_t fieldValue) {
        result += ("  " + fieldName + "=" + std::to_string(fieldValue));
        result += "\n";

        return result;
    }

    std::string& NetFlowLayer::appendNetFlowFieldString(std::string &result, const std::string& fieldName, u_int32_t fieldValue, bool ipAddress) {
        if (!ipAddress) {
            return appendNetFlowFieldString(result, fieldName, fieldValue);
        }

        IPAddress address(fieldValue);
        result += "  " + fieldName + "=" + address.toString() + "(" + std::to_string(fieldValue) + ")";
        result += "\n";

        return result;
    }
    /***************************************************************************************************************
     *                                               NetFlowLayer member functions
    ****************************************************************************************************************/
    NetFlowLayer::NetFlowLayer(ProtocolType NetFlowProtocol)
    {
        setDataLen(getHeaderSizeByProtocol(NetFlowProtocol));
        setData(new uint8_t[getDataLen()]);
        memset(m_Data, 0, getDataLen());
        setProtocol(NetFlowProtocol);
    }

    u_int16_t NetFlowLayer::getVersionByData() const {
        NetFlowHeader *netflowHeader = (NetFlowHeader*)getData();
        if (netflowHeader == nullptr) {
            return NetFlow_Version_INVALID;
        }

        uint16_t version = netToHost16(netflowHeader->version);
        return version;
    }

    uint16_t NetFlowLayer::getNetFlowMaxRecordCount() const
    {
        uint16_t count = 0;
        u_int16_t version = getVersionByData();
        switch (version) {
            case NetFlow_Version_1:
            case NetFlow_Version_5:
                count = MAX_NETFLOW_V1V5_PER_PACKET;
                break;
            case NetFlow_Version_7: {
                count = MAX_NETFLOW_V7_PER_PACKET;
                break;
            }
            default:
                break;
        }

        return count;
    }

    size_t NetFlowLayer::getHeaderSize() const
    {
        return getHeaderSizeByVersion(getVersionByData());
    }

    size_t NetFlowLayer::getRecordSize() const
    {
        int recordSize = 0;
        switch (getVersionByData()) {
            case NetFlow_Version_1: {
                recordSize = sizeof(NetFlowV1Record);
                break;
            }
            case NetFlow_Version_5: {
                recordSize = sizeof(NetFlowV5Record);
                break;
            }
            case NetFlow_Version_7:{
                recordSize = sizeof(NetFlowV7Record);
                break;
            }
            default:{
                LOG_ERROR("Get NetFlow record failed, for protocol is invalid.");
                break;
            }
        }

        return recordSize;
    }

    size_t NetFlowLayer::getAllRecordSize() const
    {
        auto *netflowHeader = (NetFlowHeader*)getData();
        uint16_t countOrLen = netToHost16(netflowHeader->countOrLen);

        return (countOrLen * getRecordSize());
    }

    void NetFlowLayer::setNetFlowHeader(uint8_t* header) {
        NetFlowHeader *netFlowHeader = (NetFlowHeader*)header;
        if (netFlowHeader == nullptr) {
            LOG_ERROR("Set NetFlow header failed, for header is null.");
            return;
        }

        u_int16_t version = netToHost16(netFlowHeader->version);
        if (!isValidNetFlowVersion(version)) {
            LOG_ERROR("Set NetFlow header failed, for version is invalid.");
            return;
        }

        setProtocol(getProtocolTypeByVersion(version));
        memcpy(m_Data, netFlowHeader, getHeaderSizeByVersion(version));
    }

    void NetFlowLayer::setNetFlowRecord(uint8_t* record, uint16_t count) {
        if (record == nullptr) {
            LOG_ERROR("Set NetFlow record failed, for record is null.");
            return;
        }

        int countOrLen = getRecordCountOrLength();
        if (countOrLen != count) {
            LOG_ERROR("Set NetFlow record failed, for record count is not matched the field 'countOrLen' in header.");
            return;
        }

        memcpy(getData() + getHeaderSize(), record, countOrLen * getRecordSize());
    }

    u_int16_t NetFlowLayer::getRecordCountOrLength() const
    {
        return be16toh(getNetFlowHeader()->countOrLen);
    }

    uint8_t* NetFlowLayer::getFirstRecord() const
    {
        // check if there are records at all
        if (getDataLen() < getHeaderSize() + getRecordSize()) {
            LOG_ERROR("Get First NetFlow record failed, for DataLen is smaller than [header + record] size.");
            return nullptr;
        }

        return (getData() + getHeaderSize());
    }

    uint8_t* NetFlowLayer::getNextRecord(uint8_t* record) const
    {
        if (record == nullptr)
            return nullptr;

        // prev record was the last record
        if ((uint8_t*)record + getRecordSize() >= getData() + (int)getDataLen()) {
            return nullptr;
        }

        return (uint8_t*)((uint8_t*)record + getRecordSize());
    }

    uint8_t* NetFlowLayer::addRecordVectorAtOffset(int offset, std::vector<uint8_t*>& recordsVector)
    {
        if (offset > (int)getDataLen())
        {
            LOG_ERROR("Cannot add NetFlow records, for offset is out of layer bounds.");
            return nullptr;
        }

        if (recordsVector.empty())
        {
            LOG_ERROR("Cannot add NetFlow records, for recordsVector is empty.");
            return nullptr;
        }

        if (recordsVector.size() + getRecordCountOrLength() > getNetFlowMaxRecordCount())
        {
            LOG_ERROR("Cannot add NetFlow records, for size of recordsVector is too large.");
            return nullptr;
        }

        size_t recordSize = recordsVector.size() * getRecordSize();
        if (!extendLayer(offset, recordSize))
        {
            LOG_ERROR("Cannot add NetFlow records, for cannot extend layer.");
            return nullptr;
        }

        uint8_t* recordBuffer = new uint8_t[recordSize];
        memset(recordBuffer, 0, recordSize);

        size_t recordOffset = 0;
        size_t recordLen = getRecordSize();
        for (uint8_t* record: recordsVector)
        {
            memcpy(recordBuffer + recordOffset, (uint8_t*)record, recordLen);
            recordOffset += recordLen;
        }
        memcpy(getData() + offset, recordBuffer, recordSize);
        delete[] recordBuffer;

        getNetFlowHeader()->countOrLen = htobe16(getRecordCountOrLength() + recordsVector.size());

        return (uint8_t*)(getData() + offset);
    }

    uint8_t* NetFlowLayer::addRecordVectorAtLast(std::vector<uint8_t*>& recordsVector)
    {
        return addRecordVectorAtOffset((int) getHeaderLen(), recordsVector);
    }

    uint8_t* NetFlowLayer::addRecordVectorAtIndex(int index, std::vector<uint8_t*>& recordsVector)
    {
        int recordCnt = (int)getRecordCountOrLength();
        if ((index < 0) || (index > recordCnt))
        {
            LOG_ERROR("Cannot add NetFlow record, index %d out of bounds.", index);
            return nullptr;
        }

        if (recordsVector.size() + getRecordCountOrLength() > getNetFlowMaxRecordCount())
        {
            LOG_ERROR("Cannot add NetFlow record, for size of recordsVector is too large.");
            return nullptr;
        }

        size_t offset = getHeaderSizeByVersion(getVersionByData());
        uint8_t* curRecord = getFirstRecord();
        if (curRecord == nullptr) {
            return nullptr;
        }

        for (int i = 0; i < index; i++)
        {
            if (curRecord == nullptr)
            {
                LOG_ERROR("Cannot add record, cannot find record at index %d", i);
                return nullptr;
            }

            offset += getRecordSize();
            curRecord = getNextRecord(curRecord);
        }

        return addRecordVectorAtOffset((int) offset, recordsVector);
    }

    uint8_t* NetFlowLayer::addRecordAtOffset(int offset, uint8_t* record)
    {
        std::vector<uint8_t*> recordVector;
        recordVector.push_back(record);
        return addRecordVectorAtOffset(offset, recordVector);
    }

    uint8_t* NetFlowLayer::addRecordAtLast(uint8_t* record)
    {
        std::vector<uint8_t*> recordVector;
        recordVector.push_back(record);
        return addRecordVectorAtLast(recordVector);
    }

    uint8_t* NetFlowLayer::addRecordAtIndex(int index, uint8_t* record)
    {
        std::vector<uint8_t*> recordVector;
        recordVector.push_back(record);
        return addRecordVectorAtIndex(index, recordVector);
    }

    bool NetFlowLayer::removeRecordAtIndex(int index)
    {
        int recordCount = (int)getRecordCountOrLength();
        if ((index < 0) || (index >= recordCount))
        {
            LOG_ERROR("Cannot remove NetFlow record, index %d is out of bounds.", index);
            return false;
        }

        size_t offset = getHeaderSizeByVersion(getVersionByData());
        uint8_t* curRecord = getFirstRecord();
        for (int i = 0; i < index; i++)
        {
            if (curRecord == nullptr)
            {
                LOG_ERROR("Cannot remove NetFlow record at index %d, cannot find record at index %d.", index, i);
                return false;
            }

            offset += getRecordSize();
            curRecord = getNextRecord(curRecord);
        }

        if (!shortenLayer((int)offset, getRecordSize()))
        {
            LOG_ERROR("Cannot remove NetFlow record at index %d, cannot shorted layer.", index);
            return false;
        }

        getNetFlowHeader()->countOrLen = htobe16(recordCount - 1);

        return true;
    }

    bool NetFlowLayer::removeAllRecords()
    {
        int offset = (int)sizeof(getHeaderSizeByVersion(getVersionByData()));
        if (!shortenLayer(offset, getHeaderLen() - offset))
        {
            LOG_ERROR("Cannot remove all NetFlow records, cannot shorted layer.");
            return false;
        }

        getNetFlowHeader()->countOrLen = 0;

        return true;
    }

    std::string NetFlowLayer::toString() const
    {
        std::string NetFlowVer = std::to_string(NetFlow_Version_INVALID);
        switch (getProtocol())
        {
            case NetFlow_v1:
                NetFlowVer = std::to_string(NetFlow_Version_1) ;
                break;
            case NetFlow_v5:
                NetFlowVer = std::to_string(NetFlow_Version_5) ;
                break;
            case NetFlow_v7:
                NetFlowVer = std::to_string(NetFlow_Version_7) ;
                break;
            case NetFlow_v9:
                NetFlowVer = std::to_string(NetFlow_Version_9) ;
                break;
            case NetFlow_IPFIX:
                NetFlowVer = std::to_string(NetFlow_Version_IPFIX) ;
                break;
            default:
                break;
        }

        return ("NetFlow Version " + NetFlowVer + " Layer");
    }

    /***************************************************************************************************************
     *                                               NetFlowV1Layer functions
    ****************************************************************************************************************/
    std::string NetFlowV1Layer::toString() const
    {
        std::string toStr;
        NetFlowV1Header *header = (NetFlowV1Header*)getNetFlowHeader();

        appendNetHeaderTitle(toStr, "NetFlow Header:\n");
        appendNetFlowFieldString(toStr, "version", netToHost16(header->version));
        appendNetFlowFieldString(toStr, "count", netToHost16(header->count));
        appendNetFlowFieldString(toStr, "sysUptime", netToHost32(header->sysUptime));
        appendNetFlowFieldString(toStr, "unix_secs", netToHost32(header->unix_secs));
        appendNetFlowFieldString(toStr, "unix_nsecs", netToHost32(header->unix_nsecs));

        if (header->count <= 0) {
            return toStr;
        }

        NetFlowV1Record *record = (NetFlowV1Record*)getFirstRecord();
        appendNetHeaderTitle(toStr, "NetFlow Record(s):");

        for (int i = 0; i < netToHost16(header->count); ++i) {
            std::string indexStr = "index(" + std::to_string(i) + ")" + ":\n";
            appendNetHeaderTitle(toStr, indexStr);

            appendNetFlowFieldString(toStr, "srcaddr", netToHost32(record->srcaddr), true);
            appendNetFlowFieldString(toStr, "dstaddr", netToHost32(record->dstaddr), true);
            appendNetFlowFieldString(toStr, "nexthop", netToHost32(record->nexthop), true);
            appendNetFlowFieldString(toStr, "input", netToHost32(record->input));
            appendNetFlowFieldString(toStr, "output", netToHost32(netToHost32(record->output)));
            appendNetFlowFieldString(toStr, "dPkts", netToHost32(record->dPkts));
            appendNetFlowFieldString(toStr, "dOctets", netToHost32(record->dOctets));
            appendNetFlowFieldString(toStr, "first", netToHost32(record->first));
            appendNetFlowFieldString(toStr, "last", netToHost32(record->last));
            appendNetFlowFieldString(toStr, "srcport", netToHost32(record->srcport));
            appendNetFlowFieldString(toStr, "dstport", netToHost32(record->dstport));
            appendNetFlowFieldString(toStr, "pad", record->pad);
            appendNetFlowFieldString(toStr, "proto", record->proto);
            appendNetFlowFieldString(toStr, "tos", record->tos);
            appendNetFlowFieldString(toStr, "tcp_flags", record->tcp_flags);

            record = (NetFlowV1Record*)getNextRecord((uint8_t*)record);
            if (record == nullptr) {
                break;
            }
        }

        return toStr;
    }

    /***************************************************************************************************************
     *                                               NetFlowV5Layer functions
    ****************************************************************************************************************/
    std::string NetFlowV5Layer::toString() const
    {
        std::string toStr;
        NetFlowV5Header *header = (NetFlowV5Header*)getNetFlowHeader();

        appendNetHeaderTitle(toStr, "NetFlow Header:\n");
        appendNetFlowFieldString(toStr, "version", netToHost16(header->version));
        appendNetFlowFieldString(toStr, "count", netToHost16(header->count));
        appendNetFlowFieldString(toStr, "sysUptime", netToHost32(header->sysUptime));
        appendNetFlowFieldString(toStr, "unix_secs", netToHost32(header->unix_secs));
        appendNetFlowFieldString(toStr, "unix_nsecs", netToHost32(header->unix_nsecs));
        appendNetFlowFieldString(toStr, "sequenceNumber", netToHost32(header->sequenceNumber));
        appendNetFlowFieldString(toStr, "engine_type", header->engine_type);
        appendNetFlowFieldString(toStr, "engine_id", header->engine_id);
        appendNetFlowFieldString(toStr, "sampleRate", netToHost16(header->sampleRate));

        if (header->count <= 0) {
            return toStr;
        }

        NetFlowV5Record *record = (NetFlowV5Record*)getFirstRecord();
        appendNetHeaderTitle(toStr, "NetFlow Record(s):");

        for (int i = 0; i < netToHost16(header->count); ++i) {
            std::string indexStr = "index(" + std::to_string(i) + ")" + ":\n";
            appendNetHeaderTitle(toStr, indexStr);

            appendNetFlowFieldString(toStr, "srcaddr", netToHost32(record->srcaddr), true);
            appendNetFlowFieldString(toStr, "dstaddr", netToHost32(record->dstaddr), true);
            appendNetFlowFieldString(toStr, "nexthop", netToHost32(record->nexthop), true);
            appendNetFlowFieldString(toStr, "input", netToHost32(record->input));
            appendNetFlowFieldString(toStr, "output", netToHost32(netToHost32(record->output)));
            appendNetFlowFieldString(toStr, "dPkts", netToHost32(record->dPkts));
            appendNetFlowFieldString(toStr, "dOctets", netToHost32(record->dOctets));
            appendNetFlowFieldString(toStr, "first", netToHost32(record->first));
            appendNetFlowFieldString(toStr, "last", netToHost32(record->last));
            appendNetFlowFieldString(toStr, "srcport", netToHost32(record->srcport));
            appendNetFlowFieldString(toStr, "dstport", netToHost32(record->dstport));
            appendNetFlowFieldString(toStr, "pad1", record->pad1);
            appendNetFlowFieldString(toStr, "tcp_flags", record->tcp_flags);
            appendNetFlowFieldString(toStr, "proto", record->proto);
            appendNetFlowFieldString(toStr, "tos", record->tos);
            appendNetFlowFieldString(toStr, "pad1", record->src_as);
            appendNetFlowFieldString(toStr, "tcp_flags", record->dst_as);
            appendNetFlowFieldString(toStr, "proto", record->src_mask);
            appendNetFlowFieldString(toStr, "tos", record->dst_mask);
            appendNetFlowFieldString(toStr, "pad2", record->pad2);

            record = (NetFlowV5Record*)getNextRecord((uint8_t*)record);
            if (record == nullptr) {
                break;
            }
        }

        return toStr;
    }

    /***************************************************************************************************************
     *                                               NetFlowV7Layer functions
    ****************************************************************************************************************/
    std::string NetFlowV7Layer::toString() const
    {
        std::string toStr;
        NetFlowV7Header *header = (NetFlowV7Header*)getNetFlowHeader();

        appendNetHeaderTitle(toStr, "NetFlow Header:\n");
        appendNetFlowFieldString(toStr, "version", netToHost16(header->version));
        appendNetFlowFieldString(toStr, "count", netToHost16(header->count));
        appendNetFlowFieldString(toStr, "sysUptime", netToHost32(header->sysUptime));
        appendNetFlowFieldString(toStr, "unix_secs", netToHost32(header->unix_secs));
        appendNetFlowFieldString(toStr, "unix_nsecs", netToHost32(header->unix_nsecs));
        appendNetFlowFieldString(toStr, "sequenceNumber", netToHost32(header->sequenceNumber));
        appendNetFlowFieldString(toStr, "reserved", netToHost32(header->reserved));

        if (header->count <= 0) {
            return toStr;
        }

        NetFlowV7Record *record = (NetFlowV7Record*)getFirstRecord();
        appendNetHeaderTitle(toStr, "NetFlow Record(s):");

        for (int i = 0; i < netToHost16(header->count); ++i) {
            std::string indexStr = "index(" + std::to_string(i) + ")" + ":\n";
            appendNetHeaderTitle(toStr, indexStr);

            appendNetFlowFieldString(toStr, "srcaddr", netToHost32(record->srcaddr), true);
            appendNetFlowFieldString(toStr, "dstaddr", netToHost32(record->dstaddr), true);
            appendNetFlowFieldString(toStr, "nexthop", netToHost32(record->nexthop), true);
            appendNetFlowFieldString(toStr, "input", netToHost32(record->input));
            appendNetFlowFieldString(toStr, "output", netToHost32(netToHost32(record->output)));
            appendNetFlowFieldString(toStr, "dPkts", netToHost32(record->dPkts));
            appendNetFlowFieldString(toStr, "dOctets", netToHost32(record->dOctets));
            appendNetFlowFieldString(toStr, "first", netToHost32(record->first));
            appendNetFlowFieldString(toStr, "last", netToHost32(record->last));
            appendNetFlowFieldString(toStr, "srcport", netToHost32(record->srcport));
            appendNetFlowFieldString(toStr, "dstport", netToHost32(record->dstport));
            appendNetFlowFieldString(toStr, "flags", record->flags);
            appendNetFlowFieldString(toStr, "tcp_flags", record->tcp_flags);
            appendNetFlowFieldString(toStr, "proto", record->proto);
            appendNetFlowFieldString(toStr, "tos", record->tos);
            appendNetFlowFieldString(toStr, "pad1", record->src_as);
            appendNetFlowFieldString(toStr, "tcp_flags", record->dst_as);
            appendNetFlowFieldString(toStr, "proto", record->src_mask);
            appendNetFlowFieldString(toStr, "tos", record->dst_mask);
            appendNetFlowFieldString(toStr, "pad2", record->pad2);
            appendNetFlowFieldString(toStr, "router_sc", record->router_sc);

            record = (NetFlowV7Record*)getNextRecord((uint8_t*)record);
            if (record == nullptr) {
                break;
            }
        }

        return toStr;
    }

    /***************************************************************************************************************
     *                                               NetFlowV9Layer functions
    ****************************************************************************************************************/
    std::string NetFlowV9Layer::toString() const
    {
        std::string toStr;
        NetFlowV9Header *header = (NetFlowV9Header*)getNetFlowHeader();

        appendNetHeaderTitle(toStr, "NetFlow Header:\n");
        appendNetFlowFieldString(toStr, "version", netToHost16(header->version));
        appendNetFlowFieldString(toStr, "count", netToHost16(header->count));
        appendNetFlowFieldString(toStr, "sysUptime", netToHost32(header->sysUptime));
        appendNetFlowFieldString(toStr, "unix_secs", netToHost32(header->unix_secs));
        appendNetFlowFieldString(toStr, "sequenceNumber", netToHost32(header->sequenceNumber));
        appendNetFlowFieldString(toStr, "sourceId", netToHost32(header->sourceId));

        if (header->count <= 0) {
            return toStr;
        }

        return toStr;
    }
}