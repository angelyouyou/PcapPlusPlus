#ifndef PACKETPP_NetFlow_LAYER
#define PACKETPP_NetFlow_LAYER

#include "Layer.h"
#include "IpAddress.h"
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
#pragma pack(push, 1)
/* ********* NETFLOW ****************** */

/*
  For more info see:
    https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html
    https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.pdf
    https://datatracker.ietf.org/doc/html/rfc3954
    https://datatracker.ietf.org/doc/html/rfc7011
*/

/* ********************************* */
    #define MAX_NETFLOW_V1_PER_PACKET   30
    #define MAX_NETFLOW_V5_PER_PACKET   30
    #define MAX_NETFLOW_V7_PER_PACKET   28

    #define NETFLOW_TEMPLATE       0
    #define OPTION_TEMPLATE     1

    #define SHORT_SNAPLEN       0
    #define LONG_SNAPLEN        1

    #define STATIC_FIELD_LEN    1
    #define VARIABLE_FIELD_LEN  2

    #define BOTH_IPV4_IPV6      1
    #define ONLY_IPV4           2
    #define ONLY_IPV6           3
    #define STANDARD_ENTERPRISE_ID    0

    typedef enum enumNetFlow_Version
    {
        /** NetFlow v1 */
        NetFlow_Version_1   = 1,

        /** NetFlow v5 */
        NetFlow_Version_5  = 5,

        /** NetFlow v7 */
        NetFlow_Version_7    = 7,

        /** NetFlow v9 */
        NetFlow_Version_9 = 9,

        /** NetFlow IPFIX */
        NetFlow_Version_IPFIX = 10
    }NetFlowVersion;

    typedef enum enumElementFormat{
        ascii_format = 0,     /* ASCII format */
        hex_format,           /* HEX format */
        numeric_format,       /* Numeric format */
        ipv6_address_format   /* IPv6 address format */
    } ElementFormat;

    typedef enum enumElementDumpFormat{
        dump_as_uint = 0, /* 1234567890 */
        dump_as_formatted_uint, /* 123'456 */
        dump_as_ip_port,
        dump_as_ip_proto,
        dump_as_ipv4_address,
        dump_as_ipv6_address,
        dump_as_mac_address,
        dump_as_epoch,
        dump_as_bool,
        dump_as_tcp_flags,
        dump_as_hex,
        dump_as_ascii
    } ElementDumpFormat;

    /**
    * @struct netflow_header
    * NetFlow v1/v5/v7/v9 basic protocol header
    */
    typedef struct netflow_header {
        u_int16_t version;         /* Version */
        u_int16_t countOrLen;      /* The number of records in PDU, or the length of the IPFIX PDU. */
    }NetFlowHeader;

    typedef struct netflow_v1_header {
        u_int16_t version;         /* Current version = 1*/
        u_int16_t count;           /* The number of records in PDU. */
        u_int32_t sysUptime;       /* Current time in msecs since router booted */
        u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
        u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
    }NetFlowV1Header;

    typedef struct netflow_v1_record {
        u_int32_t srcaddr;    /* Source IP Address */
        u_int32_t dstaddr;    /* Destination IP Address */
        u_int32_t nexthop;    /* Next hop router's IP Address */
        u_int16_t input;      /* Input interface index */
        u_int16_t output;     /* Output interface index */
        u_int32_t dPkts;      /* Packets sent in Duration */
        u_int32_t dOctets;    /* Octets sent in Duration */
        u_int32_t first;      /* SysUptime at start of flow */
        u_int32_t last;       /* and of last packet of the flow */
        u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int16_t pad;        /* pad to word boundary */
        u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
        u_int8_t  tos;        /* IP Type-of-Service */
        u_int8_t  pad2[7];    /* pad to word boundary */
    }NetFlowV1Record;

    typedef struct single_netflow_v1_rec {
        NetFlowV1Header netflowHeader; /*  */
        NetFlowV1Record netflowRecord[MAX_NETFLOW_V1_PER_PACKET + 1 ];/* safe against buffer overflows */
    } NetFlow1Packet;

/* ***************************************** */
    typedef struct netflow_v5_header {
        u_int16_t version;         /* Current version=5*/
        u_int16_t count;           /* The number of records in PDU. */
        u_int32_t sysUptime;       /* Current time in msecs since router booted */
        u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
        u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
        u_int32_t sequenceNumber; /* Sequence number of total flows seen */
        u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
        u_int8_t  engine_id;       /* Slot number of the flow switching engine */
        u_int16_t sampleRate;      /* Packet capture sample rate */
    }NetFlowV5Header;

    typedef struct netflow_v5_record {
        u_int32_t srcaddr;    /* Source IP Address */
        u_int32_t dstaddr;    /* Destination IP Address */
        u_int32_t nexthop;    /* Next hop router's IP Address */
        u_int16_t input;      /* Input interface index */
        u_int16_t output;     /* Output interface index */
        u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
        u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
        u_int32_t first;      /* SysUptime at start of flow */
        u_int32_t last;       /* and of last packet of the flow */
        u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int8_t pad1;        /* pad to word boundary */
        u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
        u_int8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
        u_int8_t tos;         /* IP Type-of-Service */
        u_int16_t src_as;     /* source peer/origin Autonomous System */
        u_int16_t dst_as;     /* dst peer/origin Autonomous System */
        u_int8_t src_mask;    /* source route's mask bits */
        u_int8_t dst_mask;    /* destination route's mask bits */
        u_int16_t pad2;       /* pad to word boundary */
    }NetFlowV5Record;

    typedef struct single_netflow_v5_rec {
        NetFlowV5Header netflowHeader;
        NetFlowV5Record netflowRecord[MAX_NETFLOW_V5_PER_PACKET + 1];/* safe against buffer overflows */
    } NetFlow5Packet;

/* ************************************ */

/* ********************************* */

    typedef struct netflow_v7_header {
        u_int16_t version;         /* Current version=7*/
        u_int16_t count;           /* The number of records in PDU. */
        u_int32_t sysUptime;       /* Current time in msecs since router booted */
        u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
        u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
        u_int32_t sequenceNumber;  /* Sequence number of total flows seen */
        u_int32_t reserved;
    }NetFlowV7Header;

    typedef struct netflow_v7_record {
        u_int32_t srcaddr;    /* Source IP Address */
        u_int32_t dstaddr;    /* Destination IP Address */
        u_int32_t nexthop;    /* Next hop router's IP Address */
        u_int16_t input;      /* Input interface index */
        u_int16_t output;     /* Output interface index */
        u_int32_t dPkts;      /* Packets sent in Duration */
        u_int32_t dOctets;    /* Octets sent in Duration */
        u_int32_t first;      /* SysUptime at start of flow */
        u_int32_t last;       /* and of last packet of the flow */
        u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
        u_int8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
        u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
        u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
        u_int8_t  tos;        /* IP Type-of-Service */
        u_int16_t dst_as;     /* dst peer/origin Autonomous System */
        u_int16_t src_as;     /* source peer/origin Autonomous System */
        u_int8_t  dst_mask;   /* destination route's mask bits */
        u_int8_t  src_mask;   /* source route's mask bits */
        u_int16_t pad2;       /* pad to word boundary */
        u_int32_t router_sc;  /* Router which is shortcut by switch */
    }NetFlowV7Record;

    typedef struct single_netflow_v7_rec {
        NetFlowV7Header netflowHeader;
        NetFlowV7Record netflowRecord[MAX_NETFLOW_V7_PER_PACKET + 1];/* safe against buffer overflows */
    } NetFlow7Packet;

/* ************************************ */

    /* NetFlow v9/IPFIX */
    typedef struct netflow_v9_header {
        u_int16_t version;         /* Current version=9*/
        u_int16_t count;           /* The number of records in PDU. */
        u_int32_t sysUptime;       /* Current time in msecs since router booted */
        u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
        u_int32_t sequenceNumber;  /* Sequence number of total flows seen */
        u_int32_t sourceId;        /* Source id */
    } NetFlowV9Header;

    typedef struct netflow_v9_template_field {
        u_int16_t fieldId;
        u_int16_t fieldLen;
        u_int8_t  isPenField;
        u_int32_t enterpriseId;
    } NetFlowV9V10TemplateField;

    typedef struct netflow_v9_template_header {
        u_int16_t templateFlowset; /* = 0 */
        u_int16_t flowsetLen;
    } NetFlowV9TemplateHeader;

    typedef struct netflow_v9_template_def {
        u_int16_t templateId;
        u_int16_t fieldCount;
    } NetFlowV9TemplateDef;

    typedef struct netflow_v9_ipfix_simple_template {
        /* V9TemplateHeader */
        u_int16_t flowsetLen;

        /* V9TemplateDef */
        u_int8_t flowVersion;
        u_int16_t templateId;
        u_int16_t fieldCount;
        u_int16_t scopeFieldCount;
        u_int16_t v9ScopeLen;
        u_int32_t netflow_device_ip;
        u_int32_t observation_domain_id_source_id; /* IPFIX: observation_domain_id, v9: source_id */
        u_int8_t isOptionTemplate;
    } NetFlowV9IPFIXSimpleTemplate;

    typedef struct netflow_v9_option_template {
        u_int16_t templateFlowset; /* = 0 */
        u_int16_t flowsetLen;
        u_int16_t templateId;
        u_int16_t optionScopeLen;
        u_int16_t optionLen;
    } NetFlowV9OptionTemplate;

    typedef struct netflow_v9_netflow_set {
        u_int16_t templateId;
        u_int16_t flowsetLen;
    } NetFlowV9FlowSet;

    typedef struct netflow_set {
        u_int16_t templateId;
        u_int16_t fieldCount;
    } NetFlowFlowSet;

    typedef struct netflow_v9_ipfix_set {
        NetFlowV9IPFIXSimpleTemplate templateInfo;
        u_int16_t flowLen; /* Real flow length */
        NetFlowV9V10TemplateField *fields;
        struct netflow_v9_ipfix_set *next;
    } NetFlowV9IPFIXSet;

    typedef struct netflow_v9_ipfix_template_elementids {
        u_int8_t isInUse; /* 1=used by the template, 0=not in use */
        u_int8_t protoMode; /* BOTH_IPV4_IPV6, ONLY_IPV4, ONLY_IPV6 */
        const u_int8_t  isOptionTemplate; /* 0=flow template, 1=option template */
        const u_int8_t  useLongSnaplen;
        const u_int32_t templateElementEnterpriseId;
        const u_int16_t templateElementId;
        u_int8_t variableFieldLength; /* This is not a const as it can be set */
        u_int16_t templateElementLen; /* This is not a const as it can be set */
        const ElementFormat elementFormat; /* Only for elements longer than 4 bytes */
        const ElementDumpFormat fileDumpFormat; /* Hint when data has to be printed on
					     a human readable form */
        const char *netflowElementName;
        const char **ipfixElementName;
        const char *templateElementDescr;
    } NetFlowV9V10TemplateElementId;

/* ******************************************* */

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Version Number          |            Length             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Export Time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Sequence Number                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Observation Domain ID                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

    typedef struct netflow_ipfix_header {
        u_int16_t version;             /* Current version = 10 */
        u_int16_t len;                 /* The length of the IPFIX PDU */
        u_int32_t sysUptime;           /* Current time in msecs since router booted */
        u_int32_t sequenceNumber;      /* Sequence number of total flows seen */
        u_int32_t observationDomainId; /* Source id */
    } NetFlowIPFIXHeader;

    typedef struct netflow_ipfix_set {
        u_int16_t set_id;
        u_int16_t set_len;
    } NetFlowIPFIXSet;

    typedef struct netflow_ipfix_field {
        u_int16_t field_id;
        u_int16_t field_len;
        u_int32_t enterprise_number;
    } NetFlowIPFIXField;

    /* Bitmask */
    typedef struct bitmask_selector{
        u_int32_t num_bits;
        void *bits_memory;
    } BitmaskSelector;

    #define NETFLOW_MIN_HEADER_LEN sizeof(NetFlowHeader)
    #define NETFLOW_V1_HEADER_LEN sizeof(NetFlowV1Header)
    #define NETFLOW_V1_RECORD_LEN sizeof(NetFlowV1Record)
    #define NETFLOW_V5_HEADER_LEN sizeof(NetFlowV5Header)
    #define NETFLOW_V5_RECORD_LEN sizeof(NetFlowV5Record)
    #define NETFLOW_V7_HEADER_LEN sizeof(NetFlowV7Header)
    #define NETFLOW_V7_RECORD_LEN sizeof(NetFlowV7Record)

/* ******************************************* */
 #pragma pack(pop)

    /**
     * @class NetFlowLayer
     * A base class for all NetFlow protocol classes. This is an abstract class and cannot be instantiated,
     * only its child classes can be instantiated. The inherited classes represent the different versions of the protocol:
     * NetFlow v1/v5/v7/v9
     */
    class NetFlowLayer : public Layer
    {
    private:
        uint8_t* addRecordAt(int offset);
    protected:
        NetFlowLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType NetFlowVer)
        : Layer(data, dataLen, prevLayer, packet) { m_Protocol = NetFlowVer; }

        NetFlowLayer(ProtocolType NetFlowVer);

        static size_t getHeaderSizeByVersion(ProtocolType NetFlowVer);
        static size_t getRecordSizeByVersion(ProtocolType NetFlowVer);
    public:

        virtual ~NetFlowLayer() {};

        /**
         * Get a pointer to the raw NetFlow v1/v5/v7/v9/IPFIX header. Notice this points directly to the data, so every change will change the actual packet data
         * @return A pointer to the @ref NetFlowHeader
         */
        NetFlowHeader* getNetFlowHeader() const { return (NetFlowHeader*)m_Data; }

        /**
         * Set a pointer to the raw NetFlow v1/v5/v7/v9 header. Notice this points directly to the data, so every change will change the actual packet data
         * @return A pointer to the @ref netflow_header
         */
        NetFlowHeader* setNetFlowHeader(NetFlowHeader* header);

        /**
		 * A static method that checks whether the port is considered as NetFlow(default)
		 * @param[in] port The port number to be checked
		 */
        static bool isDefaultNetFlowPort(uint16_t port) { return (port == 9996); }

        /**
         * A static method that gets raw NetFlow data (byte stream) and returns the NetFlow version of this NetFlow message
         * @param[in] data The NetFlow raw data (byte stream)
         * @param[in] dataLen Raw data length
         * @param[in] packet A pointer to the Packet instance where layer will be stored in
         * @return One of the values NetFlow v1/v5/v7/v9 according to detected NetFlow version or ::UnknownProtocol if couldn't detect
         * NetFlow version
         */
        static NetFlowLayer* parseNetFlowLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

        /**
         * A static method that checks raw NetFlow data (byte stream) and returns validation of this NetFlow message
         * @param[in] data The NetFlow raw data (byte stream)
         * @param[in] dataLen Raw data length
         * @return True if valid, otherwise false
         */
        static bool isNetFlowLayerValid(uint8_t* data, size_t dataLen, Packet* packet);

        // implement abstract methods
        /**
	    * @return The number of records or length in this message (as extracted from the netflow_header#countOrLen field)
	    */
        uint16_t getRecordCountOrLength() const;

        /**
         * @return A pointer to the first record or NULL if no records exist. Notice the return value is a pointer to the real data,
         * so changes in the return value will affect the packet data
         */
        uint8_t* getFirstRecord() const;

        /**
         * Get the record that comes next to a given record. If "record" is NULL then NULL will be returned.
         * If "record" is the last record or if it is out of layer bounds NULL will be returned also. Notice the return value is a
         * pointer to the real data casted to record type (as opposed to a copy of the option data). So changes in the return
         * value will affect the packet data
         * @param[in] record The record to start searching from
         * @return The next record or NULL if "record" is NULL, last or out of layer bounds
         */
        uint8_t* getNextRecord(uint8_t* record) const;

        /**
         * Add a new record at a the end of the record list. The netflow_header#countorLen field will be
         * incremented accordingly
         * @return The method constructs a new record, adds it to the end of the record list of NetFlow message and
         * returns a pointer to the new message. If something went wrong in creating or adding the ne record a NULL value is returned
         * and an appropriate error message is printed to log
         */
        uint8_t* addRecord();

        /**
         * Add a new record at a certain index of th record list. The netflow_header#countorLen field will be
         * incremented accordingly
         * @param[in] index The index to add the new address at
         * @return The method constructs a new record, adds it to the NetFlow message and returns a pointer to the new message.
         * If something went wrong in creating or adding the new record a NULL value is returned and an appropriate error message is
         * printed to log
         */
        uint8_t* addRecordAtIndex(int index);

        /**
         * Remove a record at a certain index. The netflow_header#numOfRecords field will be decremented accordingly
         * @param[in] index The index of the record to be removed
         * @return True if record was removed successfully or false otherwise. If false is returned an appropriate error message
         * will be printed to log
         */
        bool removeRecordAtIndex(int index);

        /**
         * Remove all records in the message. The netflow_header#numOfRecords field will be set to 0
         * @return True if all records were cleared successfully or false otherwise. If false is returned an appropriate error message
         * will be printed to log
         */
        bool removeAllRecords();

        // implement abstract methods
        /**
         * Does nothing for this layer (NetFlow layer is always last)
         */
        void parseNextLayer() {}

        /**
	    * @return The message size in bytes which include the size of the basic header + the size of the record list
	    */
        size_t getHeaderLen() const override { return sizeof(NetFlowHeader); }

        std::string toString() const;

        void computeCalculateFields() {};

        OsiModelLayer getOsiModelLayer() const { return OsiModelApplicationLayer; }
    };

    /**
     * @class NetFlowV1Layer
     * Represents NetFlow v1 layer. This class represents all the different messages of NetFlow v1
     */
    class NetFlowV1Layer : public NetFlowLayer
    {
    public:
        /** A constructor that creates the layer from an existing packet raw data
        * @param[in] data A pointer to the raw data
        * @param[in] dataLen Size of the data in bytes
        * @param[in] prevLayer A pointer to the previous layer
        * @param[in] packet A pointer to the Packet instance where layer will be stored in
        */
        NetFlowV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
                : NetFlowLayer(data, dataLen, prevLayer, packet, NetFlow_v1) {}
        /**
        * A constructor that allocates a new NetFlow packet with 0 record
        */
        NetFlowV1Layer() : NetFlowLayer(NetFlow_v1) {}

        /**
         * A destructor for this layer (does nothing)
         */
        ~NetFlowV1Layer() {}

        // implement abstract methods

        /**
         * Get a pointer to the raw NetFlow v1 header. Notice this points directly to the data, so every change will change the actual packet data
         * @return A pointer to the @ref netflow_header
         */
        NetFlowV1Header* getNetFlowV1Header() const { return (NetFlowV1Header*)m_Data; }

        /**
         * Set a pointer to the raw NetFlow v1 header. Notice this points directly to the data, so every change will change the actual packet data
         * @return A pointer to the @ref netflow_header
         */
        void setNetFlowV1Header(NetFlowV1Header* header) const;

        /**
         * @return NetFlow v1 record data. If the layer isn't of type NetFlow v1, NULL is returned.
         */
        NetFlowV1Record * getNetFlowV1Record();

        /**
        * Set NetFlow v1 record message data.
        * @param[in] NetFlowV1Record
        */
        void setNetFlowV1Record(NetFlowV1Record *record);

        /**
	    * @return The message size in bytes which include the size of the basic header + the size of the record list
	    */
        size_t getHeaderLen() const override { return m_DataLen; }

        void computeCalculateFields() {};
    };

    /**
     * @class NetFlowV5Layer
     * Represents NetFlow v5 layer. This class represents all the different messages of NetFlow v5
     */
    class NetFlowV5Layer : public NetFlowLayer
    {
    public:
         /** A constructor that creates the layer from an existing packet raw data
         * @param[in] data A pointer to the raw data
         * @param[in] dataLen Size of the data in bytes
         * @param[in] prevLayer A pointer to the previous layer
         * @param[in] packet A pointer to the Packet instance where layer will be stored in
         */
         NetFlowV5Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
            : NetFlowLayer(data, dataLen, prevLayer, packet, NetFlow_v5) {}

        /**
         * A destructor for this layer (does nothing)
         */
        ~NetFlowV5Layer() {}

        /**
         * Get a pointer to the raw NetFlow v5 header. Notice this points directly to the data, so every change will change the actual packet data
         * @return A pointer to the @ref NetFlowV5Header
         */
        NetFlowV5Header* getNetFlowV5Header() const { return (NetFlowV5Header *)m_Data; }

        /**
         * Set a pointer to the raw NetFlow v5 header. Notice this points directly to the data, so every change will change the actual packet data
         */
        void setNetFlowV5Header(NetFlowV5Header* header) const;

        /**
         * @return NetFlow v5 record data. If the layer isn't of type NetFlow v5, NULL is returned.
         */
        NetFlowV5Record * getNetFlowV5Record();

        /**
        * Set NetFlow v5 record message data.
        * @param[in] record
        */
        void setNetFlowV5Record(NetFlowV5Record *record);

        /**
	    * @return The message size in bytes which include the size of the basic header + the size of the record list
	    */
        size_t getHeaderLen() const override { return m_DataLen; }

        /**
	    * Does nothing for this layer (NetFlow layer is always last)
	    */
        void parseNextLayer() {}

        void computeCalculateFields() {};
    };
}

#endif // PACKETPP_NetFlow_LAYER
