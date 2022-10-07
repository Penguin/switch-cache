/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IP_PROT_UDP  = 0x11; // protocol opcode for UDP
const bit<16> UDP_PORT = 1234; // "special" port that will ID packets as request/response

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header request_t { // simple header to hold just requested key
    bit<8> key;
}

header response_t { // more complex header to hold requested key, valildity, and the associated value
    bit<8> key;
    bit<8> is_valid;
    bit<32> value;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    request_t    request;
    response_t   response;
}



parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROT_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) { // determines if the packet is a request or a response
            UDP_PORT: parse_request;
            default: parse_response;
        }
    }

    state parse_request {
        packet.extract(hdr.request);
        transition accept;
    }

    state parse_response {
        packet.extract(hdr.response);
        transition accept;
    }
}



control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(256) values; // register that will act as the switch cache,
                                   // storing values from the server at their associated index

    bit<32> foundval = 0; // temporary storage value for if we get a cache hit on the register

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action retval(bit<32> value) { // sets the proper headers and data to return the packet to the client
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;

        bit<16> tmpDstPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpDstPort;
        hdr.udp.checksum = 0;
        hdr.udp.length_ = hdr.udp.length_ + 5;

        hdr.request.setInvalid();
        hdr.response.setValid();

        hdr.response.key = hdr.request.key;
        hdr.response.is_valid = 1;
        hdr.response.value = value;
    }

    action check_register() { // checks for a cache hit
        values.read(foundval, (bit<32>)hdr.request.key);
    }

    action store_in_reg() { // stores a server response value in the cache
        values.write((bit<32>)hdr.response.key, (bit<32>)hdr.response.value);
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table static_cache { // cache table for statically declared pairs
        key = {
            hdr.request.key: exact;
        }
        actions = {
            retval;
            check_register;
            NoAction;
        }
        size = 1024;
        default_action = check_register; // default action if we get a static cache miss- check the register cache
    }
    
    apply {
        if (hdr.request.isValid()) {
            static_cache.apply(); // checking for a static cache hit, by default checks for a register cache hit if we get a static cache miss

            if (foundval !=0) { // if foundval has been changed, we got a cache hit and can return that value to the client
                retval(foundval);
                foundval = 0;
            }
        }
        else if(hdr.response.isValid()) {
            store_in_reg();
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}



control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}



control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}



control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.response);
        packet.emit(hdr.request);
    }
}



V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
