#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_REC = 16w0x9966;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;


const ether_type_t ETHERTYPE_VQ = 16w0x4002;

    /***********************  H E A D E R S  ************************/


header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header calc_h {
    bit<8> op;
    bit<32> result;
}

header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> dest_ip;
}

struct headers {
    pktgen_timer_header_t timer;
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    calc_h       calc;
    arp_h   arp;
}


struct empty_header_t {}

struct empty_metadata_t {}

struct my_ingress_metadata_t {
    bit<32>  qID;
    bit<32>  vQueueLimit;

}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


parser SwitchIngressParser(
       packet_in packet, 
       out headers hdr, 
       out my_ingress_metadata_t md,
       out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        pktgen_timer_header_t pktgen_pd_hdr = packet.lookahead<pktgen_timer_header_t>();
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_VLAN:  parse_vlan;
            ETHERTYPE_ARP:  parse_arp;
            default: accept;
        }
    }
    
    state parse_vlan {
        packet.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP:  parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_calc;
    }

    state parse_calc {
        packet.extract(hdr.calc);
        transition accept;
    }
}


control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in my_ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                        hdr.ipv4.version,
                        hdr.ipv4.ihl,
                        hdr.ipv4.diffserv,
                        hdr.ipv4.total_len,
                        hdr.ipv4.identification,
                        hdr.ipv4.flags,
                        hdr.ipv4.ttl,
                        hdr.ipv4.protocol,
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr
                    });

        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout headers hdr, 
        inout my_ingress_metadata_t md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    

    Register <bit<32>, bit<32>> (32w1024)  vQueue;


    // action that read the queue depth, and decides if the packet can pass the queue or not
    RegisterAction<bit<32>, bit<32>, bit<1>>(vQueue) queue_action = {
        void apply(inout bit<32> value, out bit<1> readvalue){
            
            // check if the queue has limit remaining, if yes, return 1 and increase the queue size, if not, return 0
           if(value < md.vQueueLimit){
                readvalue = 1;
                value = value + 1;
            }else{
                readvalue = 0;
            }
        }
    };

    // action to update the queue lenght with the generated packets
    RegisterAction<bit<32>, bit<32>, bit<1>>(vQueue) queue_update = {
        void apply(inout bit<32> value, out bit<1> readvalue){
            
            value = 0;
            readvalue = 1;
        }
    };


    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    action send(bit<9> port, bit<32> id) {
        ig_intr_tm_md.ucast_egress_port = port;
        md.qID = id;
        
    }

    table forward {
        key = {
            hdr.ipv4.dst_addr        : exact;
        }
        actions = {
            send;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    action qLimit(bit<32> limit){
        md.vQueueLimit = limit;
    }

    table getQueueLimit {
        key = {
            md.qID        : exact;
        }
        actions = {
            qLimit;
            //@defaultonly drop;
        }
        //const default_action = drop();
        size = 1024;
    }


    apply {


        if (ig_intr_md.ingress_port == 68 ){ig_intr_tm_md.ucast_egress_port = 196;}

        // production packets, vQueues should be applied
        else if (ig_intr_md.ingress_port != 68 && ig_intr_md.ingress_port != 196){
        
            // decides output port and gets the vQueue ID
            forward.apply();
            
            //with the vQueueID, get the queue limit
            getQueueLimit.apply();

            //with the queue ID and Limit, apply the queue action to decide if the packet will be droped or not
            if(queue_action.execute(md.qID)==0){

                // drop the packet, the queue is full
                ig_intr_dprsr_md.drop_ctl = 0x1;            
            }

        }
        // generation packets, vQueues should be updated
        else{

            //update the queue depth. In this first version just turn it 0
            queue_update.execute(5);

        }

        ig_intr_tm_md.bypass_egress = 1w1;

    }
}


// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;