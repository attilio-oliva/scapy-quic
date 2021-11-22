from scapy.all import *
from scapy.layers.tls.extensions import TLS_Ext_Unknown

_quic_transport_params = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
    # extensions
    0x0020: "max_datagram_frame_size",
    0x0C37: "quantum_readiness",
}

#@dataclass
#class QuicPreferredAddress:
#    ipv4_address: Optional[Tuple[str, int]]
#    ipv6_address: Optional[Tuple[str, int]]
#    connection_id: bytes
#    stateless_reset_token: bytes
    
class QUIC_Transport_Param(Packet):
     fields_desc = [ByteEnumField("type", 0x00, _quic_transport_params),
                    FieldLenField("len", None, length_of="value", fmt="B"),
                    StrLenField("value",None,length_from=lambda pkt: pkt.len)
     ]



class QUIC_Ext_Transport(TLS_Ext_Unknown):
    name = "TLS Extension - QUIC transport parameters (for ClientHello)"
    fields_desc = [ShortField("type", 0x39),
                   FieldLenField("len", None, length_of="parameters"),
                   PacketListField("parameters", [],
                                  QUIC_Transport_Param,
                                  length_from=lambda pkt: pkt.len)]
    @classmethod
    def initial(cls, scid):
        list = [QUIC_Transport_Param(type=0x01,value=b'\x80\x00\x75\x30'), #max_idle_timeout
                QUIC_Transport_Param(type=0x04,value=b'\x45\xAC'), #max_payload
                QUIC_Transport_Param(type=0x0f,value=scid), #initial_source_conn_id
                ]
        ext = QUIC_Ext_Transport()
        
        ext.parameters = list
        ext.len = sum(len(bytes(param)) for param in ext.parameters)
        
        return ext

