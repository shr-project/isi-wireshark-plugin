#ifndef _PACKET_ISI_H
#define _PACKET_ISI_H

/* Wireshark ID of the protocol */
extern int proto_isi;

/* Subtree variables */
extern guint32 ett_isi_msg;
extern guint32 ett_isi_network_gsm_band_info;
extern guint32 ett_isi_info;

extern guint32 hf_isi_res;

void dissect_isi_common(const char *resource, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_isi_subpacket(guint32 hf_sub_type, guint8 offset, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, void (*detail_cb)(guint8, tvbuff_t*, packet_info*, proto_item*, proto_tree*));

#endif
