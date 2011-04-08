#ifndef _PACKET_ISI_H
#define _PACKET_ISI_H

/* Wireshark ID of the protocol */
extern int proto_isi;

/* Subtree variables */
extern guint32 ett_isi_msg;
extern guint32 ett_isi_network_gsm_band_info;
extern guint32 ett_isi_info;

void dissect_isi_common(const char *resource, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif
