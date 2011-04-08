/* isi-network.c
 * Dissector for ISI's network resource
 * Copyright 2010, Sebastian Reichel <sre@ring0.de>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/prefs.h>
#include <epan/packet.h>

#include "packet-isi.h"
#include "isi-network.h"

static const value_string isi_network_id[] = {
	{0x00, "NET_MODEM_REG_STATUS_GET_REQ"},
	{0x01, "NET_MODEM_REG_STATUS_GET_RESP"},
	{0x02, "NET_MODEM_REG_STATUS_IND"},
	{0x03, "NET_MODEM_AVAILABLE_GET_REQ"},
	{0x04, "NET_MODEM_AVAILABLE_GET_RESP"},
	{0x05, "NET_AVAILABLE_CANCEL_REQ"},
	{0x06, "NET_AVAILABLE_CANCEL_RESP"},
	{0x07, "NET_SET_REQ"},
	{0x08, "NET_SET_RESP"},
	{0x09, "NET_SET_CANCEL_REQ"},
	{0x0A, "NET_SET_CANCEL_RESP"},
	{0x0B, "NET_RSSI_GET_REQ"},
	{0x0C, "NET_RSSI_GET_RESP"},
	{0x0D, "NET_CS_CONTROL_REQ"},
	{0x0E, "NET_CS_CONTROL_RESP"},
	{0x0F, "NET_CS_WAKEUP_REQ"},
	{0x10, "NET_CS_WAKEUP_RESP"},
	{0x11, "NET_TEST_CARRIER_REQ"},
	{0x12, "NET_TEST_CARRIER_RESP"},
	{0x19, "NET_CS_STATE_IND"},
	{0x1A, "NET_NEIGHBOUR_CELLS_REQ"},
	{0x1B, "NET_NEIGHBOUR_CELLS_RESP"},
	{0x1C, "NET_NETWORK_SELECT_MODE_SET_REQ"},
	{0x1D, "SIZE_NET_NETWORK_SELECT_MODE_SET_RESP"},
	{0x1E, "NET_RSSI_IND"},
	{0x20, "NET_CIPHERING_IND"},
	{0x27, "NET_TIME_IND"},
	{0x28, "NET_OLD_OPER_NAME_READ_REQ"},
	{0x29, "NET_OLD_OPER_NAME_READ_RESP"},
	{0x2C, "NET_CHANNEL_INFO_IND"},
	{0x2D, "NET_CHANNEL_INFO_REQ"},
	{0x2E, "NET_CHANNEL_INFO_RESP"},
	{0x31, "NET_GSM_LCS_LOCATION_IND"},
	{0x32, "NET_SIM_REFRESH_REQ"},
	{0x33, "NET_SIM_REFRESH_RESP"},
	{0x34, "NET_GSM_LCS_ASTNC_NTF"},
	{0x35, "NET_RAT_IND"},
	{0x36, "NET_RAT_REQ"},
	{0x37, "NET_RAT_RESP"},
	{0x38, "NET_AGPS_FRAME_TRIGGER_REQ"},
	{0x39, "NET_AGPS_FRAME_TRIGGER_RESP"},
	{0x3A, "NET_CS_STATE_REQ"},
	{0x3B, "NET_CS_STATE_RESP"},
	{0x3C, "NET_UMA_INFO_IND"},
	{0x3D, "NET_RRLP_SUPL_HANDLE_REQ"},
	{0x3E, "NET_RRLP_SUPL_HANDLE_RESP"},
	{0x3F, "NET_RADIO_INFO_IND"},
	{0x40, "NET_CELL_INFO_GET_REQ"},
	{0x41, "NET_CELL_INFO_GET_RESP"},
	{0x42, "NET_CELL_INFO_IND"},
	{0x43, "NET_NITZ_NAME_IND"},
	{0xE0, "NET_REG_STATUS_GET_REQ"},
	{0xE1, "NET_REG_STATUS_GET_RESP"},
	{0xE2, "NET_REG_STATUS_IND"},
	{0xE3, "NET_AVAILABLE_GET_REQ"},
	{0xE4, "NET_AVAILABLE_GET_RESP"},
	{0xE5, "NET_OPER_NAME_READ_REQ"},
	{0xE6, "NET_OPER_NAME_READ_RESP"},
	{0xF0, "NET_COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_network_status_sub_id[] = {
	{0x00, "NET_REG_INFO_COMMON"},
	{0x02, "NET_OPERATOR_INFO_COMMON"},
	{0x04, "NET_RSSI_CURRENT"},
	{0x09, "NET_GSM_REG_INFO"},
	{0x0B, "NET_DETAILED_NETWORK_INFO"},
	{0x0C, "NET_GSM_OPERATOR_INFO"},
	{0x11, "NET_GSM_BAND_INFO"},
	{0x2C, "NET_RAT_INFO"},
	{0xE1, "NET_AVAIL_NETWORK_INFO_COMMON"},
	{0xE7, "NET_OPER_NAME_INFO"},
	{0x00, NULL}
};

static const value_string isi_network_cell_info_sub_id[] = {
	{0x46, "NET_GSM_CELL_INFO"},
	{0x47, "NET_WCDMA_CELL_INFO"},
	{0x50, "NET_EPS_CELL_INFO"},
	{0x00, NULL}
};

static dissector_handle_t isi_network_handle;
static void dissect_isi_network(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_network_cmd = -1;
static guint32 hf_isi_network_data_sub_pkgs = -1;
static guint32 hf_isi_network_status_sub_type = -1;
static guint32 hf_isi_network_status_sub_len = -1;
static guint32 hf_isi_network_status_sub_lac = -1;
static guint32 hf_isi_network_status_sub_cid = -1;
static guint32 hf_isi_network_status_sub_msg = -1;
static guint32 hf_isi_network_status_sub_msg_len = -1;
static guint32 hf_isi_network_cell_info_sub_type = -1;
static guint32 hf_isi_network_cell_info_sub_len  = -1;
static guint32 hf_isi_network_cell_info_sub_operator = -1;
static guint32 hf_isi_network_gsm_band_900 = -1;
static guint32 hf_isi_network_gsm_band_1800 = -1;
static guint32 hf_isi_network_gsm_band_1900 = -1;
static guint32 hf_isi_network_gsm_band_850 = -1;

static const int *gsm_band_fields[] = {
	&hf_isi_network_gsm_band_900,
	&hf_isi_network_gsm_band_1800,
	&hf_isi_network_gsm_band_1900,
	&hf_isi_network_gsm_band_850,
	NULL
};

void proto_reg_handoff_isi_network(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_network_handle = create_dissector_handle(dissect_isi_network, proto_isi);
		dissector_add("isi.resource", 0x0a, isi_network_handle);
	}
}

void proto_register_isi_network(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_network_cmd,
		  { "Command", "isi.network.cmd", FT_UINT8, BASE_HEX, isi_network_id, 0x0, "Command", HFILL }},
		{ &hf_isi_network_data_sub_pkgs,
		  { "Number of Subpackets", "isi.network.pkgs", FT_UINT8, BASE_DEC, NULL, 0x0, "Number of Subpackets", HFILL }},
		{ &hf_isi_network_status_sub_type,
		  { "Subpacket Type", "isi.network.sub.type", FT_UINT8, BASE_HEX, isi_network_status_sub_id, 0x0, "Subpacket Type", HFILL }},
		{ &hf_isi_network_status_sub_len,
		  { "Subpacket Length", "isi.network.sub.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Subpacket Length", HFILL }},
		{ &hf_isi_network_status_sub_lac,
		  { "Location Area Code (LAC)", "isi.network.sub.lac", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Location Area Code (LAC)", HFILL }},
		{ &hf_isi_network_status_sub_cid,
		  { "Cell ID (CID)", "isi.network.sub.cid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Cell ID (CID)", HFILL }},
		{ &hf_isi_network_status_sub_msg_len,
		  { "Message Length", "isi.network.sub.msg", FT_UINT16, BASE_DEC, NULL, 0x0, "Message Length", HFILL }},
		{ &hf_isi_network_status_sub_msg,
		  { "Message", "isi.network.sub.msg", FT_STRING, BASE_NONE, NULL, 0x0, "Message", HFILL }},
		{ &hf_isi_network_cell_info_sub_type,
		  { "Subpacket Type", "isi.network.sub.type", FT_UINT8, BASE_HEX, isi_network_cell_info_sub_id, 0x0, "Subpacket Type", HFILL }},
		{ &hf_isi_network_cell_info_sub_len,
		  { "Subpacket Length", "isi.network.sub.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Subpacket Length", HFILL }},
		{ &hf_isi_network_cell_info_sub_operator,
		  { "Operator Code", "isi.network.sub.operator", FT_UINT24, BASE_HEX, NULL, 0x0, "Operator Code", HFILL }},
		{ &hf_isi_network_gsm_band_900,
		  { "900 Mhz Band", "isi.network.sub.gsm_band_900", FT_BOOLEAN, 32, NULL, 0x00000001, "", HFILL }},
		{ &hf_isi_network_gsm_band_1800,
		  { "1800 Mhz Band", "isi.network.sub.gsm_band_1800", FT_BOOLEAN, 32, NULL, 0x00000002, "", HFILL }},
		{ &hf_isi_network_gsm_band_1900,
		  { "1900 Mhz Band", "isi.network.sub.gsm_band_1900", FT_BOOLEAN, 32, NULL, 0x00000004, "", HFILL }},
		{ &hf_isi_network_gsm_band_850,
		  { "850 Mhz Band", "isi.network.sub.gsm_band_850", FT_BOOLEAN, 32, NULL, 0x00000008, "", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.network", dissect_isi_network, proto_isi);
}

/* would be nice if wireshark could handle unicode... */
static void* utf16_to_ascii(char *in, guint16 len) {
	char *out = malloc(len+1);

	int i;
	for(i=0; i<len; i++) {
		out[i] = in[(i*2)+1];
	}

	out[len] = 0x00;

	return out;
}

static void dissect_isi_network_status(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	guint8 len = tvb->length;
	int i;

	guint8 pkgcount = tvb_get_guint8(tvb, 0x02);
	proto_tree_add_item(tree, hf_isi_network_data_sub_pkgs, tvb, 0x02, 1, FALSE);

	size_t offset = 0x03; // subpackets start here
	for(i=0; i<pkgcount; i++) {
		guint8 sptype = tvb_get_guint8(tvb, offset+0);
		guint8 splen = tvb_get_guint8(tvb, offset+1);

		proto_item *subitem = proto_tree_add_text(tree, tvb, offset, splen, "Subpacket (%s)", val_to_str(sptype, isi_network_status_sub_id, "unknown: 0x%x"));
		proto_tree *subtree = proto_item_add_subtree(subitem, ett_isi_msg);

		proto_tree_add_item(subtree, hf_isi_network_status_sub_type, tvb, offset+0, 1, FALSE);
		proto_tree_add_item(subtree, hf_isi_network_status_sub_len, tvb,  offset+1, 1, FALSE);

		offset += 2;

		switch(sptype) {
			case 0x00: // NET_REG_INFO_COMMON
				/* FIXME: TODO */
				break;
			case 0x09: // NET_GSM_REG_INFO
				proto_tree_add_item(subtree, hf_isi_network_status_sub_lac, tvb, offset+0, 2, FALSE);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_cid, tvb, offset+4, 4, FALSE);
				/* FIXME: TODO */
				break;
			case 0xe3: ; // UNKNOWN
				/* FIXME: TODO: byte 0: message type (provider name / network name) ? */

				guint16 strlen = tvb_get_ntohs(tvb, offset+2);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_msg_len, tvb, offset+2, 2, FALSE);

				char *utf16 = tvb_memdup(tvb, offset+4, strlen*2);
				char *ascii = utf16_to_ascii(utf16, strlen);
				proto_item *subitem = proto_tree_add_string(subtree, hf_isi_network_status_sub_msg, tvb, offset+4, strlen*2, ascii);
				break;
			default:
				break;
		}

		offset += splen - 2;
	}
}

static void dissect_isi_network_cell_info_ind(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	guint8 len = tvb->length;
	int i;

	guint8 pkgcount = tvb_get_guint8(tvb, 0x02);
	proto_tree_add_item(tree, hf_isi_network_data_sub_pkgs, tvb, 0x02, 1, FALSE);

	size_t offset = 0x03;

	for(i=0; i<pkgcount; i++) {
		guint8 sptype = tvb_get_guint8(tvb, offset+0);
		guint8 splen = tvb_get_guint8(tvb, offset+1);

		proto_item *subitem = proto_tree_add_text(tree, tvb, offset, splen, "Subpacket (%s)", val_to_str(sptype, isi_network_cell_info_sub_id, "unknown: 0x%x"));
		proto_tree *subtree = proto_item_add_subtree(subitem, ett_isi_msg);

		proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_type, tvb, offset+0, 1, FALSE);
		proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_len, tvb,  offset+1, 1, FALSE);

		offset += 2;

		switch(sptype) {
			case 0x50: // NET_EPS_CELL_INFO
				/* TODO: not yet implemented */
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x46: // NET_GSM_CELL_INFO
				proto_tree_add_item(subtree, hf_isi_network_status_sub_lac, tvb, offset+0, 2, FALSE);
				proto_tree_add_item(subtree, hf_isi_network_status_sub_cid, tvb, offset+2, 4, FALSE);
				proto_tree_add_bitmask_text(subtree, tvb, offset+6, 4, "GSM Bands: ", "all bands, since none is selected", ett_isi_network_gsm_band_info, gsm_band_fields, FALSE, BMT_NO_FALSE | BMT_NO_TFS);
				proto_tree_add_item(subtree, hf_isi_network_cell_info_sub_operator, tvb, offset+10, 3, FALSE);
				/* TODO: analysis of the following 5 bytes (which were 0x00 in my dumps) */
				break;
			case 0x47: // NET_WCDMA_CELL_INFO
				/* TODO: not yet implemented */
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			default:
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}

		offset += splen - 2;
	}
}

static void dissect_isi_network(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_network_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch(cmd) {
			case 0x07:
				col_set_str(pinfo->cinfo, COL_INFO, "Network Selection Request");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x20:
				col_set_str(pinfo->cinfo, COL_INFO, "Network Ciphering Indication");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0xE2:
				col_set_str(pinfo->cinfo, COL_INFO, "Network Status Indication");
				dissect_isi_network_status(tvb, pinfo, item, tree);
				break;
			case 0x42:
				col_set_str(pinfo->cinfo, COL_INFO, "Network Cell Info Indication");
				dissect_isi_network_cell_info_ind(tvb, pinfo, item, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Network packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}
