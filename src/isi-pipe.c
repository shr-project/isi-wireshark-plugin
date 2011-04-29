
/* isi-pipe.c
 * Dissector for ISI's pipe resource
 * Copyright 2011, Klaus Kurzmann <mok@fluxnetz.de>
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
#include "isi-pipe.h"

static const value_string isi_pipe_id[] = {
	{0x66, "PNS_PIPE_DISABLED_IND"},
	{0x00, "PNS_PIPE_CREATE_REQ"},
	{0x01, "PNS_PIPE_CREATE_RESP"},
	{0x61, "PNS_PIPE_CREATED_IND"},
	{0x40, "PNS_PEP_CONNECT_REQ"},
	{0x41, "PNS_PEP_CONNECT_RESP"},
	{0x48, "PNS_PEP_CTRL_REQ"},
	{0x49, "PNS_PEP_CTRL_RESP"},
	{0x06, "PNS_PIPE_ENABLE_REQ"},
	{0x07, "PNS_PIPE_ENABLE_RESP"},
	{0x64, "PNS_PIPE_ENABLED_IND"},
	{0x46, "PNS_PEP_ENABLE_REQ"},
	{0x47, "PNS_PEP_ENABLE_RESP"},
	{0x20, "PNS_PIPE_DATA"},
	{0x62, "PNS_PIPE_REMOVED_IND"},
	{0x4A, "PNS_PEP_STATUS_IND_REQ"},
	{0x4B, "PNS_PEP_STATUS_IND_RESP"},
	{0x60, "PNS_PEP_STATUS_IND"},
	{0x04, "PNS_PIPE_RESET_REQ"},
	{0x05, "PNS_PIPE_RESET_RESP"},
	{0x63, "PNS_PIPE_RESET_IND"},
	{0x44, "PNS_PEP_RESET_REQ"},
	{0x45, "PNS_PEP_RESET_RESP"},
	{0x02, "PNS_PIPE_REMOVE_REQ"},
	{0x03, "PNS_PIPE_REMOVE_RESP"},
	{0x42, "PNS_PEP_DISCONNECT_REQ"},
	{0x43, "PNS_PEP_DISCONNECT_RESP"},
	{0x08, "PNS_PIPE_REDIRECT_REQ"},
	{0x09, "PNS_PIPE_REDIRECT_RESP"},
	{0x65, "PNS_PIPE_REDIRECTED_IND"},
	{0x4C, "PNS_PEP_DISABLE_REQ"},
	{0x4D, "PNS_PEP_DISABLE_RESP"},
	{0x00, NULL}
};

static const value_string isi_pipe_subblock_id[] = {
	{0x00, "PN_PIPE_SB_CREATE_REQ_PEP_SUB_TYPE"},
	{0x01, "PN_PIPE_SB_CONNECT_REQ_PEP_SUB_TYPE"},
	{0x02, "PN_PIPE_SB_REDIRECT_REQ_PEP_SUB_TYPE"},
	{0x03, "PN_PIPE_SB_NEGOTIATED_FC"},
	{0x04, "PN_PIPE_SB_REQUIRED_FC_TX"},
	{0x05, "PN_PIPE_SB_PREFERRED_FC_RX"},
	{0x00, NULL}
};

static const value_string isi_pipe_pipe_state_after[] = {
	{0x00, "PN_PIPE_DISABLE"},
	{0x01, "PN_PIPE_ENABLE"},
	{0x00, NULL}
};

static const value_string isi_pipe_pep_state_after[] = {
	{0x00, "PN_PEP_DISABLE"},
	{0x01, "PN_PEP_ENABLE"},
	{0x00, NULL}
};

static const value_string isi_pipe_priority[] = {
	{0x01, "PN_MSG_PRIORITY_LOW"},
	{0x02, "PN_MSG_PRIORITY_HIGH"},
	{0x00, NULL}
};

static const value_string isi_pipe_pep_type[] = {
	{0x00, "PN_PEP_TYPE_COMMON"},
	{0x01, "PN_PEP_TYPE_COMM"},
	{0x02, "PN_PEP_TYPE_SOCKET_BEARER"},
	{0x03, "PN_PEP_TYPE_DCS"},
	{0x04, "PN_PEP_TYPE_GPRS"},
	{0x05, "PN_PEP_TYPE_OBEX"},
	{0x06, "PN_PEP_TYPE_PRINT"},
	{0x07, "PN_PEP_TYPE_TCH"},
	{0x08, "PN_PEP_TYPE_GAMES"},
	{0x09, "PN_PEP_TYPE_DATA_BEARER"},
	{0x0B, "PN_PEP_TYPE_TCPIP"},
	{0x0C, "PN_PEP_TYPE_RAN_SYNC"},
	{0x0D, "PN_PEP_TYPE_BT_ACC"},
	{0x0E, "PN_PEP_TYPE_TLP"},
	{0x10, "PN_PEP_TYPE_SAP"},
	{0x11, "PN_PEP_TYPE_COMMON_ONE_CREDIT"},
	{0x12, "PN_PEP_TYPE_BT_HFP_HF"},
	{0x13, "PN_PEP_TYPE_LCIF"},
	{0x14, "PN_PEP_TYPE_FLUSH"},
	{0x15, "PN_PEP_TYPE_ETHERNET"},
	{0x00, NULL}
};

static const value_string isi_pipe_error[] = {
	{0x00, "PN_PIPE_NO_ERROR"},
	{0x01, "PN_PIPE_ERR_INVALID_PARAM"},
	{0x02, "PN_PIPE_ERR_INVALID_HANDLE"},
	{0x03, "PN_PIPE_ERR_INVALID_CTRL_ID"},
	{0x04, "PN_PIPE_ERR_NOT_ALLOWED"},
	{0x05, "PN_PIPE_ERR_PEP_IN_USE"},
	{0x06, "PN_PIPE_ERR_OVERLOAD"},
	{0x07, "PN_PIPE_ERR_DEV_DISCONNECTED"},
	{0x08, "PN_PIPE_ERR_TIMEOUT"},
	{0x09, "PN_PIPE_ERR_ALL_PIPES_IN_USE"},
	{0x0A, "PN_PIPE_ERR_GENERAL"},
	{0x0B, "PN_PIPE_ERR_NOT_SUPPORTED"},
	{0x00, NULL}
};



static dissector_handle_t isi_pipe_handle;
static void dissect_isi_pipe(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_pipe_cmd = -1;
static guint32 hf_isi_pipe_subblock_type = -1;
static guint32 hf_isi_pipe_pipe_state_after = -1;
static guint32 hf_isi_pipe_pep_state_after = -1;
static guint32 hf_isi_pipe_priority = -1;
static guint32 hf_isi_pipe_first_pep_dev = -1;
static guint32 hf_isi_pipe_first_pep_obj = -1;
static guint32 hf_isi_pipe_first_pep_type = -1;
static guint32 hf_isi_pipe_second_pep_dev = -1;
static guint32 hf_isi_pipe_second_pep_obj = -1;
static guint32 hf_isi_pipe_second_pep_type = -1;
static guint32 hf_isi_pipe_handle = -1;
static guint32 hf_isi_pipe_error = -1;
static guint32 hf_isi_pipe_pep1_error = -1;
static guint32 hf_isi_pipe_pep2_error = -1;
static guint32 hf_isi_pipe_other_pep_type = -1;
static guint32 hf_isi_pipe_pep_type = -1;
static guint32 hf_isi_pipe_indication_id = -1;

void proto_reg_handoff_isi_pipe(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_pipe_handle = create_dissector_handle(dissect_isi_pipe, proto_isi);
		dissector_add("isi.resource", 0xd9, isi_pipe_handle);
	}
}

void proto_register_isi_pipe(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_pipe_cmd,
			{ "Command", "isi.pipe.cmd", FT_UINT8, BASE_HEX, isi_pipe_id, 0x0, "Command", HFILL }},
		{ &hf_isi_pipe_subblock_type,
			{ "Subblock-Id", "isi.pipe.subblock_id", FT_UINT8, BASE_HEX, isi_pipe_subblock_id, 0x0, "Subblock-Id", HFILL }},
		{ &hf_isi_pipe_pipe_state_after,
			{ "Pipe State After Creation", "isi.pipe.state_after", FT_UINT8, BASE_HEX, isi_pipe_pipe_state_after, 0x0, "Pipe State After Creation", HFILL }},
		{ &hf_isi_pipe_pep_state_after,
			{ "PEP State After Creation", "isi.pipe.pep_state_after", FT_UINT8, BASE_HEX, isi_pipe_pep_state_after, 0x0, "PEP State After Creation", HFILL }},
		{ &hf_isi_pipe_priority,
			{ "Priority", "isi.pipe.priority", FT_UINT8, BASE_HEX, isi_pipe_priority, 0x0, "Priority", HFILL }},
		{ &hf_isi_pipe_first_pep_dev,
			{ "First PEP Device", "isi.pipe.first_pep_dev", FT_UINT8, BASE_HEX, NULL, 0x0, "First PEP Device", HFILL }},
		{ &hf_isi_pipe_first_pep_obj,
			{ "First PEP Object", "isi.pipe.first_pep_obj", FT_UINT8, BASE_HEX, NULL, 0x0, "Frist PEP Object", HFILL }},
		{ &hf_isi_pipe_first_pep_type,
			{ "First PEP Type", "isi.pipe.first_pep_type", FT_UINT8, BASE_HEX, isi_pipe_pep_type, 0x0, "First PEP Type", HFILL }},
		{ &hf_isi_pipe_second_pep_dev,
			{ "Second PEP Device", "isi.pipe.first_pep_dev", FT_UINT8, BASE_HEX, NULL, 0x0, "Second PEP Device", HFILL }},
		{ &hf_isi_pipe_second_pep_obj,
			{ "Second PEP Object", "isi.pipe.first_pep_obj", FT_UINT8, BASE_HEX, NULL, 0x0, "Second PEP Object", HFILL }},
		{ &hf_isi_pipe_second_pep_type,
			{ "Second PEP Type", "isi.pipe.first_pep_type", FT_UINT8, BASE_HEX, isi_pipe_pep_type, 0x0, "Second PEP Type", HFILL }},
		{ &hf_isi_pipe_handle,
			{ "Pipe Handle", "isi.pipe.handle", FT_UINT8, BASE_HEX, NULL, 0x0, "Pipe Handle", HFILL }},
		{ &hf_isi_pipe_error,
			{ "Error Code", "isi.pipe.error", FT_UINT8, BASE_HEX, isi_pipe_error, 0x0, "Error Code", HFILL }},
		{ &hf_isi_pipe_pep1_error,
			{ "PEP 1 Error", "isi.pipe.pep1_error", FT_UINT8, BASE_HEX, isi_pipe_error, 0x0, "PEP 1 Error", HFILL }},
		{ &hf_isi_pipe_pep2_error,
			{ "PEP 2 Error", "isi.pipe.pep2_error", FT_UINT8, BASE_HEX, isi_pipe_error, 0x0, "PEP 2 Error", HFILL }},
		{ &hf_isi_pipe_other_pep_type,
			{ "Other PEP Type", "isi.pipe.other_pep_type", FT_UINT8, BASE_HEX, isi_pipe_pep_type, 0x0, "Other PEP Type", HFILL }},
		{ &hf_isi_pipe_pep_type,
			{ "PEP Type", "isi.pipe.pep_type", FT_UINT8, BASE_HEX, isi_pipe_pep_type, 0x0, "PEP Type", HFILL }},
		{ &hf_isi_pipe_indication_id,
			{ "Indication ID", "isi.pipe.indication_id", FT_UINT8, BASE_HEX, NULL, 0x0, "Indication ID", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.pipe", dissect_isi_pipe, proto_isi);
}


static void dissect_isi_pipe_subblock(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x00: /* PN_PIPE_SB_CREATE_REQ_PEP_SUB_TYPE */
		case 0x01: /* PN_PIPE_SB_CONNECT_REQ_PEP_SUB_TYPE */
		case 0x02: /* PN_PIPE_SB_REDIRECT_REQ_PEP_SUB_TYPE */
		case 0x03: /* PN_PIPE_SB_NEGOTIATED_FC */
		case 0x04: /* PN_PIPE_SB_REQUIRED_FC_TX */
		case 0x05: /* PN_PIPE_SB_PREFERRED_FC_RX */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock");
			break;
	}
}

static void dissect_isi_pipe(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_pipe_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x00: /* PNS_PIPE_CREATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Create Request");
				proto_tree_add_item(tree, hf_isi_pipe_pipe_state_after, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_priority, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_first_pep_dev, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_first_pep_obj, tvb, 4, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_first_pep_type, tvb, 5, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_second_pep_dev, tvb, 7, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_second_pep_obj, tvb, 8, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_second_pep_type, tvb, 9, 1, FALSE);
				dissect_isi_subpacket(hf_isi_pipe_subblock_type, 11, tvb, pinfo, item, tree, dissect_isi_pipe_subblock);
                                break;
			case 0x01: /* PNS_PIPE_CREATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Create Response");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_error, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep1_error, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep2_error, tvb, 4, 1, FALSE);
				break;
			case 0x06: /* PNS_PIPE_ENABLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Enable Request");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				break;
			case 0x07: /* PNS_PIPE_ENABLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Enable Response");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_error, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep1_error, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep2_error, tvb, 4, 1, FALSE);
				break;
			case 0x20: /* PNS_PIPE_DATA */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Data");
				break;
			case 0x40: /* PNS_PEP_CONNECT_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "PEP Connect Request");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep_state_after, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_other_pep_type, tvb, 3, 1, FALSE);
				dissect_isi_subpacket(hf_isi_pipe_subblock_type, 7, tvb, pinfo, item, tree, dissect_isi_pipe_subblock);
				break;
			case 0x41: /* PNS_PEP_CONNECT_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "PEP Connect Response");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_error, tvb, 2, 1, FALSE);
				dissect_isi_subpacket(hf_isi_pipe_subblock_type, 7, tvb, pinfo, item, tree, dissect_isi_pipe_subblock);
				break;
			case 0x46: /* PNS_PEP_ENABLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "PEP Enable Request");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				break;
			case 0x47: /* PNS_PEP_ENABLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "PEP Enable Response");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_error, tvb, 2, 1, FALSE);
				break;
			case 0x60: /* PNS_PEP_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "PEP Status Indiciation");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_pep_type, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_pipe_indication_id, tvb, 3, 1, FALSE);
				// TODO: indication data
				break;
			case 0x61: /* PNS_PIPE_CREATED_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Created Indiciation");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_pipe_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_pipe_subblock);
				break;
			case 0x64: /* PNS_PIPE_ENABLED_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Pipe Enabled Indiciation");
				proto_tree_add_item(tree, hf_isi_pipe_handle, tvb, 1, 1, FALSE);
				break;

			case 0xF0: /* PIPE_COMMON_MESSAGE */
				dissect_isi_common("PIPE", tvb, pinfo, tree);
				break;
			case 0x66: /* PNS_PIPE_DISABLED_IND */
			case 0x48: /* PNS_PEP_CTRL_REQ */
			case 0x49: /* PNS_PEP_CTRL_RESP */
			case 0x62: /* PNS_PIPE_REMOVED_IND */
			case 0x4A: /* PNS_PEP_STATUS_IND_REQ */
			case 0x4B: /* PNS_PEP_STATUS_IND_RESP */
			case 0x04: /* PNS_PIPE_RESET_REQ */
			case 0x05: /* PNS_PIPE_RESET_RESP */
			case 0x63: /* PNS_PIPE_RESET_IND */
			case 0x44: /* PNS_PEP_RESET_REQ */
			case 0x45: /* PNS_PEP_RESET_RESP */
			case 0x02: /* PNS_PIPE_REMOVE_REQ */
			case 0x03: /* PNS_PIPE_REMOVE_RESP */
			case 0x42: /* PNS_PEP_DISCONNECT_REQ */
			case 0x43: /* PNS_PEP_DISCONNECT_RESP */
			case 0x08: /* PNS_PIPE_REDIRECT_REQ */
			case 0x09: /* PNS_PIPE_REDIRECT_RESP */
			case 0x65: /* PNS_PIPE_REDIRECTED_IND */
			case 0x4C: /* PNS_PEP_DISABLE_REQ */
			case 0x4D: /* PNS_PEP_DISABLE_RESP */
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unhandled Pipe packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}





