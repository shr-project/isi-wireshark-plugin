/* isi-ss.c
 * Dissector for ISI's Subscriber Services resource
 * Copyright 2010, Sebastian Reichel <sre@ring0.de>
 * Copyright 2010, Tyson Key <tyson.key@gmail.com>
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
#include "isi-ss.h"

static const value_string isi_ss_message_id[] = {
	{0x00, "SS_SERVICE_REQ"},
	{0x01, "SS_SERVICE_COMPLETED_RESP"},
	{0x02, "SS_SERVICE_FAILED_RESP"},
	{0x04, "SS_GSM_USSD_SEND_REQ"},
	{0x05, "SS_GSM_USSD_SEND_RESP"},
	{0x06, "SS_GSM_USSD_RECEIVE_IND"},
	{0x09, "SS_STATUS_IND"},
	{0x10, "SS_SERVICE_COMPLETED_IND"},
	{0xF0, "SS_COMMON_MESSAGE"},
};

static const value_string isi_ss_ussd_type[] = {
	{0x01, "SS_GSM_USSD_MT_REPLY"},
	{0x02, "SS_GSM_USSD_COMMAND"},
	{0x03, "SS_GSM_USSD_REQUEST"},
	{0x04, "SS_GSM_USSD_NOTIFY"},
	{0x05, "SS_GSM_USSD_END"},
};

static const value_string isi_ss_subblock[] = {
	{0x00, "SS_FORWARDING"}, 
	{0x01, "SS_STATUS_RESULT"}, 
	{0x03, "SS_GSM_PASSWORD"},
	{0x04, "SS_GSM_FORWARDING_INFO"},
	{0x05, "SS_GSM_FORWARDING_FEATURE"}, 
	{0x08, "SS_GSM_DATA"}, 
	{0x09, "SS_GSM_BSC_INFO"}, 
	{0x0B, "SS_GSM_PASSWORD_INFO"}, 
	{0x0D, "SS_GSM_INDICATE_PASSWORD_ERROR"}, 
	{0x0E, "SS_GSM_INDICATE_ERROR"}, 
	{0x2F, "SS_GSM_ADDITIONAL_INFO"}, 
	{0x32, "SS_GSM_USSD_STRING"}, 
};

static const value_string isi_ss_operation[] = {
	{0x01, "SS_ACTIVATION"},
	{0x02, "SS_DEACTIVATION"},
	{0x03, "SS_REGISTRATION"},
	{0x04, "SS_ERASURE"},
	{0x05, "SS_INTERROGATION"},
	{0x06, "SS_GSM_PASSWORD_REGISTRATION"},
};

static dissector_handle_t isi_ss_handle;
static void dissect_isi_ss(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_ss_message_id = -1;
static guint32 hf_isi_ss_ussd_type = -1;
static guint32 hf_isi_ss_subblock_count = -1;
static guint32 hf_isi_ss_subblock = -1;
static guint32 hf_isi_ss_operation = -1;

void proto_reg_handoff_isi_ss(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_ss_handle = create_dissector_handle(dissect_isi_ss, proto_isi);
		dissector_add("isi.resource", 0x06, isi_ss_handle);
	}
}

void proto_register_isi_ss(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_ss_message_id,
		  { "Message ID", "isi.ss.msg_id", FT_UINT8, BASE_HEX, isi_ss_message_id, 0x0, "Message ID", HFILL }},
		{ &hf_isi_ss_ussd_type,
		  { "USSD Type", "isi.ss.ussd_type", FT_UINT8, BASE_HEX, isi_ss_ussd_type, 0x0, "USSD Type", HFILL }},
		{ &hf_isi_ss_subblock_count,
		  { "Subblock Count", "isi.ss.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock Count", HFILL }},
		{ &hf_isi_ss_subblock,
		  { "Subblock", "isi.ss.subblock", FT_UINT8, BASE_HEX, isi_ss_subblock, 0x0, "Subblock", HFILL }},
		{ &hf_isi_ss_operation,
		  { "Operation", "isi.ss.operation", FT_UINT8, BASE_HEX, isi_ss_operation, 0x0, "Operation", HFILL }},  
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.ss", dissect_isi_ss, proto_isi);
}

static void dissect_isi_ss(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_ss_message_id, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch(cmd) {
			case 0x00: /* SS_SERVICE_REQ */
				proto_tree_add_item(tree, hf_isi_ss_operation, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x05:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Call Barring Interrogation");
						break;
					case 0x06:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request");
						break;
				}
				break; 
				
			case 0x01: /* SS_SERVICE_COMPLETED_RESP */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Response");
						break;
				}
				break; 
				
			case 0x02: /* SS_SERVICE_FAILED_RESP */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response");
						break;
				}
				break; 
				
			case 0x04: /* SS_GSM_USSD_SEND_REQ */
				proto_tree_add_item(tree, hf_isi_ss_ussd_type, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_ss_subblock_count, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_ss_subblock, tvb, 3, 1, FALSE);
				
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Send Request");
						break;
				}
				break; 
				
			case 0x05: /* SS_GSM_USSD_SEND_RESP */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Send Response");
						break;
				}
				break; 
				
			case 0x06: /* SS_GSM_USSD_RECEIVE_IND */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "GSM USSD Message Received Indication");
						break;
				}
				break; 
				
			case 0x09: /* SS_STATUS_IND */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Status Indication");
						break;
				}
				break; 
				
			case 0x10: /* SS_SERVICE_COMPLETED_IND */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Indication");
						break;
				}
				break; 
		  
			case 0xF0: /* SS_COMMON_MESSAGE */
				//proto_tree_add_item(tree, hf_isi_ss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x2F:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message");
						break;
				}
				break; 

				
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
				break;
		}
	}
}
