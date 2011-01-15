/* isi-ss.c
 * Dissector for ISI's Short Message Service resource
 * Copyright 2010, Sebastian Reichel <sre@ring0.de>
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
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
#include "isi-sms.h"

#include <epan/dissectors/packet-gsm_sms.h>

static const value_string isi_sms_message_id[] = {
	{0x00, "SMS_MESSAGE_CAPABILITY_REQ"},
	{0x01, "SMS_MESSAGE_CAPABILITY_RESP"},
	{0x02, "SMS_MESSAGE_SEND_REQ"},
	{0x03, "SMS_MESSAGE_SEND_RESP"},
	{0x04, "SMS_RECEIVED_MT_PP_IND"},
	{0x05, "SMS_RECEIVED_MWI_PP_IND"},
	{0x06, "SMS_PP_ROUTING_REQ"},
	{0x07, "SMS_PP_ROUTING_RESP"},
	{0x08, "SMS_PP_ROUTING_NTF"},
	{0x09, "SMS_GSM_RECEIVED_PP_REPORT_REQ"},
	{0x0A, "SMS_GSM_RECEIVED_PP_REPORT_RESP"},
	{0x0B, "SMS_GSM_CB_ROUTING_REQ"},
	{0x0C, "SMS_GSM_CB_ROUTING_RESP"},
	{0x0D, "SMS_GSM_CB_ROUTING_NTF"},
	{0x0E, "SMS_GSM_TEMP_CB_ROUTING_REQ"},
	{0x0F, "SMS_GSM_TEMP_CB_ROUTING_RESP"},
	{0x10, "SMS_GSM_TEMP_CB_ROUTING_NTF"},
	{0x11, "SMS_GSM_CBCH_PRESENT_IND"},
	{0x12, "SMS_PARAMETERS_UPDATE_REQ"},                
	{0x13, "SMS_PARAMETERS_UPDATE_RESP"},               
	{0x14, "SMS_PARAMETERS_READ_REQ"},                  
	{0x15, "SMS_PARAMETERS_READ_RESP"},                 
	{0x16, "SMS_PARAMETERS_CAPACITY_REQ"},              
	{0x17, "SMS_PARAMETERS_CAPACITY_RESP"},             
	{0x18, "SMS_GSM_SETTINGS_UPDATE_REQ"},              
	{0x19, "SMS_GSM_SETTINGS_UPDATE_RESP"},   
	{0x1A, "SMS_GSM_SETTINGS_READ_REQ"},
	{0x1B, "SMS_GSM_SETTINGS_READ_RESP"},
	{0x1C, "SMS_GSM_MCN_SETTING_CHANGED_IND"},
	{0x1D, "SMS_MEMORY_CAPACITY_EXC_IND"},
	{0x1E, "SMS_STORAGE_STATUS_UPDATE_REQ"},
	{0x1F, "SMS_STORAGE_STATUS_UPDATE_RESP"},
	{0x22, "SMS_MESSAGE_SEND_STATUS_IND"},
	{0x23, "SMS_GSM_RESEND_CANCEL_REQ"},
	{0x24, "SMS_GSM_RESEND_CANCEL_RESP"},
	{0x25, "SMS_SM_CONTROL_ACTIVATE_REQ"},
	{0x26, "SMS_SM_CONTROL_ACTIVATE_RESP"},
	/* 0x29 is undocumented, but appears in traces */
	{0xF0, "COMMON_MESSAGE"},
	{0x00, NULL} 
};

static const value_string isi_sms_routing_command[] = {
	{0x00, "SMS_ROUTING_RELEASE"},
	{0x01, "SMS_ROUTING_SET"},
	{0x02, "SMS_ROUTING_SUSPEND"},
	{0x03, "SMS_ROUTING_RESUME"},
	{0x04, "SMS_ROUTING_UPDATE"},
	{0x05, "SMS_ROUTING_QUERY"},
	{0x06, "SMS_ROUTING_QUERY_ALL"},
	{0x00, NULL}
};

static const value_string isi_sms_routing_mode[] = {
	{0x00, "SMS_GSM_ROUTING_MODE_CLASS_DISP"},
	{0x01, "SMS_GSM_ROUTING_MODE_CLASS_TE"},
	{0x02, "SMS_GSM_ROUTING_MODE_CLASS_ME"},
	{0x03, "SMS_GSM_ROUTING_MODE_CLASS_SIM"},
	{0x04, "SMS_GSM_ROUTING_MODE_CLASS_UD1"},
	{0x05, "SMS_GSM_ROUTING_MODE_CLASS_UD2"},
	{0x06, "SMS_GSM_ROUTING_MODE_DATACODE_WAP"},
	{0x07, "SMS_GSM_ROUTING_MODE_DATACODE_8BIT"},
	{0x08, "SMS_GSM_ROUTING_MODE_DATACODE_TXT"},
	{0x09, "SMS_GSM_ROUTING_MODE_MWI_DISCARD"},
	{0x0A, "SMS_GSM_ROUTING_MODE_MWI_STORE"},
	{0x0B, "SMS_GSM_ROUTING_MODE_ALL"},
	{0x0C, "SMS_GSM_ROUTING_MODE_CB_DDL"},
	{0x00, NULL}
};

static const value_string isi_sms_route[] = {
	{0x00, "SMS_ROUTE_GPRS_PREF"},
	{0x01, "SMS_ROUTE_CS"},
	{0x02, "SMS_ROUTE_GPRS"},
	{0x03, "SMS_ROUTE_CS_PREF"},
	{0x04, "SMS_ROUTE_DEFAULT"},
	{0x00, NULL}
};

/*
static const value_string isi_sms_subblock[] = {
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
*/

static const value_string isi_sms_send_status[] = {
	{0x00, "SMS_MSG_REROUTED"},
	{0x01, "SMS_MSG_REPEATED"},
	{0x02, "SMS_MSG_WAITING_NETWORK"},
	{0x03, "SMS_MSG_IDLE"},
	{0x00, NULL},
};

static const value_string isi_sms_common_message_id[] = {
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
};

static dissector_handle_t isi_sms_handle;
static void dissect_isi_sms(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_sms_message_id = -1;
static guint32 hf_isi_sms_routing_command = -1;
static guint32 hf_isi_sms_routing_mode = -1;
static guint32 hf_isi_sms_route = -1;
static guint32 hf_isi_sms_subblock_count = -1;
static guint32 hf_isi_sms_send_status = -1;
static guint32 hf_isi_sms_common_message_id = -1;

void proto_reg_handoff_isi_sms(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_sms_handle = create_dissector_handle(dissect_isi_sms, proto_isi);
		dissector_add("isi.resource", 0x02, isi_sms_handle);
	}
}

void proto_register_isi_sms(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_sms_message_id,
		  { "Message ID", "isi.sms.msg_id", FT_UINT8, BASE_HEX, isi_sms_message_id, 0x0, "Message ID", HFILL }},
		{ &hf_isi_sms_routing_command,
		  { "SMS Routing Command", "isi.sms.routing.command", FT_UINT8, BASE_HEX, isi_sms_routing_command, 0x0, "SMS Routing Command", HFILL }},
		{ &hf_isi_sms_routing_mode,
		  { "Routing Mode", "isi.sms.routing.mode", FT_UINT8, BASE_HEX, isi_sms_routing_mode, 0x0, "Routing Mode", HFILL }}, 
		{ &hf_isi_sms_route,
		  { "Message Route", "isi.sms.route", FT_UINT8, BASE_HEX, isi_sms_route, 0x0, "Message Route", HFILL }}, 
		{ &hf_isi_sms_subblock_count,
		  { "Subblock Count", "isi.sms.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock Count", HFILL }},
		{ &hf_isi_sms_send_status,
		  { "Sending Status", "isi.sms.sending_status", FT_UINT8, BASE_HEX, isi_sms_send_status, 0x0, "Sending Status", HFILL }},    
//		{ &hf_isi_sms_subblock,
//		  { "Subblock", "isi.sms.subblock", FT_UINT8, BASE_HEX, isi_sms_subblock, 0x0, "Subblock", HFILL }},
		{ &hf_isi_sms_common_message_id,
		  { "Common Message ID", "isi.sms.common.msg_id", FT_UINT8, BASE_HEX, isi_sms_common_message_id, 0x0, "Common Message ID", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.sms", dissect_isi_sms, proto_isi);
}

static void dissect_isi_sms(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_sms_message_id, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch(cmd) {
			case 0x03: /* SMS_MESSAGE_SEND_RESP */
				proto_tree_add_item(tree, hf_isi_sms_subblock_count, tvb, 2, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
//					case 0x05:
//						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Interrogation");
//						break;
//				case 0x06:
//						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
//						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Send Response");
						break;
				}
				break; 
				
			case 0x06: /* SMS_PP_ROUTING_REQ */
				proto_tree_add_item(tree, hf_isi_sms_routing_command, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_subblock_count, tvb, 2, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
//					case 0x05:
//						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Interrogation");
//						break;
//				case 0x06:
//						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: GSM Password Registration");
//						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Point-to-Point Routing Request");
						break;
				}
				break; 
				
			case 0x07: /* SMS_PP_ROUTING_RESP */
//				//proto_tree_add_item(tree, hf_isi_sms_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
//					//case 0x2F:
//					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
//					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Point-to-Point Routing Response");
						break;
				}
				break; 
				
			case 0x0B: /* SMS_GSM_CB_ROUTING_REQ */
				proto_tree_add_item(tree, hf_isi_sms_routing_command, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sms_routing_mode, tvb, 2, 1, FALSE);
//				proto_tree_add_item(tree, hf_isi_sms_cb_subject_list_type, tvb, 3, 1, FALSE);
//				proto_tree_add_item(tree, hf_isi_sms_cb_subject_count, tvb, 4, 1, FALSE);
//				proto_tree_add_item(tree, hf_isi_sms_cb_language_count, tvb, 5, 1, FALSE);
//				proto_tree_add_item(tree, hf_isi_sms_cb_range, tvb, 6, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x00:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Release");
						break;
					case 0x01:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Set");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Request");
						break;
				}
				break; 
								
			case 0x0C: /* SMS_GSM_CB_ROUTING_RESP */
//				proto_tree_add_item(tree, hf_isi_sms_operation, tvb, 1, 1, FALSE);
//				proto_tree_add_item(tree, hf_isi_sms_service_code, tvb, 2, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
//					case 0x05:
//						col_set_str(pinfo->cinfo, COL_INFO, "Service Completed Response: Interrogation");
//						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS GSM Cell Broadcast Routing Response");
						break;
				}
				break; 

			case 0x22: /* SMS_MESSAGE_SEND_STATUS_IND */
				proto_tree_add_item(tree, hf_isi_sms_send_status, tvb, 1, 1, FALSE);
				/* The second byte is a "segment" identifier/"Message Reference" */
				proto_tree_add_item(tree, hf_isi_sms_route, tvb, 3, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x02:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status: Waiting for Network");
						break;
					case 0x03:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status: Idle");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Message Sending Status Indication");
						break;
				}
				break; 	

			case 0xF0: /* SS_COMMON_MESSAGE */
				proto_tree_add_item(tree, hf_isi_sms_common_message_id, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x01: /* COMM_SERVICE_NOT_IDENTIFIED_RESP */
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: Service Not Identified Response");
						break;
					case 0x12: /* COMM_ISI_VERSION_GET_REQ */
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Request");
						break;
					case 0x13: /* COMM_ISI_VERSION_GET_RESP */
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISI Version Get Response");
						break;
					case 0x14: /* COMM_ISA_ENTITY_NOT_REACHABLE_RESP */
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: ISA Entity Not Reachable");
						break;
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
