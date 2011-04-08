/* isi-call.c
 * Dissector for ISI's call resource
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
#include "isi-call.h"

static const value_string isi_call_id[] = {
	{0x01, "CALL_CREATE_REQ"},
	{0x02, "CALL_CREATE_RESP"},
	{0x03, "CALL_COMING_IND"},
	{0x04, "CALL_MO_ALERT_IND"},
	{0x05, "CALL_MT_ALERT_IND"},
	{0x06, "CALL_WAITING_IND"},
	{0x07, "CALL_ANSWER_REQ"},
	{0x08, "CALL_ANSWER_RESP"},
	{0x09, "CALL_RELEASE_REQ"},
	{0x0A, "CALL_RELEASE_RESP"},
	{0x0B, "CALL_RELEASE_IND"},
	{0x0C, "CALL_TERMINATED_IND"},
	{0x0D, "CALL_STATUS_REQ"},
	{0x0E, "CALL_STATUS_RESP"},
	{0x0F, "CALL_STATUS_IND"},
	{0x10, "CALL_SERVER_STATUS_IND"},
	{0x11, "CALL_CONTROL_REQ"},
	{0x12, "CALL_CONTROL_RESP"},
	{0x13, "CALL_CONTROL_IND"},
	{0x14, "CALL_MODE_SWITCH_REQ"},
	{0x15, "CALL_MODE_SWITCH_RESP"},
	{0x16, "CALL_MODE_SWITCH_IND"},
	{0x17, "CALL_DTMF_SEND_REQ"},
	{0x18, "CALL_DTMF_SEND_RESP"},
	{0x19, "CALL_DTMF_STOP_REQ"},
	{0x1A, "CALL_DTMF_STOP_RESP"},
	{0x1B, "CALL_DTMF_STATUS_IND"},
	{0x1C, "CALL_DTMF_TONE_IND"},
	{0x1E, "CALL_RECONNECT_IND"},
	{0x1F, "CALL_PROPERTY_GET_REQ"},
	{0x20, "CALL_PROPERTY_GET_RESP"},
	{0x21, "CALL_PROPERTY_SET_REQ"},
	{0x22, "CALL_PROPERTY_SET_RESP"},
	{0x23, "CALL_PROPERTY_SET_IND"},
	{0x28, "CALL_EMERGENCY_NBR_CHECK_REQ"},
	{0x29, "CALL_EMERGENCY_NBR_CHECK_RESP"},
	{0x26, "CALL_EMERGENCY_NBR_GET_REQ"},
	{0x27, "CALL_EMERGENCY_NBR_GET_RESP"},
	{0x24, "CALL_EMERGENCY_NBR_MODIFY_REQ"},
	{0x25, "CALL_EMERGENCY_NBR_MODIFY_RESP"},
	{0xA0, "CALL_GSM_NOTIFICATION_IND"},
	{0xA1, "CALL_GSM_USER_TO_USER_REQ"},
	{0xA2, "CALL_GSM_USER_TO_USER_RESP"},
	{0xA3, "CALL_GSM_USER_TO_USER_IND"},
	{0xA4, "CALL_GSM_BLACKLIST_CLEAR_REQ"},
	{0xA5, "CALL_GSM_BLACKLIST_CLEAR_RESP"},
	{0xA6, "CALL_GSM_BLACKLIST_TIMER_IND"},
	{0xA7, "CALL_GSM_DATA_CH_INFO_IND"},
	{0xAA, "CALL_GSM_CCP_GET_REQ"},
	{0xAB, "CALL_GSM_CCP_GET_RESP"},
	{0xAC, "CALL_GSM_CCP_CHECK_REQ"},
	{0xAD, "CALL_GSM_CCP_CHECK_RESP"},
	{0xA9, "CALL_GSM_COMING_REJ_IND"},
	{0xA8, "CALL_GSM_RAB_IND"},
	{0xAE, "CALL_GSM_IMMEDIATE_MODIFY_IND"},
	{0x2A, "CALL_CREATE_NO_SIMATK_REQ"},
	{0xAF, "CALL_GSM_SS_DATA_IND"},
	{0x2B, "CALL_TIMER_REQ"},
	{0x2C, "CALL_TIMER_RESP"},
	{0x2D, "CALL_TIMER_NTF"},
	{0x2E, "CALL_TIMER_IND"},
	{0x2F, "CALL_TIMER_RESET_REQ"},
	{0x30, "CALL_TIMER_RESET_RESP"},
	{0x31, "CALL_EMERGENCY_NBR_IND"},
	{0x32, "CALL_SERVICE_DENIED_IND"},
	{0x34, "CALL_RELEASE_END_REQ"},
	{0x35, "CALL_RELEASE_END_RESP"},
	{0x33, "CALL_USER_CONNECT_IND"},
	{0x40, "CALL_AUDIO_CONNECT_IND"},
	{0x36, "CALL_KODIAK_ALLOW_CTRL_REQ"},
	{0x37, "CALL_KODIAK_ALLOW_CTRL_RESP"},
	{0x38, "CALL_SERVICE_ACTIVATE_IND"},
	{0x39, "CALL_SERVICE_ACTIVATE_REQ"},
	{0x3A, "CALL_SERVICE_ACTIVATE_RESP"},
	{0x3B, "CALL_SIM_ATK_IND"},
	{0x3C, "CALL_CONTROL_OPER_IND"},
	{0x3E, "CALL_TEST_CALL_STATUS_IND"},
	{0x3F, "CALL_SIM_ATK_INFO_IND"},
	{0x41, "CALL_SECURITY_IND"},
	{0x42, "CALL_MEDIA_HANDLE_REQ"},
	{0x43, "CALL_MEDIA_HANDLE_RESP"},
	{0x00, NULL}
};

static dissector_handle_t isi_call_handle;
static void dissect_isi_call(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_call_cmd = -1;


void proto_reg_handoff_isi_call(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_call_handle = create_dissector_handle(dissect_isi_call, proto_isi);
		dissector_add("isi.resource", 0x01, isi_call_handle);
	}
}

void proto_register_isi_call(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_call_cmd,
			{ "Command", "isi.call.cmd", FT_UINT8, BASE_HEX, isi_call_id, 0x0, "Command", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.call", dissect_isi_call, proto_isi);
}


static void dissect_isi_call(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_call_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x01: /* CALL_CREATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Create Request");
				break;
			case 0x02: /* CALL_CREATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Create Response");
				break;
			case 0x03: /* CALL_COMING_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Coming Indication");
				break;
			case 0x04: /* CALL_MO_ALERT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call MO Allert Indication");
				break;
			case 0x05: /* CALL_MT_ALERT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call MT Allert Indication");
				break;
			case 0x06: /* CALL_WAITING_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Waiting Indication");
				break;
			case 0x07: /* CALL_ANSWER_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Answer Request");
				break;
			case 0x08: /* CALL_ANSWER_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Answer Response");
				break;
			case 0x09: /* CALL_RELEASE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Release Request");
				break;
			case 0x0A: /* CALL_RELEASE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Release Response");
				break;
			case 0x0B: /* CALL_RELEASE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Release Indication");
				break;
			case 0x0C: /* CALL_TERMINATED_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Terminated Indication");
				break;
			case 0x0D: /* CALL_STATUS_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Status Request");
				break;
			case 0x0E: /* CALL_STATUS_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Status Response");
				break;
			case 0x0F: /* CALL_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Status Indication");
				break;
			case 0x10: /* CALL_SERVER_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Server Status Indication");
				break;
			case 0x11: /* CALL_CONTROL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Control Request");
				break;
			case 0x12: /* CALL_CONTROL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Control Response");
				break;
			case 0x13: /* CALL_CONTROL_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Control Indication");
				break;
			case 0x14: /* CALL_MODE_SWITCH_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Mode Switch Request");
				break;
			case 0x15: /* CALL_MODE_SWITCH_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Mode Switch Response");
				break;
			case 0x16: /* CALL_MODE_SWITCH_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Mode Switch Indication");
				break;
			case 0x17: /* CALL_DTMF_SEND_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Send Request");
				break;
			case 0x18: /* CALL_DTMF_SEND_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Send Response");
				break;
			case 0x19: /* CALL_DTMF_STOP_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Stop Request");
				break;
			case 0x1A: /* CALL_DTMF_STOP_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Stop Response");
				break;
			case 0x1B: /* CALL_DTMF_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Status Indication");
				break;
			case 0x1C: /* CALL_DTMF_TONE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call DTMF Tone Indication");
				break;
			case 0x1E: /* CALL_RECONNECT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Reconnect Indication");
				break;
			case 0x1F: /* CALL_PROPERTY_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Property Get Request");
				break;
			case 0x20: /* CALL_PROPERTY_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Property Get Response");
				break;
			case 0x21: /* CALL_PROPERTY_SET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Property Set Request");
				break;
			case 0x22: /* CALL_PROPERTY_SET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Property Set Response");
				break;
			case 0x23: /* CALL_PROPERTY_SET_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Property Set Indication");
				break;
			case 0x28: /* CALL_EMERGENCY_NBR_CHECK_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Check Request");
				break;
			case 0x29: /* CALL_EMERGENCY_NBR_CHECK_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Check Response");
				break;
			case 0x26: /* CALL_EMERGENCY_NBR_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Get Request");
				break;
			case 0x27: /* CALL_EMERGENCY_NBR_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Get Response");
				break;
			case 0x24: /* CALL_EMERGENCY_NBR_MODIFY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Modify Request");
				break;
			case 0x25: /* CALL_EMERGENCY_NBR_MODIFY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Modify Response");
				break;
			case 0xA0: /* CALL_GSM_NOTIFICATION_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Notification Indication");
				break;
			case 0xA1: /* CALL_GSM_USER_TO_USER_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM User To User Request");
				break;
			case 0xA2: /* CALL_GSM_USER_TO_USER_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM User To User Response");
				break;
			case 0xA3: /* CALL_GSM_USER_TO_USER_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM User To User Indication");
				break;
			case 0xA4: /* CALL_GSM_BLACKLIST_CLEAR_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Blacklist Clear Request");
				break;
			case 0xA5: /* CALL_GSM_BLACKLIST_CLEAR_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Blacklist Clear Response");
				break;
			case 0xA6: /* CALL_GSM_BLACKLIST_TIMER_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Blacklist Timer Indication");
				break;
			case 0xA7: /* CALL_GSM_DATA_CH_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Data Channel Info Indication");
				break;
			case 0xAA: /* CALL_GSM_CCP_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM CCP Get Request");
				break;
			case 0xAB: /* CALL_GSM_CCP_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM CCP Get Response");
				break;
			case 0xAC: /* CALL_GSM_CCP_CHECK_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM CCP Check Request");
				break;
			case 0xAD: /* CALL_GSM_CCP_CHECK_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM CCP Check Response");
				break;
			case 0xA9: /* CALL_GSM_COMING_REJ_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Coming Reject Indication");
				break;
			case 0xA8: /* CALL_GSM_RAB_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM RAB Indication");
				break;
			case 0xAE: /* CALL_GSM_IMMEDIATE_MODIFY_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM Immediate Modify Indication");
				break;
			case 0x2A: /* CALL_CREATE_NO_SIMATK_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Create No SIMATK Request");
				break;
			case 0xAF: /* CALL_GSM_SS_DATA_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call GSM SS Data Indication");
				break;
			case 0x2B: /* CALL_TIMER_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer Request");
				break;
			case 0x2C: /* CALL_TIMER_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer Response");
				break;
			case 0x2D: /* CALL_TIMER_NTF */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer NTF");
				break;
			case 0x2E: /* CALL_TIMER_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer Indication");
				break;
			case 0x2F: /* CALL_TIMER_RESET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer Reset Request");
				break;
			case 0x30: /* CALL_TIMER_RESET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Timer Reset Response");
				break;
			case 0x31: /* CALL_EMERGENCY_NBR_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Emergency NBR Indication");
				break;
			case 0x32: /* CALL_SERVICE_DENIED_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Service Denied Indication");
				break;
			case 0x34: /* CALL_RELEASE_END_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Release End Request");
				break;
			case 0x35: /* CALL_RELEASE_END_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Release End Response");
				break;
			case 0x33: /* CALL_USER_CONNECT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call User Connect Indication");
				break;
			case 0x40: /* CALL_AUDIO_CONNECT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Audio Connect Indication");
				break;
			case 0x36: /* CALL_KODIAK_ALLOW_CTRL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Kodiak Allow Control Request");
				break;
			case 0x37: /* CALL_KODIAK_ALLOW_CTRL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Kodiak Allow Control Response");
				break;
			case 0x38: /* CALL_SERVICE_ACTIVATE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Service Activate Indication");
				break;
			case 0x39: /* CALL_SERVICE_ACTIVATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Service Activate Request");
				break;
			case 0x3A: /* CALL_SERVICE_ACTIVATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Service Activate Response");
				break;
			case 0x3B: /* CALL_SIM_ATK_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call SIM ATK Indication");
				break;
			case 0x3C: /* CALL_CONTROL_OPER_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Control Operator Indication");
				break;
			case 0x3E: /* CALL_TEST_CALL_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Test Call Status Indication");
				break;
			case 0x3F: /* CALL_SIM_ATK_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call SIM ATK Info Indication");
				break;
			case 0x41: /* CALL_SECURITY_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Security Indication");
				break;
			case 0x42: /* CALL_MEDIA_HANDLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Media Handle Request");
				break;
			case 0x43: /* CALL_MEDIA_HANDLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Call Media Handle Response");
				break;

			case 0xF0: /* CALL_COMMON_MESSAGE */
				dissect_isi_common("Call", tvb, pinfo, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Call packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}




