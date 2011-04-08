/* isi-mtc.c
 * Dissector for ISI's mobile terminal controller resource
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
#include "isi-mtc.h"

static const value_string isi_mtc_id[] = {
	{0x03, "MTC_POWER_OFF_REQ"},
	{0x66, "MTC_POWER_OFF_RESP"},
	{0x04, "MTC_POWER_ON_REQ"},
	{0x67, "MTC_POWER_ON_RESP"},
	{0x06, "MTC_RESET_GENERATE_REQ"},
	{0x69, "MTC_RESET_GENERATE_RESP"},
	{0x05, "MTC_SLEEP_REQ"},
	{0x68, "MTC_SLEEP_RESP"},
	{0x01, "MTC_STATE_REQ"},
	{0x64, "MTC_STATE_RESP"},
	{0xC0, "MTC_STATE_INFO_IND"},
	{0x02, "MTC_STATE_QUERY_REQ"},
	{0x65, "MTC_STATE_QUERY_RESP"},
	{0x07, "MTC_SLEEP_ENABLE_REQ"},
	{0x6A, "MTC_SLEEP_ENABLE_RESP"},
	{0x08, "MTC_SLEEP_DISABLE_REQ"},
	{0x6B, "MTC_SLEEP_DISABLE_RESP"},
	{0x09, "MTC_CLOCK_CHANGE_REQ"},
	{0x6C, "MTC_CLOCK_CHANGE_RESP"},
	{0xC1, "MTC_CLOCK_CHANGE_IND"},
	{0x0A, "MTC_WATCHDOG_CONTROL_REQ"},
	{0x6D, "MTC_WATCHDOG_CONTROL_RESP"},
	{0x0B, "MTC_STARTUP_SYNQ_REQ"},
	{0x6E, "MTC_STARTUP_SYNQ_RESP"},
	{0x0C, "MTC_FORCE_STARTUP_STATE_REQ"},
	{0x6F, "MTC_FORCE_STARTUP_STATE_RESP"},
	{0x0D, "MTC_RAT_REQ"},
	{0x70, "MTC_RAT_RESP"},
	{0x0E, "MTC_RAT_QUERY_REQ"},
	{0x71, "MTC_RAT_QUERY_RESP"},
	{0x10, "MTC_EXT_MEM_ACCESS_REQ"},
	{0x73, "MTC_EXT_MEM_ACCESS_RESP"},
	{0x0F, "MTC_MEM_DL_REQ"},
	{0x72, "MTC_MEM_DL_RESP"},
	{0x11, "MTC_RESET_CONTROL_REQ"},
	{0x74, "MTC_RESET_CONTROL_RESP"},
	{0x13, "MTC_SOS_STATUS_QUERY_REQ"},
	{0x76, "MTC_SOS_STATUS_QUERY_RESP"},
	{0x12, "MTC_SHUTDOWN_SYNC_REQ"},
	{0x75, "MTC_SHUTDOWN_SYNC_RESP"},
	{0x14, "MTC_GENERIC_STATUS_QUERY_REQ"},
	{0x77, "MTC_GENERIC_STATUS_QUERY_RESP"},
	{0x15, "MTC_RF_CONTROL_REQ"},
	{0x78, "MTC_RF_CONTROL_RESP"},
	{0x16, "MTC_RF_STATUS_QUERY_REQ"},
	{0x79, "MTC_RF_STATUS_QUERY_RESP"},
	{0xC2, "MTC_RF_STATUS_INFO_IND"},
	{0x7A, "MTC_RAT_INFO_NTF"},
	{0x17, "MTC_VCORE_READ_REQ"},
	{0x7B, "MTC_VCORE_READ_RESP"},
	{0x7C, "MTC_DSP_GENIO_CONFIG_NTF"},
	{0x30, "PERF_SET_REQ"},
	{0x90, "PERF_SET_RESP"},
	{0x31, "PERF_STATE_REQ"},
	{0x91, "PERF_STATE_RESP"},
	{0x32, "PERF_SETTINGS_WRITE_REQ"},
	{0x92, "PERF_SETTINGS_WRITE_RESP"},
	{0x33, "PERF_INFO_REQ"},
	{0x93, "PERF_INFO_RESP"},
	{0xF0, "COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_mtc_state[] = {
	{0x00, "MTC_POWER_OFF"},
	{0x01, "MTC_NORMAL"},
	{0x02, "MTC_CHARGING"},
	{0x03, "MTC_ALARM"},
	{0x04, "MTC_TEST"},
	{0x05, "MTC_LOCAL"},
	{0x06, "MTC_WARRANTY"},
	{0x07, "MTC_RELIABILITY"},
	{0x08, "MTC_SELFTEST_FAIL"},
	{0x09, "MTC_SWDL"},
	{0x0A, "MTC_RF_INACTIVE"},
	{0x0B, "MTC_ID_WRITE"},
	{0x0C, "MTC_DISCHARGING"},
	{0x0D, "MTC_DISK_WIPE"},
	{0x0E, "MTC_SW_RESET"},
	{0xFF, "MTC_CMT_ONLY_MODE"},
};

static const value_string isi_mtc_status[] = {
	{0x00, "MTC_OK"},
	{0x01, "MTC_FAIL"},
	{0x02, "MTC_NOT_ALLOWED"},
	{0x05, "MTC_STATE_TRANSITION_GOING_ON"},
	{0x06, "MTC_ALREADY_ACTIVE"},
	{0x10, "MTC_SERVICE_DISABLED"},
	{0x13, "MTC_NOT_READY_YET"},
	{0x14, "MTC_NOT_SUPPORTED"},
	{0x16, "MTC_TRANSITION_ONGOING"},
	{0x17, "MTC_RESET_REQUIRED"},
};

static const value_string isi_mtc_action[] = {
	{0x03, "MTC_START"},
	{0x04, "MTC_READY"},
	{0x0C, "MTC_NOS_READY"},
	{0x11, "MTC_SOS_START"},
	{0x12, "MTC_SOS_READY"},
	{0x14, "MTC_NOT_SUPPORTED"},
	{0x15, "MTC_NOT_AVAILABLE"},
};

static dissector_handle_t isi_mtc_handle;
static void dissect_isi_mtc(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_mtc_cmd = -1;
static guint32 hf_isi_mtc_current_state = -1;
static guint32 hf_isi_mtc_target_state = -1;
static guint32 hf_isi_mtc_status = -1;
static guint32 hf_isi_mtc_action = -1;


void proto_reg_handoff_isi_mtc(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_mtc_handle = create_dissector_handle(dissect_isi_mtc, proto_isi);
		dissector_add("isi.resource", 0x15, isi_mtc_handle);
	}
}

void proto_register_isi_mtc(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_mtc_cmd,
			{ "Command", "isi.mtc.cmd", FT_UINT8, BASE_HEX, isi_mtc_id, 0x0, "Command", HFILL }},
		{ &hf_isi_mtc_current_state,
			{ "Current State", "isi.mtc.current_state", FT_UINT8, BASE_HEX, isi_mtc_state, 0x0, "Current State", HFILL }},
		{ &hf_isi_mtc_target_state,
			{ "Target State", "isi.mtc.target_state", FT_UINT8, BASE_HEX, isi_mtc_state, 0x0, "Target State", HFILL }},
		{ &hf_isi_mtc_status,
			{ "Status", "isi.mtc.status", FT_UINT8, BASE_HEX, isi_mtc_status, 0x0, "Status", HFILL }},
		{ &hf_isi_mtc_action,
			{ "Action", "isi.mtc.action", FT_UINT8, BASE_HEX, isi_mtc_action, 0x0, "Action", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.mtc", dissect_isi_mtc, proto_isi);
}


static void dissect_isi_mtc(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_mtc_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x01: /* MTC_STATE_REQ */
				proto_tree_add_item(tree, hf_isi_mtc_target_state, tvb, 1, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State");
				break;
			case 0x64: /* MTC_STATE_RESP */
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State");
				break;
			case 0x02: /* MTC_STATE_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Query");
				break;
			case 0x65: /* MTC_STATE_QUERY_RESP */
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_target_state, tvb, 2, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Query");
				break;
			case 0x03: /* MTC_POWER_OFF_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power Off");
				break;
			case 0x66: /* MTC_POWER_OFF_RESP */
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power Off");
				break;
			case 0x0B: /* MTC_STARTUP_SYNQ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Startup Synq");
				break;
			case 0x6E: /* MTC_STARTUP_SYNQ_RESP */
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Startup Synq");
				break;
			case 0x12: /* MTC_SHUTDOWN_SYNC_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Shutdown Sync");
				break;
			case 0xC0: /* MTC_STATE_INFO_IND */
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_action, tvb, 2, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Info Indication");
				break;
			case 0xC2: /* MTC_RF_STATUS_INFO_IND */
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_action, tvb, 2, 1, FALSE);
				col_set_str(pinfo->cinfo, COL_INFO, "MTC RF Status Info Indication");
				break;
			case 0xF0: /* COMMON_MESSAGE */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Common Message");
				dissect_isi_common("MTC", tvb, pinfo, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown MTC packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}



