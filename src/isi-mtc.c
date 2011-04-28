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

static const value_string isi_mtc_subblock[] = {
	{0x01, "MTC_SB_MEM_DL_DATA"},
	{0x02, "MTC_SB_LONG_PWR_KEY_COUNT"},
	{0x30, "PERF_SB_OPERATING_POINT"},
	{0x31, "PERF_SB_SERVICE_SETTING"},
	{0x32, "PERF_SB_PERFORMANCE"},
	{0x33, "PERF_SB_HW_CONF_VCORE"},
	{0x36, "PERF_SB_HW_CONF_VCORE_PROD"},
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

static const value_string isi_mtc_reset_type[] = {
	{0x01, "MTC_RESET_DEVICE_CDSP"},
	{0x02, "MTC_RESET_DEVICE_ADSP"},
	{0xFF, "MTC_RESET_ALL"},
};

static const value_string isi_mtc_sleep_type[] = {
	{0x09, "MTC_LIGHT_SLEEP"},
	{0x0A, "MTC_DEEP_SLEEP"},
};

static const value_string isi_mtc_clock_type[] = {
	{0x01, "MTC_SYSTEM_CLOCK"},
	{0x02, "MTC_PROCESSOR_CLOCK"},
};

static const value_string isi_mtc_clock_action[] = {
	{0x01, "MTC_SYSTEM_MODE_GSM"},
	{0x02, "MTC_SYSTEM_MODE_DAMPS"},
	{0x10, "MTC_HIGH_FREQUENCY_RESERVE"},
	{0x20, "MTC_HIGH_FREQUENCY_RELEASE"},
};

static const value_string isi_mtc_wd_action[] = {
	{0x01, "MTC_WATCHDOG_ENABLE"},
	{0x02, "MTC_WATCHDOG_DISABLE"},
};

static const value_string isi_mtc_force_action[] = {
	{0x0E, "MTC_SET"},
	{0x0F, "MTC_CLEAR"},
};

static const value_string isi_mtc_rat_state[] = {
	{0x00, "MTC_NO_CHANGE"},
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
};

static const value_string isi_mtc_rat[] = {
	{0x00, "MTC_UNKNOWN_RAT"},
	{0x01, "MTC_NO_RAT_SELECTION"},
	{0x02, "MTC_GSM_RAT"},
	{0x03, "MTC_UMTS_RAT"},
};

static dissector_handle_t isi_mtc_handle;
static void dissect_isi_mtc(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_mtc_cmd = -1;
static guint32 hf_isi_mtc_subblock = -1;
static guint32 hf_isi_mtc_current_state = -1;
static guint32 hf_isi_mtc_target_state = -1;
static guint32 hf_isi_mtc_status = -1;
static guint32 hf_isi_mtc_action = -1;
static guint32 hf_isi_mtc_reset_type = -1;
static guint32 hf_isi_mtc_sleep_type = -1;
static guint32 hf_isi_mtc_clock_type = -1;
static guint32 hf_isi_mtc_clock_action = -1;
static guint32 hf_isi_mtc_wd_action = -1;
static guint32 hf_isi_mtc_wd_mask = -1;
static guint32 hf_isi_mtc_force_action = -1;
static guint32 hf_isi_mtc_rat_state = -1;
static guint32 hf_isi_mtc_rat = -1;
static guint32 hf_isi_mtc_mem_user = -1;
static guint32 hf_isi_mtc_mem_blocks = -1;
static guint32 hf_isi_mtc_timeout = -1;


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
		{ &hf_isi_mtc_subblock,
			{ "Subblock-Type", "isi.mtc.subblock.type", FT_UINT8, BASE_HEX, isi_mtc_subblock, 0x0, "Subblock-Type", HFILL }},
		{ &hf_isi_mtc_current_state,
			{ "Current State", "isi.mtc.current_state", FT_UINT8, BASE_HEX, isi_mtc_state, 0x0, "Current State", HFILL }},
		{ &hf_isi_mtc_target_state,
			{ "Target State", "isi.mtc.target_state", FT_UINT8, BASE_HEX, isi_mtc_state, 0x0, "Target State", HFILL }},
		{ &hf_isi_mtc_status,
			{ "Status", "isi.mtc.status", FT_UINT8, BASE_HEX, isi_mtc_status, 0x0, "Status", HFILL }},
		{ &hf_isi_mtc_action,
			{ "Action", "isi.mtc.action", FT_UINT8, BASE_HEX, isi_mtc_action, 0x0, "Action", HFILL }},
		{ &hf_isi_mtc_timeout,
			{ "Timeout", "isi.mtc.timeout", FT_UINT16, BASE_DEC, NULL, 0x0, "Timeout", HFILL }},
		{ &hf_isi_mtc_reset_type,
			{ "Reset-Type", "isi.mtc.reset_type", FT_UINT8, BASE_HEX, isi_mtc_reset_type, 0x0, "Reset-Type", HFILL }},
		{ &hf_isi_mtc_sleep_type,
			{ "Sleep-Type", "isi.mtc.sleep_type", FT_UINT8, BASE_HEX, isi_mtc_sleep_type, 0x0, "Sleep-Type", HFILL }},
		{ &hf_isi_mtc_clock_type,
			{ "Clock-Type", "isi.mtc.clock_type", FT_UINT8, BASE_HEX, isi_mtc_clock_type, 0x0, "Clock-Type", HFILL }},
		{ &hf_isi_mtc_clock_action,
			{ "Clock-Action", "isi.mtc.clock_action", FT_UINT8, BASE_HEX, isi_mtc_clock_action, 0x0, "Clock-Action", HFILL }},
		{ &hf_isi_mtc_wd_action,
			{ "Watchdog-Action", "isi.mtc.wd_action", FT_UINT8, BASE_HEX, isi_mtc_wd_action, 0x0, "Watchdog-Action", HFILL }},
		{ &hf_isi_mtc_wd_mask,
			{ "Watchdog-List", "isi.mtc.wd_list", FT_UINT8, BASE_HEX, NULL, 0x0, "Watchdog-List", HFILL }},
		{ &hf_isi_mtc_force_action,
			{ "Force-Action", "isi.mtc.force_action", FT_UINT8, BASE_HEX, isi_mtc_force_action, 0x0, "Force-Action", HFILL }},
		{ &hf_isi_mtc_rat_state,
			{ "RAT State", "isi.mtc.rat_state", FT_UINT8, BASE_HEX, isi_mtc_rat_state, 0x0, "RAT State", HFILL }},
		{ &hf_isi_mtc_rat,
			{ "RAT", "isi.mtc.rat", FT_UINT8, BASE_HEX, isi_mtc_rat, 0x0, "RAT", HFILL }},
		{ &hf_isi_mtc_mem_user,
			{ "MEM User", "isi.mtc.mem_user", FT_UINT8, BASE_HEX, NULL, 0x0, "MEM User", HFILL }},
		{ &hf_isi_mtc_mem_blocks,
			{ "Blocks", "isi.mtc.mem_blocks", FT_UINT8, BASE_DEC, NULL, 0x0, "Blocks", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.mtc", dissect_isi_mtc, proto_isi);
}

static void dissect_isi_mtc_subblock(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x01: /* MTC_SB_MEM_DL_DATA */
		case 0x02: /* MTC_SB_LONG_PWR_KEY_COUNT */
		case 0x30: /* PERF_SB_OPERATING_POINT */
		case 0x31: /* PERF_SB_SERVICE_SETTING */
		case 0x32: /* PERF_SB_PERFORMANCE */
		case 0x33: /* PERF_SB_HW_CONF_VCORE */
		case 0x36: /* PERF_SB_HW_CONF_VCORE_PROD */
		default:
			break;
	}
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
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Request");
				proto_tree_add_item(tree, hf_isi_mtc_target_state, tvb, 1, 1, FALSE);
				break;
			case 0x64: /* MTC_STATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x02: /* MTC_STATE_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Query Request");
				break;
			case 0x65: /* MTC_STATE_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Query Response");
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_target_state, tvb, 2, 1, FALSE);
				break;
			case 0x03: /* MTC_POWER_OFF_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power Off Request");
				break;
			case 0x66: /* MTC_POWER_OFF_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power Off Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x04: /* MTC_POWER_ON_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power On Request");
				break;
			case 0x67: /* MTC_POWER_ON_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Power On Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x05: /* MTC_SLEEP_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Request");
				proto_tree_add_item(tree, hf_isi_mtc_timeout, tvb, 1, 2, FALSE);
				break;
			case 0x68: /* MTC_SLEEP_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x06: /* MTC_RESET_GENERATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Reset Generate Request");
				proto_tree_add_item(tree, hf_isi_mtc_reset_type, tvb, 1, 1, FALSE);
				break;
			case 0x69: /* MTC_RESET_GENERATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Reset Generate Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x07: /* MTC_SLEEP_ENABLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Enable Request");
				proto_tree_add_item(tree, hf_isi_mtc_sleep_type, tvb, 1, 1, FALSE);
				break;
			case 0x6A: /* MTC_SLEEP_ENABLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Enable Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x08: /* MTC_SLEEP_DISABLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Disable Request");
				proto_tree_add_item(tree, hf_isi_mtc_sleep_type, tvb, 1, 1, FALSE);
				break;
			case 0x6B: /* MTC_SLEEP_DISABLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Sleep Disable Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x09: /* MTC_CLOCK_CHANGE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Clock Change Request");
				proto_tree_add_item(tree, hf_isi_mtc_clock_type, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_clock_action, tvb, 2, 1, FALSE);
				break;
			case 0x6C: /* MTC_CLOCK_CHANGE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Clock Change Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x0A: /* MTC_WATCHDOG_CONTROL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Watchdog Control Request");
				proto_tree_add_item(tree, hf_isi_mtc_wd_action, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_wd_mask, tvb, 2, 1, FALSE);
				break;
			case 0x6D: /* MTC_WATCHDOG_CONTROL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Watchdog Control Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x0B: /* MTC_STARTUP_SYNQ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Startup Synq Request");
				break;
			case 0x6E: /* MTC_STARTUP_SYNQ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Startup Synq Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x0C: /* MTC_FORCE_STARTUP_STATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Force Startup State Request");
				proto_tree_add_item(tree, hf_isi_mtc_force_action, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_target_state, tvb, 2, 1, FALSE);
				break;
			case 0x6F: /* MTC_FORCE_STARTUP_STATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Force Startup State Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x0D: /* MTC_RAT_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC RAT Request");
				proto_tree_add_item(tree, hf_isi_mtc_rat, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_rat_state, tvb, 2, 1, FALSE);
				break;
			case 0x70: /* MTC_RAT_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x0E: /* MTC_RAT_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC RAT Query Request");
				break;
			case 0x71: /* MTC_RAT_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC RAT Query Response");
				proto_tree_add_item(tree, hf_isi_mtc_rat, tvb, 1, 1, FALSE);
				break;
			case 0x0F: /* MTC_MEM_DL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC MEM DL Request");
				proto_tree_add_item(tree, hf_isi_mtc_mem_user, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_mem_blocks, tvb, 2, 1, FALSE);
				break;
			case 0x72: /* MTC_MEM_DL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC MEM DL Response");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x10: /* MTC_EXT_MEM_ACCESS_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				// TODO: action
				proto_tree_add_item(tree, hf_isi_mtc_mem_user, tvb, 2, 1, FALSE);
				break;
			case 0x73: /* MTC_EXT_MEM_ACCESS_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0x11: /* MTC_RESET_CONTROL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x74: /* MTC_RESET_CONTROL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x12: /* MTC_SHUTDOWN_SYNC_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC Shutdown Sync Request");
				break;
			case 0x75: /* MTC_SHUTDOWN_SYNC_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				proto_tree_add_item(tree, hf_isi_mtc_status, tvb, 1, 1, FALSE);
				break;
			case 0xC0: /* MTC_STATE_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC State Info Indication");
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_action, tvb, 2, 1, FALSE);
				break;
			case 0x13: /* MTC_SOS_STATUS_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x76: /* MTC_SOS_STATUS_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x14: /* MTC_GENERIC_STATUS_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x77: /* MTC_GENERIC_STATUS_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x15: /* MTC_RF_CONTROL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x78: /* MTC_RF_CONTROL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x16: /* MTC_RF_STATUS_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x79: /* MTC_RF_STATUS_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x17: /* MTC_VCORE_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x30: /* PERF_SET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x90: /* PERF_SET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x31: /* PERF_STATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x91: /* PERF_STATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x32: /* PERF_SETTINGS_WRITE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x92: /* PERF_SETTINGS_WRITE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x33: /* PERF_INFO_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x93: /* PERF_INFO_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x7A: /* MTC_RAT_INFO_NTF */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x7B: /* MTC_VCORE_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0x7C: /* MTC_DSP_GENIO_CONFIG_NTF */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0xC1: /* MTC_CLOCK_CHANGE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "");
				break;
			case 0xC2: /* MTC_RF_STATUS_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "MTC RF Status Info Indication");
				proto_tree_add_item(tree, hf_isi_mtc_current_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_mtc_action, tvb, 2, 1, FALSE);
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



