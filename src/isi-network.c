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
	{0x01, "NET_MODEM_AVAIL_NETWORK_INFO_COMMON"},
	{0x02, "NET_OPERATOR_INFO_COMMON"},
	{0x04, "NET_RSSI_CURRENT"},
	{0x05, "NET_TEST_CARRIER_PARAM"},
	{0x09, "NET_GSM_REG_INFO"},
	{0x0B, "NET_DETAILED_NETWORK_INFO"},
	{0x0C, "NET_GSM_OPERATOR_INFO"},
	{0x0D, "NET_GSM_HOME_CELLS_INFO"},
	{0x0E, "NET_GSM_SIM_NMR_INFO"},
	{0x0F, "NET_MODEM_CAUSE_EXTENSION"},
	{0x10, "NET_TIME_INFO"},
	{0x11, "NET_GSM_BAND_INFO"},
	{0x13, "NET_RSSI_GSM_STRONGEST"},
	{0x15, "NET_RESUME_INFO"},
	{0x17, "NET_BAND_INFO"},
	{0x19, "NET_LICENSE_BLOCK_INFO"},
	{0x28, "NET_UARFCN_INFO"},
	{0x29, "NET_CIPHERING_INFO"},
	{0x2C, "NET_RAT_INFO"},
	{0x2D, "NET_TEST_WCDMA_PARMS"},
	{0x2E, "NET_GSM_LCS_GPS_REF_TIME"},
	{0x2F, "NET_GSM_LCS_GPS_REF_LOCATION"},
	{0x30, "NET_GSM_LCS_GPS_DGPS_CORRECTIONS"},
	{0x31, "NET_GSM_LCS_GPS_NAVIGATION"},
	{0x32, "NET_GSM_LCS_GPS_IONOSPHERIC"},
	{0x33, "NET_GSM_LCS_GPS_UTC"},
	{0x34, "NET_GSM_LCS_GPS_ALMANAC"},
	{0x35, "NET_GSM_LCS_GPS_AQUISITION"},
	{0x36, "NET_GSM_LCS_GPS_BAD_SAT"},
	{0x37, "NET_MODEM_UMA_SERVICE_ZONE_INFO"},
	{0x38, "NET_UMA_FAILURE_INFO"},
	{0x39, "NET_MODEM_CURRENT_CELL_INFO"},
	{0x3A, "NET_GSM_LCS_SUPL"},
	{0x3B, "NET_GSM_LCS_EXT_REF_IE"},
	{0x3C, "NET_UTRAN_RADIO_INFO"},
	{0x3D, "NET_UTRAN_SIM_NMR_INFO"},
	{0x3E, "NET_ECID_GERAN_INFO"},
	{0x3F, "NET_ECID_UTRAN_FDD_INFO"},
	{0x40, "NET_TEST_GSM_SCAN_PARAMS"},
	{0x41, "NET_TEST_WCDMA_SCAN_PARAMS"},
	{0x42, "NET_TEST_GSM_HO_PARAMS"},
	{0x43, "NET_TEST_WRAN_HO_PARAMS"},
	{0x44, "NET_GSM_LCS_GPS_TIME_ASSIST_MEAS"},
	{0x45, "NET_GSM_LCS_GPS_REF_TIME_UNC"},
	{0x46, "NET_GSM_CELL_INFO"},
	{0x47, "NET_WCDMA_CELL_INFO"},
	{0x48, "NET_FULL_NITZ_NAME"},
	{0x49, "NET_SHORT_NITZ_NAME"},
	{0xE1, "NET_AVAIL_NETWORK_INFO_COMMON"},
	{0xE3, "NET_GSM_REG_NETWORK_INFO"},
	{0xE7, "NET_OPER_NAME_INFO"},
	{0x00, NULL}
};

static const value_string isi_network_success_code[] = {
	{0x00, "NET_CAUSE_OK"},
	{0x01, "NET_CAUSE_COMMUNICATION_ERROR"},
	{0x02, "NET_CAUSE_INVALID_PARAMETER"},
	{0x03, "NET_CAUSE_NO_SIM"},
	{0x04, "NET_CAUSE_SIM_NOT_YET_READY"},
	{0x05, "NET_CAUSE_NET_NOT_FOUND"},
	{0x06, "NET_CAUSE_REQUEST_NOT_ALLOWED"},
	{0x07, "NET_CAUSE_CALL_ACTIVE"},
	{0x08, "NET_CAUSE_SERVER_BUSY"},
	{0x09, "NET_CAUSE_SECURITY_CODE_REQUIRED"},
	{0x0A, "NET_CAUSE_NOTHING_TO_CANCEL"},
	{0x0B, "NET_CAUSE_UNABLE_TO_CANCEL"},
	{0x0C, "NET_CAUSE_NETWORK_FORBIDDEN"},
	{0x0D, "NET_CAUSE_REQUEST_REJECTED"},
	{0x0E, "NET_CAUSE_CS_NOT_SUPPORTED"},
	{0x0F, "NET_CAUSE_PAR_INFO_NOT_AVAILABLE"},
	{0x10, "NET_CAUSE_NOT_DONE"},
	{0x11, "NET_CAUSE_NO_SELECTED_NETWORK"},
	{0x12, "NET_CAUSE_REQUEST_INTERRUPTED"},
	{0x14, "NET_CAUSE_TOO_BIG_INDEX"},
	{0x15, "NET_CAUSE_MEMORY_FULL"},
	{0x16, "NET_CAUSE_SERVICE_NOT_ALLOWED"},
	{0x17, "NET_CAUSE_NOT_SUPPORTED_IN_TECH"},
};

static const value_string isi_network_search_mode[] = {
	{0x00, "NET_MANUAL_SEARCH"},
	{0x01, "NET_NEW_SEARCH_START"},
	{0x02, "NET_NEW_SEARCH_NEXT"},
	{0x03, "NET_NEW_EXTENDED_SEARCH_START"},
};

static const value_string isi_network_registration_status[] = {
	{0x00, "NET_REG_STATUS_HOME"},
	{0x01, "NET_REG_STATUS_ROAM"},
	{0x02, "NET_REG_STATUS_ROAM_BLINK"},
	{0x03, "NET_REG_STATUS_NOSERV"},
	{0x04, "NET_REG_STATUS_NOSERV_SEARCHING"},
	{0x05, "NET_REG_STATUS_NOSERV_NOTSEARCHING"},
	{0x06, "NET_REG_STATUS_NOSERV_NOSIM"},
	{0x08, "NET_REG_STATUS_POWER_OFF"},
	{0x09, "NET_REG_STATUS_NSPS"},
	{0x0A, "NET_REG_STATUS_NSPS_NO_COVERAGE"},
	{0x0B, "NET_REG_STATUS_NOSERV_SIM_REJECTED_BY_NW"},
};

static const value_string isi_network_selection_mode[] = {
	{0x00, "NET_SELECT_MODE_UNKNOWN"},
	{0x01, "NET_SELECT_MODE_MANUAL"},
	{0x02, "NET_SELECT_MODE_AUTOMATIC"},
	{0x03, "NET_SELECT_MODE_USER_RESELECTION"},
	{0x04, "NET_SELECT_MODE_NO_SELECTION"},
};

static const value_string isi_network_rat_name[] = {
	{0x01, "NET_GSM_RAT"},
	{0x02, "NET_UMTS_RAT"},
};

static const value_string isi_network_rat_type[] = {
	{0x00, "NET_CURRENT_RAT"},
	{0x01, "NET_SUPPORTED_RATS"},
};

static const value_string isi_network_ciphering_status[] = {
	{0x00, "NET_CIPHERING_INDICATOR_OFF"},
	{0x01, "NET_CIPHERING_INDICATOR_ON"},
	{0x02, "NET_CIPHERING_NO_CONNECTION"},
};

static const value_string isi_network_ciphering_key_status[] = {
	{0x00, "NET_KEY_STATUS_UNKNOWN"},
	{0x01, "NET_KEY_STATUS_DERIVED"},
	{0x02, "NET_KEY_STATUS_NOT_DERIVED"},
};

static const value_string isi_network_ciphering_context[] = {
	{0x00, "NET_CONTEXT_UNKNOWN"},
	{0x01, "NET_CONTEXT_GSM"},
	{0x02, "NET_CONTEXT_UMTS"},
};

static const value_string isi_network_cs_type[] = {
	{0x00, "NET_CS_GSM"},
};

static const value_string isi_network_cs_state[] = {
	{0x00, "NET_CS_INACTIVE"},
	{0x01, "NET_CS_ACTIVE"},
};

static const value_string isi_network_cs_operation[] = {
	{0x00, "NET_CS_OP_MODE_NORMAL"},
	{0x01, "NET_CS_OP_MODE_GAN_ONLY"},
};

static const value_string isi_network_measurement_type[] = {
	{0x01, "NET_STRONGEST_RSSIS"},
	{0x02, "NET_CURRENT_CELL_RSSI"},
};

static const value_string isi_network_type[] = {
	{0x00, "NET_GSM_HOME_PLMN"},
	{0x01, "NET_GSM_PREFERRED_PLMN"},
	{0x02, "NET_GSM_FORBIDDEN_PLMN"},
	{0x03, "NET_GSM_OTHER_PLMN"},
	{0x04, "NET_GSM_NO_PLMN_AVAIL"},
};

static const value_string isi_network_name_type[] = {
	{0x00, "NET_HARDCODED_LATIN_OPER_NAME"},
	{0x01, "NET_HARDCODED_USC2_OPER_NAME"},
	{0x02, "NET_NITZ_SHORT_OPER_NAME"},
	{0x03, "NET_NITZ_FULL_OPER_NAME"},
	{0x06, "NET_CNTRY_INIT_MNC_OPER_NAME"},
	{0x07, "NET_MCC_NBR_MNC_NBR_OPER_NAME"},
	{0x08, "NET_SIM_OPER_NAME"},
	{0x09, "NET_EONS_SHORT_OPER_NAME"},
	{0x0A, "NET_EONS_FULL_OPER_NAME"},
	{0xFF, "NET_HIGHEST_PRIORITY_OPER_NAME"},
};

static const value_string isi_network_gsm_band_info[] = {
	{0x00, "NET_GSM_BAND_900_1800"},
	{0x01, "NET_GSM_BAND_850_1900"},
	{0x02, "NET_GSM_BAND_INFO_NOT_AVAIL"},
	{0x03, "NET_GSM_BAND_ALL_SUPPORTED_BANDS"},
	{0xB0, "NET_GSM_BAND_850_LOCKED"},
	{0xA0, "NET_GSM_BAND_900_LOCKED"},
	{0xA1, "NET_GSM_BAND_1800_LOCKED"},
	{0xB1, "NET_GSM_BAND_1900_LOCKED"},
};

static dissector_handle_t isi_network_handle;
static void dissect_isi_network(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_network_cmd = -1;
static guint32 hf_isi_network_data_sub_pkgs = -1;
static guint32 hf_isi_network_data_sub_type = -1;
static guint32 hf_isi_network_data_sub_len = -1;
static guint32 hf_isi_network_status_sub_lac = -1;
static guint32 hf_isi_network_status_sub_cid = -1;
static guint32 hf_isi_network_status_sub_msg = -1;
static guint32 hf_isi_network_status_sub_msg_len = -1;
static guint32 hf_isi_network_gsm_band_info = -1;
static guint32 hf_isi_network_gsm_band_900 = -1;
static guint32 hf_isi_network_gsm_band_1800 = -1;
static guint32 hf_isi_network_gsm_band_1900 = -1;
static guint32 hf_isi_network_gsm_band_850 = -1;
static guint32 hf_isi_network_rat_type = -1;
static guint32 hf_isi_network_rat_name = -1;
static guint32 hf_isi_network_rat_info = -1;
static guint32 hf_isi_network_success_code = -1;
static guint32 hf_isi_network_uarfcn = -1;
static guint32 hf_isi_network_ciphering_status = -1;
static guint32 hf_isi_network_ciphering_key_status = -1;
static guint32 hf_isi_network_ciphering_context = -1;
static guint32 hf_isi_network_registration_status = -1;
static guint32 hf_isi_network_registration_protocol = -1;
static guint32 hf_isi_network_selection_mode = -1;
static guint32 hf_isi_network_search_mode = -1;
static guint32 hf_isi_network_cs_type = -1;
static guint32 hf_isi_network_cs_state = -1;
static guint32 hf_isi_network_cs_operation = -1;
static guint32 hf_isi_network_cs_services = -1;
static guint32 hf_isi_network_measurement_type = -1;
static guint32 hf_isi_network_rssi_bars = -1;
static guint32 hf_isi_network_rssi_db = -1;
static guint32 hf_isi_network_operator_code = -1;
static guint32 hf_isi_network_service_status = -1;
static guint32 hf_isi_network_type = -1;
static guint32 hf_isi_network_name_type = -1;
static guint32 hf_isi_network_country_initials = -1;
static guint32 hf_isi_network_gprs_support = -1;
static guint32 hf_isi_network_gprs_mode = -1;
static guint32 hf_isi_network_gprs_services = -1;
static guint32 hf_isi_network_egprs_support = -1;
static guint32 hf_isi_network_dtm_support = -1;
static guint32 hf_isi_network_current_rac = -1;
static guint32 hf_isi_network_hdspa_available = -1;
static guint32 hf_isi_network_hsupa_available = -1;



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
		{ &hf_isi_network_data_sub_type,
		  { "Subpacket Type", "isi.network.sub.type", FT_UINT8, BASE_HEX, isi_network_status_sub_id, 0x0, "Subpacket Type", HFILL }},
		{ &hf_isi_network_status_sub_lac,
		  { "Location Area Code (LAC)", "isi.network.sub.lac", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, "Location Area Code (LAC)", HFILL }},
		{ &hf_isi_network_status_sub_cid,
		  { "Cell ID (CID)", "isi.network.sub.cid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, "Cell ID (CID)", HFILL }},
		{ &hf_isi_network_status_sub_msg_len,
		  { "Message Length", "isi.network.sub.msg", FT_UINT16, BASE_DEC, NULL, 0x0, "Message Length", HFILL }},
		{ &hf_isi_network_status_sub_msg,
		  { "Message", "isi.network.sub.msg", FT_STRING, BASE_NONE, NULL, 0x0, "Message", HFILL }},
		{ &hf_isi_network_operator_code,
		  { "Operator Code", "isi.network.sub.operator", FT_UINT24, BASE_HEX, NULL, 0x0, "Operator Code", HFILL }},
		{ &hf_isi_network_gsm_band_info,
		  { "GSM Band Info", "isi.network.gsm_band_info", FT_UINT8, BASE_HEX, isi_network_gsm_band_info, 0x0, "GSM Band Info", HFILL }},
		{ &hf_isi_network_gsm_band_900,
		  { "900 Mhz Band", "isi.network.sub.gsm_band_900", FT_BOOLEAN, 32, NULL, 0x00000001, "", HFILL }},
		{ &hf_isi_network_gsm_band_1800,
		  { "1800 Mhz Band", "isi.network.sub.gsm_band_1800", FT_BOOLEAN, 32, NULL, 0x00000002, "", HFILL }},
		{ &hf_isi_network_gsm_band_1900,
		  { "1900 Mhz Band", "isi.network.sub.gsm_band_1900", FT_BOOLEAN, 32, NULL, 0x00000004, "", HFILL }},
		{ &hf_isi_network_gsm_band_850,
		  { "850 Mhz Band", "isi.network.sub.gsm_band_850", FT_BOOLEAN, 32, NULL, 0x00000008, "", HFILL }},
		{ &hf_isi_network_rat_type,
		  { "RAT Type", "isi.network.rat.type", FT_UINT8, BASE_HEX, isi_network_rat_type, 0x0, "RAT Type", HFILL }},
		{ &hf_isi_network_rat_name,
		  { "RAT Name", "isi.network.rat.name", FT_UINT8, BASE_HEX, isi_network_rat_name, 0x0, "RAT Name", HFILL }},
		{ &hf_isi_network_success_code,
		  { "Success Code", "isi.network.success", FT_UINT8, BASE_HEX, isi_network_success_code, 0x0, "Success Code", HFILL }},
		{ &hf_isi_network_rat_info,
		  { "Additional Info", "isi.network.rat.info", FT_STRING, BASE_NONE, NULL, 0x0, "Additional Info", HFILL }},
		{ &hf_isi_network_uarfcn,
		  { "UARFCN", "isi.network.channel.uarfcn", FT_UINT16, BASE_DEC, NULL, 0x0, "UARFCN", HFILL }},
		{ &hf_isi_network_ciphering_status,
		  { "Ciphering Status", "isi.network.cipher.status", FT_UINT8, BASE_HEX, isi_network_ciphering_status, 0x0, "Ciphering Status", HFILL }},
		{ &hf_isi_network_ciphering_key_status,
		  { "Ciphering Key Status", "isi.network.cipher.keystatus", FT_UINT8, BASE_HEX, isi_network_ciphering_key_status, 0x0, "Ciphering Key Status", HFILL }},
		{ &hf_isi_network_ciphering_context,
		  { "Ciphering Context", "isi.network.cipher.context", FT_UINT8, BASE_HEX, isi_network_ciphering_context, 0x0, "Ciphering Context", HFILL }},
		{ &hf_isi_network_registration_status,
		  { "Registration Status", "isi.network.reg.status", FT_UINT8, BASE_HEX, isi_network_registration_status, 0x0, "Registration Status", HFILL }},
		{ &hf_isi_network_registration_protocol,
		  { "Registration Protocol", "isi.network.reg.protocol", FT_UINT8, BASE_HEX, NULL, 0x0, "Registration Protocol", HFILL }},
		{ &hf_isi_network_selection_mode,
		  { "Selection Mode", "isi.network.reg.selection_mode", FT_UINT8, BASE_HEX, isi_network_selection_mode, 0x0, "Selection Mode", HFILL }},
		{ &hf_isi_network_search_mode,
		  { "Search Mode", "isi.network.modem.search_mode", FT_UINT8, BASE_HEX, isi_network_search_mode, 0x0, "Search Mode", HFILL }},
		{ &hf_isi_network_cs_type,
		  { "CS Type", "isi.network.cs.type", FT_UINT8, BASE_HEX, isi_network_cs_type, 0x0, "CS Type", HFILL }},
		{ &hf_isi_network_cs_state,
		  { "CS State", "isi.network.cs.state", FT_UINT8, BASE_HEX, isi_network_cs_state, 0x0, "CS State", HFILL }},
		{ &hf_isi_network_cs_operation,
		  { "CS Operation", "isi.network.cs.operation", FT_UINT8, BASE_HEX, isi_network_cs_operation, 0x0, "CS Operation", HFILL }},
		{ &hf_isi_network_measurement_type,
		  { "Measurement Type", "isi.network.measurement", FT_UINT8, BASE_HEX, isi_network_measurement_type, 0x0, "Measurement", HFILL }},
		{ &hf_isi_network_rssi_bars,
		  { "Signal Strength (bars)", "isi.network.signal.bars", FT_UINT8, BASE_DEC, NULL, 0x0, "Signal Strength (Bars)", HFILL }},
		{ &hf_isi_network_rssi_db,
		  { "Signal Strength (dB)", "isi.network.signal.db", FT_UINT8, BASE_DEC, NULL, 0x0, "Signal Strength (dB)", HFILL }},
		{ &hf_isi_network_type,
		  { "Network Type", "isi.network.type", FT_UINT8, BASE_HEX, isi_network_type, 0x0, "Network Type", HFILL }},
		{ &hf_isi_network_service_status,
		  { "Service Status", "isi.network.status", FT_UINT8, BASE_HEX, NULL, 0x0, "Service Status", HFILL }},
		{ &hf_isi_network_name_type,
		  { "Name Type", "isi.network.oper.name.type", FT_UINT8, BASE_HEX, isi_network_name_type, 0x0, "Name Type", HFILL }},
		{ &hf_isi_network_country_initials,
		  { "Country Initials", "isi.network.oper.name.country", FT_UINT8, BASE_HEX, NULL, 0x0, "Coutry Initials", HFILL }},
		{ &hf_isi_network_cs_services,
		  { "CS Services", "isi.network.cell.cs_services", FT_UINT8, BASE_HEX, NULL, 0x0, "CS Services", HFILL }},
		{ &hf_isi_network_gprs_services,
		  { "GPRS Services", "isi.network.cell.gprs_services", FT_UINT8, BASE_HEX, NULL, 0x0, "GPRS Services", HFILL }},
		{ &hf_isi_network_egprs_support,
		  { "EGPRS Support", "isi.network.cell.egprs_support", FT_UINT8, BASE_HEX, NULL, 0x0, "EGPRS Support", HFILL }},
		{ &hf_isi_network_dtm_support,
		  { "DTM Support", "isi.network.cell.dtm_support", FT_UINT8, BASE_HEX, NULL, 0x0, "DTM Support", HFILL }},
		{ &hf_isi_network_current_rac,
		  { "Current RAC", "isi.network.cell.current_rac", FT_UINT8, BASE_HEX, NULL, 0x0, "Current RAC", HFILL }},
		{ &hf_isi_network_hdspa_available,
		  { "HDSPA Available", "isi.network.cell.hdspa_available", FT_UINT8, BASE_HEX, NULL, 0x0, "HDSPA Available", HFILL }},
		{ &hf_isi_network_hsupa_available,
		  { "HSUPA Available", "isi.network.cell.hsupa_available", FT_UINT8, BASE_HEX, NULL, 0x0, "HSUPA Available", HFILL }},
		{ &hf_isi_network_gprs_support,
		  { "GPRS Support", "isi.network.cell.gprs_support", FT_UINT8, BASE_HEX, NULL, 0x0, "GPRS Support", HFILL }},
		{ &hf_isi_network_gprs_mode,
		  { "GPRS Mode", "isi.network.cell.gprs_mode", FT_UINT8, BASE_HEX, NULL, 0x0, "GPRS Mode", HFILL }},
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

static void _sub_reg_info_common(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_registration_status, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_selection_mode, tvb, 3, 1, FALSE);
}

static void _sub_ciphering_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_ciphering_key_status, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_ciphering_context, tvb, 3, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_rat_name, tvb, 4, 2, FALSE);
}


static void _sub_modem_current_cell_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_status_sub_lac, tvb, 2, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_network_status_sub_cid, tvb, 4, 4, FALSE);
	proto_tree_add_item(tree, hf_isi_network_operator_code, tvb, 8, 3, FALSE);
	proto_tree_add_item(tree, hf_isi_network_gsm_band_info, tvb, 11, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_type, tvb, 12, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_gprs_support, tvb, 13, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_gprs_mode, tvb, 14, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_cs_services, tvb, 15, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_gprs_services, tvb, 16, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_egprs_support, tvb, 17, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_dtm_support, tvb, 17, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_current_rac, tvb, 18, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_hdspa_available, tvb, 19, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_hsupa_available, tvb, 20, 1, FALSE);
}

static void _sub_gsm_cell_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_status_sub_lac, tvb, 2, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_network_status_sub_cid, tvb, 4, 4, FALSE);
	proto_tree_add_bitmask_text(tree, tvb, 6, 4, "GSM Bands: ", "all bands, since none is selected", ett_isi_network_gsm_band_info, gsm_band_fields, FALSE, BMT_NO_FALSE | BMT_NO_TFS);
	// FIXME: proto_tree_add_item(tree, hf_isi_network_cell_info_sub_operator, tvb, offset, 3, FALSE);
}

static void _sub_wcdma_cell_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_status_sub_lac, tvb, 2, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_network_status_sub_cid, tvb, 4, 4, FALSE);
	// TODO: show wcdma bands
	proto_tree_add_item(tree, hf_isi_network_operator_code, tvb, 12, 3, FALSE);
	proto_tree_add_item(tree, hf_isi_network_service_status, tvb, 15, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_type, tvb, 16, 1, FALSE);
}

static void _sub_gsm_reg_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_status_sub_lac, tvb, 0, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_network_status_sub_cid, tvb, 4, 4, FALSE);
}

static void _sub_rat_info(tvbuff_t *tvb, proto_tree *tree) {
	guint8 extlen = tvb_get_guint8(tvb, 3);
	proto_tree_add_item(tree, hf_isi_network_rat_name, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_rat_info, tvb, 4, extlen, FALSE);
}

static void _sub_uarfcn_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_uarfcn, tvb, 2, 2, FALSE);
}

static void _sub_rssi_current(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_network_rssi_bars, tvb, 1, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_rssi_db, tvb, 2, 1, FALSE);
}

static void _sub_gsm_reg_network_info(tvbuff_t *tvb, proto_tree *tree) {
	guint8 l = tvb_get_guint8(tvb, 5);
	proto_tree_add_item(tree, hf_isi_network_name_type, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_network_country_initials, tvb, 3, 1, FALSE);
	char *utf16 = tvb_memdup(tvb, 6, l*2);
	char *ascii = utf16_to_ascii(utf16, l);
	proto_tree_add_string(tree, hf_isi_network_status_sub_msg, tvb, 6, l*2, ascii);
}

static void dissect_isi_network_subpacket(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x00: _sub_reg_info_common(tvb, tree); break;         /* NET_REG_INFO_COMMON */
		case 0x04: _sub_rssi_current(tvb, tree); break;            /* NET_RSSI_CURRENT */
		case 0x09: _sub_gsm_reg_info(tvb, tree); break;            /* NET_GSM_REG_INFO */
		case 0x28: _sub_uarfcn_info(tvb, tree); break;             /* NET_UARFCN_INFO */
		case 0x29: _sub_ciphering_info(tvb, tree); break;          /* NET_CIPHERING_INFO */
		case 0x2C: _sub_rat_info(tvb, tree); break;                /* NET_RAT_INFO */
		case 0x39: _sub_modem_current_cell_info(tvb, tree); break; /* NET_MODEM_CURRENT_CELL_INFO */
		case 0x46: _sub_gsm_cell_info(tvb, tree); break;           /* NET_GSM_CELL_INFO */
		case 0x47: _sub_wcdma_cell_info(tvb, tree); break;         /* NET_WCDMA_CELL_INFO */
		case 0xE3: _sub_gsm_reg_network_info(tvb, tree); break;    /* NET_GSM_REG_NETWORK_INFO */
		case 0x01: /* NET_MODEM_AVAIL_NETWORK_INFO_COMMON */
		case 0x02: /* NET_OPERATOR_INFO_COMMON */
		case 0x05: /* NET_TEST_CARRIER_PARAM */
		case 0x0B: /* NET_DETAILED_NETWORK_INFO */
		case 0x0C: /* NET_GSM_OPERATOR_INFO */
		case 0x0D: /* NET_GSM_HOME_CELLS_INFO */
		case 0x0E: /* NET_GSM_SIM_NMR_INFO */
		case 0x0F: /* NET_MODEM_CAUSE_EXTENSION */
		case 0x10: /* NET_TIME_INFO */
		case 0x11: /* NET_GSM_BAND_INFO */
		case 0x13: /* NET_RSSI_GSM_STRONGEST */
		case 0x15: /* NET_RESUME_INFO */
		case 0x17: /* NET_BAND_INFO */
		case 0x19: /* NET_LICENSE_BLOCK_INFO */
		case 0x2D: /* NET_TEST_WCDMA_PARMS */
		case 0x2E: /* NET_GSM_LCS_GPS_REF_TIME */
		case 0x2F: /* NET_GSM_LCS_GPS_REF_LOCATION */
		case 0x30: /* NET_GSM_LCS_GPS_DGPS_CORRECTIONS */
		case 0x31: /* NET_GSM_LCS_GPS_NAVIGATION */
		case 0x32: /* NET_GSM_LCS_GPS_IONOSPHERIC */
		case 0x33: /* NET_GSM_LCS_GPS_UTC */
		case 0x34: /* NET_GSM_LCS_GPS_ALMANAC */
		case 0x35: /* NET_GSM_LCS_GPS_AQUISITION */
		case 0x36: /* NET_GSM_LCS_GPS_BAD_SAT */
		case 0x37: /* NET_MODEM_UMA_SERVICE_ZONE_INFO */
		case 0x38: /* NET_UMA_FAILURE_INFO */
		case 0x3A: /* NET_GSM_LCS_SUPL */
		case 0x3B: /* NET_GSM_LCS_EXT_REF_IE */
		case 0x3C: /* NET_UTRAN_RADIO_INFO */
		case 0x3D: /* NET_UTRAN_SIM_NMR_INFO */
		case 0x3E: /* NET_ECID_GERAN_INFO */
		case 0x3F: /* NET_ECID_UTRAN_FDD_INFO */
		case 0x40: /* NET_TEST_GSM_SCAN_PARAMS */
		case 0x41: /* NET_TEST_WCDMA_SCAN_PARAMS */
		case 0x42: /* NET_TEST_GSM_HO_PARAMS */
		case 0x43: /* NET_TEST_WRAN_HO_PARAMS */
		case 0x44: /* NET_GSM_LCS_GPS_TIME_ASSIST_MEAS */
		case 0x45: /* NET_GSM_LCS_GPS_REF_TIME_UNC */
		case 0x48: /* NET_FULL_NITZ_NAME */
		case 0x49: /* NET_SHORT_NITZ_NAME */
		case 0xE1: /* NET_AVAIL_NETWORK_INFO_COMMON */
		case 0xE7: /* NET_OPER_NAME_INFO */
		default:
			   //proto_tree_add_item(tree, hf_isi_network_data_sub_type, tvb, 
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
			break;
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
			case 0x00: /* NET_MODEM_REG_STATUS_GET_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Registration Status Request");
				break;
			case 0x01: /* NET_MODEM_REG_STATUS_GET_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Registration Status Response");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x02: /* NET_MODEM_REG_STATUS_IND (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Registration Status Indication");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x03: /* NET_MODEM_AVAILABLE_GET_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Available Get Request");
				proto_tree_add_item(tree, hf_isi_network_search_mode, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x04: /* NET_MODEM_AVAILABLE_GET_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Available Get Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x05: /* NET_AVAILABLE_CANCEL_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Available Cancel Request");
				break;
			case 0x06: /* NET_AVAILABLE_CANCEL_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Modem Available Cancel Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				break;
			case 0x07: /* NET_SET_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Set Request");
				proto_tree_add_item(tree, hf_isi_network_registration_protocol, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x08: /* NET_SET_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Set Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x09: /* NET_SET_CANCEL_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Set Cancel Request");
				break;
			case 0x0A: /* NET_SET_CANCEL_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Set Cancel Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				break;
			case 0x0B: /* NET_RSSI_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RSSI Get Request");
				proto_tree_add_item(tree, hf_isi_network_cs_type, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_measurement_type, tvb, 2, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 7, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x0C: /* NET_RSSI_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RSSI Get Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x0D: /* NET_CS_CONTROL_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS Control Request");
				break;
			case 0x0E: /* NET_CS_CONTROL_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS Control Response");
				break;
			case 0x0F: /* NET_CS_WAKEUP_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS Wakeup Request");
				break;
			case 0x10: /* NET_CS_WAKEUP_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS Wakeup Response");
				break;
			case 0x11: /* NET_TEST_CARRIER_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Test Carrier Request");
				break;
			case 0x12: /* NET_TEST_CARRIER_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Test Carrier Response");
				break;
			case 0x19: /* NET_CS_STATE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS State Indication");
				proto_tree_add_item(tree, hf_isi_network_cs_state, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_cs_type, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_cs_operation, tvb, 3, 1, FALSE);
				break;
			case 0x1A: /* NET_NEIGHBOUR_CELLS_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Neighbour Cells Request");
				break;
			case 0x1B: /* NET_NEIGHBOUR_CELLS_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Neighbour Cells Response");
				break;
			case 0x1C: /* NET_NETWORK_SELECT_MODE_SET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Select Mode Set Request");
				break;
			case 0x1D: /* SIZE_NET_NETWORK_SELECT_MODE_SET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Select Mode Set Response");
				break;
			case 0x1E: /* NET_RSSI_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RSSI Indication");
				proto_tree_add_item(tree, hf_isi_network_rssi_bars, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_rssi_db, tvb, 2, 1, FALSE);
				break;
			case 0x20: /* NET_CIPHERING_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Ciphering Indication");
				proto_tree_add_item(tree, hf_isi_network_ciphering_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x27: /* NET_TIME_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Time Indication");
				break;
			case 0x28: /* NET_OLD_OPER_NAME_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Old Operator Name Read Request");
				break;
			case 0x29: /* NET_OLD_OPER_NAME_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Old Operator Name Read Response");
				break;
			case 0x2C: /* NET_CHANNEL_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Channel Info Indication");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x2D: /* NET_CHANNEL_INFO_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Channel Info Request");
				break;
			case 0x2E: /* NET_CHANNEL_INFO_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Channel Info Response");
				break;
			case 0x31: /* NET_GSM_LCS_LOCATION_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network GSM LCS Location Indication");
				break;
			case 0x32: /* NET_SIM_REFRESH_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network SIM Refresh Request");
				break;
			case 0x33: /* NET_SIM_REFRESH_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network SIM Refresh Response");
				break;
			case 0x34: /* NET_GSM_LCS_ASTNC_NTF */
				col_set_str(pinfo->cinfo, COL_INFO, "Network GSM LCS ASTNC NTF");
				break;
			case 0x35: /* NET_RAT_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RAT Indication");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x36: /* NET_RAT_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RAT Request");
                                proto_tree_add_item(tree, hf_isi_network_rat_type, tvb, 1, 1, FALSE);
				break;
			case 0x37: /* NET_RAT_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network RAT Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x38: /* NET_AGPS_FRAME_TRIGGER_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network AGPS Frame Trigger Request");
				break;
			case 0x39: /* NET_AGPS_FRAME_TRIGGER_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network AGPS Frame Trigger Response");
				break;
			case 0x3A: /* NET_CS_STATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS State Request");
				break;
			case 0x3B: /* NET_CS_STATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network CS State Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_cs_state, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_network_cs_operation, tvb, 3, 1, FALSE);
				break;
			case 0x3C: /* NET_UMA_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network UMA Info Indication");
				break;
			case 0x3D: /* NET_RRLP_SUPL_HANDLE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Netwrok RRLP SUPL Handle Request");
				break;
			case 0x3E: /* NET_RRLP_SUPL_HANDLE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Netwrok RRLP SUPL Handle Response");
				break;
			case 0x3F: /* NET_RADIO_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Radio Info Indication");
				break;
			case 0x40: /* NET_CELL_INFO_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Cell Info Get Request");
				break;
			case 0x41: /* NET_CELL_INFO_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Cell Info Get Response");
				break;
			case 0x42: /* NET_CELL_INFO_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Cell Info Indication");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0x43: /* NET_NITZ_NAME_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network NITZ Name Indication");
				break;
			case 0xE0: /* NET_REG_STATUS_GET_REQ (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Registration Status Get Request");
				break;
			case 0xE1: /* NET_REG_STATUS_GET_RESP (complete) */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Registration Status Get Response");
				proto_tree_add_item(tree, hf_isi_network_success_code, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0xE2: /* NET_REG_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Registration Status Indication");
				dissect_isi_subpacket(hf_isi_network_data_sub_type, 3, tvb, pinfo, item, tree, dissect_isi_network_subpacket);
				break;
			case 0xE3: /* NET_AVAILABLE_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Available Get Request");
				break;
			case 0xE4: /* NET_AVAILABLE_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Available Get Response");
				break;
			case 0xE5: /* NET_OPER_NAME_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Operator Name Read Request");
				break;
			case 0xE6: /* NET_OPER_NAME_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Network Operator Name Read Response");
				break;

			case 0xF0:
				dissect_isi_common("Network", tvb, pinfo, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Network packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}
