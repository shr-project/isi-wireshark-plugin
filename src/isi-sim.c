/* isi-simauth.c
 * Dissector for ISI's SIM resource
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
#include "isi-sim.h"

static const value_string isi_sim_message_id[] = {
	{0x19, "SIM_NETWORK_INFO_REQ"},
	{0x1A, "SIM_NETWORK_INFO_RESP"},
	{0x1D, "SIM_IMSI_REQ_READ_IMSI"},
	{0x1E, "SIM_IMSI_RESP_READ_IMSI"},
	{0x21, "SIM_SERV_PROV_NAME_REQ"},
	{0x22, "SIM_SERV_PROV_NAME_RESP"},
	{0xBA, "SIM_READ_FIELD_REQ"},
	{0xBB, "SIM_READ_FIELD_RESP"},
	{0xBC, "SIM_SMS_REQ"},
	{0xBD, "SIM_SMS_RESP"},
	{0xDC, "SIM_PB_REQ_SIM_PB_READ"},
	{0xDD, "SIM_PB_RESP_SIM_PB_READ"},
	{0xEF, "SIM_IND"},
	{0xF0, "SIM_COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_sim_service_type[] = {
	{0x01, "SIM_ST_PIN"},
	{0x05, "SIM_ST_ALL_SERVICES"},
	{0x0D, "SIM_ST_INFO"},
	{0x2C, "SIM_ST_READ_SERV_PROV_NAME"},
	{0x0F, "SIM_PB_READ"},
	{0x2D, "READ_IMSI"},
	{0x2F, "READ_HPLMN"},
	{0x52, "READ_PARAMETER"},
	{0x53, "UPDATE_PARAMETER"},
	{0x66, "ICC"},
	{0x00, NULL}
};

static const value_string isi_sim_cause[] = {
	{0x00, "SIM_SERV_NOT_AVAIL"},
	{0x01, "SIM_SERV_OK"},
	{0x02, "SIM_SERV_PIN_VERIFY_REQUIRED"},
	{0x03, "SIM_SERV_PIN_REQUIRED"},
	{0x04, "SIM_SERV_SIM_BLOCKED"},
	{0x05, "SIM_SERV_SIM_PERMANENTLY_BLOCKED"},
	{0x06, "SIM_SERV_SIM_DISCONNECTED"},
	{0x07, "SIM_SERV_SIM_REJECTED"},
	{0x08, "SIM_SERV_LOCK_ACTIVE"},
	{0x09, "SIM_SERV_AUTOLOCK_CLOSED"},
	{0x0A, "SIM_SERV_AUTOLOCK_ERROR"},
	{0x0B, "SIM_SERV_INIT_OK"},
	{0x0C, "SIM_SERV_INIT_NOT_OK"},
	{0x0D, "SIM_SERV_WRONG_OLD_PIN"},
	{0x0E, "SIM_SERV_PIN_DISABLED"},
	{0x0F, "SIM_SERV_COMMUNICATION_ERROR"},
	{0x10, "SIM_SERV_UPDATE_IMPOSSIBLE"},
	{0x11, "SIM_SERV_NO_SECRET_CODE_IN_SIM"},
	{0x12, "SIM_SERV_PIN_ENABLE_OK"},
	{0x13, "SIM_SERV_PIN_DISABLE_OK"},
	{0x15, "SIM_SERV_WRONG_UNBLOCKING_KEY"},
	{0x2E, "SIM_SERV_ILLEGAL_NUMBER"},
	{0x1C, "SIM_SERV_NOT_OK"},
	{0x1E, "SIM_SERV_PN_LIST_ENABLE_OK"},
	{0x1F, "SIM_SERV_PN_LIST_DISABLE_OK"},
	{0x20, "SIM_SERV_NO_PIN"},
	{0x21, "SIM_SERV_PIN_VERIFY_OK"},
	{0x22, "SIM_SERV_PIN_BLOCKED"},
	{0x23, "SIM_SERV_PIN_PERM_BLOCKED"},
	{0x24, "SIM_SERV_DATA_NOT_AVAIL"},
	{0x25, "SIM_SERV_IN_HOME_ZONE"},
	{0x27, "SIM_SERV_STATE_CHANGED"},
	{0x28, "SIM_SERV_INF_NBR_READ_OK"},
	{0x29, "SIM_SERV_INF_NBR_READ_NOT_OK"},
	{0x2A, "SIM_SERV_IMSI_EQUAL"},
	{0x2B, "SIM_SERV_IMSI_NOT_EQUAL"},
	{0x2C, "SIM_SERV_INVALID_LOCATION"},
	{0x35, "SIM_SERV_STA_SIM_REMOVED"},
	{0x36, "SIM_SERV_SECOND_SIM_REMOVED_CS"},
	{0x37, "SIM_SERV_CONNECTED_INDICATION_CS"},
	{0x38, "SIM_SERV_SECOND_SIM_CONNECTED_CS"},
	{0x39, "SIM_SERV_PIN_RIGHTS_LOST_IND_CS"},
	{0x3A, "SIM_SERV_PIN_RIGHTS_GRANTED_IND_CS"},
	{0x3B, "SIM_SERV_INIT_OK_CS"},
	{0x3C, "SIM_SERV_INIT_NOT_OK_CS"},
	{0x19, "SIM_FDN_ENABLED"},
	{0x1A, "SIM_FDN_DISABLED"},
	{0x45, "SIM_SERV_INVALID_FILE"},
	{0x4F, "SIM_SERV_DATA_AVAIL"},
	{0x49, "SIM_SERV_ICC_EQUAL"},
	{0x4A, "SIM_SERV_ICC_NOT_EQUAL"},
	{0x4B, "SIM_SERV_SIM_NOT_INITIALISED"},
	{0x50, "SIM_SERV_SERVICE_NOT_AVAIL"},
	{0x57, "SIM_SERV_FDN_STATUS_ERROR"},
	{0x58, "SIM_SERV_FDN_CHECK_PASSED"},
	{0x59, "SIM_SERV_FDN_CHECK_FAILED"},
	{0x5A, "SIM_SERV_FDN_CHECK_DISABLED"},
	{0x5B, "SIM_SERV_FDN_CHECK_NO_FDN_SIM"},
	{0x5C, "SIM_STA_ISIM_AVAILABLE_PIN_REQUIRED"},
	{0x5D, "SIM_STA_ISIM_AVAILABLE"},
	{0x5E, "SIM_STA_USIM_AVAILABLE"},
	{0x5F, "SIM_STA_SIM_AVAILABLE"},
	{0x60, "SIM_STA_ISIM_NOT_INITIALISED"},
	{0x61, "SIM_STA_IMS_READY"},
	{0x96, "SIM_STA_APP_DATA_READ_OK"},
	{0x97, "SIM_STA_APP_ACTIVATE_OK"},
	{0x98, "SIM_STA_APP_ACTIVATE_NOT_OK"},
	{0xF9, "SIM_SERV_NOT_DEFINED"},
	{0xFA, "SIM_SERV_NOSERVICE"},
	{0xFB, "SIM_SERV_NOTREADY"},
	{0xFC, "SIM_SERV_ERROR"},
	{0x30, "SIM_SERV_CIPHERING_INDICATOR_DISPLAY_REQUIRED"},
	{0x31, "SIM_SERV_CIPHERING_INDICATOR_DISPLAY_NOT_REQUIRED"},
	{0x4D, "SIM_SERV_FILE_NOT_AVAILABLE"}
};

static const value_string isi_sim_hlpmn_countries[] = {
	{0x32F4, "United Kingdom (234)"}
};

static const value_string isi_sim_hlpmn_operators[] = {
	{0x01, "O2 - UK (10)"},
	{0x02, "3 UK (20)"},
	{0x33, "Orange UK (33)"},
};


static dissector_handle_t isi_sim_handle;
static void dissect_isi_sim(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_sim_message_id = -1;
static guint32 hf_isi_sim_service_type = -1;
static guint32 hf_isi_sim_cause = -1;
static guint32 hf_isi_sim_secondary_cause = -1;
static guint32 hf_isi_sim_hlpmn_countries = -1;
static guint32 hf_isi_sim_hlpmn_operators = -1;

void proto_reg_handoff_isi_sim(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_sim_handle = create_dissector_handle(dissect_isi_sim, proto_isi);
		dissector_add("isi.resource", 0x09, isi_sim_handle);
	}
}

void proto_register_isi_sim(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_sim_message_id,
		  { "Message ID", "isi.sim.msg_id", FT_UINT8, BASE_HEX, isi_sim_message_id, 0x0, "Message ID", HFILL }},
		  { &hf_isi_sim_service_type,
		  { "Service Type", "isi.sim.service_type", FT_UINT8, BASE_HEX, isi_sim_service_type, 0x0, "Service Type", HFILL }},
		  { &hf_isi_sim_cause,
		  { "Cause", "isi.sim.cause", FT_UINT8, BASE_HEX, isi_sim_cause, 0x0, "Cause", HFILL }},
		  { &hf_isi_sim_secondary_cause,
		  { "Secondary Cause", "isi.sim.secondary_cause", FT_UINT8, BASE_HEX, isi_sim_cause, 0x0, "Secondary Cause", HFILL }},
		  { &hf_isi_sim_hlpmn_countries,
		  { "Country", "isi.sim.hlpmn_country", FT_UINT16, BASE_HEX, isi_sim_hlpmn_countries, 0x0, "Country", HFILL }},
		  { &hf_isi_sim_hlpmn_operators,
		  { "Operator", "isi.sim.hlpmn_operator", FT_UINT8, BASE_HEX, isi_sim_hlpmn_operators, 0x0, "Operator", HFILL }}

	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.sim", dissect_isi_sim, proto_isi);
}

static void dissect_isi_sim(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_sim_message_id, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch(cmd) {
		  
			case 0x19: /* SIM_NETWORK_INFO_REQ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x2F:
						col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request");
						break;
				}
				break;

			case 0x1A: /* SIM_NETWORK_INFO_RESP */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 2, 1, FALSE);

				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x2F:
						proto_tree_add_item(tree, hf_isi_sim_hlpmn_countries, tvb, 3, 2, FALSE);
						proto_tree_add_item(tree, hf_isi_sim_hlpmn_operators, tvb, 5, 1, FALSE);
				
						col_set_str(pinfo->cinfo, COL_INFO, "Network Information Response: Home PLMN");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Network Information Response");
						break;
				}
				break;
				
			case 0x1D: /* SIM_IMSI_REQ_READ_IMSI */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Read IMSI Request");
						break;
				}
				break;

			case 0x1E: /* SIM_IMSI_RESP_READ_IMSI */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Read IMSI Response");
						break;
				}
				break;
				
			case 0x21: /* SIM_SERV_PROV_NAME_REQ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Request");
						break;
				}
				break;
				
			case 0x22: /* SIM_SERV_PROV_NAME_RESP */
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
					case 0x2c:
						proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 1, 1, FALSE);
						proto_tree_add_item(tree, hf_isi_sim_secondary_cause, tvb, 2, 1, FALSE);
						col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Response: Invalid Location");
						break;
						col_set_str(pinfo->cinfo, COL_INFO, "Service Provider Name Response");
						break;
				}
				break;
				
			case 0xBA: /* SIM_READ_FIELD_REQ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x66:
						col_set_str(pinfo->cinfo, COL_INFO, "Read Field Request: Integrated Circuit Card Identification (ICCID)");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Read Field Request");
						break;
				}
				break;
				
			case 0xBB: /* SIM_READ_FIELD_RESP */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x66:
						proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 2, 1, FALSE);
						col_set_str(pinfo->cinfo, COL_INFO, "Read Field Response: Integrated Circuit Card Identification (ICCID)");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Read Field Response");
						break;
				}
				break;
				
			case 0xBC: /* SIM_SMS_REQ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Request");
						break;
				}
				break;
				
			case 0xBD: /* SIM_SMS_RESP */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "SMS Response");
						break;
				}
				break;

			case 0xDC: /* SIM_PB_REQ_SIM_PB_READ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Phonebook Read Request");
						break;
				}
				break;

			case 0xDD: /* SIM_PB_RESP_SIM_PB_READ */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Phonebook Read Response");
						break;
				}
				break;
				
			case 0xEF: /* SIM_IND */
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Indicator");
						break;
				}
				break;
				
			case 0xF0: /* SIM_COMMON_MESSAGE */
				proto_tree_add_item(tree, hf_isi_sim_cause, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_secondary_cause, tvb, 2, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x00:
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: SIM Server Not Available");
						break;
					case 0x12:
						col_set_str(pinfo->cinfo, COL_INFO, "Common Message: PIN Enable OK");
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
