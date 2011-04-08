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

#include <epan/dissectors/packet-e212.h>
#include <epan/bitswap.h>

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
	{0xC0, "SIM_STATUS_REQ"},
	{0xC1, "SIM_STATUS_RESP"},
	{0xDC, "SIM_PB_REQ_SIM_PB_READ"},
	{0xDD, "SIM_PB_RESP_SIM_PB_READ"},
	{0xED, "SIM_SERVER_READY_IND"},
	{0xEF, "SIM_IND"},
	{0xF0, "SIM_COMMON_MESSAGE"},
	{0x00, NULL}
};

static const value_string isi_sim_service_type[] = {
	{0x00, "SIM_ST_CARD_STATUS"},
	{0x01, "SIM_ST_PIN"},
	{0x05, "SIM_ST_ALL_SERVICES"},
	{0x0D, "SIM_ST_INFO"},
	{0x0F, "SIM_PB_READ"},
	{0x15, "SIM_ST_CAT_SUPPORT_ENABLE"},
	{0x16, "SIM_ST_CAT_SUPPORT_DISABLE"},
	{0x2C, "SIM_ST_READ_SERV_PROV_NAME"},
	{0x2D, "READ_IMSI"},
	{0x2F, "READ_HPLMN"},
	{0x35, "READ_DYN_FLAGS"},
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

static const value_string isi_sim_pb_subblock[] = {
	{0xE4, "SIM_PB_INFO_REQUEST"},
	{0xFB, "SIM_PB_STATUS"},
	{0xFE, "SIM_PB_LOCATION"},
	{0xFF, "SIM_PB_LOCATION_SEARCH"},
};

static const value_string isi_sim_pb_type[] = {
	{0xC8, "SIM_PB_ADN"},
};

static const value_string isi_sim_pb_tag[] = {
	{0xCA, "SIM_PB_ANR"},
	{0xDD, "SIM_PB_EMAIL"},
	{0xF7, "SIM_PB_SNE"},
};

static dissector_handle_t isi_sim_handle;
static void dissect_isi_sim(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_sim_message_id = -1;
static guint32 hf_isi_sim_service_type = -1;
static guint32 hf_isi_sim_cause = -1;
static guint32 hf_isi_sim_secondary_cause = -1;

static int hf_isi_sim_subblock_count = -1;
static int hf_isi_sim_subblock_size = -1;

static guint32 hf_isi_sim_pb_subblock = -1;
static guint32 hf_isi_sim_pb_type = -1;
static guint32 hf_isi_sim_pb_location = -1;
static guint32 hf_isi_sim_pb_tag_count = -1;
static guint32 hf_isi_sim_pb_tag = -1;

/* static int hf_isi_sim_imsi_byte_1 = -1;
static int hf_isi_sim_imsi_byte_2 = -1; */

tvbuff_t *next_tvb;
int reported_length, available_length;

static int hf_isi_sim_imsi_length = -1;

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
		  {&hf_isi_sim_subblock_count,
		  { "Subblock Count", "isi.sim.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock Count", HFILL }},
		  {&hf_isi_sim_subblock_size,
		  { "Subblock Size", "isi.sim.subblock_size", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock Size", HFILL }},
		  { &hf_isi_sim_pb_subblock,
		  { "Subblock", "isi.sim.pb.subblock", FT_UINT8, BASE_HEX, isi_sim_pb_subblock, 0x0, "Subblock", HFILL }},
		  { &hf_isi_sim_pb_type,
		  { "Phonebook Type", "isi.sim.pb.type", FT_UINT8, BASE_HEX, isi_sim_pb_type, 0x0, "Phonebook Type", HFILL }},
		  {&hf_isi_sim_pb_location,
		  { "Phonebook Location", "isi.sim.pb.location", FT_UINT8, BASE_DEC, NULL, 0x0, "Phonebook Location", HFILL }},
		  {&hf_isi_sim_pb_tag_count,
		  { "Tag Count", "isi.sim.pb.tag.count", FT_UINT8, BASE_DEC, NULL, 0x0, "Tag Count", HFILL }},
		  { &hf_isi_sim_pb_tag,
		  { "Phonebook Item Type", "isi.sim.pb.tag", FT_UINT8, BASE_HEX, isi_sim_pb_tag, 0x0, "Phonebook Item Type", HFILL }},
		  /* {&hf_isi_sim_imsi_byte_1,
		  { "IMSI Byte 1", "isi.sim.imsi.byte1", FT_UINT16, BASE_HEX, NULL, 0xF0, NULL, HFILL }},*/
		  {&hf_isi_sim_imsi_length,
		  { "IMSI Length", "isi.sim.imsi.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
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
						dissect_e212_mcc_mnc(tvb, pinfo, tree, 3, 1);
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

				/* If properly decoded, an IMSI should look like 234 100 733569423 in split Base10

				0000   1e 2d 01 08 | 29 43 01 | 70 33 65 49 32
						     92 34 10 | 07 33 56 94 23
						     
				Switch 0x29 to produce 0x92

				AND 0x92 with 0xF0 to strip the leading 9

				Switch 0x43 to produce 0x34

				Concatenate 0x02 and 0x34 to produce 0x02 34 - which is our MCC for the UK

				Switch 0x01 to produce 0x10 - first byte of the MNC

				Switch 0x70 to produce 0x07 - second bit of the MNC, and first bit of the MSIN

				Remainder of MSIN follows:

				Switch 0x33 to produce 0x33 

				Switch 0x65 to produce 0x56 

				Switch 0x49 to produce 0x94

				Switch 0x32 to produce 0x23

				When regrouped, we should have something that looks like 0x02|0x34|0x10|0x07|0x33|0x56|0x94|0x23

				Can we use the E212 dissector? 
				  No, it appears that the current version of the dissector is hard-coded in a way that ignores all of our set-up work. :(

				*/

				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					default:
						proto_tree_add_item(tree, hf_isi_sim_imsi_length, tvb, 3, 1, FALSE);

						/*
						next_tvb = tvb_new_subset(tvb, 0, -1, -1);
						proto_tree_add_item(tree, hf_isi_sim_imsi_byte_1, next_tvb, 4, 1, ENC_LITTLE_ENDIAN);
						dissect_e212_mcc_mnc(next_tvb, pinfo, tree, 4, FALSE );  
						proto_tree_add_item(tree, hf_E212_msin, tvb, 2, 7, FALSE);

						*/

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
			  
				/* A phonebook record in a typical O2 UK SIM card issued in 2009 can hold:

				 * A name encoded in UTF-16/UCS-2 - up to 18 (or 15 double-byte/accented) characters can be entered on an S60 device
				 * Up to 2 telephone numbers - up to 2 * 20 (or 40-1 field) characters can be entered on an S60 device
				 * An e-mail address encoded in UTF-16/UCS-2 - up to 40 characters can be entered on an S60 device
 
				 Up to 250 of these records can be stored, and 9 of them are pre-populated on a brand new card.

				*/
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_subblock_count, tvb, 2, 2, ENC_LITTLE_ENDIAN); 
				proto_tree_add_item(tree, hf_isi_sim_pb_subblock, tvb, 4, 1, FALSE);

				//Should probably be 8, and not 2048... Officially starts/ends at 5/3, I think.
				proto_tree_add_item(tree, hf_isi_sim_subblock_size, tvb, 6, 2, ENC_LITTLE_ENDIAN);  

				proto_tree_add_item(tree, hf_isi_sim_pb_type, tvb, 8, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_pb_location, tvb, 9, 2, FALSE);

				proto_tree_add_item(tree, hf_isi_sim_pb_subblock, tvb, 12, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_subblock_count, tvb, 13, 2, ENC_BIG_ENDIAN);

				proto_tree_add_item(tree, hf_isi_sim_pb_tag_count, tvb, 15, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_pb_type, tvb, 18, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 20, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 22, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_sim_pb_tag, tvb, 24, 1, FALSE);

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

			case 0xF0: /* COMMON_MESSAGE */
				dissect_isi_common("SIM", tvb, pinfo, tree);
				break;

			default:
				col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
				break;
		}
	}
}
