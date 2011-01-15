/* isi-ss.c
 * Dissector for ISI's General Stack Server resource
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
#include "isi-gss.h"

static const value_string isi_gss_message_id[] = {
	{0x00, "GSS_CS_SERVICE_REQ"},
	{0x01, "GSS_CS_SERVICE_RESP"},
	{0x02, "GSS_CS_SERVICE_FAIL_RESP"},
	{0xF0, "COMMON_MESSAGE"},
};

static const value_string isi_gss_subblock[] = {
	{0x0B, "GSS_RAT_INFO"},
};

static const value_string isi_gss_operation[] = {
	{0x0E, "GSS_SELECTED_RAT_WRITE"},
	{0x9C, "GSS_SELECTED_RAT_READ"},
};

static const value_string isi_gss_cause[] = {
	{0x01, "GSS_SERVICE_FAIL"},
	{0x02, "GSS_SERVICE_NOT_ALLOWED"},
	{0x03, "GSS_SERVICE_FAIL_CS_INACTIVE"},
};

static const value_string isi_gss_common_message_id[] = {
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
};

static dissector_handle_t isi_gss_handle;
static void dissect_isi_gss(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_gss_message_id = -1;
static guint32 hf_isi_gss_subblock = -1;
static guint32 hf_isi_gss_operation = -1;
static guint32 hf_isi_gss_subblock_count = -1;
static guint32 hf_isi_gss_cause = -1;
static guint32 hf_isi_gss_common_message_id = -1;

void proto_reg_handoff_isi_gss(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_gss_handle = create_dissector_handle(dissect_isi_gss, proto_isi);
		dissector_add("isi.resource", 0x32, isi_gss_handle);
	}
}

void proto_register_isi_gss(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_gss_message_id,
		  { "Message ID", "isi.gss.msg_id", FT_UINT8, BASE_HEX, isi_gss_message_id, 0x0, "Message ID", HFILL }},
		{ &hf_isi_gss_subblock,
		  { "Subblock", "isi.gss.subblock", FT_UINT8, BASE_HEX, isi_gss_subblock, 0x0, "Subblock", HFILL }},
		{ &hf_isi_gss_operation,
		  { "Operation", "isi.gss.operation", FT_UINT8, BASE_HEX, isi_gss_operation, 0x0, "Operation", HFILL }},
		{ &hf_isi_gss_subblock_count,
		  { "Subblock Count", "isi.gss.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock Count", HFILL }},
		{ &hf_isi_gss_cause,
		  { "Cause", "isi.gss.cause", FT_UINT8, BASE_HEX, isi_gss_cause, 0x0, "Cause", HFILL }},
		{ &hf_isi_gss_common_message_id,
		  { "Common Message ID", "isi.gss.common.msg_id", FT_UINT8, BASE_HEX, isi_gss_common_message_id, 0x0, "Common Message ID", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.gss", dissect_isi_gss, proto_isi);
}

static void dissect_isi_gss(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_gss_message_id, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch(cmd) {
			case 0x00: /* GSS_CS_SERVICE_REQ */
				proto_tree_add_item(tree, hf_isi_gss_operation, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x0E:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Radio Access Type Write");
						break;

					case 0x9C:
						proto_tree_add_item(tree, hf_isi_gss_subblock_count, tvb, 2, 1, FALSE);
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request: Radio Access Type Read");
						break;

					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Request");
						break;
				}
				break;

			case 0x01: /* GSS_CS_SERVICE_RESP */
				//proto_tree_add_item(tree, hf_isi_gss_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					//case 0x9C:
					//	col_set_str(pinfo->cinfo, COL_INFO, "Network Information Request: Read Home PLMN");
					//	break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Response");
						break;
				}
				break;

			case 0x02: /* GSS_CS_SERVICE_FAIL_RESP */
				proto_tree_add_item(tree, hf_isi_gss_operation, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gss_cause, tvb, 2, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x9C:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response: Radio Access Type Read");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "Service Failed Response");
						break;
				}
				break;

			case 0xF0: /* Common Message */
				proto_tree_add_item(tree, hf_isi_gss_common_message_id, tvb, 1, 1, FALSE);
				//proto_tree_add_item(tree, hf_isi_gss_cause, tvb, 2, 1, FALSE);
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
