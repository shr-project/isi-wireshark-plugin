/* isi-nameservice.c
 * Dissector for ISI's Name Service resource
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
#include "isi-nameservice.h"

static const value_string isi_nameservice_id[] = {
	{0x01, "PNS_NAME_QUERY_REQ"},
	{0x02, "PNS_NAME_QUERY_RESP"},
	{0x03, "PNS_NAME_ADD_IND"},
	{0x04, "PNS_NAME_REMOVE_IND"},
	{0x05, "PNS_NAME_ADD_REQ"},
	{0x06, "PNS_NAME_ADD_RESP"},
	{0x07, "PNS_NAME_REMOVE_REQ"},
	{0x08, "PNS_NAME_REMOVE_RESP"},
	{0x00, NULL}
};

static const value_string isi_nameservice_reason[] = {
	{0x00, "PN_NAME_OK"},
	{0x01, "PN_NAME_NOT_ALLOWED"},
	{0x02, "PN_NAME_NO_ROOM"},
	{0x03, "PN_NAME_UNKNOWN"},
};

static dissector_handle_t isi_nameservice_handle;
static void dissect_isi_nameservice(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_nameservice_cmd = -1;
static guint32 hf_isi_nameservice_name = -1;
static guint32 hf_isi_nameservice_dev = -1;
static guint32 hf_isi_nameservice_obj = -1;
static guint32 hf_isi_nameservice_flags = -1;
static guint32 hf_isi_nameservice_reason = -1;
static guint32 hf_isi_nameservice_bitmask = -1;
static guint32 hf_isi_nameservice_matches_total = -1;
static guint32 hf_isi_nameservice_matches = -1;


void proto_reg_handoff_isi_nameservice(void) {
	static gboolean initialized=FALSE;

	if(!initialized) {
		isi_nameservice_handle = create_dissector_handle(dissect_isi_nameservice, proto_isi);
		dissector_add("isi.resource", 0xdb, isi_nameservice_handle);
	}
}

void proto_register_isi_nameservice(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_nameservice_cmd,
			{ "Command", "isi.nameservice.cmd", FT_UINT8, BASE_HEX, isi_nameservice_id, 0x0, "Command", HFILL }},
		{ &hf_isi_nameservice_name,
			{ "Name", "isi.nameservice.name", FT_UINT32, BASE_HEX, NULL, 0x0, "Name", HFILL }},
		{ &hf_isi_nameservice_dev,
			{ "Dev", "isi.nameservice.dev", FT_UINT8, BASE_HEX, NULL, 0x0, "Dev", HFILL }},
		{ &hf_isi_nameservice_obj,
			{ "Object", "isi.nameservice.obj", FT_UINT8, BASE_HEX, NULL, 0x0, "Object", HFILL }},
		{ &hf_isi_nameservice_flags,
			{ "Flags", "isi.nameservice.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "Flags", HFILL }},
		{ &hf_isi_nameservice_reason,
			{ "Reason", "isi.nameservice.reason", FT_UINT8, BASE_HEX, isi_nameservice_reason, 0x0, "Reason", HFILL }},
		{ &hf_isi_nameservice_bitmask,
			{ "Bitmask", "isi.nameservice.bitmask", FT_UINT32, BASE_HEX, NULL, 0x0, "Bitmask", HFILL }},
		{ &hf_isi_nameservice_matches_total,
			{ "Total Matches", "isi.nameservice.total_matches", FT_UINT16, BASE_DEC, NULL, 0x0, "Matches", HFILL }},
		{ &hf_isi_nameservice_matches,
			{ "Matches in Message", "isi.nameservice.matches_in_message", FT_UINT16, BASE_DEC, NULL, 0x0, "Matches", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.nameservice", dissect_isi_nameservice, proto_isi);
}

static void dissect_isi_nameservice_name(guint32 count, guint32 offset, tvbuff_t *tvb, packet_info *pinfo, proto_item *tree) {
	guint32 nr;
	for(nr = 0; nr < count; nr++, count--) {
		proto_item *subitem = proto_tree_add_text(tree, tvb, offset, 0x08, "Entry %d", nr + 1);
		proto_tree *subtree = proto_item_add_subtree(subitem, ett_isi_msg);
		proto_tree_add_item(subtree, hf_isi_nameservice_name, tvb, 3, 4, FALSE);
		proto_tree_add_item(subtree, hf_isi_nameservice_dev, tvb, 8, 1, FALSE);
		proto_tree_add_item(subtree, hf_isi_nameservice_obj, tvb, 9, 1, FALSE);
		proto_tree_add_item(subtree, hf_isi_nameservice_flags, tvb, 10, 1, FALSE);
	}
}


static void dissect_isi_nameservice(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_nameservice_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x01: /* PNS_NAME_QUERY_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Query Request");
				proto_tree_add_item(tree, hf_isi_nameservice_name, tvb, 3, 4, FALSE);
				proto_tree_add_item(tree, hf_isi_nameservice_bitmask, tvb, 8, 4, FALSE);
				break;
			case 0x02: /* PNS_NAME_QUERY_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Query Response");
				proto_tree_add_item(tree, hf_isi_nameservice_matches_total, tvb, 1, 2, FALSE);
				proto_tree_add_item(tree, hf_isi_nameservice_matches, tvb, 3, 2, FALSE);
				dissect_isi_nameservice_name(hf_isi_nameservice_matches, 5, tvb, pinfo, tree);
				break;
			case 0x03: /* PNS_NAME_ADD_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Add Indication");
				proto_tree_add_item(tree, hf_isi_nameservice_matches_total, tvb, 1, 2, FALSE);
				proto_tree_add_item(tree, hf_isi_nameservice_matches, tvb, 3, 2, FALSE);
				dissect_isi_nameservice_name(hf_isi_nameservice_matches, 5, tvb, pinfo, tree);
				break;
			case 0x04: /* PNS_NAME_REMOVE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Remove Indication");
				proto_tree_add_item(tree, hf_isi_nameservice_matches_total, tvb, 1, 2, FALSE);
				proto_tree_add_item(tree, hf_isi_nameservice_matches, tvb, 3, 2, FALSE);
				dissect_isi_nameservice_name(hf_isi_nameservice_matches, 5, tvb, pinfo, tree);
				break;
			case 0x05: /* PNS_NAME_ADD_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Add Request");
                                dissect_isi_nameservice_name(1, 5, tvb, pinfo, tree);
				break;
			case 0x06: /* PNS_NAME_ADD_RESPONSE */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Add Response");
				proto_tree_add_item(tree, hf_isi_nameservice_reason, tvb, 1, 1, FALSE);
				break;
			case 0x07: /* PNS_NAME_REMOVE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Remove Request");
				proto_tree_add_item(tree, hf_isi_nameservice_name, tvb, 3, 4, FALSE);
				break;
			case 0x08: /* PNS_NAME_REMOVE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Remove Response");
				proto_tree_add_item(tree, hf_isi_nameservice_reason, tvb, 1, 1, FALSE);
				break;

			case 0xF0: /* COMMON_MESSAGE */
				dissect_isi_common("Nameservice", tvb, pinfo, tree);
				break;

			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Nameservice packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}

