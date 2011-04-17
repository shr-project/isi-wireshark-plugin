/* isi-commgr.c
 * Dissector for ISI's commgr resource
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
#include "isi-commgr.h"

static const value_string isi_commgr_id[] = {
	{0x10, "PNS_SUBSCRIBED_RESOURCES_IND"},
	{0x11, "PNS_SUBSCRIBED_RESOURCES_PMM_IND"},
	{0x12, "PNS_SUBSCRIBED_RESOURCES_EXTEND_IND"},
	{0x13, "PNS_SUBSCRIBED_RESOURCES_PMM_EXTEND_IND"},
	{0x00, NULL}
};


static dissector_handle_t isi_commgr_handle;
static void dissect_isi_commgr(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_commgr_cmd = -1;
static guint32 hf_isi_commgr_resource_count = -1;


void proto_reg_handoff_isi_commgr(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_commgr_handle = create_dissector_handle(dissect_isi_commgr, proto_isi);
		dissector_add("isi.resource", 0x10, isi_commgr_handle);
	}
}

void proto_register_isi_commgr(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_commgr_cmd,
			{ "Command", "isi.commgr.cmd", FT_UINT8, BASE_HEX, isi_commgr_id, 0x0, "Command", HFILL }},
		{ &hf_isi_commgr_resource_count,
			{ "Resource-Count", "isi.commgr.resource_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Resource-Count", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.commgr", dissect_isi_commgr, proto_isi);
}

static void _show_resources(tvbuff_t *tvb, proto_tree *tree) {
	guint8 cnt, f;

	cnt = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_isi_commgr_resource_count, tvb, 1, 1, FALSE);
	for(f = 0; f < cnt; f++) {
		proto_tree_add_item(tree, hf_isi_res, tvb, 2+f, 1, FALSE);
	}
}

static void dissect_isi_commgr(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_commgr_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x10: /* PNS_SUBSCRIBED_RESOURCES_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Subscribed Resources Indication");
				_show_resources(tvb, tree);
				break;
			case 0x11: /* PNS_SUBSCRIBED_RESOURCES_PMM_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Subscribed Resources PMM Indication");
				_show_resources(tvb, tree);
				break;
			case 0x12: /* PNS_SUBSCRIBED_RESOURCES_EXTEND_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Subscribed Resources Extended Indication");
				_show_resources(tvb, tree);
				break;
			case 0x13: /* PNS_SUBSCRIBED_RESOURCES_PMM_EXTEND_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "Subscribed Resources PMM Extended Indication");
				_show_resources(tvb, tree);
				break;

			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Indication packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}



