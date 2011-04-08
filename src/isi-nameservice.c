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

static dissector_handle_t isi_nameservice_handle;
static void dissect_isi_nameservice(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_nameservice_cmd = -1;


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
			{ "Command", "isi.nameservice.cmd", FT_UINT8, BASE_HEX, isi_nameservice_id, 0x0, "Command", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.nameservice", dissect_isi_nameservice, proto_isi);
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
			case 0x05: /* PNS_NAME_ADD_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Nameservice Add ");
				break;

			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Nameservice packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}

