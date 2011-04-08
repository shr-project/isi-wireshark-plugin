/* isi-nameservice.c
 * Dissector for ISI's Radio Settings resource
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
#include "isi-radiosettings.h"

static const value_string isi_radiosettings_id[] = {
	{0x00, NULL}
};

static dissector_handle_t isi_radiosettings_handle;
static void dissect_isi_radiosettings(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_radiosettings_cmd = -1;


void proto_reg_handoff_isi_radiosettings(void) {
	static gboolean initialized=FALSE;

	if(!initialized) {
		isi_radiosettings_handle = create_dissector_handle(dissect_isi_radiosettings, proto_isi);
		dissector_add("isi.resource", 0xB4, isi_radiosettings_handle);
	}
}

void proto_register_isi_radiosettings(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_radiosettings_cmd,
			{ "Command", "isi.radiosettings.cmd", FT_UINT8, BASE_HEX, isi_radiosettings_id, 0x0, "Command", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.radiosettings", dissect_isi_radiosettings, proto_isi);
}


static void dissect_isi_radiosettings(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_radiosettings_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Radio Settings packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}

