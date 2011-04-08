/* isi-light.c
 * Dissector for ISI's light resource
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
#include "isi-light.h"

static const value_string isi_light_id[] = {
	{0x01, "LIGHT_SETTINGS_READ_REQ"},
	{0x02, "LIGHT_SETTINGS_READ_RESP"},
	{0x03, "LIGHT_SETTINGS_WRITE_REQ"},
	{0x04, "LIGHT_SETTINGS_WRITE_RESP"},
	{0x05, "LIGHT_CONTROL_REQ"},
	{0x06, "LIGHT_CONTROL_RESP"},
	{0x07, "LIGHT_STATUS_CHANGED_IND"},
	{0x08, "LIGHT_ALC_READ_REQ"},
	{0x09, "LIGHT_ALC_READ_RESP"},
	{0x0E, "LIGHT_ALC_CALIB_REQ"},
	{0x0F, "LIGHT_ALC_CALIB_RESP"},
	{0x2F, "LIGHT_ALC_POLIWAG_CALIB_REQ"},
	{0x30, "LIGHT_ALC_POLIWAG_CALIB_RESP"},
	{0x2D, "LIGHT_ALC_HW_TYPE_REQ"},
	{0x2E, "LIGHT_ALC_HW_TYPE_RESP"},
	{0x0A, "LIGHT_ALC_TUNE_REQ"},
	{0x0B, "LIGHT_ALC_TUNE_RESP"},
	{0x0C, "LIGHT_ALC_TRIGGER_REQ"},
	{0x0D, "LIGHT_ALC_TRIGGER_RESP"},
	{0x10, "LIGHT_ALC_TRIGGER_IND"},
	{0x1A, "LIGHT_ALC_RC_CALIB_REQ"},
	{0x1B, "LIGHT_ALC_RC_CALIB_RESP"},
	{0x1C, "LIGHT_ALC_SAVE_CALIB_VALUE_REQ"},
	{0x1D, "LIGHT_ALC_SAVE_CALIB_VALUE_RESP"},
	{0x11, "LIGHT_DISCO_ENABLE_REQ"},
	{0x12, "LIGHT_DISCO_ENABLE_RESP"},
	{0x13, "LIGHT_DISCO_PATTERN_REQ"},
	{0x14, "LIGHT_DISCO_PATTERN_REQ"},
	{0x15, "LIGHT_DISCO_SEQUENCE_REQ"},
	{0x16, "LIGHT_DISCO_SEQUENCE_RESP"},
	{0x17, "LIGHT_DISCO_SEQUENCE_IND"},
	{0x18, "LIGHT_DISCO_COLOUR_REQ"},
	{0x19, "LIGHT_DISCO_COLOUR_RESP"},
	{0x20, "LIGHT_CHANNEL_REQ"},
	{0x21, "LIGHT_CHANNEL_RESP"},
	{0x1E, "LIGHT_INFO_QUERY_REQ"},
	{0x1F, "LIGHT_INFO_QUERY_RESP"},
	{0x22, "LIGHT_CONF_REQ"},
	{0x23, "LIGHT_CONF_RESP"},
	{0x24, "LIGHT_CHANNEL_SETTINGS_WRITE_REQ"},
	{0x25, "LIGHT_CHANNEL_SETTINGS_WRITE_RESP"},
	{0x26, "LIGHT_CHANNEL_SETTINGS_READ_REQ"},
	{0x27, "LIGHT_CHANNEL_SETTINGS_READ_RESP"},
	{0x28, "LIGHT_SEQUENCE_REQ"},
	{0x29, "LIGHT_SEQUENCE_RESP"},
	{0x2A, "LIGHT_SEQUENCE_NTF"},
	{0x2B, "LIGHT_SEQUENCE_CONF_REQ"},
	{0x2C, "LIGHT_SEQUENCE_CONF_RESP"},
	{0x31, "LIGHT_CALIBRATION_DATA_READ_REQ"},
	{0x32, "LIGHT_CALIBRATION_DATA_READ_RESP"},
	{0x33, "LIGHT_CALIBRATION_DATA_WRITE_REQ"},
	{0x34, "LIGHT_CALIBRATION_DATA_WRITE_RESP"},
	{0x35, "LIGHT_SELF_TEST_REQ"},
	{0x36, "LIGHT_SELF_TEST_RESP"},
	{0x37, "LIGHT_SEQUENCE_COLOUR_REQ"},
	{0x38, "LIGHT_SEQUENCE_COLOUR_RESP"},
	{0x39, "LIGHT_LYSTI_LED_TEST_REQ"},
	{0x3A, "LIGHT_LYSTI_LED_TEST_RESP"},
	{0x00, NULL}
};

static dissector_handle_t isi_light_handle;
static void dissect_isi_light(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_light_cmd = -1;


void proto_reg_handoff_isi_light(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_light_handle = create_dissector_handle(dissect_isi_light, proto_isi);
		dissector_add("isi.resource", 0x3A, isi_light_handle);
	}
}

void proto_register_isi_light(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_light_cmd,
			{ "Command", "isi.light.cmd", FT_UINT8, BASE_HEX, isi_light_id, 0x0, "Command", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.light", dissect_isi_light, proto_isi);
}


static void dissect_isi_light(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_light_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown Light packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}




