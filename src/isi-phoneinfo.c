/* isi-phoneinfo.c
 * Dissector for ISI's phone info resource
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
#include "isi-phoneinfo.h"

static const value_string isi_phoneinfo_id[] = {
	{0x00, "INFO_SERIAL_NUMBER_READ_REQ"},
	{0x01, "INFO_SERIAL_NUMBER_READ_RESP"},
	{0x0f, "INFO_PP_CUSTOMER_DEFAULTS_REQ"},
	{0x10, "INFO_PP_CUSTOMER_DEFAULTS_RESP"},
	{0x02, "INFO_PP_READ_REQ"},
	{0x03, "INFO_PP_READ_RESP"},
	{0x04, "INFO_PP_WRITE_REQ"},
	{0x05, "INFO_PP_WRITE_RESP"},
	{0x06, "INFO_PP_IND"},
	{0x29, "INFO_PP_DATA_READ_REQ"},
	{0x2a, "INFO_PP_DATA_READ_RESP"},
	{0x2b, "INFO_PP_DATA_WRITE_REQ"},
	{0x2c, "INFO_PP_DATA_WRITE_RESP"},
	{0x2d, "INFO_PP_DATA_IND"},
	{0x07, "INFO_VERSION_READ_REQ"},
	{0x08, "INFO_VERSION_READ_RESP"},
	{0x09, "INFO_VERSION_WRITE_REQ"},
	{0x0a, "INFO_VERSION_WRITE_RESP"},
	{0x0b, "INFO_PROD_INFO_READ_REQ"},
	{0x0c, "INFO_PROD_INFO_READ_RESP"},
	{0x0d, "INFO_PROD_INFO_WRITE_REQ"},
	{0x0e, "INFO_PROD_INFO_WRITE_RESP"},
	{0x11, "INFO_PRODUCT_TYPE_WRITE_REQ"},
	{0x12, "INFO_PRODUCT_TYPE_WRITE_RESP"},
	{0x13, "INFO_PRODUCT_TYPE_READ_REQ"},
	{0x14, "INFO_PRODUCT_TYPE_READ_RESP"},
	{0x15, "INFO_PRODUCT_INFO_READ_REQ"},
	{0x16, "INFO_PRODUCT_INFO_READ_RESP"},
	{0x19, "INFO_BT_ID_WRITE_REQ"},
	{0x1a, "INFO_BT_ID_WRITE_RESP"},
	{0x17, "INFO_BT_ID_READ_REQ"},
	{0x18, "INFO_BT_ID_READ_RESP"},
	{0x1b, "INFO_WT_READ_REQ"},
	{0x1c, "INFO_WT_READ_RESP"},
	{0x1d, "INFO_WT_WRITE_REQ"},
	{0x1e, "INFO_WT_WRITE_RESP"},
	{0x1f, "INFO_LONG_DATA_READ_REQ"},
	{0x20, "INFO_LONG_DATA_READ_RESP"},
	{0x21, "INFO_LONG_DATA_WRITE_REQ"},
	{0x22, "INFO_LONG_DATA_WRITE_RESP"},
	{0x23, "INFO_WLAN_INFO_READ_REQ"},
	{0x24, "INFO_WLAN_INFO_READ_RESP"},
	{0x25, "INFO_IP_PASSTHROUGH_READ_REQ"},
	{0x26, "INFO_IP_PASSTHROUGH_READ_RESP"},
	{0x27, "INFO_WLAN_INFO_WRITE_REQ"},
	{0x28, "INFO_WLAN_INFO_WRITE_RESP"},
	{0x2e, "INFO_WLAN_INFO_WRITE_RESP"},
	{0x2f, "INFO_PRODUCT_RAT_BAND_READ_RESP"},
	{0x30, "INFO_PRODUCT_RAT_BAND_WRITE_REQ"},
	{0x31, "INFO_PRODUCT_RAT_BAND_WRITE_RESP"},
	{0x00, NULL}
};

static dissector_handle_t isi_phoneinfo_handle;
static void dissect_isi_phoneinfo(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_phoneinfo_cmd = -1;


void proto_reg_handoff_isi_phoneinfo(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_phoneinfo_handle = create_dissector_handle(dissect_isi_phoneinfo, proto_isi);
		dissector_add("isi.resource", 0x1b, isi_phoneinfo_handle);
	}
}

void proto_register_isi_phoneinfo(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_phoneinfo_cmd,
			{ "Command", "isi.phoneinfo.cmd", FT_UINT8, BASE_HEX, isi_phoneinfo_id, 0x0, "Command", HFILL }}
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.phoneinfo", dissect_isi_phoneinfo, proto_isi);
}


static void dissect_isi_phoneinfo(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_phoneinfo_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0xF0: /* COMMON_MESSAGE */
				dissect_isi_common("PhoneInfo", tvb, pinfo, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown PhoneInfo packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}



