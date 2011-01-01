/* isi-simauth.c
 * Dissector for ISI's SIM resource
 * Copyright 2010, Tyson Key <tyson.key@gmail.com>
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



static dissector_handle_t isi_sim_handle;
static void dissect_isi_sim(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_sim_message_id = -1;
static guint32 hf_isi_sim_service_type = -1;

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
		  { "Service Type", "isi.sim.service_type", FT_UINT8, BASE_HEX, isi_sim_service_type, 0x0, "Service Type", HFILL }}

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

			case 0x1D: /* SIM_IMSI_REQ_READ_IMSI isi_sim_service_type */
				proto_tree_add_item(tree, hf_isi_sim_service_type, tvb, 1, 1, FALSE);
				code = tvb_get_guint8(tvb, 1);
				switch(code) {
					case 0x2D: //READ_IMSI
						col_set_str(pinfo->cinfo, COL_INFO, "Read IMSI");
						break;
					default:
						col_set_str(pinfo->cinfo, COL_INFO, "unknown SIM packet");
						break;
				}
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
				break;
		}
	}
}
