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
	{0x2e, "INFO_PRODUCT_RAT_BAND_READ_REQ"},
	{0x2f, "INFO_PRODUCT_RAT_BAND_READ_RESP"},
	{0x30, "INFO_PRODUCT_RAT_BAND_WRITE_REQ"},
	{0x31, "INFO_PRODUCT_RAT_BAND_WRITE_RESP"},
	{0x00, NULL}
};

static const value_string isi_phoneinfo_sub_id[] = {
	{0x41, "INFO_SB_SN_IMEI_PLAIN"},
	{0x42, "INFO_SB_SN_IMEI_SPARE_TO_NET"},
	{0x44, "INFO_SB_SN_ESN_PLAIN"},
	{0x45, "INFO_SB_SN_ESN_HEX"},
	{0x56, "INFO_SB_SN_ESNX_PLAIN"},
	{0x5A, "INFO_SB_SN_ESNX_HEX"},
	{0x61, "INFO_SB_SN_MEID_HEX"},
	{0x62, "INFO_SB_SN_MEID_HEX_ASCII"},
	{0x80, "INFO_SB_SN_MEID_PLAIN"},
	{0x46, "INFO_SB_SN_PDC"},
	{0x48, "INFO_SB_MCUSW_VERSION"},
	{0x5B, "INFO_SB_BT_MCM_VERSION"},
	{0x49, "INFO_SB_HW_VERSION"},
	{0x4A, "INFO_SB_PCI_VERSION"},
	{0x4B, "INFO_SB_UEM_VERSION"},
	{0x4C, "INFO_SB_UPP_VERSION"},
	{0x54, "INFO_SB_RFIC_VERSION"},
	{0x77, "INFO_SB_BOM_ID"},
	{0x55, "INFO_SB_DSP_VERSION"},
	{0x5F, "INFO_SB_ADSP_VERSION"},
	{0x65, "INFO_SB_ADSP_DEVICE_ID"},
	{0x66, "INFO_SB_ADSP_REVISION_ID"},
	{0x64, "INFO_SB_VERSION_BY_DSP_CORE_SRV"},
	{0x58, "INFO_SB_PPM_VERSION"},
	{0x47, "INFO_SB_PP"},
	{0x74, "INFO_SB_PP_DATA"},
	{0x4D, "INFO_SB_PRODUCTION_SN"},
	{0x59, "INFO_SB_LONG_PRODUCTION_SN"},
	{0x4E, "INFO_SB_PRODUCT_CODE"},
	{0x4F, "INFO_SB_BASIC_PRODUCT_CODE"},
	{0x50, "INFO_SB_MODULE_CODE"},
	{0x51, "INFO_SB_FLASH_CODE"},
	{0x52, "INFO_SB_ORDER_NUMBER"},
	{0x53, "INFO_SB_PRODUCT_SPECIFIC_DATA"},
	{0x5C, "INFO_SB_ATO"},
	{0x5D, "INFO_SB_SN_DEFAULT"},
	{0x5E, "INFO_SB_SN_DEFAULT_TYPE"},
	{0x67, "INFO_SB_BAND_CS_TYPE"},
	{0x63, "INFO_SB_SN_DEFAULT_PLAIN"},
	{0x03, "INFO_SB_PRODUCT_TYPE_CS_SEC"},
	{0x01, "INFO_SB_PRODUCT_TYPE_CS"},
	{0x02, "INFO_SB_PRODUCT_TYPE_HW_INFO"},
	{0x01, "INFO_SB_PRODUCT_INFO_NAME"},
	{0x02, "INFO_SB_PRODUCT_INFO_CATEGORY"},
	{0x03, "INFO_SB_PRODUCT_INFO_XID"},
	{0x04, "INFO_SB_PRODUCT_INFO_DEV_NAME"},
	{0x05, "INFO_SB_PRODUCT_INFO_COMP01"},
	{0x06, "INFO_SB_PRODUCT_INFO_NAME_COMPRESSED"},
	{0x07, "INFO_SB_PRODUCT_INFO_MANUFACTURER"},
	{0x08, "INFO_SB_PRODUCT_INFO_XCVR_ID"},
	{0x09, "INFO_SB_PRODUCT_INFO_NUM_ID"},
	{0x0A, "INFO_SB_PRODUCT_INFO_TYPE_ID"},
	{0x0B, "INFO_SB_USB_VENDOR_ID"},
	{0x0C, "INFO_SB_USB_MASS_ID"},
	{0x0D, "INFO_SB_USB_NOKIA_ID"},
	{0x0E, "INFO_SB_USB_SICD_ID"},
	{0x10, "INFO_SB_USB_RNDIS_ID"},
	{0x0F, "INFO_SB_BT_PID"},
	{0x01, "INFO_SB_BT_ID_PLAIN"},
	{0x02, "INFO_SB_BT_ID_SEC"},
	{0x01, "INFO_SB_WT_ORIG_SN_INFO"},
	{0x02, "INFO_SB_WT_ORIG_MAN_MONTH_YEAR"},
	{0x03, "INFO_SB_WT_OWN_MAN_MONTH_YEAR"},
	{0x04, "INFO_SB_WT_REPAIR_MONTH_YEAR"},
	{0x05, "INFO_SB_WT_PURCH_MONTH_YEAR"},
	{0x06, "INFO_SB_WT_WIS"},
	{0x07, "INFO_SB_WT_RPF"},
	{0x6C, "INFO_SB_RETU_VER"},
	{0x6D, "INFO_SB_TAHVO_VER"},
	{0x73, "INFO_SB_RAP_VERSION"},
	{0x60, "INFO_SB_PRODUCT_VARIANT_NUMBER"},
	{0x76, "INFO_SB_GAZOO"},
	{0x00, NULL}
};

static const value_string isi_phoneinfo_product_target[] = {
	{0x01, "INFO_PRODUCT_NAME"},
	{0x02, "INFO_PRODUCT_CATEGORY"},
	{0x03, "INFO_PRODUCT_XID"},
	{0x04, "INFO_PRODUCT_DEV_NAME"},
	{0x05, "INFO_PRODUCT_COMP01"},
	{0x06, "INFO_PRODUCT_NAME_COMPRESSED"},
	{0x07, "INFO_PRODUCT_MANUFACTURER"},
	{0x08, "INFO_PRODUCT_XCVR_ID"},
	{0x09, "INFO_PRODUCT_NUM_ID"},
	{0x0A, "INFO_PRODUCT_TYPE_ID"},
	{0x0B, "INFO_USB_VENDOR_ID"},
	{0x0C, "INFO_USB_MASS_ID"},
	{0x0D, "INFO_USB_NOKIA_ID"},
	{0x0E, "INFO_USB_SICD_ID"},
	{0x0F, "INFO_BT_PID"},
	{0x10, "INFO_USB_RNDIS_ID"},
	{0x00, NULL}
};

static const value_string isi_phoneinfo_status[] = {
	{0x00, "INFO_OK"},
	{0x01, "INFO_FAIL"},
	{0x02, "INFO_NO_NUMBER"},
	{0x03, "INFO_NOT_SUPPORTED"},
	{0x00, NULL}
};

static const value_string isi_phoneinfo_snr_type[] = {
	{0x41, "INFO_SN_IMEI_PLAIN"},
	{0x42, "INFO_SN_IMEI_SPARE_TO_NET"},
	{0x43, "INFO_SN_IMEI_SV_TO_NET"},
	{0x44, "INFO_SN_ESN_PLAIN"},
	{0x56, "INFO_SN_ESNX_PLAIN"},
	{0x45, "INFO_SN_ESN_HEX"},
	{0x5A, "INFO_SN_ESNX_HEX"},
	{0x46, "INFO_SN_PDC"},
	{0x5D, "INFO_SN_DEFAULT"},
	{0x5E, "INFO_SN_DEFAULT_PLAIN"},
	{0x61, "INFO_SN_MEID_HEX"},
	{0x62, "INFO_SN_MEID_HEX_ASCII"},
	{0x63, "INFO_SN_MEID_PLAIN"},
	{0x00, NULL}
};

static value_string isi_phoneinfo_version_target[] = {
	{0x0001, "INFO_MCUSW"},
	{0x0002, "INFO_HW"},
	{0x0004, "INFO_PCI"},
	{0x0008, "INFO_UEM"},
	{0x0010, "INFO_UPP"},
	{0x0020, "INFO_RFIC"},
	{0x0040, "INFO_DSP"},
	{0x0080, "INFO_LCD"},
	{0x0100, "INFO_PPM"},
	{0x0200, "INFO_BT_MCM"},
	{0x0400, "INFO_ADSP"},
	{0x1000, "INFO_FLIP_MCUSW"},
	{0x2000, "INFO_ADSP_DEVICE_ID"},
	{0x4000, "INFO_ADSP_REVISION_ID"},
	{0x8000, "INFO_GAZOO"},
	{0x0000, NULL}
};

static value_string isi_phoneinfo_version_target2[] = {
	{0x00000001, "INFO_BOOTCODE_VER"},
	{0x00000002, "INFO_APE_SW_CORE_VER"},
	{0x00000004, "INFO_VARIANT_VER"},
	{0x00000008, "INFO_APE_TEST_VER"},
	{0x00000010, "INFO_RETU"},
	{0x00000020, "INFO_TAHVO"},
	{0x00000040, "INFO_APE_HW_VERSION"},
	{0x00000080, "INFO_APE_ADSP_SW"},
	{0x00000100, "INFO_CAMERA"},
	{0x00000200, "INFO_APE_BT_VERSION"},
	{0x00000400, "INFO_CONTENT_PACK"},
	{0x00000800, "INFO_RAP"},
	{0x00001000, "INFO_APE_CUI_LCD_VERSION"},
	{0x00002000, "INFO_APE_IPDC_VERSION"},
	{0x00004000, "INFO_APE_DVB_H_RX_HW_VER"},
	{0x00008000, "INFO_APE_DVB_H_RX_SW_VER"},
	{0x00010000, "INFO_APE_DVB_H_RX_BOOTLOADER_VER"},
	{0x00020000, "INFO_CAMERA2"},
	{0x00040000, "INFO_CONTENT_VERSIONS"},
	{0x00080000, "INFO_ROFS_VERSIONS"},
	{0x00100000, "INFO_BOM_ID_VERSION"},
	{0x00200000, "INFO_NAVISCROLL_VERSION"},
	{0x00400000, "INFO_ACCELEROMETER_VERSION"},
	{0x00000000, NULL}
};

static dissector_handle_t isi_phoneinfo_handle;
static void dissect_isi_phoneinfo(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_phoneinfo_cmd = -1;
static guint32 hf_isi_phoneinfo_status = -1;
static guint32 hf_isi_phoneinfo_product_target = -1;
static guint32 hf_isi_phoneinfo_subblock_count = -1;
static guint32 hf_isi_phoneinfo_subblock_type = -1;
static guint32 hf_isi_phoneinfo_subblock_length = -1;
static guint32 hf_isi_phoneinfo_subblock_value = -1;
static guint32 hf_isi_phoneinfo_snr_type = -1;
static guint32 hf_isi_phoneinfo_version_target = -1;
static guint32 hf_isi_phoneinfo_version_target2 = -1;
static guint32 hf_isi_phoneinfo_version = -1;
static guint32 hf_isi_phoneinfo_serial = -1;


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
			{ "Command", "isi.phoneinfo.cmd", FT_UINT8, BASE_HEX, isi_phoneinfo_id, 0x0, "Command", HFILL }},
		{ &hf_isi_phoneinfo_status,
			{ "Status", "isi.phoneinfo.status", FT_UINT8, BASE_HEX, isi_phoneinfo_status, 0x0, "Status", HFILL }},
		{ &hf_isi_phoneinfo_product_target,
			{ "Target", "isi.phoneinfo.target", FT_UINT8, BASE_HEX, isi_phoneinfo_product_target, 0x0, "Target", HFILL }},
		{ &hf_isi_phoneinfo_subblock_count,
			{ "Subblock-Count", "isi.phoneinfo.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock-Count", HFILL }},
		{ &hf_isi_phoneinfo_subblock_type,
			{ "Subblock-Type", "isi.phoneinfo.subblock.type", FT_UINT8, BASE_HEX, isi_phoneinfo_sub_id, 0x0, "Subblock-Type", HFILL }},
		{ &hf_isi_phoneinfo_subblock_length,
			{ "Length", "isi.phoneinfo.subblock.length", FT_UINT8, BASE_DEC, NULL, 0x0, "Length", HFILL }},
		{ &hf_isi_phoneinfo_subblock_value,
			{ "Value", "isi.phoneinfo.subblock.value", FT_STRING, BASE_NONE, NULL, 0x0, "Value", HFILL }},
		{ &hf_isi_phoneinfo_snr_type,
			{ "SN-Type", "isi.phoneinfo.sn.type", FT_UINT8, BASE_HEX, isi_phoneinfo_snr_type, 0x0, "SN-Type", HFILL }},
		{ &hf_isi_phoneinfo_version_target,
			{ "Version-Target", "isi.phoneinfo.version.target", FT_UINT16, BASE_HEX, isi_phoneinfo_version_target, 0x0, "Version-Target", HFILL }},
		{ &hf_isi_phoneinfo_version_target2,
			{ "Version-Target 2", "isi.phoneinfo.version.target2", FT_UINT32, BASE_HEX, isi_phoneinfo_version_target2, 0x0, "Version-Target 2", HFILL }},
		{ &hf_isi_phoneinfo_version,
			{ "Version-String", "isi.phoneinfo.version.string", FT_STRING, BASE_NONE, NULL, 0x0, "Version-String", HFILL }},
		{ &hf_isi_phoneinfo_serial,
			{ "Serial-Nr", "isi.phoneinfo.serial", FT_STRING, BASE_NONE, NULL, 0x0, "Serial-nr", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.phoneinfo", dissect_isi_phoneinfo, proto_isi);
}



static void _sub_sb_string(tvbuff_t *tvb, proto_tree *tree, guint8 offset, guint32 hf) {
	guint8 l = tvb_get_guint8(tvb, offset);
	proto_tree_add_string(tree, hf, tvb, offset+1, l, tvb_memdup(tvb, offset+1, l));
}


static void dissect_isi_phoneinfo_subpacket_wt(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x01: /* INFO_SB_WT_ORIG_SN_INFO */
		case 0x02: /* INFO_SB_WT_ORIG_MAN_MONTH_YEAR */
		case 0x03: /* INFO_SB_WT_OWN_MAN_MONTH_YEAR */
		case 0x04: /* INFO_SB_WT_REPAIR_MONTH_YEAR */
		case 0x05: /* INFO_SB_WT_PURCH_MONTH_YEAR */
		case 0x06: /* INFO_SB_WT_WIS */
		case 0x07: /* INFO_SB_WT_RPF */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock (wt)");
			break;
	}
}

static void dissect_isi_phoneinfo_subpacket_cs(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {

		case 0x01: /* INFO_SB_PRODUCT_TYPE_CS */
		case 0x02: /* INFO_SB_PRODUCT_TYPE_HW_INFO */
		case 0x03: /* INFO_SB_PRODUCT_TYPE_CS_SEC */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock (cs)");
			break;
	}
}

static void dissect_isi_phoneinfo_subpacket_product(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x01: /* INFO_SB_PRODUCT_INFO_NAME */
		case 0x02: /* INFO_SB_PRODUCT_INFO_CATEGORY */
		case 0x03: /* INFO_SB_PRODUCT_INFO_XID */
		case 0x04: /* INFO_SB_PRODUCT_INFO_DEV_NAME */
		case 0x05: /* INFO_SB_PRODUCT_INFO_COMP01 */
		case 0x06: /* INFO_SB_PRODUCT_INFO_NAME_COMPRESSED */
		case 0x07: /* INFO_SB_PRODUCT_INFO_MANUFACTURER */
		case 0x08: /* INFO_SB_PRODUCT_INFO_XCVR_ID */
		case 0x09: /* INFO_SB_PRODUCT_INFO_NUM_ID */
		case 0x0A: /* INFO_SB_PRODUCT_INFO_TYPE_ID */
		case 0x0B: /* INFO_SB_USB_VENDOR_ID */
		case 0x0C: /* INFO_SB_USB_MASS_ID */
		case 0x0D: /* INFO_SB_USB_NOKIA_ID */
		case 0x0E: /* INFO_SB_USB_SICD_ID */
		case 0x10: /* INFO_SB_USB_RNDIS_ID */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock (product)");
			break;
	}
}

static void dissect_isi_phoneinfo_subpacket_bt(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x01: /* INFO_SB_BT_ID_PLAIN */
		case 0x02: /* INFO_SB_BT_ID_SEC */
		case 0x0F: /* INFO_SB_BT_PID */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock (bt)");
			break;
	}
}

static void dissect_isi_phoneinfo_subpacket(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x41: _sub_sb_string(tvb, tree, 3, hf_isi_phoneinfo_serial); break;   /* INFO_SB_SN_IMEI_PLAIN */
		case 0x48: _sub_sb_string(tvb, tree, 3, hf_isi_phoneinfo_version); break;  /* INFO_SB_MCUSW_VERSION */
		case 0x64: /* INFO_SB_VERSION_BY_DSP_CORE_SRV */
			   proto_tree_add_item(tree, hf_isi_phoneinfo_version_target, tvb, 2, 2, FALSE);
			   proto_tree_add_item(tree, hf_isi_phoneinfo_product_target, tvb, 4, 1, FALSE);
			   _sub_sb_string(tvb, tree, 5, hf_isi_phoneinfo_version);
			   break;

		case 0x42: /* INFO_SB_SN_IMEI_SPARE_TO_NET */
		case 0x43: /* INFO_SB_SN_IMEI_SV_TO_NET */
		case 0x44: /* INFO_SB_SN_ESN_PLAIN */
		case 0x45: /* INFO_SB_SN_ESN_HEX */
		case 0x46: /* INFO_SB_SN_PDC */
		case 0x47: /* INFO_SB_PP */
		case 0x49: /* INFO_SB_HW_VERSION */
		case 0x4A: /* INFO_SB_PCI_VERSION */
		case 0x4B: /* INFO_SB_UEM_VERSION */
		case 0x4C: /* INFO_SB_UPP_VERSION */
		case 0x4D: /* INFO_SB_PRODUCTION_SN */
		case 0x4E: /* INFO_SB_PRODUCT_CODE */
		case 0x4F: /* INFO_SB_BASIC_PRODUCT_CODE */
		case 0x50: /* INFO_SB_MODULE_CODE */
		case 0x51: /* INFO_SB_FLASH_CODE */
		case 0x52: /* INFO_SB_ORDER_NUMBER */
		case 0x53: /* INFO_SB_PRODUCT_SPECIFIC_DATA */
		case 0x54: /* INFO_SB_RFIC_VERSION */
		case 0x55: /* INFO_SB_DSP_VERSION */
		case 0x56: /* INFO_SB_SN_ESNX_PLAIN */
		case 0x57: /* INFO_SB_LCD_VERSION */
		case 0x58: /* INFO_SB_PPM_VERSION */
		case 0x59: /* INFO_SB_LONG_PRODUCTION_SN */
		case 0x5A: /* INFO_SB_SN_ESNX_HEX */
		case 0x5B: /* INFO_SB_BT_MCM_VERSION */
		case 0x5C: /* INFO_SB_ATO */
		case 0x5D: /* INFO_SB_SN_DEFAULT */
		case 0x5E: /* INFO_SB_SN_DEFAULT_TYPE */
		case 0x5F: /* INFO_SB_ADSP_VERSION */
		case 0x60: /* INFO_SB_PRODUCT_VARIANT_NUMBER */
		case 0x61: /* INFO_SB_SN_MEID_HEX */
		case 0x62: /* INFO_SB_SN_MEID_HEX_ASCII */
		// case 0x62: /* INFO_SB_FLIP_MCUSW_VERSION */
		case 0x63: /* INFO_SB_SN_DEFAULT_PLAIN */
		case 0x65: /* INFO_SB_ADSP_DEVICE_ID */
		case 0x66: /* INFO_SB_ADSP_REVISION_ID */
		case 0x67: /* INFO_SB_BAND_CS_TYPE */
		case 0x68: /* INFO_SB_BOOTCODE_VER */
		case 0x69: /* INFO_SB_APE_SW_CORE_VER */
		case 0x6A: /* INFO_SB_VARIANT_VER */
		case 0x6B: /* INFO_SB_APE_TEST_VER */
		case 0x6C: /* INFO_SB_RETU_VER */
		case 0x6D: /* INFO_SB_TAHVO_VER */
		case 0x6E: /* INFO_SB_APE_HW_VERSION */
		case 0x6F: /* INFO_SB_APE_ADSP_SW */
		case 0x70: /* INFO_SB_CAMERA_VER */
		case 0x71: /* INFO_SB_APE_BT_VERSION */
		case 0x72: /* INFO_SB_CONTENT_PACK_VER */
		case 0x73: /* INFO_SB_RAP_VERSION */
		case 0x74: /* INFO_SB_PP_DATA */
		case 0x75: /* INFO_SB_CAMERA_DETAILED_VERSION_INFO */
		case 0x76: /* INFO_SB_GAZOO */
		case 0x77: /* INFO_SB_BOM_ID */
		case 0x80: /* INFO_SB_SN_MEID_PLAIN */
		case 0x9F: /* INFO_SB_APE_CUI_LCD_VERSION */
		case 0xA1: /* INFO_SB_APE_IPDC_VERSION */
		case 0xA2: /* INFO_SB_APE_DVB_H_RX_HW_VER */
		case 0xA3: /* INFO_SB_APE_DVB_H_RX_SW_VER */
		case 0xA4: /* INFO_SB_APE_DVB_H_RX_BOOTLOADER_VER */
		case 0xA5: /* INFO_SB_CONTENT_VERSIONS */
		case 0xA6: /* INFO_SB_ROFS_VERSION */
		case 0xA7: /* INFO_SB_NAVISCROLL_VERSION */
		case 0xA8: /* INFO_SB_ACCELEROMETER_VERSION */
		//case 0xF000: /* INFO_SB_RAT_BAND_INFO */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock");
			break;
	}
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
			case 0x00: /* INFO_SERIAL_NUMBER_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Serial Number Read Request");
				proto_tree_add_item(tree, hf_isi_phoneinfo_snr_type, tvb, 1, 1, FALSE);
				break;
			case 0x01: /* INFO_SERIAL_NUMBER_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Serial Number Read Response");
				proto_tree_add_item(tree, hf_isi_phoneinfo_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_phoneinfo_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_phoneinfo_subpacket);
				break;
			case 0x07: /* INFO_VERSION_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Version Read Request");
				proto_tree_add_item(tree, hf_isi_phoneinfo_version_target, tvb, 1, 2, FALSE);
				proto_tree_add_item(tree, hf_isi_phoneinfo_version_target2, tvb, 3, 4, FALSE);
				break;
			case 0x08: /* INFO_VERSION_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Version Read Response");
				proto_tree_add_item(tree, hf_isi_phoneinfo_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_phoneinfo_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_phoneinfo_subpacket);
				break;
			case 0x15: /* INFO_PRODUCT_INFO_READ_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Product Info Read Request");
				proto_tree_add_item(tree, hf_isi_phoneinfo_product_target, tvb, 1, 1, FALSE);
				break;
			case 0x16: /* INFO_PRODUCT_INFO_READ_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Product Info Read Response");
				proto_tree_add_item(tree, hf_isi_phoneinfo_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_phoneinfo_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_phoneinfo_subpacket); 
				break;

			case 0xF0: /* COMMON_MESSAGE */
				dissect_isi_common("PhoneInfo", tvb, pinfo, tree);
				break;

			case 0x0f: /* INFO_PP_CUSTOMER_DEFAULTS_REQ */
			case 0x10: /* INFO_PP_CUSTOMER_DEFAULTS_RESP */
			case 0x02: /* INFO_PP_READ_REQ */
			case 0x03: /* INFO_PP_READ_RESP */
			case 0x04: /* INFO_PP_WRITE_REQ */
			case 0x05: /* INFO_PP_WRITE_RESP */
			case 0x06: /* INFO_PP_IND */
			case 0x29: /* INFO_PP_DATA_READ_REQ */
			case 0x2a: /* INFO_PP_DATA_READ_RESP */
			case 0x2b: /* INFO_PP_DATA_WRITE_REQ */
			case 0x2c: /* INFO_PP_DATA_WRITE_RESP */
			case 0x2d: /* INFO_PP_DATA_IND */
			case 0x09: /* INFO_VERSION_WRITE_REQ */
			case 0x0a: /* INFO_VERSION_WRITE_RESP */
			case 0x0b: /* INFO_PROD_INFO_READ_REQ */
			case 0x0c: /* INFO_PROD_INFO_READ_RESP */
			case 0x0d: /* INFO_PROD_INFO_WRITE_REQ */
			case 0x0e: /* INFO_PROD_INFO_WRITE_RESP */
			case 0x11: /* INFO_PRODUCT_TYPE_WRITE_REQ */
			case 0x12: /* INFO_PRODUCT_TYPE_WRITE_RESP */
			case 0x13: /* INFO_PRODUCT_TYPE_READ_REQ */
			case 0x14: /* INFO_PRODUCT_TYPE_READ_RESP */
			case 0x19: /* INFO_BT_ID_WRITE_REQ */
			case 0x1a: /* INFO_BT_ID_WRITE_RESP */
			case 0x17: /* INFO_BT_ID_READ_REQ */
			case 0x18: /* INFO_BT_ID_READ_RESP */
			case 0x1b: /* INFO_WT_READ_REQ */
			case 0x1c: /* INFO_WT_READ_RESP */
			case 0x1d: /* INFO_WT_WRITE_REQ */
			case 0x1e: /* INFO_WT_WRITE_RESP */
			case 0x1f: /* INFO_LONG_DATA_READ_REQ */
			case 0x20: /* INFO_LONG_DATA_READ_RESP */
			case 0x21: /* INFO_LONG_DATA_WRITE_REQ */
			case 0x22: /* INFO_LONG_DATA_WRITE_RESP */
			case 0x23: /* INFO_WLAN_INFO_READ_REQ */
			case 0x24: /* INFO_WLAN_INFO_READ_RESP */
			case 0x25: /* INFO_IP_PASSTHROUGH_READ_REQ */
			case 0x26: /* INFO_IP_PASSTHROUGH_READ_RESP */
			case 0x27: /* INFO_WLAN_INFO_WRITE_REQ */
			case 0x28: /* INFO_WLAN_INFO_WRITE_RESP */
			case 0x2e: /* INFO_PRODUCT_RAT_BAND_READ_REQ */
			case 0x2f: /* INFO_PRODUCT_RAT_BAND_READ_RESP */
			case 0x30: /* INFO_PRODUCT_RAT_BAND_WRITE_REQ */
			case 0x31: /* INFO_PRODUCT_RAT_BAND_WRITE_RESP */
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unknown PhoneInfo packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}



