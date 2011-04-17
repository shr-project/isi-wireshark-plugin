/* isi-selftest.c
 * Dissector for ISI's selftest resource
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
#include "isi-selftest.h"

static const value_string isi_selftest_cmd[] = {
	{0x00, "ST_RUN_REQ"},
	{0x01, "ST_RUN_RESP"},
	{0x02, "ST_RESULTS_GET_REQ"},
	{0x03, "ST_RESULTS_GET_RESP"},
	{0x04, "ST_SELFTEST_LIST_GET_REQ"},
	{0x05, "ST_SELFTEST_LIST_GET_RESP"},
	{0x06, "ST_SELFTEST_NAMES_GET_REQ"},
	{0x07, "ST_SELFTEST_NAMES_GET_RESP"},
	{0x08, "ST_DETAILED_RESULTS_GET_REQ"},
	{0x09, "ST_DETAILED_RESULTS_GET_RESP"},
	{0x0A, "ST_PRODUCT_TEST_REQ"},
	{0x0B, "ST_PRODUCT_TEST_RESP"},
	{0x00, NULL}
};

static const value_string isi_selftest_subblock_type[] = {
	{0x00, "ST_SB_SELFTEST_LIST"},
	{0x01, "ST_SB_SELFTEST_RESULT"},
	{0x02, "ST_SB_SELFTEST_NAME"},
	{0x03, "ST_SB_SELFTEST_DETAILED_RESULTS"},
	{0x04, "ST_SB_DISPLAY_PATTERN"},
	{0x05, "ST_SB_TVOUT_PATTERN"},
	{0x00, NULL}
};

static const value_string isi_selftest_action[] = {
	{0x00, "Selftest Start"},
	{0x01, "Selftest Stop"},
	{0x00, NULL}
};

static const value_string isi_selftest_type[] = {
	{0x00, "ST_LISTED_TESTS"},
	{0x01, "ST_STARTUP_TESTS"},
	{0x02, "ST_RUNTIME_TESTS"},
	{0x03, "ST_ALL_POSSIBLE_TESTS"},
	{0x04, "ST_BACKGROUND_TESTS"},
	{0x00, NULL}
};

static const value_string isi_selftest_status[] = {
	{0x00, "ST_OK"},
	{0x01, "ST_FAIL"},
	{0x02, "ST_BUSY"},
	{0x03, "ST_NOT_EXECUTED"},
	{0x04, "ST_NOT_SUPPORTED"},
	{0x05, "ST_SHORT_CIRCUIT"},
	{0x06, "ST_NO_SIGNAL"},
	{0x07, "ST_NO_POWER"},
	{0x08, "ST_WRONG_OR_MISSING_ID"},
	{0x09, "ST_NO_SIM"},
	{0x0A, "ST_MINOR"},
	{0x0B, "ST_SEVERE"},
	{0x0C, "ST_FATAL"},
	{0x0D, "ST_TIMEOUT"},
	{0x0E, "ST_EXECUTING"},
	{0x00, NULL}
};

static value_string isi_selftest_id[] = {
	{0x01, "ST_AUX_DA_LOOP_TEST"},
	{0x02, "ST_CURRENT_CONS_TEST"},
	{0x03, "ST_EAR_DATA_LOOP_TEST"},
	{0x04, "ST_CDMA_DSP_ALL_TEST"},
	{0x05, "ST_CAMERA_ACCELERATOR_TEST"},
	{0x06, "ST_IR_LOOP_TEST"},
	{0x07, "ST_KEYBOARD_STUCK_TEST"},
	{0x08, "ST_MBUS_RX_TX_LOOP_TEST"},
	{0x09, "ST_PMM_CHECKSUM_TEST"},
	{0x0A, "ST_PPM_VALIDITY_TEST"},
	{0x0B, "ST_TILT_SENSOR_IF_TEST"},
	{0x0C, "ST_SIM_CLK_LOOP_TEST"},
	{0x0D, "ST_SIM_IO_CTRL_LOOP_TEST"},
	{0x0E, "ST_MICB1_TEST"},
	{0x0F, "ST_SLEEP_X_LOOP_TEST"},
	{0x10, "ST_TEMP_SENSOR_IF_TEST"},
	{0x11, "ST_TX_IDP_LOOP_TEST"},
	{0x12, "ST_TX_IQ_DP_LOOP_TEST"},
	{0x13, "ST_KELVIN_VIBRA_TEST"},
	{0x14, "ST_BACKUP_BATT_TEST"},
	{0x15, "ST_LPRF_IF_TEST"},
	{0x16, "ST_CAMERA_IF_TEST"},
	{0x17, "ST_KELVIN_BATVOLTAGE_TEST"},
	{0x18, "ST_CDMA_MEMORY_BUFFER_TEST"},
	{0x19, "ST_EXTERNAL_RAM_TEST"},
	{0x1A, "ST_KELVIN_CAPACITOR_TEST"},
	{0x1B, "ST_KELVIN_AUDIO_TEST"},
	{0x1C, "ST_KELVIN_MIC_TEST"},
	{0x1D, "ST_KELVIN_MISC_TEST"},
	{0x1E, "ST_RF_CHIP_ID_TEST"},
	{0x1F, "ST_KELVIN_CHARGING_TEST"},
	{0x20, "ST_AMB_LIGHT_SENSOR_TEST"},
	{0x21, "ST_SIM_LOCK_TEST"},
	{0x22, "ST_USB_CHARGING_TEST"},
	{0x23, "ST_NAVISCROLL_TEST"},
	{0x24, "ST_SEC_LCD_IF_TEST"},
	{0x25, "ST_SEC_CAMERA_IF_TEST"},
	{0x26, "ST_CAMERA_AUTOFOCUS_TEST"},
	{0x27, "ST_WARRANTY_TEST"},
	{0x28, "ST_PMM_VALIDITY_TEST"},
	{0x29, "ST_FLASH_CHECKSUM_TEST"},
	{0x2A, "ST_RADIO_TEST"},
	{0x2B, "ST_LCD_TEST"},
	{0x2C, "ST_LPRF_AUDIO_LINES_TEST"},
	{0x2D, "ST_IR_IF_TEST"},
	{0x2E, "ST_UEM_CBUS_IF_TEST"},
	{0x2F, "ST_AEM_CBUS_IF_TEST"},
	{0x30, "ST_PROX_FAULT_TEST"},
	{0x31, "ST_VIBRA_TEST_TEST"},
	{0x32, "ST_MMC_INT_TEST"},
	{0x33, "ST_PA_TEMP_TEST"},
	{0x34, "ST_KEYB_LINE_TEST"},
	{0x35, "ST_WCDMA_IF_TEST"},
	{0x36, "ST_EXT_RAM_DATA_BUS_TEST"},
	{0x37, "ST_EXT_RAM_ADDR_BUS_TEST"},
	{0x38, "ST_CDSP_SLEEPCLK_FREQ_TEST"},
	{0x39, "ST_CURRENT_GAUGE_IF_TEST"},
	{0x3A, "ST_CMT_APE_WAKEUP_TEST"},
	{0x3B, "ST_MAIN_LCD_IF_TEST"},
	{0x3C, "ST_TOUCH_STUCK_TEST"},
	{0x3D, "ST_QWERTY_IF_TEST"},
	{0x3E, "ST_QWERTY_STUCK_TEST"},
	{0x3F, "ST_APE_DAC_CTRL_IF_TEST"},
	{0x40, "ST_APE_RAM_TEST"},
	{0x41, "ST_APE_POST_CODE_TEST"},
	{0x42, "ST_ADSP_STARTUP_TEST"},
	{0x43, "ST_ADSP_EXT_FLASH_TEST"},
	{0x44, "ST_SW_TYPE_VALIDITY_TEST"},
	{0x45, "ST_BACKLIGHT_TEST"},
	{0x46, "ST_NAND_FLASH_ID_TEST"},
	{0x47, "ST_BT_WAKEUP_TEST"},
	{0x48, "ST_WLAN_TEST"},
	{0x49, "ST_XABUS_TEST"},
	{0x4A, "ST_CDSP_TXC_DATA_TEST"},
	{0x4B, "ST_CDSP_WCDMA_TX_POWER_TEST"},
	{0x4C, "ST_CDSP_WCDMA_TX_IQ_QUAL_TEST"},
	{0x4D, "ST_CDSP_GSM_TX_POWER_TEST"},
	{0x4E, "ST_CDSP_GSM_TX_IQ_QUAL_TEST"},
	{0x4F, "ST_CDSP_RX_PLL_PHASE_LOCK_TEST"},
	{0x50, "ST_CDSP_TX_PLL_PHASE_LOCK_TEST"},
	{0x51, "ST_CDSP_RX_IQ_LOOP_BACK_TEST"},
	{0x52, "ST_CDSP_PWR_DETECTOR_BIAS_TEST"},
	{0x53, "ST_CDSP_RF_SUPPLY_TEST"},
	{0x54, "ST_CDSP_PA_COMBINATION_TEST"},
	{0x55, "ST_CDSP_TX_IQ_TEST"},
	{0x56, "ST_CDSP_RF_BB_IF_TEST"},
	{0x58, "ST_TAHVOINT_TEST"},
	{0x59, "ST_IVE_TEST"},
	{0x5A, "ST_PWR_KEY_TEST"},
	{0x5B, "ST_USB_LOOP_TEST"},
	{0x5C, "ST_BT_WLAN_COEXISTENCE_TEST"},
	{0x5D, "ST_SECURITY_TEST"},
	{0x5E, "ST_GPS_TEST"},
	{0x5F, "ST_PWRONX_PULSE_TEST"},
	{0x60, "ST_HOOKINT_TEST"},
	{0x61, "ST_MASS_MEMORY_IF_TEST"},
	{0x62, "ST_2ND_JOYSTICK_STUCK_TEST"},
	{0x63, "ST_IRDA_LED_STRESS_TEST"},
	{0x64, "ST_CAMERA_FLASHLIGHT_TEST"},
	{0x65, "ST_BTEMP_TEST"},
	{0x66, "ST_APE_EM_ASIC_TEST"},
	{0x67, "ST_TOUCH_IF_TEST"},
	{0x68, "ST_ACCEL_IF_TEST"},
	{0x69, "ST_INTERNAL_ANTENNA_TEST"},
	{0x6A, "ST_DVBH_TEST"},
	{0x6B, "ST_BT_SLEEP_CLK_TEST"},
	{0x6C, "ST_EXT_DEVICE_TEST"},
	{0x6D, "ST_ZOOM_TEST"},
	{0x6E, "ST_PREPAID_CSTYPE_TEST"},
	{0x6F, "ST_HRM_TEST"},
	{0x70, "ST_BT_CLK_REQ_TEST"},
	{0x71, "ST_LCD_CONTROLLER_TEST"},
	{0x72, "ST_IO_EXPANDER_IF_TEST"},
	{0x73, "ST_TVOUT_IF_TEST"},
	{0x74, "ST_KELVIN_XEAR_TEST"},
	{0x75, "ST_DIGIMIC_TEST"},
	{0x76, "ST_CDSP_ANTENNA_TEST"},
	{0x77, "ST_IIC_TEST"},
	{0x78, "ST_CAMERA_REVEAL_TEST"},
	{0x79, "ST_LED_FLASH_TEST"},
	{0x7A, "ST_FMTX_TEST"},
	{0x7B, "ST_CDSP_RX_IQ_TEST"},
	{0x7C, "ST_CDSP_STROBE_TEST"},
	{0x7D, "ST_CDSP_DIGI_RXTX_IF_TEST"},
	{0x7E, "ST_CDSP_SMPS_TEST"},
	{0x7F, "ST_CDSP_PA_ID_PIN_TEST"},
	{0x80, "ST_CDSP_SLEEPCLOCK_FREQ_TEST"},
	{0xC8, "ST_CDSP_NO_TEST"},
	{0xC9, "ST_MAGNETOMETER_TEST"},
	{0xCA, "ST_ELECTROMAGNET_TEST"},
	{0xCB, "ST_CHIPSET_API_PMU_TEST"},
	{0xCC, "ST_CHIPSET_API_RFPA_TEST"},
	{0xCD, "ST_CHIPSET_API_VIBRA_TEST"},
	{0xCE, "ST_CHIPSET_API_MIC_TEST"},
	{0xCF, "ST_CHIPSET_API_EARP_TEST"},
	{0xD0, "ST_CHIPSET_API_IHF_TEST"},
	{0xD1, "ST_HEADSET_AMPLIFIER_TEST"},
	{0xD2, "ST_SNV_MEMORY_TEST"},
	{0xD3, "ST_WIMAX_SLEEP_CLK_TEST"},
	{0xD4, "ST_WIMAX_BOOT_IO_TEST"},
	{0xD5, "ST_FINGERPRINT_SENSOR_TEST"},
	{0xD6, "ST_MODEM_IRQ_TEST"},
	{0xD7, "ST_MODEM_TX_START_TEST"},
	{0xD8, "ST_MODEM_IQ_IF_TEST"},
	{0xD9, "ST_MODEM_FDI_TEST"},
	{0xDA, "ST_MODEM_TBTIMEMARK_TEST"},
	{0xDB, "ST_MODEM_CMTTIMEMARK_TEST"},
	{0xDC, "ST_MODEM_SDRAM_TEST"},
	{0xDD, "ST_MODEM_VCORESMPS_TESTS"},
	{0xDE, "ST_LED_CONTROLLER_TEST"},
	{0x00, NULL}
};

static dissector_handle_t isi_selftest_handle;
static void dissect_isi_selftest(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_selftest_cmd = -1;
static guint32 hf_isi_selftest_subblock_type = -1;
static guint32 hf_isi_selftest_subblock_count = -1;
static guint32 hf_isi_selftest_action = -1;
static guint32 hf_isi_selftest_type = -1;
static guint32 hf_isi_selftest_status = -1;
static guint32 hf_isi_selftest_id = -1;


void proto_reg_handoff_isi_selftest(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_selftest_handle = create_dissector_handle(dissect_isi_selftest, proto_isi);
		dissector_add("isi.resource", 0x35, isi_selftest_handle);
	}
}

void proto_register_isi_selftest(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_selftest_cmd,
			{ "Command", "isi.selftest.cmd", FT_UINT8, BASE_HEX, isi_selftest_cmd, 0x0, "Command", HFILL }},
		{ &hf_isi_selftest_subblock_type,
			{ "Subblock-Type", "isi.selftest.subblock_type", FT_UINT8, BASE_HEX, isi_selftest_subblock_type, 0x0, "Subblock-Type", HFILL }},
		{ &hf_isi_selftest_subblock_count,
			{ "Subblock-Count", "isi.selftest.subblock_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Subblock-Count", HFILL }},
		{ &hf_isi_selftest_type,
			{ "Test-Type", "isi.selftest.type", FT_UINT8, BASE_HEX, isi_selftest_type, 0x0, "Test-Type", HFILL }},
		{ &hf_isi_selftest_action,
			{ "Action", "isi.selftest.action", FT_UINT8, BASE_HEX, isi_selftest_action, 0x0, "Action", HFILL }},
		{ &hf_isi_selftest_status,
			{ "Status", "isi.selftest.status", FT_UINT8, BASE_HEX, isi_selftest_status, 0x0, "Status", HFILL }},
		{ &hf_isi_selftest_id,
			{ "Test-Id", "isi.selftest.id", FT_UINT8, BASE_HEX, isi_selftest_id, 0x0, "Test-Id", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.selftest", dissect_isi_selftest, proto_isi);
}

static void _sub_result(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_selftest_id, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_selftest_status, tvb, 3, 1, FALSE);
}

static void dissect_isi_selftest_subblock(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x01: _sub_result(tvb, tree); break;        /* ST_SB_SELFTEST_RESULT */

		case 0x00: /* ST_SB_SELFTEST_LIST */
		case 0x02: /* ST_SB_SELFTEST_NAME */
		case 0x03: /* ST_SB_SELFTEST_DETAILED_RESULTS */
		case 0x04: /* ST_SB_DISPLAY_PATTERN */
		case 0x05: /* ST_SB_TVOUT_PATTERN */

		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
			break;
	}
}

static void dissect_isi_selftest(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_selftest_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {
			case 0x00: /* ST_RUN_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Run Request");
                                proto_tree_add_item(tree, hf_isi_selftest_type, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_selftest_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_selftest_subblock);
				break;
			case 0x01: /* ST_RUN_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Run Response");
                                proto_tree_add_item(tree, hf_isi_selftest_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_selftest_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_selftest_subblock);
				break;
			case 0x02: /* ST_RESULTS_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Results Get Request");
                                proto_tree_add_item(tree, hf_isi_selftest_type, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_selftest_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_selftest_subblock);
				break;
			case 0x03: /* ST_RESULTS_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Results Get Response");
                                proto_tree_add_item(tree, hf_isi_selftest_status, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_selftest_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_selftest_subblock);
				break;
			case 0x04: /* ST_SELFTEST_LIST_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest List Get Request");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x05: /* ST_SELFTEST_LIST_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest List Get Response");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x06: /* ST_SELFTEST_NAMES_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Names Get Request");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x07: /* ST_SELFTEST_NAMES_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Names Get Response");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x08: /* ST_DETAILED_RESULTS_GET_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Detailed Results Get Request");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x09: /* ST_DETAILED_RESULTS_GET_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Detailed Results Get Response");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x0A: /* ST_PRODUCT_TEST_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Product Test Request");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
			case 0x0B: /* ST_PRODUCT_TEST_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "Selftest Product Test Response");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;

			case 0xF0: /* COMMON_MESSAGE */
				dissect_isi_common("Selftest", tvb, pinfo, tree);
				break;
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unhandled Selftest packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}





