/* packet-isi.c
 * Dissector for ISI protocol
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
#include "isi-network.h"
#include "isi-sim.h"
#include "isi-simauth.h"
#include "isi-gps.h"

#define ISI_LTYPE 0xF5

int proto_isi = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;
static dissector_handle_t isi_handle;

/* Dissector table for the isi resource */
static dissector_table_t isi_resource_dissector_table;

/* Forward-declare the dissector functions */
static void dissect_isi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string hf_isi_device[] = {
	{0x00, "Modem" },
	{0x6c, "Host" },
	{0xFF, "Any" },
	{0x00, NULL },
};

static const value_string hf_isi_resource[] = {
	{0x01, "Call"},
	{0x02, "SMS"},
	{0x03, "Phonebook"},
	{0x04, "Phone Status"},
	{0x05, "Settings"},
	{0x06, "Subscriber Services"},
	{0x07, "Custom Idle Framework"},
	{0x08, "Security"},
	{0x09, "SIM"},
	{0x0A, "Network"},
	{0x0B, "Audio control"},
	{0x0C, "Keyboard"},
	{0x0D, "Blackberry Email"},
	{0x0E, "Plato Panel"},
	{0x0F, "Echo"},
	{0x10, "Indication"},
	{0x11, "Java"},
	{0x12, "Local Connectivity"},
	{0x13, "Calendar"},
	{0x14, "SMS memory message"},
	{0x15, "Mobile Terminal Control"},
	{0x16, "Circuit Switched Data"},
	{0x17, "Energy management"},
	{0x18, "Menu"},
	{0x19, "Time Services"},
	{0x1A, "Bearer/Socket Test"},
	{0x1B, "Phone Info"},
	{0x1C, "Accessory"},
	{0x1D, "Universal Diagnostic Monitor Support"},
	{0x1E, "UI Themes"},
	{0x1F, "Tone"},
	{0x20, "Car"},
	{0x21, "SOS ADL"},
	{0x22, "Provisioning"},
	{0x23, "Permanent Data"},
	{0x24, "DAMPS & CDMA NAM serverCDMA"},
	{0x25, "Functional Covers interface to Java"},
	{0x26, "Wireless Datagram Protocol"},
	{0x27, "Wireless Transaction Layer Security"},
	{0x28, "Temporaty WAP (WTP)"},
	{0x29, "Temporaty WAP (WSP)"},
	{0x2A, "DAMPS Layer 1"},
	{0x2B, "Socket Server"},
	{0x2C, "Help"},
	{0x2D, "Temporaty WAP (Cache)"},
	{0x2E, "Temporaty WAP (Script)"},
	{0x2F, "TDMA Calling card"},
	{0x31, "GPRS"},
	{0x32, "GSM Stack Server"}, /* Mysterious type 50 - I don't know what this is*/
	{0x33, "Mobile Station Test Interface"},
	{0x34, "ND"},
	{0x35, "Selftest"},
	{0x36, "Obex"},
	{0x37, "Print"},
	{0x38, "Monitor"},
	{0x39, "User Profile"},
	{0x3A, "Light"},
	{0x3B, "SWDL"},
	{0x3C, "GSM CS Layer 1"},
	{0x3D, "DAMPS Stack"},
	{0x3E, "FM Radio"},
	{0x3F, "WAP Connectivity"},
	{0x40, "Test"},
	{0x41, "Wallet Security Module"},
	{0x42, "Warranty Transfer"},
	{0x43, "Non volatile data"},
	{0x44, "Secbox"},
	{0x45, "Combox"},
	{0x46, "Real Time Streaming Protocol"},
	{0x47, "Sensor"},
	{0x48, "APDU"},
	{0x49, "Content Dispatch"},
	{0x4A, "Voice"},
	{0x4B, "EXT SIM"},
	{0x4C, "AMPS Layer 3"},
	{0x4D, "AMPS Frame Layer"},
	{0x4E, "AMPS Modem"},
	{0x4F, "CDMA Layer 1"},
	{0x50, "CDMA Layer 2"},
	{0x51, "CDMA Layer 3"},
	{0x52, "CDMA System Selection"},
	{0x53, "Simlock"},
	{0x54, "GPS"},
	{0x55, "ToDo"},
	{0x56, "System mode control"},
	{0x57, "Voice recognition and recording"},
	{0x58, "EPOC Test"},
	{0x59, "EPOC Selftest"},
	{0x5A, "Application ToolKit"},
	{0x5B, "WCDMA CS Physical Layer"},
	{0x5C, "SyncML"},
	{0x5D, "Versit"},
	{0x5E, "EPOC side monitor"},
	{0x5F, "CDMA Data - RLP"},
	{0x60, "Bearer control"},
	{0x61, "Camera"},
	{0x62, "EPOC Info"},
	{0x63, "Wallet"},
	{0x64, "Local Connectivity InterFace"},
	{0x65, "IMPS Contacts"},
	{0x66, "Messaging Services"},
	{0x67, "POC (Push-to-talk)"},
	{0x68, "HTTP server side"},
	{0x69, "IMODE mail"},
	{0x6A, "IMODE page loader"},
	{0x6B, "HTTP 1.1 protocol"},
	{0x6C, "Secure Sockets Layer"},
	{0x6D, "File Manager"},
	{0x6E, "BlueTooth"},
	{0x6F, "Auxiliary DownLoad (for reflashing)"},
	{0x70, "Touchpad"},
	{0x71, "Wireless Identity Module and Certificates"},
	{0x72, "Concierge"},
	{0x73, "Session Initiation Protocol"},
	{0x74, "Real-time Transport Protocol"},
	{0x75, "Music"},
	{0x76, "Instant Messaging and Presence Service"},
	{0x77, "Tune Player"},
	{0x78, "Accesory message"},
	{0x79, "Accesory Indication"},
	{0x7A, "UI settings"},
	{0x7B, "SPR"},
	{0x7C, "Ostrich"},
	{0x7D, "Location UI"},
	{0x7E, "CoreSW MCU task for DSP code download"},
	{0x7F, "PhoNet Acknowledge messages"},
	{0x80, "BlueTooth core"},
	{0x81, "I2C core"},
	{0x8C, "Universal Integrated Circuit Card"},
	{0x8D, "Modem SIM (MMS)"},
	{0x8E, "AT Modem Server"},
	{0x8F, "AT Application Server"},
	{0x90, "Modem LCS Server"},
	{0x91, "Modem Test Server"},
	{0x94, "ODIN"},
	{0x95, "Wireless Telephony Application"},
	{0x9A, "CDMA DSP Layer 1 Data"},
	{0x9B, "CDMA Data Only Control"},
	{0x9C, "CDMA Data Only Data"},
	{0x9D, "Programmable Requirements Interface"},
	{0x9E, "Verizona Access Manager"},
	{0x9F, "Wireless Wide Area Network"},
	{0xA0, "Generic intelligent accessory interface"},
	{0xA1, "IP Multimedia Subsystem (IMS) and Session Initiation Protocol (SIP)"},
	{0xA2, "SOS PERManent Server"},
	{0xA3, "PoC UI Engine"},
	{0xA4, "Presence"},
	{0xA5, "XML Configuration Access Protocol"},
	{0xA6, "POC Group Server"},
	{0xA7, "Common Settings Module"},
	{0xA8, "Media Communication Library Engine"},
	{0xA9, "TRACFONE carrier pre-paid feature"},
	{0xAA, "Message Storage Server"},
	{0xAB, "Multimedia and E-mail Services Server"},
	{0xAC, "Vertu Bus Test server"},
	{0xAD, "DP2 Download Agent Server"},
	{0xAE, "IP Communications Server"},
	{0xAF, "TSS Hardware access server"},
	{0xB0, "UMA Symbian Controller Server"},
	{0xB1, "Video Protocol Server"},
	{0xB2, "Wireless LAN (WLAN) connectivity Server"},
	{0xB3, "News Delivery Server"},
	{0xB4, "WCDMA Radio Factory Server"},
	{0xB5, "EUTRAN L2 layers towards MACN layers server"},
	{0xB6, "EUTRAN L1 layer server"},
	{0xB7, "RF control and tuning"},
	{0xB8, "Instance Message Engine"},
	{0xB9, "Timing & NAT Traversal (TNT)"},
	{0xBA, "Backup Server"},
	{0xBB, "File Identity Manager"},
	{0xBC, "Mobility Policy (MOP)"},
	{0xBD, "Landmark Server"},
	{0xBE, "Mobile Broadcast Services"},
	{0xBF, "Forward Error Correction (FEC)"},
	{0xC0, "Generic Bootstrapping Architecture (GBA)"},
	{0xC1, "Dynamic Loader"},
	{0xC2, "Modem MCE Server"},
	{0xC3, "Modem HW Monitor 2"},
	{0xC4, "Modem HW Monitor 3"},
	{0xC5, "Modem Info"},
	{0xC6, "Resource Manager"},
	{0xC7, "Vendor specific production related tests"},
	{0xC8, "NET Server in Modem SW"},
	{0xC9, "CALL Server in Modem SW"},
	{0xCA, "Generic Metadata System"},
	{0xCE, "Extensible Authentication Protocol"},
	{0xCF, "My5 Protocol"},
	{0xD0, "PhoNet registration Messages"},
	{0xD1, "Remote Procedure Call requests"},
	{0xD2, "Remote Procedure Call responses"},
	{0xD3, "Config"},
	{0xD4, "Slave Logout"},
	{0xD5, "Error Info"},
	{0xD6, "Dev Connection Info"},
	{0xD7, "Media Module Control Messages"},
	{0xD8, "Check Rasmus"},
	{0xD9, "Pipe Messages"},
	{0xDA, "PhoNet alive messages"},
	{0xDB, "Name Service Messages"},
	{0xDC, "Router indications"},
	{0xDD, "LN EE Response"},
	{0xDE, "SuperDongle challenge/response"},
	{0xDF, "Unused System Res 1"},
	{0xE0, "Enhanced resource id message"},
	{0xE1, "Private interface messages"},
	{0xE2, "SOS Audio Server"},
	{0xE3, "Startup Control"},
	{0xE4, "KODIAK PoC Server"},
	{0xE5, "Payload Test Server"},
	{0xE6, "DSP Core"},
	{0xE7, "DSP Video"},
	{0xE8, "DSP Voice"},
	{0xE9, "DSP Midi"},
	{0xEA, "ADSP Core"},
	{0xEB, "DSP Self Test"},
	{0xEC, "DSP Common Test"},
	{0xED, "WCDMA DSP CS"},
	{0xEE, "WCDMA DSP Test"},
	{0xF0, "GSM DSP CS"},
	{0xF1, "GSM DSP Test"},
	{0xF2, "GSM DSP"},
	{0xF3, "DSP Audio"},
	{0xF4, "DAMPS DSP CS"},
	{0xF5, "DAMPS DSP Test"},
	{0xF6, "DAMPS DSP"},
	{0xF7, "TETRA DSP"},
	{0xF8, "TETRA DSP Test"},
	{0xF9, "TETRA DSP CS"},
	{0xFA, "CDMA DSP L1"},
	{0xFB, "AMPS DSP L1"},
	{0xFC, "CDMA DSP"},
	{0xFD, "DSP GPRS"},
	{0xFE, "DSP Music"},
};

static const value_string isi_common_cmd[] = {
	{0x14, "COMM_ISA_ENTITY_NOT_REACHABLE_RESP"},
	{0x01, "COMM_SERVICE_NOT_IDENTIFIED_RESP"},
	{0x02, "COMM_SERVER_VERSION_GET_REQ"},
	{0x03, "COMM_SERVER_VERSION_GET_RESP"},
	{0x12, "COMM_ISI_VERSION_GET_REQ"},
	{0x13, "COMM_ISI_VERSION_GET_RESP"},
	{0x04, "COMM_FTD_DATA_REQ"},
	{0x05, "COMM_FTD_DATA_RESP"},
	{0x06, "COMM_FTD_TEST_DATA_REQ"},
	{0x07, "COMM_FTD_TEST_DATA_RESP"},
	{0x08, "COMM_FTD_DATA_DEACTIVATE_REQ"},
	{0x09, "COMM_FTD_DATA_DEACTIVATE_RESP"},
	{0x0C, "COMM_PWR_OFF_CONFIRM_REQ"},
	{0x0D, "COMM_PWR_OFF_CONFIRM_RESP"},
	{0x0E, "COMM_NVD_SET_DEFAULT_REQ"},
	{0x0F, "COMM_NVD_SET_DEFAULT_RESP"},
	{0x10, "COMM_NVD_VERSION_CHK_REQ"},
	{0x11, "COMM_NVD_VERSION_CHK_RESP"},
	{0x15, "COMM_RF_CONTROL_REQ"},
	{0x16, "COMM_RF_CONTROL_RESP"},
	{0x17, "COMM_SERVICE_NOT_AUTHENTICATED_RESP"},
};


static guint32 hf_isi_rdev = -1;
static guint32 hf_isi_sdev = -1;
static guint32 hf_isi_res  = -1;
static guint32 hf_isi_len  = -1;
static guint32 hf_isi_robj = -1;
static guint32 hf_isi_sobj = -1;
static guint32 hf_isi_id   = -1;
static guint32 hf_isi_comcmd = -1;
static guint32 hf_isi_version_major = -1;
static guint32 hf_isi_version_minor = -1;

/* Subtree handles: set by register_subtree_array */
static guint32 ett_isi = -1;
guint32 ett_isi_msg = -1;
guint32 ett_isi_network_gsm_band_info = -1;

#ifdef ISI_USB
/* Experimental approach based upon the one used for PPP*/
static gboolean dissect_usb_isi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	tvbuff_t *next_tvb = NULL;

	if(tvb_get_guint8(tvb, 0) == 0x1B) {
		next_tvb = tvb_new_subset_remaining(tvb, 1);
		dissect_isi(next_tvb, pinfo, tree);
	}
	else
		return (FALSE);
	return (TRUE);
}
#endif

/* Handler registration */
void proto_reg_handoff_isi(void) {
	static gboolean initialized=FALSE;

	if(!initialized) {
		data_handle = find_dissector("data");
		isi_handle = create_dissector_handle(dissect_isi, proto_isi);
		dissector_add("sll.ltype", ISI_LTYPE, isi_handle);

		/* handoff resource dissectors */
		proto_reg_handoff_isi_sim_auth();
		proto_reg_handoff_isi_sim();
		proto_reg_handoff_isi_network();
		proto_reg_handoff_isi_gps();
		proto_reg_handoff_isi_ss();
		proto_reg_handoff_isi_gss();
		proto_reg_handoff_isi_sms();
		proto_reg_handoff_isi_mtc();
		proto_reg_handoff_isi_nameservice();
		proto_reg_handoff_isi_radiosettings();
		proto_reg_handoff_isi_phoneinfo();
		proto_reg_handoff_isi_call();
		proto_reg_handoff_isi_light();

#ifdef ISI_USB
		heur_dissector_add("usb.bulk", dissect_usb_isi, proto_isi);
#endif
	}
}

void proto_register_isi(void) {
	/* A header field is something you can search/filter on.
	 * 
	 * We create a structure to register our fields. It consists of an
	 * array of hf_register_info structures, each of which are of the format
	 * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	 */
	static hf_register_info hf[] = {
		{ &hf_isi_rdev,
		  { "Receiver Device", "isi.rdev", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_device), 0x0, "Receiver Device ID", HFILL }},
		{ &hf_isi_sdev,
		  { "Sender Device", "isi.sdev", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_device), 0x0, "Sender Device ID", HFILL }},
		{ &hf_isi_res,
		  { "Resource", "isi.res", FT_UINT8, BASE_HEX,
		    VALS(hf_isi_resource), 0x0, "Resource ID", HFILL }},
		{ &hf_isi_len,
		  { "Length", "isi.len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Length", HFILL }},
		{ &hf_isi_robj,
		  { "Receiver Object", "isi.robj", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "Receiver Object", HFILL }},
		{ &hf_isi_sobj,
		  { "Sender Object", "isi.sobj", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "Sender Object", HFILL }},
		{ &hf_isi_id,
		  { "Packet ID", "isi.id", FT_UINT8, BASE_DEC,
		    NULL, 0x0, "Packet ID", HFILL }},
		{ &hf_isi_comcmd,
		  { "Sub Command", "isi.comcmd", FT_UINT8, BASE_HEX,
		    isi_common_cmd, 0x0, "Common Command", HFILL }},
		{ &hf_isi_version_major,
		  { "ISI Version Major", "isi.version_major", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "ISI Version Major", HFILL }},
		{ &hf_isi_version_minor,
		  { "ISI Version Minor", "isi.version_minor", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "ISI Version Minor", HFILL }},
    };

	static gint *ett[] = {
		&ett_isi,
		&ett_isi_msg,
		&ett_isi_network_gsm_band_info
	};

	proto_isi = proto_register_protocol("Intelligent Service Interface", "ISI", "isi");

	proto_register_field_array(proto_isi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("isi", dissect_isi, proto_isi);

	/* create new dissector table for isi resource */
	isi_resource_dissector_table = register_dissector_table("isi.resource", "ISI resource", FT_UINT8, BASE_HEX);

	/* register resource dissectors */
	proto_register_isi_sim();
	proto_register_isi_sim_auth();
	proto_register_isi_network();
	proto_register_isi_gps();
	proto_register_isi_ss();
	proto_register_isi_gss();
	proto_register_isi_sms();
	proto_register_isi_mtc();
	proto_register_isi_nameservice();
	proto_register_isi_radiosettings();
	proto_register_isi_phoneinfo();
	proto_register_isi_call();
	proto_register_isi_light();
}

/* The dissector itself */
static void dissect_isi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	proto_tree *isi_tree = NULL;
	guint position = 0;
	proto_item *item = NULL;
	tvbuff_t *content = NULL;

	guint8 src = 0;
	guint8 dst = 0;
	guint8 resource = 0;
	guint16 length = 0;

	if(check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISI");
	
	if(check_col(pinfo->cinfo,COL_INFO))
		col_clear(pinfo->cinfo,COL_INFO);

	if(tree) {
		/* If tree != NULL, we're doing a detailed dissection of the
		 * packet, so we need to construct a tree. */

		/* Start with a top-level item to add everything else to */
		item = proto_tree_add_item(tree, proto_isi, tvb, position, -1, FALSE);
		isi_tree = proto_item_add_subtree(item, ett_isi);

		/* Common Phonet/ISI Header */
		proto_tree_add_item(isi_tree, hf_isi_rdev, tvb, 0, 1, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_sdev, tvb, 1, 1, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_res,  tvb, 2, 1, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_len,  tvb, 3, 2, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_robj, tvb, 5, 1, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_sobj, tvb, 6, 1, FALSE);
		proto_tree_add_item(isi_tree, hf_isi_id,   tvb, 7, 1, FALSE);

		length = tvb_get_ntohs(tvb, 3) - 3;
		resource = tvb_get_guint8(tvb, 2);
		dst = tvb_get_guint8(tvb, 0);
		src = tvb_get_guint8(tvb, 1);

		if(tvb->length - 8 < length) {
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "Broken Length (%d > %d)", length, tvb->length-8);
			length = tvb->length - 8;
		}

		col_set_str(pinfo->cinfo, COL_DEF_SRC, val_to_str_const(src, hf_isi_device, "Unknown"));
		col_set_str(pinfo->cinfo, COL_DEF_DST, val_to_str_const(dst, hf_isi_device, "Unknown"));

		content = tvb_new_subset(tvb, 8, length, length);

		/* Call subdissector depending on the resource ID */
		if(!dissector_try_port(isi_resource_dissector_table, resource, content, pinfo, isi_tree))
			call_dissector(data_handle, content, pinfo, isi_tree);
	}
}

void dissect_isi_common(const char *resource, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	char *c_subcmd = "unknown common command";
	guint8 comcmd = tvb_get_guint8(tvb, 1);
	proto_tree_add_item(tree, hf_isi_comcmd, tvb, 1, 1, FALSE);

	switch(comcmd) {
		case 0x01: /* COMM_SERVICE_NOT_IDENTIFIED_RESP */
			c_subcmd = "Service Not Identified Response";
			break;
		case 0x02: /* COMM_SERVER_VERSION_GET_REQ */
			c_subcmd = "Server Version Get Request";
			break;
		case 0x03: /* COMM_SERVER_VERSION_GET_RESP */
			c_subcmd = "Server Version Get Response";
			break;
		case 0x04: /* COMM_FTD_DATA_REQ */
			c_subcmd = "FTD Data Request";
			break;
		case 0x05: /* COMM_FTD_DATA_RESP */
			c_subcmd = "FTD Data Response";
			break;
		case 0x06: /* COMM_FTD_TEST_DATA_REQ */
			c_subcmd = "FTD Test Data Request";
			break;
		case 0x07: /* COMM_FTD_TEST_DATA_RESP */
			c_subcmd = "FTD Test Data Response";
			break;
		case 0x08: /* COMM_FTD_DATA_DEACTIVATE_REQ */
			c_subcmd = "FTD Data Deactivate Request";
			break;
		case 0x09: /* COMM_FTD_DATA_DEACTIVATE_RESP */
			c_subcmd = "FTD Data Deactivate Response";
			break;
		case 0x0C: /* COMM_PWR_OFF_CONFIRM_REQ */
			c_subcmd = "Power Off Confirm Request";
			break;
		case 0x0D: /* COMM_PWR_OFF_CONFIRM_RESP */
			c_subcmd = "Power Off Confirm Response";
			break;
		case 0x0E: /* COMM_NVD_SET_DEFAULT_REQ */
			c_subcmd = "NVD Set Default Request";
			break;
		case 0x0F: /* COMM_NVD_SET_DEFAULT_RESP */
			c_subcmd = "NVD Set Default Response";
			break;
		case 0x10: /* COMM_NVD_VERSION_CHK_REQ */
			c_subcmd = "NVD Version Check Request";
			break;
		case 0x11: /* COMM_NVD_VERSION_CHK_RESP */
			c_subcmd = "NVD Version Check Response";
			break;
		case 0x12: /* COMM_ISI_VERSION_GET_REQ */
			c_subcmd = "ISI Version Get Request";
			break;
		case 0x13: /* COMM_ISI_VERSION_GET_RESP */
			c_subcmd = "ISI Version Get Response";
			proto_tree_add_item(tree, hf_isi_version_major, tvb, 2, 1, FALSE);
			proto_tree_add_item(tree, hf_isi_version_minor, tvb, 3, 1, FALSE);
			break;
		case 0x14: /* COMM_ISA_ENTITY_NOT_REACHABLE_RESP */
			c_subcmd = "ISA Entity Not Reachable Response";
			break;
		case 0x15: /* COMM_RF_CONTROL_REQ */
			c_subcmd = "RF Control Request";
			break;
		case 0x16: /* COMM_RF_CONTROL_RESP */
			c_subcmd = "RF Control Response";
			break;
		case 0x17: /* COMM_SERVICE_NOT_AUTHENTICATED_RESP */
			c_subcmd = "Service Not Authenticated Response";
			break;
		default:
			//expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
			break;
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s Common Message: %s", resource, c_subcmd);
}

