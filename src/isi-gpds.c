/* isi-gpds.c
 * Dissector for ISI's gpds resource
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
#include "isi-gpds.h"

static const value_string isi_gpds_id[] = {
	{0x00, "GPDS_LL_CONFIGURE_REQ"},
	{0x01, "GPDS_LL_CONFIGURE_RESP"},
	{0x02, "GPDS_CONTEXT_ID_CREATE_REQ"},
	{0x03, "GPDS_CONTEXT_ID_CREATE_RESP"},
	{0x04, "GPDS_CONTEXT_ID_CREATE_IND"},
	{0x05, "GPDS_CONTEXT_ID_DELETE_IND"},
	{0x20, "GPDS_LL_BIND_REQ"},
	{0x21, "GPDS_LL_BIND_RESP"},
	{0x06, "GPDS_CONTEXT_CONFIGURE_REQ"},
	{0x07, "GPDS_CONTEXT_CONFIGURE_RESP"},
	{0x2A, "GPDS_CONTEXT_MODIFY_REQ"},
	{0x2B, "GPDS_CONTEXT_MODIFY_RESP"},
	{0x2C, "GPDS_CONTEXT_MODIFY_IND"},
	{0x08, "GPDS_CONTEXT_ACTIVATE_REQ"},
	{0x09, "GPDS_CONTEXT_ACTIVATE_RESP"},
	{0x0A, "GPDS_CONTEXT_ACTIVATE_IND"},
	{0x25, "GPDS_CONTEXT_ACTIVATING_IND"},
	{0x1F, "GPDS_CONTEXT_ACTIVATE_FAIL_IND"},
	{0x0B, "GPDS_CONTEXT_DEACTIVATE_REQ"},
	{0x0C, "GPDS_CONTEXT_DEACTIVATE_RESP"},
	{0x0D, "GPDS_CONTEXT_DEACTIVATE_IND"},
	{0x2F, "GPDS_CONTEXT_DEACTIVATING_IND"},
	{0x0E, "GPDS_CONTEXT_NWI_ACT_REQUEST_IND"},
	{0x0F, "GPDS_CONTEXT_NWI_ACT_REJECT_REQ"},
	{0x10, "GPDS_CONTEXT_NWI_ACT_REJECT_RESP"},
	{0x11, "GPDS_CONFIGURE_REQ"},
	{0x12, "GPDS_CONFIGURE_RESP"},
	{0x13, "GPDS_ATTACH_REQ"},
	{0x14, "GPDS_ATTACH_RESP"},
	{0x15, "GPDS_ATTACH_IND"},
	{0x2D, "GPDS_ATTACH_FAIL_IND"},
	{0x16, "GPDS_DETACH_REQ"},
	{0x17, "GPDS_DETACH_RESP"},
	{0x18, "GPDS_DETACH_IND"},
	{0x19, "GPDS_STATUS_REQ"},
	{0x1A, "GPDS_STATUS_RESP"},
	{0x22, "GPDS_CONTEXT_STATUS_REQ"},
	{0x23, "GPDS_CONTEXT_STATUS_RESP"},
	{0x24, "GPDS_CONTEXT_STATUS_IND"},
	{0x1B, "GPDS_SMS_PDU_SEND_REQ"},
	{0x1C, "GPDS_SMS_PDU_SEND_RESP"},
	{0x1D, "GPDS_SMS_PDU_RECEIVE_IND"},
	{0x1E, "GPDS_TRANSFER_STATUS_IND"},
	{0x30, "GPDS_CONFIGURATION_INFO_REQ"},
	{0x31, "GPDS_CONFIGURATION_INFO_RESP"},
	{0x32, "GPDS_CONFIGURATION_INFO_IND"},
	{0x33, "GPDS_CONTEXT_AUTH_REQ"},
	{0x34, "GPDS_CONTEXT_AUTH_RESP"},
	{0x35, "GPDS_TEST_MODE_REQ"},
	{0x36, "GPDS_TEST_MODE_RESP"},
	{0x37, "GPDS_RADIO_ACTIVITY_IND"},
	{0x38, "GPDS_FORCED_READY_STATE_REQ"},
	{0x39, "GPDS_FORCED_READY_STATE_RESP"},
	{0x3A, "GPDS_CONTEXTS_CLEAR_REQ"},
	{0x3B, "GPDS_CONTEXTS_CLEAR_RESP"},
	{0x3C, "GPDS_MBMS_SERVICE_SELECTION_REQ"},
	{0x3D, "GPDS_MBMS_SERVICE_SELECTION_RESP"},
	{0x3E, "GPDS_MBMS_STATUS_IND"},
	{0x3F, "GPDS_MBMS_CONTEXT_CREATE_REQ"},
	{0x40, "GPDS_MBMS_CONTEXT_CREATE_RESP"},
	{0x41, "GPDS_MBMS_CONTEXT_ACTIVATE_REQ"},
	{0x42, "GPDS_MBMS_CONTEXT_ACTIVATE_RESP"},
	{0x43, "GPDS_MBMS_CONTEXT_DELETE_REQ"},
	{0x44, "GPDS_MBMS_CONTEXT_DELETE_RESP"},
	{0x45, "GPDS_MBMS_CONTEXT_DELETE_IND"},
	{0x46, "GPDS_MBMS_SERVICE_SELECTION_IND"},
	{0x47, "GPDS_MBMS_SERVICE_AVAILABLE_IND"},
	{0x48, "GPDS_TEST_REQ"},
	{0x49, "GPDS_TEST_RESP"},
	{0x50, "GPDS_RESOURCE_CONTROL_IND"},
	{0x51, "GPDS_RESOURCE_CONTROL_REQ"},
	{0x52, "GPDS_RESOURCE_CONTROL_RESP"},
	{0x54, "GPDS_RESOURCE_CONF_REQ"},
	{0x55, "GPDS_RESOURCE_CONF_RESP"},
	{0x53, "GPDS_RESOURCE_CONF_IND"},
	{0x56, "GPDS_PROPERTY_SET_REQ"},
	{0x57, "GPDS_PROPERTY_SET_RESP"},
	{0xEE, "GPDS_RESP"},
	{0x00, NULL}
};

static const value_string isi_gpds_subblock_id[] = {
	{0x00, "GPDS_COMP_INFO"},
	{0x01, "GPDS_QOS_REQ_INFO"},
	{0x02, "GPDS_QOS_MIN_INFO"},
	{0x03, "GPDS_QOS_NEG_INFO"},
	{0x04, "GPDS_PDP_ADDRESS_INFO"},
	{0x05, "GPDS_APN_INFO"},
	{0x10, "GPDS_FILT_SRC_IPV4_ADDR_INFO"},
	{0x20, "GPDS_FILT_SRC_IPV6_ADDR_INFO"},
	{0x30, "GPDS_FILT_PROTOCOL_INFO"},
	{0x40, "GPDS_FILT_DST_PORT_INFO"},
	{0x41, "GPDS_FILT_DST_PORT_RANGE_INFO"},
	{0x50, "GPDS_FILT_SRC_PORT_INFO"},
	{0x51, "GPDS_FILT_SRC_PORT_RANGE_INFO"},
	{0x60, "GPDS_FILT_SPI_INFO"},
	{0x70, "GPDS_FILT_TOS_INFO"},
	{0x80, "GPDS_FILT_FLOW_LABEL_INFO"},
	{0x0A, "GPDS_TFT_FILTER_INFO"},
	{0x09, "GPDS_TFT_INFO"},
	{0x06, "GPDS_QOS99_REQ_INFO"},
	{0x07, "GPDS_QOS99_MIN_INFO"},
	{0x08, "GPDS_QOS99_NEG_INFO"},
	{0x0D, "GPDS_PDNS_ADDRESS_INFO"},
	{0x0E, "GPDS_SDNS_ADDRESS_INFO"},
	{0x0B, "GPDS_USERNAME_INFO"},
	{0x0C, "GPDS_PASSWORD_INFO"},
	{0x90, "GPDS_DNS_ADDRESS_REQ_INFO"},
	{0x0F, "GPDS_CHALLENGE_INFO"},
	{0xA0, "GPDS_CONDITIONAL_DETACH_INFO"},
	{0x11, "GPDS_RESPONSE_INFO"},
	{0xA1, "GPDS_MBMS_SERVICE_BEARER_STATE"},
	{0xA2, "GPDS_MBMS_MULTICAST_PARAMS"},
	{0xA4, "GPDS_ACTIVATE_PDP_CONTEXT_REQUEST"},
	{0xA5, "GPDS_RESOURCE_CONF"},
	{0xA3, "GPDS_RESOURCE"},
	{0xA6, "GPDS_RESOURCE_CONF_REQUIRED"},
	{0xA7, "GPDS_PIPE_REDIRECTION_INFO"},
	{0xE1, "GPDS_SHARED_APN_INFO"},
	{0xE0, "GPDS_SHARED_COMP_INFO"},
	{0xE2, "GPDS_SHARED_QOS99_REQ_INFO"},
	{0xE3, "GPDS_SHARED_QOS99_MIN_INFO"},
	{0xE4, "GPDS_SHARED_QOS99_NEG_INFO"},
	{0xE6, "GPDS_SHARED_FILT_SRC_IPV4_ADDR_INFO"},
	{0xE8, "GPDS_SHARED_FILT_PROTOCOL_INFO"},
	{0xE9, "GPDS_SHARED_FILT_DST_PORT_INFO"},
	{0xEA, "GPDS_SHARED_FILT_DST_PORT_RANGE_INFO"},
	{0xEB, "GPDS_SHARED_FILT_SRC_PORT_INFO"},
	{0xEC, "GPDS_SHARED_FILT_SRC_PORT_RANGE_INFO"},
	{0xED, "GPDS_SHARED_FILT_SPI_INFO"},
	{0xEE, "GPDS_SHARED_FILT_TOS_INFO"},
	{0xEF, "GPDS_SHARED_FILT_FLOW_LABEL_INFO"},
	{0xF6, "GPDS_SHARED_TFT_PACKET_FILTER_INFO"},
	{0xF2, "GPDS_SHARED_TFT_PARAMETER_IP_FLOW_INFO"},
	{0xF1, "GPDS_SHARED_TFT_PARAMETER_AUTH_TOKEN_INFO"},
	{0xE5, "GPDS_SHARED_TFT_INFO"},
	{0xF3, "GPDS_SHARED_PCSCF_ADDRESS_REQ_INFO"},
	{0xF4, "GPDS_SHARED_PCSCF_ADDRESS_INFO"},
	{0xF5, "GPDS_SHARED_POLICY_CONTROL_REJ_CODE_INFO"},
	{0xF7, "GPDS_SHARED_IM_CN_SIGNALING_FLAG_INFO"},
	{0xF8, "GPDS_SHARED_REL5_QOS_INFO"},
	{0xF9, "GPDS_SHARED_RADIO_ACTIVITY_REQ_INFO"},
	{0xFB, "GPDS_SHARED_MBMS_SERVICE_LIST_INFO"},
	{0xFC, "GPDS_SHARED_INITIAL_DL_DCH_RATE"},
	{0x00, NULL}
};

static const value_string isi_gpds_cid[] = {
	{0xFE, "GPDS_CID_ALL"},
	{0xFF, "GPDS_CID_VOID"},
	{0x00, NULL}
};

static const value_string isi_gpds_ppp_mode[] = {
	{0x00, "GPDS_LL_FRAMED_PPP"},
	{0x01, "GPDS_LL_NONFRAMED_PPP"},
	{0x02, "GPDS_LL_PLAIN"},
	{0x00, NULL}
};


static const value_string isi_gpds_status[] = {
	{0x00, "GPDS_ERROR"},
	{0x01, "GPDS_OK"},
	{0x02, "GPDS_FAIL"},
	{0x00, NULL}
};

static const value_string isi_gpds_pdp_type[] = {
	{0x01, "GPDS_PDP_TYPE_PPP"},
	{0x21, "GPDS_PDP_TYPE_IPV4"},
	{0x57, "GPDS_PDP_TYPE_IPV6"},
	{0xFF, "GPDS_PDP_TYPE_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_context_type[] = {
	{0x00, "GPDS_CONT_TYPE_NORMAL"},
	{0x01, "GPDS_CONT_TYPE_NWI"},
	{0x02, "GPDS_CONT_TYPE_SEC"},
	{0x00, NULL}
};

static const value_string isi_gpds_cause[] = {
	{0x00, "GPDS_CAUSE_UNKNOWN"},
	{0x02, "GPDS_CAUSE_IMSI"},
	{0x03, "GPDS_CAUSE_MS_ILLEGAL"},
	{0x06, "GPDS_CAUSE_ME_ILLEGAL"},
	{0x07, "GPDS_CAUSE_GPRS_NOT_ALLOWED"},
	{0x08, "GPDS_NOT_ALLOWED"},
	{0x09, "GPDS_CAUSE_MS_IDENTITY"},
	{0x0A, "GPDS_CAUSE_DETACH"},
	{0x0B, "GPDS_PLMN_NOT_ALLOWED"},
	{0x0C, "GPDS_LA_NOT_ALLOWED"},
	{0x0D, "GPDS_ROAMING_NOT_ALLOWED"},
	{0x0E, "GPDS_CAUSE_GPRS_NOT_ALLOWED_IN_PLMN"},
	{0x10, "GPDS_CAUSE_MSC_NOT_REACH"},
	{0x11, "GPDS_CAUSE_PLMN_FAIL"},
	{0x16, "GPDS_CAUSE_NETWORK_CONGESTION"},
	{0x18, "GPDS_CAUSE_MBMS_BEARER_CAPABILITY_INSUFFICIENT"},
	{0x19, "GPDS_CAUSE_LLC_SNDCP_FAILURE"},
	{0x1A, "GPDS_CAUSE_RESOURCE_INSUFF"},
	{0x1B, "GPDS_CAUSE_APN"},
	{0x1C, "GPDS_CAUSE_PDP_UNKNOWN"},
	{0x1D, "GPDS_CAUSE_AUTHENTICATION"},
	{0x1E, "GPDS_CAUSE_ACT_REJECT_GGSN"},
	{0x1F, "GPDS_CAUSE_ACT_REJECT"},
	{0x20, "GPDS_CAUSE_SERV_OPT_NOT_SUPPORTED"},
	{0x21, "GPDS_CAUSE_SERV_OPT_NOT_SUBSCRIBED"},
	{0x22, "GPDS_CAUSE_SERV_OPT_OUT_OF_ORDER"},
	{0x23, "GPDS_CAUSE_NSAPI_ALREADY_USED"},
	{0x24, "GPDS_CAUSE_DEACT_REGULAR"},
	{0x25, "GPDS_CAUSE_QOS"},
	{0x26, "GPDS_CAUSE_NETWORK_FAIL"},
	{0x27, "GPDS_CAUSE_REACTIVATION_REQ"},
	{0x28, "GPDS_CAUSE_FEAT_NOT_SUPPORTED"},
	{0x29, "GPDS_CAUSE_TFT_SEMANTIC_ERROR"},
	{0x2A, "GPDS_CAUSE_TFT_SYNTAX_ERROR"},
	{0x2B, "GPDS_CAUSE_CONTEXT_UNKNOWN"},
	{0x2C, "GPDS_CAUSE_FILTER_SEMANTIC_ERROR"},
	{0x2D, "GPDS_CAUSE_FILTER_SYNTAX_ERROR"},
	{0x2E, "GPDS_CAUSE_CONT_WITHOUT_TFT"},
	{0x2F, "GPDS_CAUSE_MULTICAST_MEMBERSHIP_TIMEOUT"},
	{0x60, "GPDS_CAUSE_INVALID_MANDATORY_INFO"},
	{0x61, "GPDS_CAUSE_MSG_TYPE_NON_EXISTENTOR_NOT_IMPLTD"},
	{0x62, "GPDS_CAUSE_MSG_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE"},
	{0x63, "GPDS_CAUSE_IE_NON_EXISTENT_OR_NOT_IMPLEMENTED"},
	{0x64, "GPDS_CAUSE_CONDITIONAL_IE_ERROR"},
	{0x65, "GPDS_CUASEMSG_NOT_COMPATIBLE_WITH_PROTOCOL_STATE"},
	{0x6F, "GPDS_CAUSE_UNSPECIFIED"},
	{0x70, "GPDS_CAUSE_APN_INCOMPATIBLE_WITH_CURR_CTXT"},
	{0xA0, "GPDS_CAUSE_FDN"},
	{0xA1, "GPDS_CAUSE_USER_ABORT"},
	{0xA2, "GPDS_CAUSE_CS_INACTIVE"},
	{0xA3, "GPDS_CAUSE_CSD_OVERRIDE"},
	{0xA4, "GPDS_CAUSE_APN_CONTROL"},
	{0xA5, "GPDS_CAUSE_CALL_CONTROL"},
	{0xA6, "GPDS_CAUSE_TEMPERATURE_LIMIT"},
	{0xC8, "GPDS_CAUSE_RETRY_COUNTER_EXPIRED"},
	{0xC9, "GPDS_CAUSE_NO_CONNECTION"},
	{0xF5, "GPDS_CAUSE_DETACHED"},
	{0xF7, "GPDS_CAUSE_NO_SERVICE_POWER_SAVE"},
	{0xF9, "GPDS_CAUSE_SIM_REMOVED"},
	{0xFA, "GPDS_CAUSE_POWER_OFF"},
	{0xFB, "GPDS_CAUSE_LAI_FORBIDDEN_NATIONAL_ROAM_LIST"},
	{0xFC, "GPDS_CAUSE_LAI_FORBIDDEN_REG_PROVISION_LIST"},
	{0xFD, "GPDS_CAUSE_ACCESS_BARRED"},
	{0xFE, "GPDS_CAUSE_FATAL_FAILURE"},
	{0xFF, "GPDS_CAUSE_AUT_FAILURE"},
	{0x00, NULL}
};

static const value_string isi_gpds_attach_type[] = {
	{0x01, "GPDS_ATTACH_TYPE_GPRS"},
	{0x03, "GPDS_ATTACH_TYPE_COMBINED"},
	{0x00, NULL}
};

static const value_string isi_gpds_attach_status[] = {
	{0x00, "GPDS_DETACHED"},
	{0x01, "GPDS_ATTACHED"},
	{0x00, NULL}
};

static const value_string isi_gpds_transfer_status[] = {
	{0x00, "GPDS_TRANSFER_NOT_AVAIL"},
	{0x01, "GPDS_TRANSFER_AVAIL"},
	{0x00, NULL}
};

static const value_string isi_gpds_transfer_cause[] = {
	{0x02, "GPDS_TRANSFER_CAUSE_ATTACHED"},
	{0x03, "GPDS_TRANSFER_CAUSE_DETACHED"},
	{0x04, "GPDS_TRANSFER_CAUSE_RESUMED"},
	{0x05, "GPDS_TRANSFER_CAUSE_SUSPENDED_NO_COVERAGE"},
	{0x07, "GPDS_TRANSFER_CAUSE_SUSPENDED_CALL_SMS"},
	{0x08, "GPDS_TRANSFER_CAUSE_SUSPENDED_CALL"},
	{0x09, "GPDS_TRANSFER_CAUSE_SUSPENDED_RAU"},
	{0x0A, "GPDS_TRANSFER_CAUSE_SUSPENDED_LU"},
	{0x0B, "GPDS_TRANSFER_CAUSE_DSAC_RESTRICTION"},
	{0x00, NULL}
};

static const value_string isi_gpds_client_type[] = {
	{0x01, "GPDS_CONTEXT_CLIENT_SOCKET"},
	{0x02, "GPDS_CONTEXT_CLIENT_DIAL_UP"},
	{0x00, "GPDS_CONTEXT_CLIENT_UNKNOWN"},
	{0x00, NULL}
};

static const value_string isi_gpds_attach_mode[] = {
	{0x00, "GPDS_ATTACH_MODE_MANUAL"},
	{0x01, "GPDS_ATTACH_MODE_AUTOMATIC"},
	{0xFF, "GPDS_ATTACH_MODE_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_mt_act_mode[] = {
	{0x00, "GPDS_MT_ACT_MODE_REJECT"},
	{0x01, "GPDS_MT_ACT_MODE_ACCEPT"},
	{0xFF, "GPDS_MT_ACT_MODE_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_aol_context[] = {
	{0x00, "GPDS_AOL_CTX_NOT_ACTIVE"},
	{0x01, "GPDS_AOL_CTX_HPLMN_ACTIVE"},
	{0x02, "GPDS_AOL_CTX_VPLMN_ACTIVE"},
	{0x03, "GPDS_AOL_CTX_ACTIVE"},
	{0x00, NULL}
};

static const value_string isi_gpds_classc_mode[] = {
	{0x00, "GPDS_CLASSC_MODE_GPRS"},
	{0x01, "GPDS_CLASSC_MODE_GSM"},
	{0xFF, "GPDS_CLASSC_MODE_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_precedence[] = {
	{0x00, "GPDS_QOS_PREC_0"},
	{0x01, "GPDS_QOS_PREC_1"},
	{0x02, "GPDS_QOS_PREC_2"},
	{0x03, "GPDS_QOS_PREC_3"},
	{0xFF, "GPDS_QOS_PREC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_delay[] = {
	{0x00, "GPDS_QOS_DELC_0"},
	{0x01, "GPDS_QOS_DELC_1"},
	{0x02, "GPDS_QOS_DELC_2"},
	{0x03, "GPDS_QOS_DELC_3"},
	{0x04, "GPDS_QOS_DELC_4"},
	{0xFF, "GPDS_QOS_DELC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_reliability[] = {
	{0x00, "GPDS_QOS_RELC_0"},
	{0x01, "GPDS_QOS_RELC_1"},
	{0x02, "GPDS_QOS_RELC_2"},
	{0x03, "GPDS_QOS_RELC_3"},
	{0x04, "GPDS_QOS_RELC_4"},
	{0x05, "GPDS_QOS_RELC_5"},
	{0xFF, "GPDS_QOS_RELC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_peak_throughput[] = {
	{0x00, "GPDS_QOS_PETC_0"},
	{0x01, "GPDS_QOS_PETC_1"},
	{0x02, "GPDS_QOS_PETC_2"},
	{0x03, "GPDS_QOS_PETC_3"},
	{0x04, "GPDS_QOS_PETC_4"},
	{0x05, "GPDS_QOS_PETC_5"},
	{0x06, "GPDS_QOS_PETC_6"},
	{0x07, "GPDS_QOS_PETC_7"},
	{0x08, "GPDS_QOS_PETC_8"},
	{0x09, "GPDS_QOS_PETC_9"},
	{0xFF, "GPDS_QOS_PETC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_mean_throughput[] = {
	{0x00, "GPDS_QOS_METC_0"},
	{0x01, "GPDS_QOS_METC_1"},
	{0x02, "GPDS_QOS_METC_2"},
	{0x03, "GPDS_QOS_METC_3"},
	{0x04, "GPDS_QOS_METC_4"},
	{0x05, "GPDS_QOS_METC_5"},
	{0x06, "GPDS_QOS_METC_6"},
	{0x07, "GPDS_QOS_METC_7"},
	{0x08, "GPDS_QOS_METC_8"},
	{0x09, "GPDS_QOS_METC_9"},
	{0x0A, "GPDS_QOS_METC_10"},
	{0x0B, "GPDS_QOS_METC_11"},
	{0x0C, "GPDS_QOS_METC_12"},
	{0x0D, "GPDS_QOS_METC_13"},
	{0x0E, "GPDS_QOS_METC_14"},
	{0x0F, "GPDS_QOS_METC_15"},
	{0x10, "GPDS_QOS_METC_16"},
	{0x11, "GPDS_QOS_METC_17"},
	{0x12, "GPDS_QOS_METC_18"},
	{0x1F, "GPDS_QOS_METC_31"},
	{0xFF, "GPDS_QOS_METC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_traffic_class[] = {
	{0x00, "GPDS_QOS99_TRAC_SUBSCRIBED"},
	{0x01, "GPDS_QOS99_TRAC_CONVERSATIONAL"},
	{0x02, "GPDS_QOS99_TRAC_STREAMING"},
	{0x03, "GPDS_QOS99_TRAC_INTERACTIVE"},
	{0x04, "GPDS_QOS99_TRAC_BACKGROUND"},
	{0xFF, "GPDS_QOS99_TRAC_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_delivery_order[] = {
	{0x00, "GPDS_QOS99_DELO_SUBSCRIBED"},
	{0x01, "GPDS_QOS99_DELO_YES"},
	{0x02, "GPDS_QOS99_DELO_NO"},
	{0xFF, "GPDS_QOS99_DELO_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_delivery_of_erroneous_sdus[] = {
	{0x00, "GPDS_QOS99_DOES_SUBSCRIBED"},
	{0x01, "GPDS_QOS99_DOES_NO_DETECT"},
	{0x02, "GPDS_QOS99_DOES_YES"},
	{0x03, "GPDS_QOS99_DOES_NO"},
	{0xFF, "GPDS_QOS99_DOES_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_residual_bers[] = {
	{0x00, "GPDS_QOS99_RBER_SUBSCRIBED"},
	{0x52, "GPDS_QOS99_RBER_1"},
	{0x12, "GPDS_QOS99_RBER_2"},
	{0x53, "GPDS_QOS99_RBER_3"},
	{0x43, "GPDS_QOS99_RBER_4"},
	{0x13, "GPDS_QOS99_RBER_5"},
	{0x14, "GPDS_QOS99_RBER_6"},
	{0x15, "GPDS_QOS99_RBER_7"},
	{0x16, "GPDS_QOS99_RBER_8"},
	{0x68, "GPDS_QOS99_RBER_9"},
	{0xFF, "GPDS_QOS99_RBER_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_error_ratio[] = {
	{0x00, "GPDS_QOS99_SDER_SUBSCRIBED"},
	{0x12, "GPDS_QOS99_SDER_1"},
	{0x73, "GPDS_QOS99_SDER_2"},
	{0x13, "GPDS_QOS99_SDER_3"},
	{0x14, "GPDS_QOS99_SDER_4"},
	{0x15, "GPDS_QOS99_SDER_5"},
	{0x16, "GPDS_QOS99_SDER_6"},
	{0x11, "GPDS_QOS99_SDER_7"},
	{0xFF, "GPDS_QOS99_SDER_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_priority[] = {
	{0x00, "GPDS_QOS99_TRHP_SUBSCRIBED"},
	{0x01, "GPDS_QOS99_TRHP_1"},
	{0x02, "GPDS_QOS99_TRHP_2"},
	{0x03, "GPDS_QOS99_TRHP_3"},
	{0xFF, "GPDS_QOS99_TRHP_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_rel5_source_desc[] = {
	{0x00, "GPDS_SOURCE_UNKNOWN"},
	{0x01, "GPDS_SOURCE_SPEECH"},
	{0xFF, "GPDS_SOURCE_DEFAULT"},
	{0x00, NULL}
};

static const value_string isi_gpds_rel5_sgn_ind_flag[] = {
	{0x00, "GPDS_QOS_NOT_OPT_SGN"},
	{0x01, "GPDS_QOS_OPT_SGN"},
	{0xFF, "GPDS_QOS_OPT_DEFAULT"},
	{0x00, NULL}
};





static dissector_handle_t isi_gpds_handle;
static void dissect_isi_gpds(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree);

static guint32 hf_isi_gpds_cmd = -1;
static guint32 hf_isi_gpds_subblock_type = -1;
static guint32 hf_isi_gpds_cid = -1;
static guint32 hf_isi_gpds_primary_cid = -1;
static guint32 hf_isi_gpds_pipe_handle = -1;
static guint32 hf_isi_gpds_ppp_mode = -1;
static guint32 hf_isi_gpds_status = -1;
static guint32 hf_isi_gpds_pdp_type = -1;
static guint32 hf_isi_gpds_context_type = -1;
static guint32 hf_isi_gpds_cause = -1;
static guint32 hf_isi_gpds_attach_type = -1;
static guint32 hf_isi_gpds_context_count = -1;
static guint32 hf_isi_gpds_tx_byte_count = -1;
static guint32 hf_isi_gpds_rx_byte_count = -1;
static guint32 hf_isi_gpds_transfer_status = -1;
static guint32 hf_isi_gpds_transfer_cause = -1;
static guint32 hf_isi_gpds_attach_status = -1;
static guint32 hf_isi_gpds_client_type = -1;
static guint32 hf_isi_gpds_mt_act_mode = -1;
static guint32 hf_isi_gpds_aol_context = -1;
static guint32 hf_isi_gpds_classc_mode = -1;
static guint32 hf_isi_gpds_attach_mode = -1;
static guint32 hf_isi_gpds_apn = -1;
static guint32 hf_isi_gpds_pdp_address = -1;
static guint32 hf_isi_gpds_reliability = -1;
static guint32 hf_isi_gpds_delay = -1;
static guint32 hf_isi_gpds_precedence = -1;
static guint32 hf_isi_gpds_peak_throughput = -1;
static guint32 hf_isi_gpds_mean_throughput = -1;
static guint32 hf_isi_gpds_traffic_class = -1;
static guint32 hf_isi_gpds_delivery_order = -1;
static guint32 hf_isi_gpds_delivery_of_erroneous_sdus = -1;
static guint32 hf_isi_gpds_residual_ber = -1;
static guint32 hf_isi_gpds_error_ratio = -1;
static guint32 hf_isi_gpds_transfer_delay = -1;
static guint32 hf_isi_gpds_max_sdu_size = -1;
static guint32 hf_isi_gpds_max_bitrate_uplink = -1;
static guint32 hf_isi_gpds_max_bitrate_downlink = -1;
static guint32 hf_isi_gpds_gua_bitrate_uplink = -1;
static guint32 hf_isi_gpds_gua_bitrate_downlink = -1;
static guint32 hf_isi_gpds_priority = -1;
static guint32 hf_isi_gpds_rel5_source_desc = -1;
static guint32 hf_isi_gpds_rel5_sgn_ind_flag = -1;
static guint32 hf_isi_gpds_pdns_address = -1;
static guint32 hf_isi_gpds_sdns_address = -1;



void proto_reg_handoff_isi_gpds(void) {
	static gboolean initialized=FALSE;

	if (!initialized) {
		isi_gpds_handle = create_dissector_handle(dissect_isi_gpds, proto_isi);
		dissector_add("isi.resource", 0x31, isi_gpds_handle);
	}
}

void proto_register_isi_gpds(void) {
	static hf_register_info hf[] = {
		{ &hf_isi_gpds_cmd,
			{ "Command", "isi.gpds.cmd", FT_UINT8, BASE_HEX, isi_gpds_id, 0x0, "Command", HFILL }},
		{ &hf_isi_gpds_subblock_type,
			{ "Subblock-Id", "isi.gpds.subblock_id", FT_UINT8, BASE_HEX, isi_gpds_subblock_id, 0x0, "Subblock-Id", HFILL }},
		{ &hf_isi_gpds_cid,
			{ "CID", "isi.gpds.cid", FT_UINT8, BASE_HEX, isi_gpds_cid, 0x0, "CID", HFILL }},
		{ &hf_isi_gpds_primary_cid,
			{ "Primary CID", "isi.gpds.primary_cid", FT_UINT8, BASE_HEX, isi_gpds_cid, 0x0, "Primary CID", HFILL }},
		{ &hf_isi_gpds_pipe_handle,
			{ "Pipe-Handle", "isi.gpds.pipe_handle", FT_UINT8, BASE_HEX, NULL, 0x0, "Pipe-Handle", HFILL }},
		{ &hf_isi_gpds_ppp_mode,
			{ "PPP Mode", "isi.gpds.ppp_mode", FT_UINT8, BASE_HEX, isi_gpds_ppp_mode, 0x0, "PPP Mode", HFILL }},
		{ &hf_isi_gpds_status,
			{ "Status", "isi.gpds.status", FT_UINT8, BASE_HEX, isi_gpds_status, 0x0, "Status", HFILL }},
		{ &hf_isi_gpds_pdp_type,
			{ "PDP Type", "isi.gpds.pdp_type", FT_UINT8, BASE_HEX, isi_gpds_pdp_type, 0x0, "PDP Type", HFILL }},
		{ &hf_isi_gpds_context_type,
			{ "Context Type", "isi.gpds.context_type", FT_UINT8, BASE_HEX, isi_gpds_context_type, 0x0, "Context Type", HFILL }},
		{ &hf_isi_gpds_cause,
			{ "Cause", "isi.gpds.cause", FT_UINT8, BASE_HEX, isi_gpds_cause, 0x0, "Cause", HFILL }},
		{ &hf_isi_gpds_attach_type,
			{ "Attach Type", "isi.gpds.attach_type", FT_UINT8, BASE_HEX, isi_gpds_attach_type, 0x0, "Attach Type", HFILL }},
		{ &hf_isi_gpds_attach_status,
			{ "Attach Status", "isi.gpds.attach_status", FT_UINT8, BASE_HEX, isi_gpds_attach_status, 0x0, "Attach Status", HFILL }},
		{ &hf_isi_gpds_context_count,
			{ "Context Count", "isi.gpds.context_count", FT_UINT8, BASE_DEC, NULL, 0x0, "Context Count", HFILL }},
		{ &hf_isi_gpds_tx_byte_count,
			{ "TX Bytes", "isi.gpds.tx_bytes", FT_UINT32, BASE_DEC, NULL, 0x0, "TX Bytes", HFILL }},
		{ &hf_isi_gpds_rx_byte_count,
			{ "RX Bytes", "isi.gpds.rx_bytes", FT_UINT32, BASE_DEC, NULL, 0x0, "RX Bytes", HFILL }},
		{ &hf_isi_gpds_transfer_status,
			{ "Transfer Status", "isi.gpds.transfer_status", FT_UINT8, BASE_HEX, isi_gpds_transfer_status, 0x0, "Transfer Status", HFILL }},
		{ &hf_isi_gpds_transfer_cause,
			{ "Transfer Cause", "isi.gpds.transfer_cause", FT_UINT8, BASE_HEX, isi_gpds_transfer_cause, 0x0, "Transfer Cause", HFILL }},
		{ &hf_isi_gpds_client_type,
			{ "Client Type", "isi.gpds.client_type", FT_UINT8, BASE_HEX, isi_gpds_client_type, 0x0, "Client Type", HFILL }},
		{ &hf_isi_gpds_mt_act_mode,
			{ "MT Act Mode", "isi.gpds.mt_act_mode", FT_UINT8, BASE_HEX, isi_gpds_mt_act_mode, 0x0, "MT Act Mode", HFILL }},
		{ &hf_isi_gpds_aol_context,
			{ "AOL Context", "isi.gpds.aol_context", FT_UINT8, BASE_HEX, isi_gpds_aol_context, 0x0, "AOL Context", HFILL }},
		{ &hf_isi_gpds_classc_mode,
			{ "ClassC Mode", "isi.gpds.classc_mode", FT_UINT8, BASE_HEX, isi_gpds_classc_mode, 0x0, "ClassC Mode", HFILL }},
		{ &hf_isi_gpds_attach_mode,
			{ "Attach Mode", "isi.gpds.attach_mode", FT_UINT8, BASE_HEX, isi_gpds_attach_mode, 0x0, "Attach Mode", HFILL }},
		{ &hf_isi_gpds_apn,
			{ "APN", "isi.gpds.apn", FT_STRING, BASE_NONE, NULL, 0x0, "APN", HFILL }},
		{ &hf_isi_gpds_pdp_address,
			{ "PDP Address", "isi.gpds.pdp_address", FT_STRING, BASE_NONE, NULL, 0x0, "PDP Address", HFILL }},
		{ &hf_isi_gpds_precedence,
			{ "Precedence", "isi.gpds.precedence", FT_UINT8, BASE_HEX, isi_gpds_precedence, 0x0, "Precedence", HFILL }},
		{ &hf_isi_gpds_delay,
			{ "Delay", "isi.gpds.delay", FT_UINT8, BASE_HEX, isi_gpds_delay, 0x0, "Delay", HFILL }},
		{ &hf_isi_gpds_reliability,
			{ "Relilability", "isi.gpds.reliability", FT_UINT8, BASE_HEX, isi_gpds_reliability, 0x0, "Reliability", HFILL }},
		{ &hf_isi_gpds_peak_throughput,
			{ "Peak Throughput", "isi.gpds.peak_througput", FT_UINT8, BASE_HEX, isi_gpds_peak_throughput, 0x0, "Peak Throughput", HFILL }},
		{ &hf_isi_gpds_mean_throughput,
			{ "Mean Throughput", "isi.gpds.mean_througput", FT_UINT8, BASE_HEX, isi_gpds_mean_throughput, 0x0, "Mean Througput", HFILL }},
		{ &hf_isi_gpds_traffic_class,
			{ "Traffic Class", "isi.gpds.traffic_class", FT_UINT8, BASE_HEX, isi_gpds_traffic_class, 0x0, "Traffic Class", HFILL }},
		{ &hf_isi_gpds_delivery_order,
			{ "Delivery Order", "isi.gpds.delivery_order", FT_UINT8, BASE_HEX, isi_gpds_delivery_order, 0x0, "Delivery Order", HFILL }},
		{ &hf_isi_gpds_delivery_of_erroneous_sdus,
			{ "Delivery of erroneous SDUs", "isi.gpds.deliver_of_erroneous_sdus", FT_UINT8, BASE_HEX, isi_gpds_delivery_of_erroneous_sdus, 0x0, "Delivery of erroneous SDUs", HFILL }},
		{ &hf_isi_gpds_residual_ber,
			{ "Residual BER", "isi.gpds.residual_ber", FT_UINT8, BASE_HEX, isi_gpds_residual_bers, 0x0, "Residual BER", HFILL }},
		{ &hf_isi_gpds_error_ratio,
			{ "Error Ratio", "isi.gpds.error_ratio", FT_UINT8, BASE_HEX, isi_gpds_error_ratio, 0x0, "Error Ratio", HFILL }},
		{ &hf_isi_gpds_transfer_delay,
			{ "Transfer Delay", "isi.gpds.transfer_delay", FT_UINT16, BASE_DEC, NULL, 0x0, "Transfer Delay", HFILL }},
		{ &hf_isi_gpds_max_sdu_size,
			{ "Max SDU size", "isi.gpds.max_sdu", FT_UINT16, BASE_DEC, NULL, 0x0, "Max SDU size", HFILL }},
		{ &hf_isi_gpds_max_bitrate_uplink,
			{ "Max Bitrate Uplink", "isi.gpds.max_bitrate_uplink", FT_UINT16, BASE_DEC, NULL, 0x0, "Max Bitrate Uplink", HFILL }},
		{ &hf_isi_gpds_max_bitrate_downlink,
			{ "Max Bitrate Downlink", "isi.gpds.max_bitrate_downlink", FT_UINT16, BASE_DEC, NULL, 0x0, "Max Bitrate Downlink", HFILL }},
		{ &hf_isi_gpds_gua_bitrate_uplink,
			{ "GUA Bitrate Uplink", "isi.gpds.gua_bitrate_uplink", FT_UINT16, BASE_DEC, NULL, 0x0, "GUA Bitrate Uplink", HFILL }},
		{ &hf_isi_gpds_gua_bitrate_downlink,
			{ "GUA Bitrate Downlink", "isi.gpds.gua_bitrate_downlink", FT_UINT16, BASE_DEC, NULL, 0x0, "GUA Bitrate Downlink", HFILL }},
		{ &hf_isi_gpds_priority,
			{ "Priority", "isi.gpds.priority", FT_UINT8, BASE_HEX, isi_gpds_priority, 0x0, "Priority", HFILL }},
		{ &hf_isi_gpds_rel5_source_desc,
			{ "Source Desc", "isi.gpds.rel5_source_desc", FT_UINT8, BASE_HEX, isi_gpds_rel5_source_desc, 0x0, "Source Desc", HFILL }},
		{ &hf_isi_gpds_rel5_sgn_ind_flag,
			{ "Sgn Ind Flag", "isi.gpds.rel5_sgn_ind_flag", FT_UINT8, BASE_HEX, isi_gpds_rel5_sgn_ind_flag, 0x0, "Sgn Ind Flag", HFILL }},
		{ &hf_isi_gpds_pdns_address,
			{ "PDNS Address", "isi.gpds.pdns_address", FT_STRING, BASE_NONE, NULL, 0x0, "PDNS Adress", HFILL }},
		{ &hf_isi_gpds_sdns_address,
			{ "SDNS Address", "isi.gpds.sdns_address", FT_STRING, BASE_NONE, NULL, 0x0, "SDNS Adress", HFILL }},
	};

	proto_register_field_array(proto_isi, hf, array_length(hf));
	register_dissector("isi.gpds", dissect_isi_gpds, proto_isi);
}


static void _sub_gpds_qos99_neg_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_gpds_traffic_class, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_delivery_order, tvb, 3, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_delivery_of_erroneous_sdus, tvb, 4, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_residual_ber, tvb, 5, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_error_ratio, tvb, 6, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_priority, tvb, 7, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_transfer_delay, tvb, 8, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_max_sdu_size, tvb, 10, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_max_bitrate_uplink, tvb, 12, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_max_bitrate_downlink, tvb, 14, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_gua_bitrate_uplink, tvb, 16, 2, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_gua_bitrate_downlink, tvb, 18, 2, FALSE);
}

static void _sub_gpds_qos_neg_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_gpds_precedence, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_delay, tvb, 3, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_reliability, tvb, 4, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_peak_throughput, tvb, 5, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_mean_throughput, tvb, 6, 1, FALSE);
}

static void _sub_gpds_string(guint32 hf, guint8 offset, tvbuff_t *tvb, proto_tree *tree) {
	guint8 l = tvb_get_guint8(tvb, offset);
	proto_tree_add_string(tree, hf, tvb, offset+1, l, tvb_memdup(tvb, offset+1, l));
}

static void _sub_gpds_dns_address_req_info(tvbuff_t *tvb, proto_tree *tree) {
	/* seems to be empty */
}

static void _sub_gpds_shared_rel5_qos_info(tvbuff_t *tvb, proto_tree *tree) {
	proto_tree_add_item(tree, hf_isi_gpds_rel5_source_desc, tvb, 2, 1, FALSE);
	proto_tree_add_item(tree, hf_isi_gpds_rel5_sgn_ind_flag, tvb, 3, 1, FALSE);
}


static void dissect_isi_gpds_subblock(guint8 sptype, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree) {
	switch(sptype) {
		case 0x03: _sub_gpds_qos_neg_info(tvb, tree); break;                           /* GPDS_QOS_NEG_INFO */
		case 0x04: _sub_gpds_string(hf_isi_gpds_pdp_address, 3, tvb, tree); break;     /* GPDS_PDP_ADDRESS_INFO */
		case 0x05: _sub_gpds_string(hf_isi_gpds_apn, 2, tvb, tree); break;             /* GPDS_APN_INFO */
		case 0x08: _sub_gpds_qos99_neg_info(tvb, tree); break;                         /* GPDS_QOS99_NEG_INFO */
		case 0x0D: _sub_gpds_string(hf_isi_gpds_pdns_address, 3, tvb, tree); break;    /* GPDS_PDNS_ADDRESS_INFO */
		case 0x0E: _sub_gpds_string(hf_isi_gpds_sdns_address, 3, tvb, tree); break;    /* GPDS_SDNS_ADDRESS_INFO */
		case 0x90: _sub_gpds_dns_address_req_info(tvb, tree); break;                   /* GPDS_DNS_ADDRESS_REQ_INFO */
		case 0xE4: _sub_gpds_qos99_neg_info(tvb, tree); break;                         /* GPDS_SHARED_QOS99_NEG_INFO */
		case 0xF8: _sub_gpds_shared_rel5_qos_info(tvb, tree); break;                   /* GPDS_SHARED_REL5_QOS_INFO */
		case 0x00: /* GPDS_COMP_INFO */
		case 0x01: /* GPDS_QOS_REQ_INFO */
		case 0x02: /* GPDS_QOS_MIN_INFO */
		case 0x10: /* GPDS_FILT_SRC_IPV4_ADDR_INFO */
		case 0x20: /* GPDS_FILT_SRC_IPV6_ADDR_INFO */
		case 0x30: /* GPDS_FILT_PROTOCOL_INFO */
		case 0x40: /* GPDS_FILT_DST_PORT_INFO */
		case 0x41: /* GPDS_FILT_DST_PORT_RANGE_INFO */
		case 0x50: /* GPDS_FILT_SRC_PORT_INFO */
		case 0x51: /* GPDS_FILT_SRC_PORT_RANGE_INFO */
		case 0x60: /* GPDS_FILT_SPI_INFO */
		case 0x70: /* GPDS_FILT_TOS_INFO */
		case 0x80: /* GPDS_FILT_FLOW_LABEL_INFO */
		case 0x0A: /* GPDS_TFT_FILTER_INFO */
		case 0x09: /* GPDS_TFT_INFO */
		case 0x06: /* GPDS_QOS99_REQ_INFO */
		case 0x07: /* GPDS_QOS99_MIN_INFO */
		case 0x0B: /* GPDS_USERNAME_INFO */
		case 0x0C: /* GPDS_PASSWORD_INFO */
		case 0x0F: /* GPDS_CHALLENGE_INFO */
		case 0xA0: /* GPDS_CONDITIONAL_DETACH_INFO */
		case 0x11: /* GPDS_RESPONSE_INFO */
		case 0xA1: /* GPDS_MBMS_SERVICE_BEARER_STATE */
		case 0xA2: /* GPDS_MBMS_MULTICAST_PARAMS */
		case 0xA4: /* GPDS_ACTIVATE_PDP_CONTEXT_REQUEST */
		case 0xA5: /* GPDS_RESOURCE_CONF */
		case 0xA3: /* GPDS_RESOURCE */
		case 0xA6: /* GPDS_RESOURCE_CONF_REQUIRED */
		case 0xA7: /* GPDS_PIPE_REDIRECTION_INFO */
		case 0xE1: /* GPDS_SHARED_APN_INFO */
		case 0xE0: /* GPDS_SHARED_COMP_INFO */
		case 0xE2: /* GPDS_SHARED_QOS99_REQ_INFO */
		case 0xE3: /* GPDS_SHARED_QOS99_MIN_INFO */
		case 0xE6: /* GPDS_SHARED_FILT_SRC_IPV4_ADDR_INFO */
		case 0xE8: /* GPDS_SHARED_FILT_PROTOCOL_INFO */
		case 0xE9: /* GPDS_SHARED_FILT_DST_PORT_INFO */
		case 0xEA: /* GPDS_SHARED_FILT_DST_PORT_RANGE_INFO */
		case 0xEB: /* GPDS_SHARED_FILT_SRC_PORT_INFO */
		case 0xEC: /* GPDS_SHARED_FILT_SRC_PORT_RANGE_INFO */
		case 0xED: /* GPDS_SHARED_FILT_SPI_INFO */
		case 0xEE: /* GPDS_SHARED_FILT_TOS_INFO */
		case 0xEF: /* GPDS_SHARED_FILT_FLOW_LABEL_INFO */
		case 0xF6: /* GPDS_SHARED_TFT_PACKET_FILTER_INFO */
		case 0xF2: /* GPDS_SHARED_TFT_PARAMETER_IP_FLOW_INFO */
		case 0xF1: /* GPDS_SHARED_TFT_PARAMETER_AUTH_TOKEN_INFO */
		case 0xE5: /* GPDS_SHARED_TFT_INFO */
		case 0xF3: /* GPDS_SHARED_PCSCF_ADDRESS_REQ_INFO */
		case 0xF4: /* GPDS_SHARED_PCSCF_ADDRESS_INFO */
		case 0xF5: /* GPDS_SHARED_POLICY_CONTROL_REJ_CODE_INFO */
		case 0xF7: /* GPDS_SHARED_IM_CN_SIGNALING_FLAG_INFO */
		case 0xF9: /* GPDS_SHARED_RADIO_ACTIVITY_REQ_INFO */
		case 0xFB: /* GPDS_SHARED_MBMS_SERVICE_LIST_INFO */
		case 0xFC: /* GPDS_SHARED_INITIAL_DL_DCH_RATE */
		default:
			expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported subblock");
			break;
	}
}

static void dissect_isi_gpds(tvbuff_t *tvb, packet_info *pinfo, proto_item *isitree) {
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint8 cmd, code;

	if(isitree) {
		item = proto_tree_add_text(isitree, tvb, 0, -1, "Payload");
		tree = proto_item_add_subtree(item, ett_isi_msg);

		proto_tree_add_item(tree, hf_isi_gpds_cmd, tvb, 0, 1, FALSE);
		cmd = tvb_get_guint8(tvb, 0);

		switch (cmd) {

			case 0x00: /* GPDS_LL_CONFIGURE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS LL Configure Request");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_pipe_handle, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_ppp_mode, tvb, 3, 1, FALSE);
				break;
			case 0x01: /* GPDS_LL_CONFIGURE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS LL Configure Response");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_status, tvb, 2, 1, FALSE);
				break;
			case 0x02: /* GPDS_CONTEXT_ID_CREATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context ID Create Request");
				break;
			case 0x03: /* GPDS_CONTEXT_ID_CREATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context ID Create Response");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_status, tvb, 2, 1, FALSE);
				break;
			case 0x04: /* GPDS_CONTEXT_ID_CREATE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context ID Create Indication");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				break;
			case 0x06: /* GPDS_CONTEXT_CONFIGURE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Configure Request");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_pdp_type, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_context_type, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_primary_cid, tvb, 4, 1, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 7, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x07: /* GPDS_CONTEXT_CONFIGURE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Configure Response");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_status, tvb, 2, 1, FALSE);
				break;
			case 0x08: /* GPDS_CONTEXT_ACTIVATE_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Activate Request");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x09: /* GPDS_CONTEXT_ACTIVATE_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Activate Response");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_status, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_cause, tvb, 3, 1, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 7, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x0A: /* GPDS_CONTEXT_ACTIVATE_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Activate Indication");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 3, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x15: /* GPDS_ATTACH_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Attach Indication");
				proto_tree_add_item(tree, hf_isi_gpds_attach_type, tvb, 1, 1, FALSE);
				break;
			case 0x19: /* GPDS_STATUS_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Status Request");
				break;
			case 0x1A: /* GPDS_STATUS_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Status Response");
				proto_tree_add_item(tree, hf_isi_gpds_attach_status, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_context_count, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_tx_byte_count, tvb, 3, 4, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_rx_byte_count, tvb, 7, 4, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_transfer_status, tvb, 11, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_transfer_cause, tvb, 12, 1, FALSE);
				// TODO: the cid list
				break;
			case 0x1E: /* GPDS_TRANSFER_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Transfer Status Indication");
				proto_tree_add_item(tree, hf_isi_gpds_transfer_status, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_transfer_cause, tvb, 2, 1, FALSE);
				break;
			case 0x22: /* GPDS_CONTEXT_STATUS_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Status Request");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				break;
			case 0x23: /* GPDS_CONTEXT_STATUS_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Status Response");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_status, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_tx_byte_count, tvb, 3, 4, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_rx_byte_count, tvb, 7, 4, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 15, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x24: /* GPDS_CONTEXT_STATUS_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Status Indication");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_tx_byte_count, tvb, 3, 4, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_rx_byte_count, tvb, 7, 4, FALSE);
				break;
			case 0x25: /* GPDS_CONTEXT_ACTIVATING_IND */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Context Activating Indication");
				proto_tree_add_item(tree, hf_isi_gpds_cid, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_client_type, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_pdp_type, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_context_type, tvb, 4, 1, FALSE);
				dissect_isi_subpacket(hf_isi_gpds_subblock_type, 7, tvb, pinfo, item, tree, dissect_isi_gpds_subblock);
				break;
			case 0x30: /* GPDS_CONFIGURATION_INFO_REQ */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Configuration Info Request");
				break;
			case 0x31: /* GPDS_CONFIGURATION_INFO_RESP */
				col_set_str(pinfo->cinfo, COL_INFO, "GPDS Configuration Info Response");
				proto_tree_add_item(tree, hf_isi_gpds_attach_mode, tvb, 1, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_mt_act_mode, tvb, 2, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_classc_mode, tvb, 3, 1, FALSE);
				proto_tree_add_item(tree, hf_isi_gpds_aol_context, tvb, 4, 1, FALSE);
				break;

			case 0xF0: /* GPDS_COMMON_MESSAGE */
				dissect_isi_common("GPDS", tvb, pinfo, tree);
				break;
			case 0x05: /* GPDS_CONTEXT_ID_DELETE_IND */
			case 0x20: /* GPDS_LL_BIND_REQ */
			case 0x21: /* GPDS_LL_BIND_RESP */
			case 0x2A: /* GPDS_CONTEXT_MODIFY_REQ */
			case 0x2B: /* GPDS_CONTEXT_MODIFY_RESP */
			case 0x2C: /* GPDS_CONTEXT_MODIFY_IND */
			case 0x1F: /* GPDS_CONTEXT_ACTIVATE_FAIL_IND */
			case 0x0B: /* GPDS_CONTEXT_DEACTIVATE_REQ */
			case 0x0C: /* GPDS_CONTEXT_DEACTIVATE_RESP */
			case 0x0D: /* GPDS_CONTEXT_DEACTIVATE_IND */
			case 0x2F: /* GPDS_CONTEXT_DEACTIVATING_IND */
			case 0x0E: /* GPDS_CONTEXT_NWI_ACT_REQUEST_IND */
			case 0x0F: /* GPDS_CONTEXT_NWI_ACT_REJECT_REQ */
			case 0x10: /* GPDS_CONTEXT_NWI_ACT_REJECT_RESP */
			case 0x11: /* GPDS_CONFIGURE_REQ */
			case 0x12: /* GPDS_CONFIGURE_RESP */
			case 0x13: /* GPDS_ATTACH_REQ */
			case 0x14: /* GPDS_ATTACH_RESP */
			case 0x2D: /* GPDS_ATTACH_FAIL_IND */
			case 0x16: /* GPDS_DETACH_REQ */
			case 0x17: /* GPDS_DETACH_RESP */
			case 0x18: /* GPDS_DETACH_IND */
			case 0x1B: /* GPDS_SMS_PDU_SEND_REQ */
			case 0x1C: /* GPDS_SMS_PDU_SEND_RESP */
			case 0x1D: /* GPDS_SMS_PDU_RECEIVE_IND */
			case 0x32: /* GPDS_CONFIGURATION_INFO_IND */
			case 0x33: /* GPDS_CONTEXT_AUTH_REQ */
			case 0x34: /* GPDS_CONTEXT_AUTH_RESP */
			case 0x35: /* GPDS_TEST_MODE_REQ */
			case 0x36: /* GPDS_TEST_MODE_RESP */
			case 0x37: /* GPDS_RADIO_ACTIVITY_IND */
			case 0x38: /* GPDS_FORCED_READY_STATE_REQ */
			case 0x39: /* GPDS_FORCED_READY_STATE_RESP */
			case 0x3A: /* GPDS_CONTEXTS_CLEAR_REQ */
			case 0x3B: /* GPDS_CONTEXTS_CLEAR_RESP */
			case 0x3C: /* GPDS_MBMS_SERVICE_SELECTION_REQ */
			case 0x3D: /* GPDS_MBMS_SERVICE_SELECTION_RESP */
			case 0x3E: /* GPDS_MBMS_STATUS_IND */
			case 0x3F: /* GPDS_MBMS_CONTEXT_CREATE_REQ */
			case 0x40: /* GPDS_MBMS_CONTEXT_CREATE_RESP */
			case 0x41: /* GPDS_MBMS_CONTEXT_ACTIVATE_REQ */
			case 0x42: /* GPDS_MBMS_CONTEXT_ACTIVATE_RESP */
			case 0x43: /* GPDS_MBMS_CONTEXT_DELETE_REQ */
			case 0x44: /* GPDS_MBMS_CONTEXT_DELETE_RESP */
			case 0x45: /* GPDS_MBMS_CONTEXT_DELETE_IND */
			case 0x46: /* GPDS_MBMS_SERVICE_SELECTION_IND */
			case 0x47: /* GPDS_MBMS_SERVICE_AVAILABLE_IND */
			case 0x48: /* GPDS_TEST_REQ */
			case 0x49: /* GPDS_TEST_RESP */
			case 0x50: /* GPDS_RESOURCE_CONTROL_IND */
			case 0x51: /* GPDS_RESOURCE_CONTROL_REQ */
			case 0x52: /* GPDS_RESOURCE_CONTROL_RESP */
			case 0x54: /* GPDS_RESOURCE_CONF_REQ */
			case 0x55: /* GPDS_RESOURCE_CONF_RESP */
			case 0x53: /* GPDS_RESOURCE_CONF_IND */
			case 0x56: /* GPDS_PROPERTY_SET_REQ */
			case 0x57: /* GPDS_PROPERTY_SET_RESP */
			case 0xEE: /* GPDS_RESP */
			default:
				col_set_str(pinfo->cinfo, COL_INFO, "unhandled GPDS packet");
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN, "unsupported packet");
				break;
		}
	}
}





