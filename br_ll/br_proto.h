/*
 * Soft-BR protocol constants, baseband packet headers, FHS structure, and HCI/vendor opcodes.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bluetooth slot timing: 625 us per slot, 312.5 us per CLKN tick. */
#define BR_SLOT_US              625u
#define BR_TWO_SLOTS_US         1250u
#define BR_FOUR_SLOTS_US        2500u

/* Standard Inquiry LAPs (Bluetooth Assigned Numbers). */
#define BR_LAP_GIAC             0x9E8B33u
#define BR_LAP_LIAC             0x9E8B00u

/* Default Check Initialization (DCI) for Inquiry FHS HEC and CRC16. */
#define BR_DCI_UAP              0x00u

/* Baseband packet TYPE codes (4 bits, Core Spec Vol 2 Part B Table 6.2). */
#define BR_PKT_NULL             0x0u
#define BR_PKT_POLL             0x1u
#define BR_PKT_FHS              0x2u
#define BR_PKT_DM1              0x3u
#define BR_PKT_DH1              0x4u
#define BR_PKT_AUX1             0x9u
#define BR_PKT_DM3              0xAu
#define BR_PKT_DH3              0xBu
#define BR_PKT_DM5              0xEu
#define BR_PKT_DH5              0xFu

/* Baseband payload header LLID codes (2 bits). */
#define BR_LLID_L2CAP_CONT      0x1u
#define BR_LLID_L2CAP_START     0x2u
#define BR_LLID_LMP             0x3u

/* Maximum user bytes per baseband packet (excluding payload header & CRC16). */
#define BR_MAX_DM1_BYTES        17u
#define BR_MAX_DH1_BYTES        27u
/* A 1-slot packet both peers of the 2026-11-11 data probe acknowledged at once, where 27 bytes were refused about
 * 400 times for each success (hardware runs 21 and 22). */
#define BR_SHORT_DH1_BYTES      20u
#define BR_MAX_DM3_BYTES        121u
#define BR_MAX_DH3_BYTES        183u
/* Default Soft-BR DH3 cap leaving >180 us PLL turnaround margin before Slave RX slot. */
#define BR_DEFAULT_DH3_CAP      168u

/* Distinct Classic ACL connection handle range (disjoint from BLE 0x0000..0x000F and CIS 0x0E00+). */
#define BR_ACL_HANDLE_BASE      0x0B00u

/* H4 packet indicators. */
#define BR_H4_CMD               0x01u
#define BR_H4_ACL               0x02u
#define BR_H4_SCO               0x03u
#define BR_H4_EVT               0x04u

/* Standard Bluetooth Classic HCI Command Opcodes handled by Soft-BR. */
#define BR_HCI_OP_INQUIRY                   0x0401u
#define BR_HCI_OP_INQUIRY_CANCEL            0x0402u
#define BR_HCI_OP_CREATE_CONN               0x0405u
#define BR_HCI_OP_DISCONNECT                0x0406u
#define BR_HCI_OP_CREATE_CONN_CANCEL        0x0408u
#define BR_HCI_OP_REMOTE_NAME_REQ           0x0419u
#define BR_HCI_OP_WRITE_SCAN_ENABLE         0x0C1Au
#define BR_HCI_OP_RESET                     0x0C03u

/* Vendor-specific HCI opcode for Soft-BR control, LMP bridge, encryption, AFH, and diagnostics. */
#define BR_HCI_OP_VENDOR_BRC6               0xFC31u
#define BR_VENDOR_MAGIC_0                   'B'
#define BR_VENDOR_MAGIC_1                   'R'
#define BR_VENDOR_MAGIC_2                   'C'
#define BR_VENDOR_MAGIC_3                   '6'

typedef enum {
	BR_VS_PING              = 0x01, /* Returns fw capabilities, local Classic BD_ADDR, current CLK */
	BR_VS_GET_DIAG          = 0x02, /* Returns slot counters, ACK/NAK/CRC/HEC stats, crash fuse state */
	BR_VS_SET_KNOBS         = 0x03, /* Runtime radio knobs: tx_mode, gauss_bt05, dh3_cap, poll_interval */
	BR_VS_SEND_LMP          = 0x04, /* Queue 1..17 B LMP PDU (LLID=3) on active ACL handle */
	BR_VS_START_ENC         = 0x05, /* Atomic E0 start: pause L2CAP, send LMP_start_encryption_req, RX E0 -> TX E0 */
	BR_VS_STOP_ENC          = 0x06, /* Disable E0 encryption on active link */
	BR_VS_SET_AFH           = 0x07, /* Schedule AFH channel map + send LMP_set_afh with future instant */
	BR_VS_SET_BD_ADDR       = 0x08, /* Override local Classic BD_ADDR (auto-adjusts LAP[13:6] if requested) */
	BR_VS_ABORT_ALL         = 0x09, /* Immediate teardown of Inquiry/Page/ACL */
	BR_VS_SET_TX_SLOTS      = 0x0A, /* [slots]: longest ACL packet the peer allows us, 1 or 3 (LMP_max_slot) */
	BR_VS_GET_CHAN_STATS    = 0x0B, /* Returns pairs on the air and pairs answered per RF channel (79 + 79 bytes) */
	BR_VS_GET_GAPS          = 0x0C, /* Returns and clears the gaps in the peer's answers: [count][missed] then per gap
	                                 * start (us, 32 bit), length (100 us units, 16 bit), pairs (16 bit) */
	BR_VS_CRASH_TEST        = 0x7F, /* Intentional panic in test builds only (guarded) */
} br_vendor_subcmd_t;

typedef enum {
	BR_VSEVT_LMP_RX         = 0x01, /* [magic4][0x01][handle_lo][handle_hi][len][lmp_bytes...] */
	BR_VSEVT_ENC_STATE      = 0x02, /* [magic4][0x02][handle_lo][handle_hi][status][enc_on] */
	BR_VSEVT_DIAG_SNAPSHOT  = 0x03, /* Periodic/requested diagnostic telemetry */
} br_vendor_evt_t;

/* Standard HCI Event Codes emitted by Soft-BR. */
#define BR_HCI_EVT_INQUIRY_COMPLETE         0x01u
#define BR_HCI_EVT_INQUIRY_RESULT           0x02u
#define BR_HCI_EVT_CONN_COMPLETE            0x03u
#define BR_HCI_EVT_DISCONN_COMPLETE         0x05u
#define BR_HCI_EVT_REMOTE_NAME_COMPLETE     0x07u
#define BR_HCI_EVT_CMD_COMPLETE             0x0Eu
#define BR_HCI_EVT_CMD_STATUS               0x0Fu
#define BR_HCI_EVT_NUM_COMP_PKTS            0x13u
#define BR_HCI_EVT_INQUIRY_RESULT_RSSI      0x22u
#define BR_HCI_EVT_EXT_INQUIRY_RESULT       0x2Fu
#define BR_HCI_EVT_VENDOR                   0xFFu

/* Decoded 10-bit Baseband Packet Header. */
typedef struct {
	uint8_t lt_addr; /* 0..7 */
	uint8_t type;    /* BR_PKT_* */
	uint8_t flow;    /* 1 = GO, 0 = STOP */
	uint8_t arqn;    /* 1 = ACK, 0 = NAK */
	uint8_t seqn;    /* 0 or 1 */
} br_pkt_hdr_t;

/* Decoded 144-bit (18-byte) FHS Payload (Core Spec Vol 2 Part B §6.5.1.4). */
typedef struct {
	uint64_t parity34;          /* Low 34 bits of sender's SyncWord (sw_air[33:0]) */
	uint32_t lap;               /* 24-bit Lower Address Part */
	bool     eir;               /* Extended Inquiry Response follows */
	uint8_t  sr;                /* 2-bit Scan Repetition mode (R0=0, R1=1, R2=2) */
	uint8_t  sp;                /* 2-bit Scan Period (mandatory=2 in modern spec) */
	uint8_t  uap;               /* 8-bit Upper Address Part */
	uint16_t nap;               /* 16-bit Non-significant Address Part */
	uint32_t class_of_device;   /* 24-bit Class of Device */
	uint8_t  lt_addr;           /* 3-bit assigned LT_ADDR (1..7 in Page Master Response, 0 in Inquiry) */
	uint32_t clk27_2;           /* 26 bits: sender's CLK[27:2] */
	uint8_t  page_scan_mode;    /* 3-bit Page Scan Mode (0 = mandatory) */
} br_fhs_t;

void br_bdaddr_to_parts(const uint8_t bd_addr[6], uint32_t *lap, uint8_t *uap, uint16_t *nap);
void br_parts_to_bdaddr(uint32_t lap, uint8_t uap, uint16_t nap, uint8_t bd_addr[6]);

uint16_t br_pkt_hdr_pack10(const br_pkt_hdr_t *h);
void br_pkt_hdr_unpack10(uint16_t raw10, br_pkt_hdr_t *out);

void br_fhs_pack(const br_fhs_t *fhs, uint8_t out18[18]);
void br_fhs_unpack(const uint8_t in18[18], br_fhs_t *out);

/* Pack/unpack 1-byte (DM1/DH1) or 2-byte (DM3/DH3/DM5/DH5) ACL baseband payload header. */
bool br_pkt_is_multislot(uint8_t pkt_type);
bool br_pkt_uses_fec23(uint8_t pkt_type);
bool br_pkt_has_crc(uint8_t pkt_type);
uint8_t br_pkt_slot_count(uint8_t pkt_type);
uint16_t br_acl_hdr_pack(bool multislot, uint8_t llid, uint8_t flow, uint16_t payload_len, uint8_t out_hdr[2]);
bool br_acl_hdr_unpack(bool multislot, const uint8_t *buf, uint16_t buf_len,
		uint8_t *llid, uint8_t *flow, uint16_t *payload_len, uint8_t *hdr_bytes);

#ifdef __cplusplus
}
#endif
