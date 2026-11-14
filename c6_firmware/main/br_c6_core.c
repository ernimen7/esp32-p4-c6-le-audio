/*
 * Cyberdeck Soft-BR: ESP32-C6 core adapter - br_engine instance, LL-task hop via static
 * ble_npl_event, esp_timer, non-blocking SDIO H4 queues, and 2-crash RTC/NVS safety fuse.
 */
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_private/panic_internal.h"
#include "esp_rom_sys.h"
#include "riscv/rvruntime-frames.h"
#include "soc/soc.h"
#include "esp_attr.h"
#include "esp_bt.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nimble/nimble_npl.h"
#include "nimble/npl_freertos.h"
#include "nvs.h"

#include "br_c6.h"
#include "br_c6_crash.h"
#include "br_crypto.h"
#include "cis_c6.h"
#if CONFIG_CYBERDECK_WIFI_TAP
#include "wifi_tap.h"
#endif

static const char *TAG = "br_c6";

/* ble_ll.c.o: posts event onto the controller LL task event queue */
extern void r_ble_ll_event_send(struct ble_npl_event *ev);

/* ---- H2C ring buffer (allocated once in internal RAM) ---- */
#define BR_H2C_SLOTS    16u
#define BR_H2C_MAX_PKT  (5u + BR_ACL_SDU_MAX)

typedef enum {
	BR_H2C_TAKE  = 0,
	BR_H2C_SNOOP = 1,
} br_h2c_kind_t;

typedef struct {
	uint8_t  kind;
	uint16_t len;
	uint8_t  data[BR_H2C_MAX_PKT];
} br_h2c_slot_t;

static br_h2c_slot_t *s_h2c;
static uint32_t s_h2c_wr;
static uint32_t s_h2c_rd;
static portMUX_TYPE s_h2c_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_h2c_lost_acl;

/* ---- Engine -> Host non-blocking queue ---- */
#define BR_HOST_Q_DEPTH 32u

typedef struct {
	uint8_t *buf;
	uint16_t len;
} br_host_pkt_t;

static QueueHandle_t s_host_q;
static uint32_t s_deferred_nocp;

/* ---- LL-task kick event ---- */
#define BR_KICK_INIT     (1u << 0)
#define BR_KICK_H2C      (1u << 1)
#define BR_KICK_TIMER    (1u << 2)
#define BR_KICK_SELFTEST (1u << 3)
#define BR_KICK_WATCH    (1u << 4)
#define BR_KICK_RXEND    (1u << 5)
#define BR_KICK_SHUTDOWN (1u << 31)

static void br_kick_handler(struct ble_npl_event *ev);
static struct ble_npl_event_freertos s_kick_impl;
static struct ble_npl_event s_kick = { .event = &s_kick_impl };
static uint32_t s_kick_bits;
static SemaphoreHandle_t s_shutdown_done;

static void *s_engine_mem;
static br_engine_t *s_engine;
static esp_timer_handle_t s_timer;
static esp_timer_handle_t s_rx_timer; /* end of the next RX slot: br_c6_radio_service */
static TaskHandle_t s_ll_task;
static bool s_on;
static bool s_radio_ok;

/* ---- Crash guard (RTC + NVS, isolated from fw_guard and cis_c6) ---- */
#define BR_C6_LIVE_MAGIC 0x42524336u /* 'BRC6' */
#define BR_C6_NVS_NS     "br_c6"
#define BR_C6_NVS_CRASH  "crash"

static RTC_NOINIT_ATTR uint32_t s_rtc_live;
static bool s_boot_live;       /* the marker above as this start found it */
static uint8_t s_boot_crashes; /* crashes during Soft-BR on record for this image, this start included */

/* ---- Black box: what a crash of the chip leaves to read ----
 * Fourth hardware run, 2026-11-10: the chip resets itself a few seconds into the first inquiry, at the same place
 * twice, and the host resets it again before anything can be read. So the panic handler is wrapped (--wrap in
 * CMakeLists.txt): where it happened goes to memory that survives the chip's own reset, the next start moves it to
 * NVS (the host's reset pin does not keep that memory), and every start reports it in the trace (box_trace).
 * 2026-11-12: every image keeps the record, not only the bench image. That morning a regular image restarted the
 * chip within a second of the host's first Classic command, several times in half an hour, then no more, and left
 * nothing that says why. Two things were added for the next time: the code addresses on the stack, and the last
 * characters the ROM printed - the closed Bluetooth controller reports a failed assertion of its own there
 * ("BLE assert: line N in function F, param: ..", bt.c) right before it stops the chip, and the panic reason
 * names only the wrapper that printed it. */
#define BR_C6_PANIC_MAGIC 0x42525043u /* 'BRPC' */
#define BR_C6_TAIL_MAGIC  0x42525454u /* 'BRTT' */
#define BR_C6_NVS_DUMP    "dump"
#ifdef BR_ST_CRASH_TEST
#define BR_C6_DUMP_VER    0x83u /* the record of the black box trial: no other image reads it back as a crash */
#else
#define BR_C6_DUMP_VER    3u
#endif
/* Words on the stack that point into code. Not all of them are return addresses of the calls that led to the
 * panic - the stack also holds what earlier calls left - so more are kept than a call chain is deep: in the trial
 * on the chip (2026-11-12) the function that asserted was the eleventh. */
#define BR_C6_PANIC_CODE  24u
#define BR_C6_STACK_WORDS 256u /* how far above the stack pointer they are looked for */
#define BR_C6_ROM_TAIL    96u  /* characters kept from the ROM's output */
typedef struct {
	uint32_t magic;
	uint32_t pc;
	uint32_t ra;
	uint32_t sp;
	uint32_t cause;
	uint32_t tval;
	uint32_t code[BR_C6_PANIC_CODE]; /* nearest first; 0: no more */
	uint8_t  exception; /* panic_exception_t | pseudo cause << 7 */
	char     task[8];
	char     reason[48];
} br_c6_panic_t;
typedef struct {
	uint32_t magic;
	uint32_t n; /* characters since the start; the newest is ring[(n - 1) % BR_C6_ROM_TAIL] */
	char     ring[BR_C6_ROM_TAIL];
} br_c6_rom_tail_t;
typedef struct {
	uint8_t       ver;
	uint8_t       reset;   /* esp_reset_reason of the start that found the crash */
	uint8_t       crashes; /* crashes on record then */
	uint8_t       where;   /* BR_AT_* of the LL task, 0xFF: no record */
	uint32_t      last_esp_us;
	uint32_t      tx_done;
	uint8_t       img[4];  /* image of the start that found it, from its ELF hash: the image that crashed, unless
	                        * fw_guard went back to the previous one in between */
	uint32_t      rom_chars; /* characters the ROM printed in the run that crashed; 0: not kept */
	char          rom_tail[BR_C6_ROM_TAIL]; /* the last of them, oldest first */
	br_c6_panic_t panic;   /* magic 0: the reset left no panic record (watchdog reset, brownout) */
} br_c6_dump_t;
static RTC_NOINIT_ATTR br_c6_panic_t s_rtc_panic;
static RTC_NOINIT_ATTR br_c6_rom_tail_t s_rtc_tail;
static br_c6_dump_t s_box; /* the crash on record as this start found it; ver 0: none */

/* Code of this image (linker) and of the ROM: a stack word that points there may be a return address. */
extern const char _iram_text_start[];
extern const char _iram_text_end[];
extern const char _text_start[];
extern const char _text_end[];
#define BR_C6_ROM_TEXT_LOW  0x40000000u
#define BR_C6_ROM_TEXT_HIGH 0x40050000u

static inline __attribute__((always_inline)) bool points_into_code(uint32_t v)
{
	if ((v & 1u) != 0u) {
		return false;
	}
	return (v >= (uint32_t)(uintptr_t)_iram_text_start && v < (uint32_t)(uintptr_t)_iram_text_end) ||
	       (v >= (uint32_t)(uintptr_t)_text_start && v < (uint32_t)(uintptr_t)_text_end) ||
	       (v >= BR_C6_ROM_TEXT_LOW && v < BR_C6_ROM_TEXT_HIGH);
}

extern void __real_esp_panic_handler(panic_info_t *info);
void IRAM_ATTR __wrap_esp_panic_handler(panic_info_t *info)
{
	if (s_rtc_panic.magic != BR_C6_PANIC_MAGIC) { /* the first panic counts: a second one is a consequence */
		const RvExcFrame *f = (const RvExcFrame *)info->frame;
		s_rtc_panic.pc        = (uint32_t)(uintptr_t)info->addr;
		s_rtc_panic.ra        = (f != NULL) ? (uint32_t)f->ra : 0u;
		s_rtc_panic.sp        = (f != NULL) ? (uint32_t)f->sp : 0u;
		s_rtc_panic.cause     = (f != NULL) ? (uint32_t)f->mcause : 0u;
		s_rtc_panic.tval      = (f != NULL) ? (uint32_t)f->mtval : 0u;
		/* An abort (a failed assert) arrives as the trap that abort() ends in; the stock handler names it only
		 * after this wrapper. */
		s_rtc_panic.exception = (uint8_t)((uint8_t)(g_panic_abort ? PANIC_EXCEPTION_ABORT : info->exception) |
				(info->pseudo_excause ? 0x80u : 0u));
		const char *why  = (g_panic_abort && g_panic_abort_details != NULL) ? g_panic_abort_details : info->reason;
		const char *task = pcTaskGetName(NULL);
		for (size_t i = 0; i < sizeof(s_rtc_panic.task); i++) {
			s_rtc_panic.task[i] = (task != NULL && *task != '\0') ? *task++ : '\0';
		}
		for (size_t i = 0; i < sizeof(s_rtc_panic.reason); i++) {
			s_rtc_panic.reason[i] = (why != NULL && *why != '\0') ? *why++ : '\0';
		}
		for (size_t i = 0; i < BR_C6_PANIC_CODE; i++) {
			s_rtc_panic.code[i] = 0u;
		}
		s_rtc_panic.magic = BR_C6_PANIC_MAGIC;
		/* The stack last, with the record already valid: if reading it faults, the panic that follows skips this. */
		const uint32_t sp = s_rtc_panic.sp;
		if ((sp & 3u) == 0u && sp >= SOC_DRAM_LOW && sp < SOC_DRAM_HIGH) {
			const uint32_t *w = (const uint32_t *)(uintptr_t)sp;
			size_t n = 0;
			for (size_t i = 0; i < BR_C6_STACK_WORDS && n < BR_C6_PANIC_CODE; i++) {
				if ((uintptr_t)&w[i] >= SOC_DRAM_HIGH) {
					break;
				}
				if (points_into_code(w[i])) {
					s_rtc_panic.code[n++] = w[i];
				}
			}
		}
	}
	__real_esp_panic_handler(info);
}

/* Second output channel of the ROM's printf: its characters also come here. Any context, flash cache on or off. */
static void IRAM_ATTR rom_tail_putc(char c)
{
	s_rtc_tail.ring[s_rtc_tail.n % BR_C6_ROM_TAIL] = c;
	s_rtc_tail.n++;
}

/* Start after a crash reset: what the kept memory says goes to NVS. */
static void crash_dump_save(uint8_t crashes)
{
	memset(&s_box, 0, sizeof(s_box));
	s_box.ver     = BR_C6_DUMP_VER;
	s_box.reset   = (uint8_t)esp_reset_reason();
	s_box.crashes = crashes;
	s_box.where   = 0xFFu;
	memcpy(s_box.img, esp_app_get_description()->app_elf_sha256, sizeof(s_box.img));
	br_c6_last_t l;
	if (br_c6_radio_kept_last(&l)) {
		s_box.where       = l.where;
		s_box.last_esp_us = l.esp_us;
		s_box.tx_done     = l.tx_done;
	}
	if (s_rtc_panic.magic == BR_C6_PANIC_MAGIC) {
		s_box.panic = s_rtc_panic;
	}
	if (s_rtc_tail.magic == BR_C6_TAIL_MAGIC) {
		const uint32_t n    = s_rtc_tail.n;
		const uint32_t kept = (n < BR_C6_ROM_TAIL) ? n : BR_C6_ROM_TAIL;
		for (uint32_t i = 0; i < kept; i++) {
			s_box.rom_tail[i] = s_rtc_tail.ring[(n - kept + i) % BR_C6_ROM_TAIL];
		}
		s_box.rom_chars = n;
	}
	nvs_handle_t h;
	if (nvs_open(BR_C6_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
		if (nvs_set_blob(h, BR_C6_NVS_DUMP, &s_box, sizeof(s_box)) == ESP_OK) {
			(void)nvs_commit(h);
		}
		nvs_close(h);
	}
}

/* Every start, after crash_dump_save had its turn: the crash on record (this start's or an older one) is read for
 * the trace, and the ROM's output is kept from here on. The marker line shows in the start record (0xBB) that the
 * second channel really gets the characters. */
static void box_start(bool crash)
{
	if (!crash) {
		size_t len = sizeof(s_box);
		nvs_handle_t h;
		if (nvs_open(BR_C6_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
			if (nvs_get_blob(h, BR_C6_NVS_DUMP, &s_box, &len) != ESP_OK || len != sizeof(s_box) ||
			    s_box.ver != BR_C6_DUMP_VER) {
				memset(&s_box, 0, sizeof(s_box));
			}
			nvs_close(h);
		}
	}
	s_rtc_panic.magic = 0u;
	memset(&s_rtc_tail, 0, sizeof(s_rtc_tail));
	s_rtc_tail.magic = BR_C6_TAIL_MAGIC;
	esp_rom_install_channel_putc(2, rom_tail_putc);
	esp_rom_printf("br_c6: black box on\n");
}

static uint16_t sat16(uint32_t v)
{
	return v > 0xFFFFu ? 0xFFFFu : (uint16_t)v;
}

/* A record of this adapter in the trace the host already reads (0xFC30/0x0A); the kinds are listed further down.
 * LL task only. */
static void st_trace(uint8_t kind, uint8_t code, uint16_t cis, uint16_t acl,
		uint32_t v0, uint32_t v1, uint32_t v2, uint32_t v3)
{
	const cis_trace_t t = { .kind = kind, .code = code, .cis = cis, .acl = acl, .rsv = 0u, .v = { v0, v1, v2, v3 } };
	cis_c6_trace(NULL, &t);
}

/* The crash on record, once after every start (trace 0xBC..0xBE, 0xC9..0xCB). LL task. */
static void box_trace(void)
{
	if (s_box.ver != BR_C6_DUMP_VER) {
		return;
	}
	const br_c6_dump_t *d = &s_box;
	const bool panic = (d->panic.magic == BR_C6_PANIC_MAGIC);
	st_trace(0xBCu, panic ? d->panic.exception : 0xFFu, (uint16_t)(d->reset | ((uint16_t)d->where << 8)), d->crashes,
			d->panic.pc, d->panic.ra, d->panic.cause, d->panic.tval);
	uint32_t w[BR_C6_ROM_TAIL / 4u];
	_Static_assert(sizeof(w) >= sizeof(d->panic.reason) && sizeof(w) == sizeof(d->rom_tail), "word copies below");
	memcpy(w, d->panic.task, 8u);
	st_trace(0xBDu, 0u, 0u, sat16(d->tx_done), d->panic.sp, w[0], w[1], d->last_esp_us);
	memcpy(w, d->img, sizeof(d->img));
	st_trace(0xC9u, 0u, 0u, 0u, w[0], d->rom_chars, 0u, 0u);
	if (panic) {
		memcpy(w, d->panic.reason, sizeof(d->panic.reason));
		for (uint8_t part = 0; part < sizeof(d->panic.reason) / 16u; part++) {
			st_trace(0xBEu, part, 0u, 0u, w[4u * part], w[4u * part + 1u], w[4u * part + 2u], w[4u * part + 3u]);
		}
		for (uint8_t part = 0; part < BR_C6_PANIC_CODE / 4u && d->panic.code[4u * part] != 0u; part++) {
			const uint32_t *c = &d->panic.code[4u * part];
			st_trace(0xCAu, part, 0u, 0u, c[0], c[1], c[2], c[3]);
		}
	}
	if (d->rom_chars != 0u) {
		memcpy(w, d->rom_tail, sizeof(d->rom_tail));
		for (uint8_t part = 0; part < BR_C6_ROM_TAIL / 16u && w[4u * part] != 0u; part++) {
			st_trace(0xCBu, part, 0u, 0u, w[4u * part], w[4u * part + 1u], w[4u * part + 2u], w[4u * part + 3u]);
		}
	}
}

void br_c6_live_mark(bool live)
{
	s_rtc_live = live ? BR_C6_LIVE_MAGIC : 0u;
}

bool br_c6_on(void)
{
	return __atomic_load_n(&s_on, __ATOMIC_ACQUIRE);
}

static bool in_ll_task(void)
{
	TaskHandle_t ll = __atomic_load_n(&s_ll_task, __ATOMIC_ACQUIRE);
	return ll != NULL && !xPortInIsrContext() && xTaskGetCurrentTaskHandle() == ll;
}

br_engine_t *br_c6_engine_ll(void)
{
	return (br_c6_on() && s_radio_ok && in_ll_task()) ? s_engine : NULL;
}

static void br_kick(uint32_t bits)
{
	if (!br_c6_on()) {
		return;
	}
	__atomic_fetch_or(&s_kick_bits, bits, __ATOMIC_SEQ_CST);
	r_ble_ll_event_send(&s_kick);
}

/* ---- Host TX task & non-blocking enqueue ---- */
static void br_host_tx_task(void *arg)
{
	(void)arg;
	br_host_pkt_t p;
	for (;;) {
		if (xQueueReceive(s_host_q, &p, portMAX_DELAY) == pdTRUE) {
			(void)slave_bt_send_to_host(p.buf, p.len);
			free(p.buf);
		}
	}
}

static bool host_enqueue(const uint8_t *h4, uint16_t len)
{
	br_host_pkt_t p = {
		.buf = (uint8_t *)malloc(len),
		.len = len,
	};
	if (p.buf == NULL) {
		return false;
	}
	memcpy(p.buf, h4, len);
	if (xQueueSend(s_host_q, &p, 0) != pdTRUE) {
		free(p.buf);
		return false;
	}
	return true;
}

/* ---- LE scanning and LE connection attempts are kept apart from Soft-BR work ----
 * Hardware runs three to six, 2026-11-10: the chip was reset by the interrupt watchdog inside the controller's
 * walk over its scheduler queue six times, each time while a Soft-BR inquiry was running and at the moments the
 * host's background reconnect to its bonded LE device is due (55 s and 155 s after the host's start plus the time
 * the earlier attempts took). The probes, one slow item at a time, lived through the earlier attempts. What exactly
 * Ninth run: the same reset during the probes, with an LE scan of the host let through 2 s earlier, so the probe
 * windows count as work too and are not opened while the host scans or connects. What exactly
 * goes wrong in the queue is not known, so the two are not allowed to overlap: while the engine works, a command
 * that starts LE scanning or an LE connection attempt is answered here with Command Disallowed and never reaches
 * the controller, and the self-test does not start an inquiry while the host scans or connects. An LE connection
 * that already exists is not covered. */
#define BR_HCI_LE_SET_SCAN_ENABLE      0x200Cu
#define BR_HCI_LE_CREATE_CONN          0x200Du
#define BR_HCI_LE_SET_EXT_SCAN_ENABLE  0x2042u
#define BR_HCI_LE_EXT_CREATE_CONN      0x2043u
#define BR_HCI_ERR_COMMAND_DISALLOWED  0x0Cu
static bool s_br_probing;     /* the self-test's probe windows are being opened: they count as Soft-BR work */
static bool s_le_scanning;    /* the host has LE scanning switched on */
static bool s_le_initiating;  /* an LE connection attempt of the host is pending */
static uint32_t s_le_passed;  /* scan / connect commands let through */
static uint32_t s_le_refused; /* ... answered with Command Disallowed */
static uint16_t s_le_last_op;

#if CONFIG_CYBERDECK_BR_SELFTEST
static bool le_busy(void)
{
	return __atomic_load_n(&s_le_scanning, __ATOMIC_RELAXED) || __atomic_load_n(&s_le_initiating, __ATOMIC_RELAXED);
}
#endif

/* A command from the host. True: answered here, the controller must not see it. */
static bool le_guard_h2c(const uint8_t *h4, uint16_t len)
{
	if (len < 4u || h4[0] != BR_H4_CMD) {
		return false;
	}
	const uint16_t op = (uint16_t)((uint16_t)h4[1] | ((uint16_t)h4[2] << 8));
	if (op == BR_HCI_OP_RESET) {
		__atomic_store_n(&s_le_scanning, false, __ATOMIC_RELAXED);
		__atomic_store_n(&s_le_initiating, false, __ATOMIC_RELAXED);
		return false;
	}
	const bool connect = (op == BR_HCI_LE_CREATE_CONN || op == BR_HCI_LE_EXT_CREATE_CONN);
	const bool scan    = (op == BR_HCI_LE_SET_SCAN_ENABLE || op == BR_HCI_LE_SET_EXT_SCAN_ENABLE);
	if (!connect && !scan) {
		return false;
	}
	if (scan && (len < 5u || h4[4] == 0u)) {
		__atomic_store_n(&s_le_scanning, false, __ATOMIC_RELAXED);
		return false;
	}
	__atomic_store_n(&s_le_last_op, op, __ATOMIC_RELAXED);
	if (s_rtc_live != BR_C6_LIVE_MAGIC && !__atomic_load_n(&s_br_probing, __ATOMIC_RELAXED)) {
		__atomic_store_n(connect ? &s_le_initiating : &s_le_scanning, true, __ATOMIC_RELAXED);
		__atomic_fetch_add(&s_le_passed, 1u, __ATOMIC_RELAXED);
		return false;
	}
	/* A connection attempt is answered with Command Status, a scan switch with Command Complete. */
	const uint8_t status[] = { 0x04u, 0x0Fu, 0x04u, BR_HCI_ERR_COMMAND_DISALLOWED, 0x01u, h4[1], h4[2] };
	const uint8_t done[]   = { 0x04u, 0x0Eu, 0x04u, 0x01u, h4[1], h4[2], BR_HCI_ERR_COMMAND_DISALLOWED };
	(void)host_enqueue(connect ? status : done, sizeof(status));
	__atomic_fetch_add(&s_le_refused, 1u, __ATOMIC_RELAXED);
	return true;
}

/* An event from the controller: the end of an LE connection attempt or of a timed scan. */
static void le_guard_c2h(const uint8_t *h4, uint16_t len)
{
	if (len < 4u || h4[0] != 0x04u || h4[1] != 0x3Eu) {
		return;
	}
	const uint8_t sub = h4[3];
	if (sub == 0x01u || sub == 0x0Au || sub == 0x29u) { /* LE (Enhanced) Connection Complete, any status */
		__atomic_store_n(&s_le_initiating, false, __ATOMIC_RELAXED);
	} else if (sub == 0x11u) { /* LE Scan Timeout */
		__atomic_store_n(&s_le_scanning, false, __ATOMIC_RELAXED);
	}
}

static void flush_deferred_nocp(void)
{
	uint32_t lost = __atomic_exchange_n(&s_h2c_lost_acl, 0u, __ATOMIC_RELAXED);
	s_deferred_nocp += lost;
	if (s_deferred_nocp == 0u || uxQueueSpacesAvailable(s_host_q) == 0u) {
		return;
	}
	uint16_t cnt = (s_deferred_nocp > 0xFFFFu) ? 0xFFFFu : (uint16_t)s_deferred_nocp;
	uint8_t ev[8] = {
		0x04u,
		0x13u, /* Number Of Completed Packets */
		0x05u,
		0x01u,
		(uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu),
		(uint8_t)((BR_ACL_HANDLE_BASE >> 8) & 0xFFu),
		(uint8_t)(cnt & 0xFFu),
		(uint8_t)((cnt >> 8) & 0xFFu),
	};
	if (host_enqueue(ev, sizeof(ev))) {
		s_deferred_nocp -= cnt;
	}
}

#if CONFIG_CYBERDECK_BR_SELFTEST
/* Bench self-test (debug image only): the C6 runs a GIAC inquiry by itself and reports through the CIS trace that
 * the P4 already serves (0xFC30/0x0A, Cyberdeck GET /api/c6/cis/trace). A host that speaks Soft-BR takes over with
 * its first command (st_host_takes_over): from then on the image behaves like a regular one and only keeps
 * recording. Trace kinds:
 *   0xB0 engine: code=state, cis=results this round, acl=round, v0=slots_tx, v1=slots_rx,
 *        v2=rx_sync_ok | slots_skipped<<16, v3=hec_ok | hec_err<<8 | crc_ok<<16 | crc_err<<24 (8-bit each)
 *   0xB1 radio: cis=insert_fail, acl=skipped, v0=insert_ok, v1=tx_done, v2=rx_done, v3=rx_captured
 *   0xB2 inquiry result: code=rssi, cis=BD_ADDR[47:32], acl=round, v0=BD_ADDR[31:0], v1=class of device
 *   0xB3 RX capture: code=rssi, cis=len | hdr<<8, acl=channel, v0..v3 = first 16 raw bytes after the length byte
 *   0xB4 inquiry started: code=accepted (2 = the host took over, no more self-test inquiries), cis=round,
 *        v0=RX recipe the engine's slots use, v1=probes that received bytes, 8 bits per recipe,
 *        v2=the round's ID packets end with the sync word (1) or have 24 more bits after it (0)
 *   0xB7 RX collection (when it changes): cis=engine pairs given up, acl=slots retired,
 *        v0=RX slots collected by the adapter, v1=of those stopped past their end, v2=looks at an ended RX slot
 *        the controller still had in its queue, v3=free slots passed over because the controller still had them
 *   0xB8 probe result: code=probe, cis=recipe | radio stopped<<4 | skipped<<5, v0=RX buffer status word,
 *        v1=time stamp word, v2,v3=the eight bytes after the access address (all cleared before the window)
 *   0xB9 health (with the counters): code=RX slots with a time stamp but no bytes (stops at 255),
 *        cis=adapter service passes since the last one, acl=of those waiting for an RX
 *        slot, v0=free heap, v1=lowest free heap so far, v2=controller clock, v3=esp_timer (both us, low 32 bits)
 *   0xBA what the previous run left (first tick, when the reset kept it): code=where the LL task was (BR_AT_*),
 *        v0=controller clock and v1=esp_timer at its last adapter service pass, v2=service passes, v3=TX slots done
 *   0xBB start (first tick; a regular image: when Soft-BR starts): code=esp_reset_reason, cis=Soft-BR was live at
 *        the reset, acl=crashes on record, v0=RX recipes the probes leave out, a bit each (a window of theirs was
 *        open at a chip reset), v1=characters the ROM has printed so far in this run (0: its output is not kept)
 *   0xBC last crash on record in NVS (after 0xBB, every image): code=panic exception | pseudo cause<<7 (0xFF: the
 *        reset left no panic record), cis=reset reason of the start that found it | where the LL task was<<8,
 *        acl=crashes on record then, v0=pc, v1=ra, v2=mcause, v3=mtval
 *   0xBD the same crash: v0=sp, v1,v2=task name, v3=esp_timer at the last adapter service pass, acl=TX slots done
 *   0xBE the same crash: code=part 0..2, v0..v3=16 characters of the panic reason
 *   0xC9 the same crash: v0=image of the start that found it (first four bytes of its ELF hash, first byte
 *        lowest), v1=characters the ROM printed in the run that crashed
 *   0xCA the same crash: code=part 0..5, v0..v3=words on the stack that point into code, nearest first (0: no
 *        more); the return addresses of the calls that led to the panic are among them
 *   0xCB the same crash: code=part 0..5, v0..v3=16 of the last 96 characters the ROM printed, oldest first
 *   0xBF timing of the capture in 0xB3: acl=channel, v0=time stamp minus the slot boundary asked for, us (signed)
 *   0xC2 LE scan / connect commands of the host (when the counts change): cis=opcode of the last one,
 *        code=scanning | connection attempt pending<<1, v0=let through, v1=answered with Command Disallowed
 *   0xC3 HCI event of the engine other than an inquiry result (six a tick at most): code=event, cis=parameter
 *        length, v0..v3=the first 16 parameter bytes
 *   0xC4 command of the self-test to the engine: code=1 inquiry cancel, 2 create connection, 3 disconnect,
 *        cis=accepted, acl=connection handle (3) or ID answers taken with the length limit | ID packets end
 *        with the sync word<<1 | index of the device paged<<8 (2), v0=page scan repetition mode | clock
 *        offset<<16, v1,v2=access code of the device
 *   0xC5 page handshakes so far (when it changes): v0=ID answers that started the master response, v1=FHS packets
 *        queued, v2=FHS acknowledged by a second ID, v3=first POLL packets queued
 *   0xC7 packet timing; code 0 (when it changes): v0=pairs the engine did not hand over because they were ready
 *        too late, v1=longest time from choosing a slot to handing its pair over (us), v2=what the engine now
 *        allows for that (us), v3=items the adapter refused as too late; code 1 (once, before the first inquiry):
 *        the long-pair probe, cis=pairs asked for, acl=pairs the adapter took, v0=TX items done, v1=RX items
 *        done, v2=items skipped, v3=items refused (insert failed or too late)
 *   0xC8 data probe on a self-test connection: code=variant (0 one 3-slot packet of 164 bytes; 1, 2, 3 one
 *        1-slot packet of 23, 25, 27 bytes) | device << 4,
 *        cis=0 the 20-byte control frame (one 1-slot packet), 1 the variant's frame, acl=frame bytes;
 *        v0=TX slots | packets sent again << 16, v1=RX slots with an access code | with a good header << 16,
 *        v2=our packets acknowledged | refused << 16, v3=frames delivered whole | frames received << 16
 *   0xC6 the E0 cipher on this chip (once at the start): v0=microseconds for the key stream of a 30-byte packet,
 *        v1=for a 340-byte packet, v2=first four key stream bytes of the specification's fourth sample set
 *        (94 99 6f e0, first byte lowest)
 *        (first transmitted bit lowest), v3=address input of the hop selection (2); code 4: the image starts
 *        listening for ID packets with that access code, same fields */
#define BR_ST_TICK_US       2000000u
#define BR_ST_FIRST_TICK    16u /* 32 s after Soft-BR start: the host's HCI bring-up and the probes are done */
#define BR_ST_PERIOD_TICKS  8u  /* a new 10.24 s inquiry every 16 s */
static esp_timer_handle_t s_st_timer;
static uint32_t s_st_ticks;
static uint32_t s_st_last_start;
static bool s_st_was_active;
static uint16_t s_st_results;
static uint16_t s_st_round;
static uint32_t s_st_cap_seen;
static bool s_st_host; /* the host drives Soft-BR itself: no self-test inquiries, events go to the host */
static uint8_t s_st_probe_no;
/* A device the inquiries found is paged: the next stage of the chain, up to the baseband connection. Nobody
 * answers the device's LMP here (that host stack is on the P4), so the link is closed again after 6 s.
 * Runs eight to ten paged the owner's speaker 48 times without one answer while a computer connected to it in
 * 1.6 s, so the devices found take turns now, one a round: a second device (a computer that is discoverable)
 * shows whether paging fails for every device or for that one. */
enum { ST_PAGE_NONE = 0, ST_PAGE_FOUND, ST_PAGE_ASKED, ST_PAGE_CONNECTED, ST_PAGE_CLOSING };
#define BR_ST_PEERS 4u
/* 1: the image listens for the found device's ID packets instead of paging it (see s_st_listen). */
#define BR_ST_LISTEN_ONLY 0
typedef struct {
	uint8_t  addr[6];
	uint8_t  psrm;
	uint16_t clk_off;
	bool     found; /* an inquiry found it: clk_off is its clock offset. false: the device given at build time */
} st_peer_t;
static uint8_t s_st_page;
static st_peer_t s_st_peers[BR_ST_PEERS];
static uint8_t s_st_peer_count;
static uint8_t s_st_peer_turn; /* index of the device paged in this round */
/* Run eleven: 50 pages of the speaker without one answer while a computer connected to it in 1.6 s, and the access
 * code and hop address the chip computes are right. To tell the transmit side from the receive side the image
 * stops paging: after its first inquiry result it only listens, in 60 ms windows, for ID packets that carry the
 * found device's access code, while another device (the computer) pages it. Window n: n & 31 is the X input of the
 * hop selection, bit 5 chooses the frequency a page is sent on (0) or the one its answer comes on (1), bit 6
 * chooses the length limit for ID packets (1) or none (0). Results are ordinary probe records (0xB8). */
static bool s_st_listen;
static uint32_t s_st_listen_aa;
static uint32_t s_st_listen_ulap;
static uint16_t s_st_conn_handle;
static uint32_t s_st_conn_tick;
static uint8_t s_st_events_left; /* trace 0xC3 records still allowed in this tick */
static uint8_t s_st_probe_hits[BR_RX_RECIPE_COUNT]; /* probes that received bytes, per recipe */
_Static_assert(BR_RX_RECIPE_COUNT == 4, "trace 0xB4 packs the probe hits of four recipes into one word");

static void st_emit_counters(uint8_t state)
{
	br_diag_stats_t es;
	br_engine_get_stats(s_engine, &es);
	br_c6_radio_stats_t rs;
	br_c6_radio_get_stats(&rs);
	st_trace(0xB0u, state, s_st_results, s_st_round, es.slots_tx, es.slots_rx,
			(es.rx_sync_ok & 0xFFFFu) | (es.slots_skipped << 16),
			(es.rx_hec_ok & 0xFFu) | ((es.rx_hec_err & 0xFFu) << 8) |
			((es.rx_crc_ok & 0xFFu) << 16) | ((es.rx_crc_err & 0xFFu) << 24));
	st_trace(0xB1u, 0u, sat16(rs.insert_fail), sat16(rs.skipped), rs.insert_ok, rs.tx_done, rs.rx_done,
			rs.rx_captured);
	static uint32_t s_coll_seen = UINT32_MAX;
	const uint32_t coll = rs.rx_collected + rs.rx_overrun + rs.retired + es.pairs_lost + rs.rx_linked +
			rs.slot_linked;
	if (coll != s_coll_seen) {
		s_coll_seen = coll;
		st_trace(0xB7u, 0u, sat16(es.pairs_lost), sat16(rs.retired), rs.rx_collected, rs.rx_overrun, rs.rx_linked,
				rs.slot_linked);
	}
	if (rs.cap_seq != s_st_cap_seen) {
		s_st_cap_seen = rs.cap_seq;
		uint32_t w[4];
		memcpy(w, rs.cap_raw, sizeof(w));
		st_trace(0xB3u, (uint8_t)rs.cap_rssi, (uint16_t)(rs.cap_len | ((uint16_t)rs.cap_hdr << 8)), rs.cap_chan,
				w[0], w[1], w[2], w[3]);
		st_trace(0xBFu, 0u, 0u, rs.cap_chan, (uint32_t)rs.cap_late_us, 0u, 0u, 0u);
	}
	static uint32_t s_runs_seen;
	static uint32_t s_not_due_seen;
	st_trace(0xB9u, (uint8_t)(rs.rx_stamp_only > 255u ? 255u : rs.rx_stamp_only),
			sat16(rs.service_runs - s_runs_seen), sat16(rs.rx_not_due - s_not_due_seen),
			(uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT),
			(uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT), br_c6_now_us(NULL),
			(uint32_t)esp_timer_get_time());
	s_runs_seen    = rs.service_runs;
	s_not_due_seen = rs.rx_not_due;
	static br_page_progress_t s_progress_seen;
	br_page_progress_t pp;
	memset(&pp, 0, sizeof(pp));
	br_engine_get_page_progress(s_engine, &pp);
	if (memcmp(&pp, &s_progress_seen, sizeof(pp)) != 0) {
		s_progress_seen = pp;
		st_trace(0xC5u, 0u, 0u, 0u, pp.id_answers, pp.fhs_tx, pp.fhs_acks, pp.polls_tx);
	}
	static br_build_times_t s_build_seen;
	static uint32_t         s_late_seen;
	br_build_times_t bt;
	memset(&bt, 0, sizeof(bt));
	br_engine_get_build_times(s_engine, &bt);
	if (memcmp(&bt, &s_build_seen, sizeof(bt)) != 0 || rs.insert_late != s_late_seen) {
		s_build_seen = bt;
		s_late_seen  = rs.insert_late;
		st_trace(0xC7u, 0u, 0u, 0u, bt.late_pairs, bt.longest_us, bt.allowance_us, rs.insert_late);
	}
}

/* Second sound trial, 2026-11-10: the chip hung in the scheduler's queue walk when the first 3-slot packet went
 * out. That pair had reached the scheduler late, which the engine and the adapter now prevent; this probe asks
 * the other question, whether pairs shaped like it are safe when they come on time: a TX item as long as a full
 * DH3 packet, the RX item of the slot after it, one pair after the other the way a stream sends them. Nothing
 * has to answer. Skipped once the image has a crash on record, so that a hang here costs one restart, not two.
 * Hardware runs 19 and 20 (2026-11-11): 3 of 3 pairs done each time. Run 20 also gave the scheduler such pairs
 * late on purpose, with the adapter's check off: 100 us and 500 us after their start did no visible harm, and
 * within about 8 s of the pair that came 1000 us late the chip hung in the same queue walk as in the sound
 * trial (interrupt watchdog, r_ble_lll_sched_check_remaining_entries from r_ble_phy_isr). That test is not in the
 * image any more. */
#define BR_ST_LONG_TICK   15u   /* the tick after the last RX probe window, the one before the first inquiry */
#define BR_ST_LONG_PAIRS  3u
#define BR_ST_LONG_TX_LEN 204u  /* modem payload bytes of a DH3 packet with 183 bytes of data */
static br_c6_radio_stats_t s_st_long_before;
static uint8_t             s_st_long_asked;
static uint8_t             s_st_long_taken;

static void st_long_pairs(void)
{
	static br_radio_tx_req_t tx;
	br_radio_rx_req_t rx;
	br_c6_radio_get_stats(&s_st_long_before);
	const uint32_t now = br_c6_now_us(NULL);
	for (uint8_t k = 0; k < BR_ST_LONG_PAIRS; k++) {
		memset(&tx, 0, sizeof(tx));
		tx.anchor_us   = now + 5000u + (uint32_t)k * 5000u; /* a DH3 pair every 5 ms, as the engine can send them */
		tx.lead_us     = 60u;
		tx.chan_1mhz   = 40u;
		tx.access_addr = 0x55555555u;
		tx.tx_hdr      = 0x55u;
		tx.tx_len      = BR_ST_LONG_TX_LEN;
		memset(tx.tx_payload, 0x55, BR_ST_LONG_TX_LEN);
		tx.duration_us = (uint16_t)(56u + BR_ST_LONG_TX_LEN * 8u + 24u);
		memset(&rx, 0, sizeof(rx));
		rx.anchor_us       = tx.anchor_us + 3u * 625u;
		rx.rx_sync_win_us  = 80u;
		rx.max_duration_us = 500u;
		rx.chan_1mhz       = 41u;
		rx.access_addr     = 0x71764129u; /* the test mode's access address: nothing on the air answers to it */
		s_st_long_asked++;
		if (br_c6_schedule_tx_rx(NULL, &tx, &rx) == 0) {
			s_st_long_taken++;
		}
	}
}

/* Sound trials 3 to 6 (2026-11-11): the speaker answers every 1-slot packet and none of the 3-slot packets of the
 * stream, not even with its access code. Is it the length on the air, the 3-slot timing, or the peer? On each
 * self-test connection: a 20-byte L2CAP echo request first (one DH1, the control), then one frame that differs
 * per round, and the engine's counters for each. No LMP has run on these connections, so a peer may refuse 3-slot
 * packets as not allowed yet; a peer that acknowledges one settles the question for the radio.
 * Hardware runs 21 and 22: the 20-byte frame is acknowledged at once by both peers; 27-byte fragments are refused
 * by the computer about 400 times for each one it takes; a 3-slot packet is refused by the computer every time and
 * not answered by the speaker. The 1-slot frames of 23, 25 and 27 bytes are there to find where that starts. */
static const uint8_t s_st_data_len[4] = { 164u, 23u, 25u, 27u };
static br_diag_stats_t s_st_data_before;

static void st_data_frame(uint8_t frame_len, bool three_slots)
{
	static uint8_t h4[5u + 168u];
	if (three_slots) {
		const uint8_t allow[] = { 0x01u, 0x31u, 0xFCu, 0x06u, BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1,
			BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3, (uint8_t)BR_VS_SET_TX_SLOTS, 3u };
		(void)br_engine_hci_from_host(s_engine, allow, sizeof(allow));
	}
	br_engine_get_stats(s_engine, &s_st_data_before);
	h4[0] = BR_H4_ACL;
	h4[1] = (uint8_t)(BR_ACL_HANDLE_BASE & 0xFFu);
	h4[2] = (uint8_t)((BR_ACL_HANDLE_BASE >> 8) | 0x20u); /* first segment, automatically flushable */
	h4[3] = frame_len;
	h4[4] = 0u;
	h4[5] = (uint8_t)(frame_len - 4u); /* L2CAP: length, signalling channel 1 */
	h4[6] = 0u;
	h4[7] = 0x01u;
	h4[8] = 0x00u;
	h4[9]  = 0x08u; /* echo request */
	h4[10] = frame_len;
	h4[11] = (uint8_t)(frame_len - 8u);
	h4[12] = 0u;
	memset(&h4[13], 0xA5, (size_t)frame_len - 8u);
	(void)br_engine_hci_from_host(s_engine, h4, (uint16_t)(5u + frame_len));
}

static void st_data_report(uint8_t variant, uint8_t phase, uint8_t frame_len)
{
	br_diag_stats_t now;
	br_engine_get_stats(s_engine, &now);
	const br_diag_stats_t *b = &s_st_data_before;
	st_trace(0xC8u, (uint8_t)(variant | (s_st_peer_turn << 4)), phase, frame_len,
			(sat16(now.slots_tx - b->slots_tx)) | ((uint32_t)sat16(now.tx_retrans - b->tx_retrans) << 16),
			(sat16(now.rx_sync_ok - b->rx_sync_ok)) | ((uint32_t)sat16(now.rx_hec_ok - b->rx_hec_ok) << 16),
			(sat16(now.tx_acks - b->tx_acks)) | ((uint32_t)sat16(now.tx_naks - b->tx_naks) << 16),
			(sat16(now.acl_sdu_tx - b->acl_sdu_tx)) | ((uint32_t)sat16(now.acl_sdu_rx - b->acl_sdu_rx) << 16));
}

static void st_long_pairs_report(void)
{
	br_c6_radio_stats_t rs;
	br_c6_radio_get_stats(&rs);
	st_trace(0xC7u, 1u, s_st_long_asked, s_st_long_taken, rs.tx_done - s_st_long_before.tx_done,
			rs.rx_done - s_st_long_before.rx_done, rs.skipped - s_st_long_before.skipped,
			(rs.insert_fail - s_st_long_before.insert_fail) + (rs.insert_late - s_st_long_before.insert_late));
}

#define BR_ST_PROBE_MAGIC 0x50524230u /* 'PRB0' */
/* Kept across a chip reset: a recipe whose probe window was open when the chip was reset is not tried again by this
 * image, so one that crashes the controller cannot keep the image in a restart loop for its whole trial. */
typedef struct {
	uint32_t magic;
	uint8_t  img;    /* first byte of the image's ELF hash: another image starts clean */
	uint8_t  barred; /* a bit per recipe */
	uint8_t  flying; /* 0x80 | recipe while a probe window is open */
} st_probe_rtc_t;
static RTC_NOINIT_ATTR st_probe_rtc_t s_rtc_probe;

/* The E0 cipher runs once per encrypted packet in the link layer task; a packet pair comes every 1.25 to 2.5 ms.
 * On the first encrypted link (2026-11-10) a bit-serial version starved the chip's own tasks until the host gave
 * up on it. Inputs: the fourth sample set of Core Spec Vol 2 Part G section 1.1. */
static void st_emit_cipher_time(void)
{
	static const uint8_t key[16] = { 0x21u, 0x87u, 0xF0u, 0x4Au, 0xBAu, 0x90u, 0x31u, 0xD0u,
		                         0x78u, 0x0Du, 0x4Cu, 0x53u, 0xE0u, 0x15u, 0x3Au, 0x63u };
	static const uint8_t addr[6] = { 0x2Cu, 0x7Fu, 0x94u, 0x56u, 0x0Fu, 0x1Bu };
	static uint8_t       ks[340];
	/* The first call also fills the cipher's tables (about 0.7 ms, once): not part of a packet's time. */
	br_crypto_e0_keystream(key, addr, 0x40034BEu, ks, 1u);
	const int64_t t0 = esp_timer_get_time();
	br_crypto_e0_keystream(key, addr, 0x40034BEu, ks, 30u);
	const int64_t t1 = esp_timer_get_time();
	br_crypto_e0_keystream(key, addr, 0x40034BEu, ks, sizeof(ks));
	const int64_t t2 = esp_timer_get_time();
	st_trace(0xC6u, 0u, 0u, 0u, (uint32_t)(t1 - t0), (uint32_t)(t2 - t1),
			(uint32_t)ks[0] | ((uint32_t)ks[1] << 8) | ((uint32_t)ks[2] << 16) | ((uint32_t)ks[3] << 24), 0u);
}

static void st_emit_start(void)
{
#ifdef BR_ST_EXTRA_PEER
	if (s_st_peer_count == 0u) {
		static const uint8_t extra[6] = { BR_ST_EXTRA_PEER };
		memcpy(s_st_peers[0].addr, extra, sizeof(extra));
		s_st_peers[0].psrm = 1u; /* R1: the scan interval most devices use */
		s_st_peer_count    = 1u;
	}
#endif
	const uint8_t img = esp_app_get_description()->app_elf_sha256[0];
	if (s_rtc_probe.magic != BR_ST_PROBE_MAGIC || s_rtc_probe.img != img) {
		memset(&s_rtc_probe, 0, sizeof(s_rtc_probe));
		s_rtc_probe.magic = BR_ST_PROBE_MAGIC;
		s_rtc_probe.img   = img;
	} else if ((s_rtc_probe.flying & 0x80u) != 0u) {
		s_rtc_probe.barred |= (uint8_t)(1u << (s_rtc_probe.flying & 0x03u));
	}
	s_rtc_probe.flying = 0u;
	st_trace(0xBBu, (uint8_t)esp_reset_reason(), s_boot_live ? 1u : 0u, s_boot_crashes, s_rtc_probe.barred,
			s_rtc_tail.n, 0u, 0u);
	st_emit_cipher_time();
	br_c6_last_t l;
	if (br_c6_radio_prev_last(&l)) {
		st_trace(0xBAu, l.where, 0u, 0u, l.ll_tick, l.esp_us, l.service_runs, l.tx_done);
	}
	box_trace();
}

/* A slot br_c6_radio_service did not take back within 20 ms of its end (looked for every 20 ms): collect it if the
 * baseband has finished the item, else ask the scheduler to drop it; one that is still busy 2 s later gets the
 * radio stop. Trace 0xB5 (the first 6, then every 64th and every
 * radio stop): code=step (0 seen, 1 collect/delete, 2 radio stop), cis=slot | is_tx<<4 | baseband item is ours<<5 |
 * probe<<6 | still busy<<7 | deleted<<8, acl=ms past the end, v0=sch word 0, v1=sch bytes 52..55, v2=the slot's
 * item offset, v3=baseband state register. */
static void st_watch_slots(void)
{
	static uint8_t s_tried[8];
	static uint32_t s_seen;
	br_c6_stuck_t k;
	if (!br_c6_st_stuck(&k) || k.idx >= sizeof(s_tried)) {
		return;
	}
	uint8_t step = 0u;
	if (s_tried[k.idx] == 0u) {
		step = 1u;
	} else if (s_tried[k.idx] == 1u && k.late_us > 2000000u) {
		step = 2u;
	}
	uint16_t deleted = 0u;
	bool freed       = false;
	if (step != 0u) {
		s_tried[k.idx] = step;
		freed = br_c6_st_force(k.idx, step, &deleted);
	}
	if (freed) {
		s_tried[k.idx] = 0u;
	}
	if (step == 0u) {
		return; /* waiting for the 2 s mark: already reported */
	}
	s_seen++;
	if (s_seen <= 6u || (s_seen & 63u) == 0u || step == 2u) {
		const uint16_t flags = (uint16_t)(k.idx | (k.is_tx ? 0x10u : 0u) | (k.hw_current ? 0x20u : 0u) |
				(k.probe ? 0x40u : 0u) | (freed ? 0u : 0x80u) | ((deleted & 0xFFu) << 8));
		st_trace(0xB5u, step, flags, sat16(k.late_us / 1000u), k.sch0, k.sch_flags, k.sch_off, k.hw_state);
	}
}

/* Lone RX items before the first inquiry: on BLE advertising channel 37 (2402 MHz) with the advertising access
 * address there is something to hear wherever a phone or a computer is near, so received bytes prove the raw RX
 * path. Third hardware run: five 60 ms windows of BR_RX_RECIPE_STOCK received nothing. Now the recipes take turns,
 * one window at a time (the next opens when the last has reported, looked at every 20 ms), eight windows a tick.
 * A recipe that needed the radio stop is left out from then on: the stop can cost its slot. A window the
 * scheduler refused: trace 0xB6 (code=probe, cis=0, acl=channel, v0=access address, v1=duration us, v2=recipe);
 * every result: trace 0xB8. */
#define BR_ST_PROBE_US      60000u
#define BR_ST_PROBES_A_TICK 8u
static bool s_st_probe_flying;
static uint8_t s_st_probe_left; /* windows still to open in this tick */
static uint8_t s_st_probe_next; /* recipe to try next */

static void st_probe_step(void)
{
	br_c6_probe_t r;
	while (br_c6_st_probe_pop(&r)) {
		s_st_probe_flying  = false;
		s_rtc_probe.flying = 0u;
		if (r.recipe < (uint8_t)BR_RX_RECIPE_COUNT) {
			if (r.data[0] != 0u && s_st_probe_hits[r.recipe] < UINT8_MAX) {
				s_st_probe_hits[r.recipe]++;
			}
			if (r.held) {
				s_rtc_probe.barred |= (uint8_t)(1u << r.recipe);
			}
		}
		st_trace(0xB8u, r.probe, (uint16_t)(r.recipe | (r.held ? 0x10u : 0u) | (r.skipped ? 0x20u : 0u)), 0u,
				r.status, r.stamp, r.data[0], r.data[1]);
	}
	if (s_st_host || s_st_probe_flying || s_st_probe_left == 0u || le_busy()) {
		return;
	}
	if (s_st_listen) {
		const uint8_t no  = s_st_probe_no;
		const uint8_t x   = (uint8_t)(no & 0x1Fu);
		const uint8_t chan = ((no >> 5) & 1u) != 0u ? br_hop_page_master_rx_from_xp(s_st_listen_ulap, x)
				: br_hop_page_scan(s_st_listen_ulap, (uint32_t)x << 12);
		br_c6_radio_set_id_rx_limit(((no >> 6) & 1u) != 0u);
		s_st_probe_left--;
		s_st_probe_no++;
		if (br_c6_st_lone_rx(no, (uint8_t)BR_RX_RECIPE_STOCK, chan, s_st_listen_aa, BR_ST_PROBE_US, 0u, true) == 0) {
			s_st_probe_flying = true;
		} else {
			st_trace(0xB6u, no, 0u, chan, s_st_listen_aa, BR_ST_PROBE_US, 0u, 0u);
		}
		return;
	}
	const uint32_t aa = 0x8E89BED6u;
	for (uint8_t n = 0; n < (uint8_t)BR_RX_RECIPE_COUNT; n++) {
		const uint8_t recipe = (uint8_t)((s_st_probe_next + n) % (uint8_t)BR_RX_RECIPE_COUNT);
		if ((s_rtc_probe.barred & (1u << recipe)) != 0u) {
			continue;
		}
		s_st_probe_next = (uint8_t)((recipe + 1u) % (uint8_t)BR_RX_RECIPE_COUNT);
		s_st_probe_left--;
		s_st_probe_no++;
		if (br_c6_st_lone_rx(s_st_probe_no, recipe, 0u, aa, BR_ST_PROBE_US, 0u, false) == 0) {
			s_st_probe_flying  = true;
			s_rtc_probe.flying = (uint8_t)(0x80u | recipe);
		} else {
			st_trace(0xB6u, s_st_probe_no, 0u, 0u, aa, BR_ST_PROBE_US, recipe, 0u);
		}
		return;
	}
	s_st_probe_left = 0u; /* every recipe is left out */
}

/* The recipe whose probes received bytes most often; the one the adapter always used when none did. */
static uint8_t st_best_recipe(void)
{
	uint8_t best = (uint8_t)BR_RX_RECIPE_STOCK;
	for (uint8_t r = 0; r < (uint8_t)BR_RX_RECIPE_COUNT; r++) {
		if (s_st_probe_hits[r] > s_st_probe_hits[best]) {
			best = r;
		}
	}
	return best;
}

#define BR_ST_PROBE_FIRST_TICK 3u  /* 6 s .. 30 s: eight 60 ms windows every 2 s */
#define BR_ST_PROBE_LAST_TICK  14u
#define BR_ST_WATCH_US         20000u /* slots past their end are looked for this often */
static esp_timer_handle_t s_st_watch_timer;

#if CONFIG_CYBERDECK_WIFI_TAP
/* Soft-BR stays silent this long after Bluetooth starts: the host logs in to its network then, and the tap records
 * of that login must stay in the 32-entry trace until it reads them. */
#define BR_ST_QUIET_TICKS 10u

/* Wi-Fi tap records (wifi_tap.c) leave through the same trace. 0xC0: code=management subtype, cis/acl=BSSID bytes
 * 0-1/2-3, v0,v1=frame body bytes 0..7, v2=body bytes 8..9 | frame length<<16, v3=rssi | channel<<8 | BSSID bytes
 * 4-5<<16. 0xC1 (first tick and when the count changes): v0=management frames heard, v1=frames for this station,
 * v2=not kept. */
static void st_flush_wifi_tap(void)
{
	static uint32_t s_reported = UINT32_MAX;
	wifi_tap_rec_t r;
	for (uint8_t n = 0; n < 6u && wifi_tap_pop(&r); n++) {
		uint32_t w[3] = { 0u, 0u, 0u };
		memcpy(w, r.body, sizeof(r.body));
		st_trace(0xC0u, r.subtype, (uint16_t)((r.bssid[0] << 8) | r.bssid[1]),
				(uint16_t)((r.bssid[2] << 8) | r.bssid[3]), w[0], w[1], (w[2] & 0xFFFFu) | ((uint32_t)r.len << 16),
				(uint32_t)(uint8_t)r.rssi | ((uint32_t)r.chan << 8) | ((uint32_t)r.bssid[4] << 16) |
				((uint32_t)r.bssid[5] << 24));
	}
	wifi_tap_stats_t s;
	wifi_tap_get_stats(&s);
	if (s.matched != s_reported) {
		s_reported = s.matched;
		st_trace(0xC1u, 0u, 0u, 0u, s.mgmt, s.matched, s.dropped, 0u);
	}
}
#else
#define BR_ST_QUIET_TICKS 0u
#endif

static void st_tick(void)
{
	s_st_ticks++;
#if CONFIG_CYBERDECK_WIFI_TAP
	st_flush_wifi_tap();
#endif
	if (s_st_ticks <= BR_ST_QUIET_TICKS) {
		return;
	}
	const uint32_t tick = s_st_ticks - BR_ST_QUIET_TICKS;
	if (tick == 1u) {
		st_emit_start();
	}
#ifdef BR_ST_CRASH_TEST
	/* The black box tried on the chip: once, while no crash is on record, this start ends the way a failed
	 * assertion of the Bluetooth controller does (bt.c, osi_assert_wrapper) - its line on the ROM's output, then
	 * assert(0) in the link layer task. The starts after it find the record and run on. */
	if (tick == 20u && s_box.ver != BR_C6_DUMP_VER) {
		esp_rom_printf("BLE assert: line %d in function %s, param: 0x%x, 0x%x", 1234, "box_test", 0xAu, 0xBu);
		assert(0);
	}
#endif
#ifdef BR_ST_ABORT_TEST
	/* What a host's name requests after an inquiry do, without a host: a page is given up two seconds later
	 * (BR_VS_ABORT_ALL, as the host's abort_and_disconnect_sync sends it), whatever the engine is doing by then,
	 * and the next one starts at once, every tick. The device paged is BR_ST_EXTRA_PEER when the image was built
	 * with one - a device that answers, so the engine is stopped during a page, a handshake or a connection - and
	 * else an address nobody has. Trace 0xCC: v0=pages started, v1=pages given up while the engine was not idle,
	 * v2=pages it refused. */
	if (tick >= 4u && !le_busy()) {
		static uint32_t s_ab_pages, s_ab_aborts, s_ab_refused;
		static const uint8_t abort_all[] = { 0x01u, 0x31u, 0xFCu, 0x05u, BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1,
			BR_VENDOR_MAGIC_2, BR_VENDOR_MAGIC_3, (uint8_t)BR_VS_ABORT_ALL };
#ifdef BR_ST_EXTRA_PEER
		static const uint8_t peer[6] = { BR_ST_EXTRA_PEER };
#else
		static const uint8_t peer[6] = { 0x56u, 0x34u, 0x12u, 0x9Au, 0x00u, 0x02u };
#endif
		const uint8_t page[] = { 0x01u, 0x05u, 0x04u, 0x0Du, peer[0], peer[1], peer[2], peer[3], peer[4], peer[5],
			0x18u, 0xCCu, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u };
		if (br_engine_get_state(s_engine) != BR_STATE_IDLE) {
			(void)br_engine_hci_from_host(s_engine, abort_all, sizeof(abort_all));
			s_ab_aborts++;
		}
		(void)br_engine_hci_from_host(s_engine, page, sizeof(page));
		if (br_engine_get_state(s_engine) != BR_STATE_IDLE) {
			s_ab_pages++;
		} else {
			s_ab_refused++;
		}
		st_trace(0xCCu, 0u, 0u, 0u, s_ab_pages, s_ab_aborts, s_ab_refused, 0u);
	}
#endif
	static uint32_t s_le_seen = UINT32_MAX;
	const uint32_t le_passed  = __atomic_load_n(&s_le_passed, __ATOMIC_RELAXED);
	const uint32_t le_refused = __atomic_load_n(&s_le_refused, __ATOMIC_RELAXED);
	if (le_passed + le_refused != s_le_seen) {
		s_le_seen = le_passed + le_refused;
		st_trace(0xC2u, (uint8_t)((__atomic_load_n(&s_le_scanning, __ATOMIC_RELAXED) ? 1u : 0u) |
				(__atomic_load_n(&s_le_initiating, __ATOMIC_RELAXED) ? 2u : 0u)),
				__atomic_load_n(&s_le_last_op, __ATOMIC_RELAXED), 0u, le_passed, le_refused, 0u, 0u);
	}
	s_st_probe_left = (s_st_listen || (tick >= BR_ST_PROBE_FIRST_TICK && tick <= BR_ST_PROBE_LAST_TICK)) ?
			BR_ST_PROBES_A_TICK : 0u;
	/* From one tick before the first window to one tick after the last: a window may still be open then. */
	__atomic_store_n(&s_br_probing, s_st_listen ||
			(tick + 1u >= BR_ST_PROBE_FIRST_TICK && tick <= BR_ST_PROBE_LAST_TICK + 1u), __ATOMIC_RELAXED);
	st_probe_step();
	if (tick == BR_ST_LONG_TICK && !s_st_host && !s_st_listen && s_boot_crashes == 0u && !le_busy() &&
	    br_engine_get_state(s_engine) == BR_STATE_IDLE) {
		st_long_pairs();
	} else if (tick == BR_ST_LONG_TICK + 1u && s_st_long_asked > 0u) {
		st_long_pairs_report();
	}
	const br_state_t st = br_engine_get_state(s_engine);
	const bool active   = (st != BR_STATE_IDLE);
	/* Before the first inquiry the probe results fill the trace: the counters go out every fourth tick only. */
	if (active || s_st_was_active || (tick < BR_ST_FIRST_TICK && (tick & 3u) == 0u)) {
		st_emit_counters((uint8_t)st);
	}
	s_st_was_active = active;
	s_st_events_left = 6u;
	if (!s_st_host && s_st_page == ST_PAGE_FOUND) {
		if (st == BR_STATE_INQUIRY) {
			static const uint8_t cancel[] = { 0x01u, 0x02u, 0x04u, 0x00u };
			st_trace(0xC4u, 1u, br_engine_hci_from_host(s_engine, cancel, sizeof(cancel)) ? 1u : 0u, 0u, 0u, 0u, 0u,
					0u);
		}
		const st_peer_t *peer = &s_st_peers[s_st_peer_turn];
#if BR_ST_LISTEN_ONLY
		{
			uint32_t lap = 0u;
			uint8_t uap  = 0u;
			br_bdaddr_to_parts(peer->addr, &lap, &uap, NULL);
			const uint64_t sw = br_syncword_from_lap(lap);
			s_st_listen_aa    = (uint32_t)sw;
			s_st_listen_ulap  = br_ulap(lap, uap);
			s_st_listen       = true;
			s_st_probe_no     = 0u;
			s_st_page         = ST_PAGE_CLOSING; /* no page, no further inquiry */
			st_trace(0xC4u, 4u, 1u, (uint16_t)((uint16_t)s_st_peer_turn << 8), 0u, (uint32_t)sw, (uint32_t)(sw >> 32),
					s_st_listen_ulap);
			return;
		}
#endif
		/* HCI_Create_Connection: one-slot packets (DM1, DH1), the clock offset of the inquiry answer, no role
		 * switch */
		const uint8_t cmd[] = { 0x01u, 0x05u, 0x04u, 0x0Du, peer->addr[0], peer->addr[1], peer->addr[2],
			peer->addr[3], peer->addr[4], peer->addr[5], 0x18u, 0x00u, peer->psrm, 0x00u,
			(uint8_t)(peer->clk_off & 0xFFu), (uint8_t)((peer->clk_off >> 8) | (peer->found ? 0x80u : 0x00u)),
			0x00u };
		/* ID answers are taken without the length limit: with it the engine does not accept them (run 15). */
		const bool limit = false;
		br_c6_radio_set_id_rx_limit(limit);
		const bool ok = br_engine_hci_from_host(s_engine, cmd, sizeof(cmd));
		s_st_page = ok ? ST_PAGE_ASKED : ST_PAGE_NONE;
		/* What the page is built from, as this chip computed it: the access code and the hop address. */
		uint32_t lap = 0u;
		uint8_t uap  = 0u;
		br_bdaddr_to_parts(peer->addr, &lap, &uap, NULL);
		const uint64_t sw = br_syncword_from_lap(lap);
		st_trace(0xC4u, 2u, ok ? 1u : 0u,
				(uint16_t)((limit ? 1u : 0u) | ((s_st_round & 2u) != 0u ? 2u : 0u) | ((uint16_t)s_st_peer_turn << 8)),
				(uint32_t)peer->psrm | ((uint32_t)peer->clk_off << 16), (uint32_t)sw, (uint32_t)(sw >> 32),
				br_ulap(lap, uap));
	} else if (!s_st_host && s_st_page == ST_PAGE_CONNECTED && s_st_ticks - s_st_conn_tick < 5u) {
		/* Two rounds per frame kind, so that each of two devices gets every kind. */
		const uint8_t variant = (uint8_t)((s_st_round >> 1) & 3u);
		switch (s_st_ticks - s_st_conn_tick) {
		case 1u:
			st_data_frame(20u, false);
			break;
		case 2u:
			st_data_report(variant, 0u, 20u);
			st_data_frame(s_st_data_len[variant], variant == 0u);
			break;
		case 4u:
			st_data_report(variant, 1u, s_st_data_len[variant]);
			break;
		default:
			break;
		}
	} else if (!s_st_host && s_st_page == ST_PAGE_CONNECTED) {
		const uint8_t cmd[] = { 0x01u, 0x06u, 0x04u, 0x03u, (uint8_t)(s_st_conn_handle & 0xFFu),
			(uint8_t)(s_st_conn_handle >> 8), 0x13u };
		st_trace(0xC4u, 3u, br_engine_hci_from_host(s_engine, cmd, sizeof(cmd)) ? 1u : 0u, s_st_conn_handle, 0u, 0u,
				0u, 0u);
		s_st_page = ST_PAGE_CLOSING;
	}
	if (!s_st_host && !s_st_listen && !active && !le_busy() && tick >= BR_ST_FIRST_TICK &&
	    (s_st_last_start == 0u || tick - s_st_last_start >= BR_ST_PERIOD_TICKS)) {
		s_st_page = ST_PAGE_NONE;
		/* HCI_Inquiry: GIAC 0x9E8B33, 8 x 1.28 s, unlimited responses */
		static const uint8_t cmd[] = { 0x01u, 0x01u, 0x04u, 0x05u, 0x33u, 0x8Bu, 0x9Eu, 0x08u, 0x00u };
		s_st_round++;
		s_st_results    = 0u;
		s_st_last_start = tick;
		const uint8_t recipe = st_best_recipe();
		br_c6_radio_set_rx_recipe(recipe);
		/* Rounds 2, 3, 6, 7, ... send ID packets that end with the sync word, the others the old ones with 24 bits
		 * after it: an inquiry that still finds the device proves the new packet, the page of the same round shows
		 * whether a device in page scan needs it (run 13: it made no difference for the speaker). Vendor command:
		 * set knobs. */
		const uint8_t ends_with_sync = (uint8_t)((s_st_round >> 1) & 1u);
		/* The second knob (deviation scaled towards Classic's modulation index, br_c6_set_gauss_bt05) stays off:
		 * hardware run 22 (2026-11-11) switched it on in every other block of four rounds, and in those 12 rounds
		 * the paged computer gave no ID answer at all, against 10 connections in the 11 rounds without it. */
		const uint8_t knobs[] = { 0x01u, 0x31u, 0xFCu, 11u, BR_VENDOR_MAGIC_0, BR_VENDOR_MAGIC_1, BR_VENDOR_MAGIC_2,
			BR_VENDOR_MAGIC_3, (uint8_t)BR_VS_SET_KNOBS, 0u, 0u, 0u, 0u, 0u, ends_with_sync };
		(void)br_engine_hci_from_host(s_engine, knobs, sizeof(knobs));
		const bool ok = br_engine_hci_from_host(s_engine, cmd, sizeof(cmd));
		st_trace(0xB4u, ok ? 1u : 0u, s_st_round, 0u, recipe,
				(uint32_t)s_st_probe_hits[0] | ((uint32_t)s_st_probe_hits[1] << 8) |
				((uint32_t)s_st_probe_hits[2] << 16) | ((uint32_t)s_st_probe_hits[3] << 24), ends_with_sync, 0u);
		/* A device that was not found by an inquiry does not answer one either: when it is its turn, it is paged
		 * at the next tick without waiting for a result. */
		if (s_st_peer_count > 0u && !s_st_peers[s_st_round % s_st_peer_count].found) {
			s_st_peer_turn = (uint8_t)(s_st_round % s_st_peer_count);
			s_st_page      = ST_PAGE_FOUND;
		}
	}
}

/* The first Soft-BR command or ACL packet from the host: it drives the engine from now on. An inquiry of the
 * self-test that is still running is ended (the host's own command would get Command Disallowed). */
static void st_host_takes_over(void)
{
	if (s_st_host) {
		return;
	}
	s_st_host = true;
	if (br_engine_get_state(s_engine) != BR_STATE_IDLE) {
		br_engine_reset(s_engine);
	}
	st_trace(0xB4u, 2u, s_st_round, 0u, 0u, 0u, 0u, 0u);
	ESP_LOGW(TAG, "BENCH SELF-TEST: the host drives Soft-BR now, events go to the host");
}

/* Inquiry results and the engine's other events go to the trace, whoever sent the command. Called from inside the
 * engine: it only takes notes, st_tick acts on them. */
static void st_on_event(const uint8_t *h4, uint16_t len)
{
	if (len < 3u || h4[0] != 0x04u) {
		return;
	}
	if (h4[1] != 0x02u && h4[1] != 0x22u && h4[1] != 0x2Fu) {
		if (s_st_events_left > 0u) {
			s_st_events_left--;
			uint32_t w[4] = { 0u, 0u, 0u, 0u };
			memcpy(w, h4 + 3, (size_t)(len - 3u) < sizeof(w) ? (size_t)(len - 3u) : sizeof(w));
			st_trace(0xC3u, h4[1], h4[2], 0u, w[0], w[1], w[2], w[3]);
		}
		if (h4[1] == BR_HCI_EVT_CONN_COMPLETE && len >= 3u + 3u && s_st_page == ST_PAGE_ASKED) {
			if (h4[3] == 0x00u) {
				s_st_conn_handle = (uint16_t)((uint16_t)h4[4] | ((uint16_t)h4[5] << 8));
				s_st_conn_tick   = s_st_ticks;
				s_st_page        = ST_PAGE_CONNECTED;
			} else {
				s_st_page = ST_PAGE_NONE;
			}
		} else if (h4[1] == BR_HCI_EVT_DISCONN_COMPLETE) {
			s_st_page = ST_PAGE_NONE;
		}
		return;
	}
	if (len < 3u + 7u) {
		return;
	}
	const uint8_t *p = h4 + 3;
	const uint8_t clk_at = (h4[1] == 0x02u) ? 13u : 12u;
	if (!s_st_host && len >= 3u + clk_at + 2u) {
		uint8_t at = 0u;
		while (at < s_st_peer_count && memcmp(s_st_peers[at].addr, &p[1], 6u) != 0) {
			at++;
		}
		if (at == s_st_peer_count && s_st_peer_count < BR_ST_PEERS) {
			memcpy(s_st_peers[at].addr, &p[1], 6u);
			s_st_peer_count++;
		}
		if (at < s_st_peer_count) {
			s_st_peers[at].found   = true;
			s_st_peers[at].psrm    = p[7];
			s_st_peers[at].clk_off = (uint16_t)(((uint16_t)p[clk_at] | ((uint16_t)p[clk_at + 1u] << 8)) & 0x7FFFu);
			/* The device whose turn it is has answered this round: its clock offset is fresh. */
			if (s_st_page == ST_PAGE_NONE && at == (uint8_t)(s_st_round % s_st_peer_count)) {
				s_st_peer_turn = at;
				s_st_page      = ST_PAGE_FOUND;
			}
		}
	}
	const uint32_t lo = (uint32_t)p[1] | ((uint32_t)p[2] << 8) | ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
	const uint16_t hi = (uint16_t)(p[5] | (p[6] << 8));
	const int8_t rssi = (h4[1] != 0x02u && len >= 3u + 15u) ? (int8_t)p[14] : 0;
	const uint8_t cod_at = (h4[1] == 0x02u) ? 10u : 9u;
	const uint32_t cod = (len >= 3u + cod_at + 3u) ?
		((uint32_t)p[cod_at] | ((uint32_t)p[cod_at + 1] << 8) | ((uint32_t)p[cod_at + 2] << 16)) : 0u;
	s_st_results++;
	st_trace(0xB2u, (uint8_t)rssi, hi, s_st_round, lo, cod, 0u, 0u);
}

static void st_timer_cb(void *arg)
{
	(void)arg;
	br_kick(BR_KICK_SELFTEST);
}

static void st_watch_timer_cb(void *arg)
{
	(void)arg;
	br_kick(BR_KICK_WATCH);
}
#endif

static void op_hci_to_host(void *ctx, const uint8_t *h4, uint16_t len)
{
	(void)ctx;
	if (!h4 || len == 0u) {
		return;
	}
#if CONFIG_CYBERDECK_BR_SELFTEST
	st_on_event(h4, len);
	if (!s_st_host) {
		return; /* events of the self-test's own inquiry: the host did not send the command */
	}
#endif
	flush_deferred_nocp();

	/* Never lose an ACL credit return (04 13 05 01 00 0B c_lo c_hi) */
	if (len == 8u && h4[0] == 0x04u && h4[1] == 0x13u && h4[3] == 0x01u) {
		uint16_t h = (uint16_t)((uint16_t)h4[4] | ((uint16_t)h4[5] << 8));
		uint16_t c = (uint16_t)((uint16_t)h4[6] | ((uint16_t)h4[7] << 8));
		if (h == BR_ACL_HANDLE_BASE && !host_enqueue(h4, len)) {
			s_deferred_nocp += c;
			return;
		}
		return;
	}
	(void)host_enqueue(h4, len);
}

/* ---- Timer & Random ops ---- */
static void timer_cb(void *arg)
{
	(void)arg;
	br_kick(BR_KICK_TIMER);
}

static void rx_timer_cb(void *arg)
{
	(void)arg;
	br_kick(BR_KICK_RXEND);
}

void br_c6_rx_timer_arm(uint32_t delay_us)
{
	if (s_rx_timer == NULL) {
		return;
	}
	(void)esp_timer_stop(s_rx_timer);
	(void)esp_timer_start_once(s_rx_timer, (delay_us < 50u) ? 50u : (uint64_t)delay_us);
}

static void op_timer_start(void *ctx, uint32_t timeout_us)
{
	(void)ctx;
	(void)esp_timer_stop(s_timer);
	uint64_t us = (timeout_us < 50u) ? 50u : (uint64_t)timeout_us;
	(void)esp_timer_start_once(s_timer, us);
}

static void op_timer_stop(void *ctx)
{
	(void)ctx;
	(void)esp_timer_stop(s_timer);
}

static void op_random(void *ctx, uint8_t *buf, uint16_t len)
{
	(void)ctx;
	if (buf != NULL && len > 0u) {
		esp_fill_random(buf, len);
	}
}

static const br_platform_ops_t k_br_ops = {
	.ctx             = NULL,
	.schedule_tx     = br_c6_schedule_tx,
	.schedule_rx     = br_c6_schedule_rx,
	.schedule_tx_rx  = br_c6_schedule_tx_rx,
	.cancel_all      = br_c6_cancel_all,
	.radio_caps      = br_c6_radio_caps,
	.set_gauss_bt05  = br_c6_set_gauss_bt05,
	.hci_to_host     = op_hci_to_host,
	.now_us          = br_c6_now_us,
	.random          = op_random,
	.timer_start     = op_timer_start,
	.timer_stop      = op_timer_stop,
};

/* ---- Fast H2C classifier on SDIO RX task ---- */
static bool classify_h2c(const uint8_t *h4, uint16_t len, br_h2c_kind_t *out_kind)
{
	if (!h4 || len < 1u) {
		return false;
	}
	if (h4[0] == BR_H4_ACL) {
		if (len < 5u) {
			return false;
		}
		uint16_t h = (uint16_t)(((uint16_t)h4[1] | ((uint16_t)h4[2] << 8)) & 0x0FFFu);
		if (h == BR_ACL_HANDLE_BASE) {
			*out_kind = BR_H2C_TAKE;
			return true;
		}
		return false;
	}
	if (h4[0] != BR_H4_CMD || len < 4u) {
		return false;
	}
	uint16_t opcode = (uint16_t)((uint16_t)h4[1] | ((uint16_t)h4[2] << 8));
	uint8_t plen    = h4[3];
	if ((uint16_t)(4u + plen) > len) {
		return false;
	}

	if (opcode == BR_HCI_OP_RESET) {
		*out_kind = BR_H2C_SNOOP;
		return true;
	}
	if (opcode == BR_HCI_OP_DISCONNECT) {
		if (plen >= 3u) {
			uint16_t h = (uint16_t)(((uint16_t)h4[4] | ((uint16_t)h4[5] << 8)) & 0x0FFFu);
			if (h == BR_ACL_HANDLE_BASE) {
				*out_kind = BR_H2C_TAKE;
				return true;
			}
		}
		return false;
	}
	if (opcode == BR_HCI_OP_VENDOR_BRC6) {
		if (plen >= 5u && h4[4] == BR_VENDOR_MAGIC_0 && h4[5] == BR_VENDOR_MAGIC_1 &&
		    h4[6] == BR_VENDOR_MAGIC_2 && h4[7] == BR_VENDOR_MAGIC_3) {
			*out_kind = BR_H2C_TAKE;
			return true;
		}
		return false;
	}
	switch (opcode) {
	case BR_HCI_OP_INQUIRY:
	case BR_HCI_OP_INQUIRY_CANCEL:
	case BR_HCI_OP_CREATE_CONN:
	case BR_HCI_OP_CREATE_CONN_CANCEL:
	case BR_HCI_OP_WRITE_SCAN_ENABLE:
		*out_kind = BR_H2C_TAKE;
		return true;
	default:
		return false;
	}
}

bool br_c6_h2c(const uint8_t *h4, uint16_t len)
{
	if (!br_c6_on()) {
		return false;
	}
	if (le_guard_h2c(h4, len)) {
		return true;
	}
	br_h2c_kind_t kind = BR_H2C_TAKE;
	if (!classify_h2c(h4, len, &kind)) {
		return false;
	}
	if (len > BR_H2C_MAX_PKT) {
		if (h4[0] == BR_H4_ACL) {
			__atomic_fetch_add(&s_h2c_lost_acl, 1u, __ATOMIC_RELAXED);
			br_kick(BR_KICK_H2C);
		}
		return (kind == BR_H2C_TAKE);
	}

	bool queued = false;
	portENTER_CRITICAL(&s_h2c_mux);
	uint32_t wr = s_h2c_wr;
	uint32_t rd = __atomic_load_n(&s_h2c_rd, __ATOMIC_ACQUIRE);
	if ((wr - rd) < BR_H2C_SLOTS) {
		br_h2c_slot_t *slot = &s_h2c[wr % BR_H2C_SLOTS];
		slot->kind = (uint8_t)kind;
		slot->len  = len;
		memcpy(slot->data, h4, len);
		__atomic_store_n(&s_h2c_wr, wr + 1u, __ATOMIC_RELEASE);
		queued = true;
	}
	portEXIT_CRITICAL(&s_h2c_mux);

	if (!queued) {
		if (h4[0] == BR_H4_ACL) {
			__atomic_fetch_add(&s_h2c_lost_acl, 1u, __ATOMIC_RELAXED);
		}
		br_kick(BR_KICK_H2C);
		return (kind == BR_H2C_TAKE);
	}

	br_kick(BR_KICK_H2C);
	return (kind == BR_H2C_TAKE);
}

bool br_c6_c2h(uint8_t *h4, uint16_t len)
{
	if (br_c6_on()) {
		le_guard_c2h(h4, len);
	}
	return false;
}

static void h2c_drain(void)
{
	for (;;) {
		uint32_t rd = s_h2c_rd;
		uint32_t wr = __atomic_load_n(&s_h2c_wr, __ATOMIC_ACQUIRE);
		if (rd == wr) {
			break;
		}
		br_h2c_slot_t *slot = &s_h2c[rd % BR_H2C_SLOTS];
		if (s_radio_ok && s_engine != NULL) {
#if CONFIG_CYBERDECK_BR_SELFTEST
			if (slot->kind == BR_H2C_TAKE) {
				st_host_takes_over();
			}
#endif
			(void)br_engine_hci_from_host(s_engine, slot->data, slot->len);
		}
		__atomic_store_n(&s_h2c_rd, rd + 1u, __ATOMIC_RELEASE);
	}
}

static void br_kick_handler(struct ble_npl_event *ev)
{
	(void)ev;
	if (__atomic_load_n(&s_ll_task, __ATOMIC_ACQUIRE) == NULL) {
		__atomic_store_n(&s_ll_task, xTaskGetCurrentTaskHandle(), __ATOMIC_RELEASE);
	}
	uint32_t bits = __atomic_exchange_n(&s_kick_bits, 0u, __ATOMIC_SEQ_CST);

	if (bits & BR_KICK_SHUTDOWN) {
		if (s_engine != NULL) {
			br_engine_reset(s_engine);
		}
		br_c6_radio_reset();
		br_c6_live_mark(false);
		__atomic_store_n(&s_on, false, __ATOMIC_RELEASE);
		xSemaphoreGive(s_shutdown_done);
		return;
	}
	if (!br_c6_on()) {
		return;
	}
#if !CONFIG_CYBERDECK_BR_SELFTEST
	if (bits & BR_KICK_INIT) {
		/* A regular image says how it started and what the last crash left; the bench image does in its first tick. */
		st_trace(0xBBu, (uint8_t)esp_reset_reason(), s_boot_live ? 1u : 0u, s_boot_crashes, 0u, s_rtc_tail.n, 0u, 0u);
		box_trace();
	}
#endif
	if ((bits & BR_KICK_INIT) && !s_radio_ok) {
		if (br_c6_radio_init() == 0) {
			s_radio_ok = true;
		} else {
			ESP_LOGE(TAG, "Soft-BR radio slot alloc failed - disabling Soft-BR");
			__atomic_store_n(&s_on, false, __ATOMIC_RELEASE);
			return;
		}
	}
	if (!s_radio_ok || s_engine == NULL) {
		return;
	}

	/* First, on every wake: an RX slot that has ended is reported to the engine before the engine's own timer
	 * can give its pair up. */
	br_c6_radio_service();

	if (bits & BR_KICK_H2C) {
		h2c_drain();
	}
	if (bits & BR_KICK_TIMER) {
		br_engine_on_timer(s_engine);
	}
#if CONFIG_CYBERDECK_BR_SELFTEST
	if (bits & BR_KICK_SELFTEST) {
		st_tick();
	}
	if ((bits & BR_KICK_WATCH) && s_st_ticks > BR_ST_QUIET_TICKS) {
		st_probe_step();
		st_watch_slots();
	}
#endif
	flush_deferred_nocp();
	br_c6_live_mark(br_engine_get_state(s_engine) != BR_STATE_IDLE);
	/* Trace 0xCD, every image, when the count changes and half a minute at the earliest after the last record:
	 * v0=recycle passes of the controller that were not given an executed Soft-BR item because the baseband
	 * still pointed at it (br_c6_radio.c); each would have taken the controller's spare-block swap. */
	static uint32_t s_held_seen;
	static uint32_t s_held_us;
	const uint32_t held = br_c6_radio_pop_held();
	const uint32_t now  = (uint32_t)esp_timer_get_time();
	if (held != s_held_seen && now - s_held_us >= 30000000u) {
		s_held_seen = held;
		s_held_us   = now;
		st_trace(0xCDu, 0u, 0u, 0u, held, 0u, 0u, 0u);
	}
}

/* ---- Crash guard check ---- */
static bool reset_is_crash(esp_reset_reason_t r)
{
	switch (r) {
	case ESP_RST_PANIC:
	case ESP_RST_INT_WDT:
	case ESP_RST_TASK_WDT:
	case ESP_RST_CPU_LOCKUP:
	case ESP_RST_WDT:
		return true;
	default:
		return false;
	}
}

/* Crashes on record are forgotten after a quiet stretch (br_c6_crash.h). The write waits for flash, which neither
 * the link layer task nor the timer task that paces the Soft-BR slots may do: a task of its own, gone afterwards. */
static br_crash_rec_t s_crash_rec;

static void crash_forgive_task(void *arg)
{
	(void)arg;
	vTaskDelay(pdMS_TO_TICKS(BR_CRASH_FORGIVE_SECS * 1000u));
	const br_crash_boot_t f = br_crash_forgive(&s_crash_rec);
	if (f.write) {
		nvs_handle_t h;
		if (nvs_open(BR_C6_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
			if (nvs_set_blob(h, BR_C6_NVS_CRASH, &f.rec, sizeof(f.rec)) == ESP_OK) {
				(void)nvs_commit(h);
			}
			nvs_close(h);
		}
		ESP_LOGW(TAG, "Soft-BR: %u crash(es) on record forgotten after %u s without one",
			 (unsigned)s_crash_rec.crashes, (unsigned)BR_CRASH_FORGIVE_SECS);
	}
	vTaskDelete(NULL);
}

static bool crash_guard_allows(void)
{
	static int8_t s_allowed = -1;
	if (s_allowed >= 0) {
		return s_allowed != 0;
	}
	br_crash_rec_t stored;
	size_t len = sizeof(stored);
	bool have = false;
	nvs_handle_t h;
	if (nvs_open(BR_C6_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
		have = (nvs_get_blob(h, BR_C6_NVS_CRASH, &stored, &len) == ESP_OK && len == sizeof(stored));
		nvs_close(h);
	}
	uint8_t img[BR_CRASH_IMG_LEN];
	memcpy(img, esp_app_get_description()->app_elf_sha256, sizeof(img));
	const bool live  = (s_rtc_live == BR_C6_LIVE_MAGIC);
	const bool crash = reset_is_crash(esp_reset_reason());
	s_rtc_live = 0u;

	const br_crash_boot_t b = br_crash_boot(have ? &stored : NULL, img, live, crash);
	s_boot_live    = live;
	s_boot_crashes = b.rec.crashes;
	if (crash) {
		crash_dump_save(b.rec.crashes);
	}
	box_start(crash);
	if (live && crash) {
		ESP_LOGW(TAG, "C6 crash during Soft-BR (%u of %u)", b.rec.crashes, BR_CRASH_LIMIT);
	}
	if (b.write) {
		if (nvs_open(BR_C6_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
			if (nvs_set_blob(h, BR_C6_NVS_CRASH, &b.rec, sizeof(b.rec)) == ESP_OK) {
				(void)nvs_commit(h);
			}
			nvs_close(h);
		}
	}
	if (b.rec.crashes != 0u) {
		s_crash_rec = b.rec;
		if (xTaskCreate(crash_forgive_task, "br_ok", 3072, NULL, 1, NULL) != pdPASS) {
			ESP_LOGW(TAG, "Soft-BR: no task to forget the crashes on record");
		}
	}
	if (b.disabled) {
		ESP_LOGE(TAG, "Soft-BR disabled for this start after %u crashes - BLE & LE Audio remain active; it is back "
			 "at the next start once %u s have passed without a crash", b.rec.crashes,
			 (unsigned)BR_CRASH_FORGIVE_SECS);
	}
	s_allowed = b.disabled ? 0 : 1;
	return !b.disabled;
}

int br_c6_init(void)
{
	if (br_c6_on()) {
		return 0;
	}
	if (!crash_guard_allows()) {
		return -1;
	}
	if (s_engine_mem == NULL) {
		s_engine_mem = heap_caps_aligned_alloc(8, br_engine_storage_size(),
				MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		if (s_engine_mem == NULL) {
			ESP_LOGE(TAG, "No %lu B for Soft-BR engine", (unsigned long)br_engine_storage_size());
			return -1;
		}
	}
	if (s_h2c == NULL) {
		s_h2c = (br_h2c_slot_t *)heap_caps_malloc(sizeof(br_h2c_slot_t) * BR_H2C_SLOTS,
				MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
		if (s_h2c == NULL) {
			ESP_LOGE(TAG, "No memory for Soft-BR H2C ring");
			return -1;
		}
	}
	if (s_timer == NULL) {
		const esp_timer_create_args_t args = { .callback = timer_cb, .name = "br_c6" };
		if (esp_timer_create(&args, &s_timer) != ESP_OK) {
			ESP_LOGE(TAG, "esp_timer_create failed for Soft-BR");
			return -1;
		}
	}
	if (s_rx_timer == NULL) {
		const esp_timer_create_args_t args = { .callback = rx_timer_cb, .name = "br_c6_rx" };
		if (esp_timer_create(&args, &s_rx_timer) != ESP_OK) {
			ESP_LOGE(TAG, "esp_timer_create failed for the Soft-BR RX slot timer");
			return -1;
		}
	}
	if (s_host_q == NULL) {
		s_host_q = xQueueCreate(BR_HOST_Q_DEPTH, sizeof(br_host_pkt_t));
		if (s_host_q != NULL &&
		    xTaskCreate(br_host_tx_task, "br_host", 3072, NULL, CONFIG_ESP_DEFAULT_TASK_PRIO, NULL) != pdPASS) {
			vQueueDelete(s_host_q);
			s_host_q = NULL;
		}
		if (s_host_q == NULL) {
			ESP_LOGE(TAG, "No memory for Soft-BR host TX queue");
			return -1;
		}
	}
	if (s_shutdown_done == NULL) {
		s_shutdown_done = xSemaphoreCreateBinary();
		if (s_shutdown_done == NULL) {
			return -1;
		}
	}

	uint8_t mac[6] = {0};
	(void)esp_read_mac(mac, ESP_MAC_BT);
	s_engine = br_engine_init(s_engine_mem, br_engine_storage_size(), &k_br_ops, mac);
	if (s_engine == NULL) {
		ESP_LOGE(TAG, "br_engine_init failed");
		return -1;
	}

	uint8_t bd[6];
	br_engine_get_bdaddr(s_engine, bd);
	s_h2c_wr = s_h2c_rd = 0u;
	s_h2c_lost_acl  = 0u;
	s_deferred_nocp = 0u;
	s_kick_bits     = 0u;
	s_kick_impl.queued = false;
	s_kick_impl.fn     = br_kick_handler;
	s_kick_impl.arg    = NULL;
	__atomic_store_n(&s_ll_task, NULL, __ATOMIC_RELEASE);
	__atomic_store_n(&s_on, true, __ATOMIC_RELEASE);

	br_kick(BR_KICK_INIT);
#if CONFIG_CYBERDECK_BR_SELFTEST
#ifdef BR_ST_PASSIVE
	/* As if the host had taken over already: no probes, no inquiries, no pages of the self-test. The ticks go on,
	 * so the crash on record and the counters still reach the trace. */
	s_st_host = true;
#else
	s_st_host = false;
#endif
	if (s_st_timer == NULL) {
		const esp_timer_create_args_t st_args = { .callback = st_timer_cb, .name = "br_st" };
		if (esp_timer_create(&st_args, &s_st_timer) != ESP_OK) {
			ESP_LOGE(TAG, "esp_timer_create failed for the Soft-BR self-test");
		}
	}
	if (s_st_watch_timer == NULL) {
		const esp_timer_create_args_t w_args = { .callback = st_watch_timer_cb, .name = "br_st_w" };
		if (esp_timer_create(&w_args, &s_st_watch_timer) != ESP_OK) {
			ESP_LOGE(TAG, "esp_timer_create failed for the Soft-BR slot watch");
		}
	}
	if (s_st_watch_timer != NULL) {
		(void)esp_timer_start_periodic(s_st_watch_timer, BR_ST_WATCH_US);
	}
	if (s_st_timer != NULL) {
		(void)esp_timer_start_periodic(s_st_timer, BR_ST_TICK_US);
		ESP_LOGW(TAG, "BENCH SELF-TEST: inquiry every 16 s until the host sends a Soft-BR command, counters in the CIS trace");
	}
#endif
	ESP_LOGI(TAG, "Soft-BR Classic engine ready (%lu B, BD_ADDR %02x:%02x:%02x:%02x:%02x:%02x)",
			(unsigned long)br_engine_storage_size(),
			bd[5], bd[4], bd[3], bd[2], bd[1], bd[0]);
	return 0;
}

void br_c6_deinit(void)
{
	if (!br_c6_on()) {
		return;
	}
	(void)esp_timer_stop(s_timer);
	(void)esp_timer_stop(s_rx_timer);
#if CONFIG_CYBERDECK_BR_SELFTEST
	if (s_st_timer != NULL) {
		(void)esp_timer_stop(s_st_timer);
	}
	if (s_st_watch_timer != NULL) {
		(void)esp_timer_stop(s_st_watch_timer);
	}
#endif
	xSemaphoreTake(s_shutdown_done, 0);
	br_kick(BR_KICK_SHUTDOWN);
	if (xSemaphoreTake(s_shutdown_done, pdMS_TO_TICKS(200)) != pdTRUE) {
		ESP_LOGW(TAG, "LL task did not close Soft-BR within 200 ms");
		__atomic_store_n(&s_on, false, __ATOMIC_RELEASE);
	}
	br_c6_live_mark(false);
}
