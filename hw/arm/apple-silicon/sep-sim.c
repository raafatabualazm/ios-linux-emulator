/*
 * Apple SEP.
 *
 * Copyright (c) 2023-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
 * Copyright (c) 2023-2026 Christian Inci (chris-pcguy).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "crypto/hash.h"
#include "hw/arm/apple-silicon/dt.h"
#include "hw/arm/apple-silicon/sep-sim.h"
#include "hw/arm/apple-silicon/sep-sks-wire.h"
#include "hw/misc/apple-silicon/a7iop/core.h"
#include "hw/misc/apple-silicon/a7iop/mailbox/core.h"
#include "hw/resettable.h"
#include "qapi/error.h"
#include "qemu/guest-random.h"
#include "qemu/error-report.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "system/dma.h"
#include "art.h"
#include "libtasn1.h"

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t param;
    uint32_t data;
} QEMU_PACKED SEPMessage;

static void apple_sep_sim_note_unsupported(AppleSEPSimState *s, uint8_t ep,
                                           uint8_t op)
{
    s->diagnostic_unsupported++;
    s->diagnostic_last_unsupported_ep = ep;
    s->diagnostic_last_unsupported_op = op;
}

/*
 * Out-of-line (OOL) transfer helpers.
 *
 * s->dma_as is supplied by the board. A board with a DART passes that DART's
 * address space, so an OOL address is an IOVA; apple-modern models no DART and
 * passes the system address space, so there an OOL address is a physical
 * address. A board that wires neither leaves the field NULL -- s8000 ships that
 * way today -- and the OOL sites below would dereference it. Refuse the
 * transfer and say so instead of crashing the emulator on a guest message.
 */
static bool apple_sep_sim_ool_write(AppleSEPSimState *s, uint64_t addr,
                                    const void *buf, size_t len,
                                    const char *what)
{
    if (s->dma_as == NULL) {
        s->diagnostic_ool_errors++;
        qemu_log_mask(LOG_UNIMP, "SEP sim: %s needs an out-of-line address "
                      "space and this board supplied none; %zu-byte transfer "
                      "dropped\n", what, len);
        return false;
    }
    if (dma_memory_write(s->dma_as, addr, buf, len,
                         MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        s->diagnostic_ool_errors++;
        qemu_log_mask(LOG_GUEST_ERROR, "SEP sim: %s out-of-line write of %zu "
                      "bytes to 0x%" PRIx64 " failed\n", what, len, addr);
        return false;
    }
    return true;
}

static bool apple_sep_sim_ool_read(AppleSEPSimState *s, uint64_t addr,
                                   void *buf, size_t len, const char *what)
{
    if (s->dma_as == NULL) {
        s->diagnostic_ool_errors++;
        qemu_log_mask(LOG_UNIMP, "SEP sim: %s needs an out-of-line address "
                      "space and this board supplied none; %zu-byte read "
                      "dropped\n", what, len);
        return false;
    }
    if (dma_memory_read(s->dma_as, addr, buf, len,
                        MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
        s->diagnostic_ool_errors++;
        qemu_log_mask(LOG_GUEST_ERROR, "SEP sim: %s out-of-line read of %zu "
                      "bytes from 0x%" PRIx64 " failed\n", what, len, addr);
        return false;
    }
    return true;
}

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    uint32_t name;
} QEMU_PACKED EPAdvertisementMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint16_t size;
    uint32_t address;
} QEMU_PACKED L4InfoMessage;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    uint32_t data;
} QEMU_PACKED SetOOLMessage;

typedef enum {
    SEP_STATUS_SLEEPING = 0,
    SEP_STATUS_BOOTSTRAP = 1,
    SEP_STATUS_ACTIVE = 2,
} AppleSEPStatus;

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t op;
    uint8_t id;
    AppleSEPSimOOLInfo ool_info;
} QEMU_PACKED OOLAdvertisementMessage;

enum {
    EP_CONTROL = 0, // 'cntl'
    EP_LOGGER = 1, // 'log '
    EP_ART_STORAGE = 2, // 'arts'
    EP_ART_REQUESTS = 3, // 'artr'
    EP_TRACING = 4, // 'trac'
    EP_DEBUG = 5, // 'debu'
    EP_EMBEDDED_ISP = 6, // 'eisp'
    EP_MOBILE_SKS = 7, // 'msks'
    EP_SECURE_BIOMETRICS = 8, // 'sbio'
    EP_FACE_ID = 9, // 'sprl'
    EP_SECURE_CREDENTIALS = 10, // 'scrd'
    EP_PAIRING = 11,
    EP_SECURE_ELEMENT = 12, // 'sse '
    // 13 = ??
    EP_HDCP = 14, // 'hdcp'
    EP_UNIT_TESTING = 15, // 'unit'
    EP_XART_SLAVE = 16, // 'xars'
    EP_HILO = 17, // 'hilo'
    EP_KEYSTORE = 18, // 'sks '
    EP_XART_MASTER = 19, // 'xarm'
    EP_SMC = 20, // 'smc '
    EP_HIBERNATION = 20, // 'hibe'
    EP_NONP = 21, // 'nonp'
    EP_CYRS = 22, // 'cyrs'
    EP_SKDL = 23, // 'skdl'
    EP_STAC = 24, // 'stac'
    EP_SIDV = 25, // 'sidv'
    EP_DISCOVERY = 253,
    EP_L4INFO = 254,
    EP_BOOTSTRAP = 255,
};

enum {
    CONTROL_OP_NOP = 0,
    CONTROL_OP_ACK = 1,
    CONTROL_OP_SET_OOL_IN_ADDR = 2,
    CONTROL_OP_SET_OOL_OUT_ADDR = 3,
    CONTROL_OP_SET_OOL_IN_SIZE = 4,
    CONTROL_OP_SET_OOL_OUT_SIZE = 5,
    CONTROL_OP_TTY_IN = 10,
    CONTROL_OP_SLEEP = 12,
    CONTROL_OP_NOTIFY_ALIVE = 13,
    CONTROL_OP_SEED_DPA = 15,
    CONTROL_OP_GENERATE_RANDOM_DATA = 16,
    CONTROL_OP_OPCODE_18 = 18,
    CONTROL_OP_NAP = 19,
    CONTROL_OP_GET_SECURITY_MODE = 20,
    CONTROL_OP_SELF_TEST = 24,
    CONTROL_OP_SET_DMA_CMD_ADDR = 25,
    CONTROL_OP_SET_DMA_CMD_SIZE = 26,
    CONTROL_OP_SET_DMA_IN_ADDR = 27,
    CONTROL_OP_SET_DMA_OUT_ADDR = 28,
    CONTROL_OP_SET_DMA_IN_RELAY_ADDR = 29,
    CONTROL_OP_SET_DMA_OUT_RELAY_ADDR = 30,
    CONTROL_OP_SET_DMA_IN_SIZE = 31,
    CONTROL_OP_SET_DMA_OUT_SIZE = 32,
    CONTROL_OP_ERASE_INSTALL = 37,
    CONTROL_OP_L4_PANIC = 38,
    CONTROL_OP_SEP_OS_PANIC = 39,
};

enum {
    LOGGER_OP_UPDATE_POSITION = 11,
};

enum {
    ART_STORAGE_OP_ART_LOAD = 1, // AppleSEPARTStorage::handle_first_connected
    ART_STORAGE_OP_NO_ART = 2,
    ART_STORAGE_OP_MANIFEST = 3,
    ART_STORAGE_OP_INCOMING = 20, // AppleSEPARTStorage::_msgAction
    ART_STORAGE_OP_RECEIVED = 21,
};

enum {
    ART_REQUESTS_OP_NEW_NONCE = 20,
    ART_REQUESTS_OP_INVALIDATE_NONCE = 21,
    ART_REQUESTS_OP_COMMIT_HASH = 22,
    ART_REQUESTS_OP_COUNTER_SELF_TEST = 30,
    ART_REQUESTS_OP_PURGE_SYSTEM_TOKEN = 40,
};

enum {
    DEBUG_OP_COPY_FROM_OBJECT = 0,
    DEBUG_OP_COPY_TO_OBJECT = 1,
    DEBUG_OP_OBJECT_INFO = 2,
    DEBUG_OP_CREATE_OBJECT = 3,
    DEBUG_OP_SHARE_OBJECT = 4,
    DEBUG_OP_DUMP_TRNG_DATA = 5,
    DEBUG_OP_PROCESS_INFO = 6,
    DEBUG_OP_DUMP_COVERAGE = 7,
};

enum {
    // IOP -> AP
    XART_OP_ACK = 0,
    XART_OP_GET_XART = 0,
    XART_OP_SET_XART = 1,
    XART_OP_GET_LOCKER_RECORD = 5,
    XART_OP_ADD_LOCKER_RECORD = 6,
    XART_OP_DELETE_LOCKER_RECORD = 7,
    XART_OP_POWERED_UP = 14,
    // AP -> IOP
    // 2, 3, 4, (5, 6, 7, 8, 14)
    XART_OP_LYNX_AUTHENTICATE = 9,
    XART_OP_LYNX_GET_CPSN = 10,
    XART_OP_LYNX_GET_PUBLIC_KEY = 11,
    XART_OP_FLUSH_CACHED_XART = 12,
    XART_OP_SHUTDOWN = 13, // AppleSEPXART::xart_shtdwn_vol_unmount
    XART_OP_NONCE_GENERATE = 15,
    XART_OP_NONCE_READ = 16,
    XART_OP_NONCE_INVALIDATE = 17,
    XART_OP_COMMIT_HASH = 18,
};

#define KEYSTORE_MSG_TAG_REPLY 0x80
#define KEYSTORE_MSG_TAG_CODE_MASK 0x7F

typedef struct {
    uint8_t ep;
    uint8_t tag;
    uint8_t id;
    uint8_t _mbz0;
    uint16_t _mbz1;
    uint16_t size;
} KeystoreMessage;


#define KEYSTORE_IPC_HEADER_SIZE 0x54
#define KEYSTORE_IPC_VERSION_1 1

#define KEYSTORE_IPC_FLAG_ENCRYPTED BIT(0)
#define KEYSTORE_IPC_FLAG_EXTENDED BIT(1)

typedef struct {
    uint32_t header_body_size;
    uint8_t payload_hash[0x10];
    uint32_t ipc_version;
    uint64_t time_msecs;
    uint32_t flags;
    uint64_t id;
    uint64_t proc_uid;
    uint32_t audit_session_id;
    uint8_t ipc_digest[0x14];
    uint32_t unk0;
    uint32_t unk_mbz;
} QEMU_PACKED KeystoreIPCHeader;

G_STATIC_ASSERT(sizeof(KeystoreIPCHeader) == APPLE_SEP_SKS_WIRE_MAX);

enum {
    DISCOVERY_OP_EP_ADVERT = 0,
    DISCOVERY_OP_OOL_ADVERT = 1,
};

enum {
    BOOTSTRAP_OP_PING = 1,
    BOOTSTRAP_OP_GET_STATUS = 2,
    BOOTSTRAP_OP_GENERATE_NONCE = 3,
    BOOTSTRAP_OP_GET_NONCE_WORD = 4,
    // should rather be the original CHECK_TZ0, but tell that to Apple.
    BOOTSTRAP_OP_BOOT_TZ0 = 5,
    BOOTSTRAP_OP_BOOT_IMG4 = 6,
    BOOTSTRAP_OP_LOAD_SEP_ART = 7,
    BOOTSTRAP_OP_OPCODE_9 = 9,
    BOOTSTRAP_OP_NOTIFY_OS_ACTIVE_ASYNC = 13,
    BOOTSTRAP_OP_OPCODE_14 = 14,
    BOOTSTRAP_OP_SEND_DPA = 15,
    BOOTSTRAP_OP_OPCODE_16 = 16,
    BOOTSTRAP_OP_INTEGRITY_TREE_SIZE = 17,
    BOOTSTRAP_OP_NOTIFY_OS_ACTIVE = 21,
    // 30/31: iOS 26, AppleSEPBooter::_captureiBICKCV
    BOOTSTRAP_OP_OPCODE_30 = 30,
    BOOTSTRAP_OP_OPCODE_31 = 31,
    // 35: iOS 26, if sepfw has ar1s tag
    BOOTSTRAP_OP_OPCODE_35 = 35,
    BOOTSTRAP_OP_BOOT_TMM_MANIFEST = 36,
    BOOTSTRAP_OP_BOOT_PATCH = 37,

    BOOTSTRAP_OP_PING_ACK = 101,
    BOOTSTRAP_OP_STATUS_REPLY = 102,
    BOOTSTRAP_OP_NONCE_GENERATED = 103,
    BOOTSTRAP_OP_NONCE_WORD_REPLY = 104,
    BOOTSTRAP_OP_TZ0_ACCEPTED = 105,
    BOOTSTRAP_OP_IMG4_ACCEPTED = 106,
    BOOTSTRAP_OP_ART_ACCEPTED = 107,
    BOOTSTRAP_OP_RESUMED_FROM_RAM = 108,
    BOOTSTRAP_OP_OPCODE_9_RESPONSE = 109,
    BOOTSTRAP_OP_OPCODE_14_RESPONSE = 114,
    BOOTSTRAP_OP_DPA_SENT = 115,
    BOOTSTRAP_OP_OPCODE_16_RESPONSE = 116,
    BOOTSTRAP_OP_INTEGRITY_TREE_SIZE_RESPONSE = 117,
    BOOTSTRAP_OP_LOG_RAW = 201,
    BOOTSTRAP_OP_LOG_PRINTABLE = 202,
    BOOTSTRAP_OP_ANNOUNCE_STATUS = 210,
    BOOTSTRAP_OP_TIMEBASE_UPDATE = 254,
    BOOTSTRAP_OP_PANIC = 255,
};

static void apple_sep_sim_set_ool_in_size(AppleSEPSimState *s, uint8_t ep,
                                          uint32_t size)
{
    assert_cmpuint(ep, <, SEP_ENDPOINT_MAX);
    s->ool_state[ep].in_size = size;
}

static void apple_sep_sim_set_ool_in_addr(AppleSEPSimState *s, uint8_t ep,
                                          uint64_t addr)
{
    assert_cmpuint(ep, <, SEP_ENDPOINT_MAX);
    s->ool_state[ep].in_addr = addr;
}

static void apple_sep_sim_set_ool_out_size(AppleSEPSimState *s, uint8_t ep,
                                           uint32_t size)
{
    assert_cmpuint(ep, <, SEP_ENDPOINT_MAX);
    s->ool_state[ep].out_size = size;
}

static void apple_sep_sim_set_ool_out_addr(AppleSEPSimState *s, uint8_t ep,
                                           uint64_t addr)
{
    assert_cmpuint(ep, <, SEP_ENDPOINT_MAX);
    s->ool_state[ep].out_addr = addr;
}

static void apple_sep_sim_send_message(AppleSEPSimState *s, uint8_t ep,
                                       uint8_t tag, uint8_t op, uint8_t param,
                                       uint32_t data)
{
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *sent_msg;
    SEPMessage *sent_sep_msg;

    a7iop = APPLE_A7IOP(s);

    sent_msg = g_new0(AppleA7IOPMessage, 1);
    sent_sep_msg = (SEPMessage *)sent_msg->data;
    sent_sep_msg->ep = ep;
    sent_sep_msg->tag = tag;
    sent_sep_msg->op = op;
    sent_sep_msg->param = param;
    sent_sep_msg->data = data;
    apple_a7iop_send_ap(a7iop, sent_msg);
}

static void apple_sep_sim_message_reply(AppleSEPSimState *s, SEPMessage *msg,
                                        uint8_t op, uint8_t param,
                                        uint32_t data)
{
    apple_sep_sim_send_message(s, msg->ep, msg->tag, op, param, data);
}

static void apple_sep_sim_control_send_ack(AppleSEPSimState *s, SEPMessage *msg,
                                           uint8_t param, uint32_t data)
{
    apple_sep_sim_message_reply(s, msg, CONTROL_OP_ACK, param, data);
}

static void apple_sep_sim_handle_control_msg(AppleSEPSimState *s,
                                             SEPMessage *msg)
{
    SetOOLMessage *set_ool_msg;

    /* The setters' historical assertions disappear in production builds. */
    if (msg->op >= CONTROL_OP_SET_OOL_IN_ADDR &&
        msg->op <= CONTROL_OP_SET_OOL_OUT_SIZE &&
        ((SetOOLMessage *)msg)->id >= SEP_ENDPOINT_MAX) {
        s->diagnostic_ool_errors++;
        return;
    }

    switch (msg->op) {
    case CONTROL_OP_NOP:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: NOP\n");
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_SET_OOL_IN_ADDR:
        set_ool_msg = (SetOOLMessage *)msg;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: SET_OOL_IN_ADDR (%d, 0x%" PRIx64 ")\n",
                      set_ool_msg->id, (uint64_t)set_ool_msg->data << 12);
        apple_sep_sim_set_ool_in_addr(s, set_ool_msg->id,
                                      (uint64_t)set_ool_msg->data << 12);
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_SET_OOL_OUT_ADDR:
        set_ool_msg = (SetOOLMessage *)msg;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: SET_OOL_OUT_ADDR (%d, 0x%" PRIx64 ")\n",
                      set_ool_msg->id, (uint64_t)set_ool_msg->data << 12);
        apple_sep_sim_set_ool_out_addr(s, set_ool_msg->id,
                                       (uint64_t)set_ool_msg->data << 12);
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_SET_OOL_IN_SIZE:
        set_ool_msg = (SetOOLMessage *)msg;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: SET_OOL_IN_SIZE (%d, 0x%X)\n",
                      set_ool_msg->id, set_ool_msg->data);
        apple_sep_sim_set_ool_in_size(s, set_ool_msg->id, set_ool_msg->data);
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_SET_OOL_OUT_SIZE:
        set_ool_msg = (SetOOLMessage *)msg;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_CONTROL: SET_OOL_OUT_SIZE (%d, 0x%X)\n",
                      set_ool_msg->id, set_ool_msg->data);
        apple_sep_sim_set_ool_out_size(s, set_ool_msg->id, set_ool_msg->data);
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_GET_SECURITY_MODE:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: GET_SECURITY_MODE\n");
        apple_sep_sim_control_send_ack(s, msg, 0, 3);
        break;
    case CONTROL_OP_SELF_TEST:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: SELF_TEST\n");
        apple_sep_sim_control_send_ack(s, msg, 0, 0);
        break;
    case CONTROL_OP_ERASE_INSTALL: {
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: ERASE_INSTALL\n");
        apple_sep_sim_control_send_ack(s, msg, 0, 0);

        char error_desc[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
        asn1_node art_defs = NULL;
        asn1_node art = NULL;
        int art_rc;

        /*
         * These calls must NOT sit inside an assert. This tree builds with
         * -DNDEBUG and G_DISABLE_ASSERT, which removes the assert and the call
         * inside it, so the encode below never ran and the 512-byte buffer it
         * was supposed to fill was DMA'd to the guest uninitialised -- host
         * stack disclosure. Check the results explicitly instead.
         */
        art_rc = asn1_array2tree(art_definitions_array, &art_defs, error_desc);
        if (art_rc != ASN1_SUCCESS) {
            qemu_log_mask(LOG_UNIMP, "SEP sim: ART definitions failed to "
                          "load (%d); no ART reported\n", art_rc);
            break;
        }
        art_rc = asn1_create_element(art_defs, "ART.Header", &art);
        if (art_rc != ASN1_SUCCESS) {
            qemu_log_mask(LOG_UNIMP, "SEP sim: ART.Header element failed "
                          "(%d); no ART reported\n", art_rc);
            asn1_delete_structure(&art_defs);
            break;
        }
        uint8_t val = 0;
        asn1_write_value(art, "Version", &val, sizeof(val));
        uint16_t val16 = 0;
        asn1_write_value(art, "Info.Counter", &val16, sizeof(val16));
        char byte0x20[32] = { 0 };
        asn1_write_value(art, "Info.ManifestHash", byte0x20, 20);
        asn1_write_value(art, "Info.SleepHash", byte0x20, 20);
        asn1_write_value(art, "Info.Nonce", byte0x20, 0);
        asn1_write_value(art, "InfoHMAC", byte0x20, sizeof(byte0x20));
        char data[512] = { 0 };
        int data_len = sizeof(data);

        art_rc = asn1_der_coding(art, "", data, &data_len, error_desc);
        asn1_delete_structure(&art);
        asn1_delete_structure(&art_defs);
        if (art_rc != ASN1_SUCCESS) {
            qemu_log_mask(LOG_UNIMP, "SEP sim: ART DER encode failed (%d: %s); "
                          "nothing reported rather than sending an "
                          "unencoded buffer\n", art_rc, error_desc);
            break;
        }
        if (!apple_sep_sim_ool_write(s, s->ool_state[EP_ART_STORAGE].out_addr,
                                     data, data_len, "XART storage ART")) {
            break;
        }
        apple_sep_sim_send_message(s, EP_ART_STORAGE, 0,
                                   ART_STORAGE_OP_INCOMING, 0, 0);
        break;
    }
    default:
        apple_sep_sim_note_unsupported(s, msg->ep, msg->op);
        qemu_log_mask(LOG_GUEST_ERROR, "EP_CONTROL: Unknown opcode %d\n",
                      msg->op);
        break;
    }
}

static void apple_sep_sim_handle_arts_msg(AppleSEPSimState *s, SEPMessage *msg)
{
    switch (msg->op) {
    case ART_STORAGE_OP_RECEIVED:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_ART_STORAGE: ART_RECEIVED\n");
        break;
    default:
        apple_sep_sim_note_unsupported(s, msg->ep, msg->op);
        qemu_log_mask(LOG_GUEST_ERROR, "EP_ART_STORAGE: Unknown opcode %d\n",
                      msg->op);
        break;
    }
}

static void apple_sep_sim_xart_send_ack(AppleSEPSimState *s,
                                        SEPMessage *message, uint8_t param,
                                        uint32_t data)
{
    apple_sep_sim_message_reply(s, message, XART_OP_ACK, param, data);
}

static void apple_sep_sim_handle_xart_msg(AppleSEPSimState *s, bool slave,
                                          SEPMessage *message)
{
    const char *xart_name;

    xart_name = slave ? "SLAVE" : "MASTER";

    switch (message->op) {
    case XART_OP_FLUSH_CACHED_XART:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: FLUSH_CACHED_XART\n",
                      xart_name);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    case XART_OP_COMMIT_HASH:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: COMMIT_HASH\n", xart_name);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    case XART_OP_NONCE_GENERATE:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: NONCE_GENERATE\n",
                      xart_name);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    case XART_OP_NONCE_INVALIDATE:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: NONCE_INVALIDATE\n",
                      xart_name);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    case XART_OP_SHUTDOWN:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: SHUTDOWN\n", xart_name);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    default:
        apple_sep_sim_note_unsupported(s, message->ep, message->op);
        qemu_log_mask(LOG_GUEST_ERROR, "EP_XART_%s: Unknown opcode %d\n",
                      xart_name, message->op);
        apple_sep_sim_xart_send_ack(s, message, 0, 0);
        break;
    }
}

static void apple_sep_sim_handle_l4info(AppleSEPSimState *s, L4InfoMessage *msg)
{
    qemu_log_mask(LOG_GUEST_ERROR,
                  "EP_L4INFO: address 0x%" PRIx64 " size 0x%X\n",
                  (uint64_t)msg->address << 12, msg->size << 12);
    s->ool_state[EP_CONTROL].in_addr = (uint64_t)msg->address << 12;
    s->ool_state[EP_CONTROL].in_size = msg->size << 12;
    s->ool_state[EP_CONTROL].out_addr = (uint64_t)msg->address << 12;
    s->ool_state[EP_CONTROL].out_size = msg->size << 12;
}

static const uint8_t apple_sep_sim_eps[] = {
    EP_CONTROL,
    EP_LOGGER,
    EP_ART_STORAGE,
    EP_ART_REQUESTS,
    EP_SECURE_CREDENTIALS,
    EP_XART_SLAVE,
    EP_KEYSTORE,
    EP_XART_MASTER,
};
static const uint32_t apple_sep_sim_endpoint_names[] = {
    'cntl', 'log ', 'arts', 'artr', 'scrd', 'xars', 'sks ', 'xarm',
};

static void apple_sep_sim_advertise_eps(AppleSEPSimState *s)
{
    AppleA7IOP *a7iop;
    AppleA7IOPMessage *msg;
    EPAdvertisementMessage *ep_advert_msg;
    OOLAdvertisementMessage *ool_advert_msg;
    size_t i;

    a7iop = APPLE_A7IOP(s);

    for (i = 0; i < ARRAY_SIZE(apple_sep_sim_eps); i++) {
        msg = g_new0(AppleA7IOPMessage, 1);
        ep_advert_msg = (EPAdvertisementMessage *)msg->data;
        ep_advert_msg->ep = EP_DISCOVERY;
        ep_advert_msg->op = DISCOVERY_OP_EP_ADVERT;
        ep_advert_msg->id = apple_sep_sim_eps[i];
        ep_advert_msg->name = apple_sep_sim_endpoint_names[i];
        apple_a7iop_send_ap(a7iop, msg);

        msg = g_new0(AppleA7IOPMessage, 1);
        ool_advert_msg = (OOLAdvertisementMessage *)msg->data;
        ool_advert_msg->ep = EP_DISCOVERY;
        ool_advert_msg->op = DISCOVERY_OP_OOL_ADVERT;
        ool_advert_msg->id = apple_sep_sim_eps[i];
        memcpy(&ool_advert_msg->ool_info, s->ool_info + apple_sep_sim_eps[i],
               sizeof(AppleSEPSimOOLInfo));
        apple_a7iop_send_ap(a7iop, msg);
    }
}

static void apple_sep_sim_handle_bootstrap_msg(AppleSEPSimState *s,
                                               SEPMessage *msg)
{
    uint32_t randval = 0;
    switch (msg->op) {
    case BOOTSTRAP_OP_PING:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: PING\n");
        // needed for S8000 and T8015

        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_PING_ACK, 0, 0);
        break;
    case BOOTSTRAP_OP_GET_STATUS:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: GET_STATUS\n");

        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_STATUS_REPLY, 0, s->status);
        break;
    case BOOTSTRAP_OP_GENERATE_NONCE:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: GENERATE_NONCE\n");
        // 0xa0 is the returned length in bits

        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_NONCE_GENERATED, 0, 0xa0);
        break;
    case BOOTSTRAP_OP_GET_NONCE_WORD:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: GET_NONCE_WORD\n");
        // param is the index (not offset), and needs to be returned

        qemu_guest_getrandom(&randval, sizeof(randval), NULL);
        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_NONCE_WORD_REPLY, msg->param,
                                   randval);
        break;
    case BOOTSTRAP_OP_BOOT_TZ0:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: BOOT_TZ0\n");

        s->rsep = msg->param == 1;
        qemu_log_mask(LOG_GUEST_ERROR,
                      "EP_BOOTSTRAP: TrustZone 0 is totally OK, trust me. "
                      "Firmware type: %s\n",
                      s->rsep ? "rsep" : "sepi");
        s->status = SEP_STATUS_ACTIVE;

        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_TZ0_ACCEPTED, 0, 0);
        break;
    case BOOTSTRAP_OP_BOOT_IMG4: {
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: BOOT_IMG4\n");

        assert_true(s->rsep == (msg->param == 1));

        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_IMG4_ACCEPTED, 0, 0);
        apple_sep_sim_send_message(s, EP_CONTROL, 0, CONTROL_OP_NOTIFY_ALIVE, 0,
                                   0);

        apple_sep_sim_advertise_eps(s);
        break;
    }
    case BOOTSTRAP_OP_OPCODE_16:
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: OPCODE_16\n");
        // normally returns 0x20 random bytes, split in pieces by four bytes

        qemu_guest_getrandom(&randval, sizeof(randval), NULL);
        apple_sep_sim_send_message(s, EP_BOOTSTRAP, msg->tag,
                                   BOOTSTRAP_OP_OPCODE_16_RESPONSE, 0, randval);
        break;
    default:
        apple_sep_sim_note_unsupported(s, msg->ep, msg->op);
        qemu_log_mask(LOG_GUEST_ERROR, "EP_BOOTSTRAP: Unknown opcode %d\n",
                      msg->op);
        break;
    }
}

static uint8_t *apple_sep_sim_gen_sks_hash(uint8_t *buf, uint32_t msg_size,
                                         bool modern)
{
    AppleSEPSKSWire wire;

    if (!apple_sep_sks_wire_parse(buf, msg_size, modern, &wire)) {
        return NULL;
    }
    struct iovec iov[] = {
        {
            .iov_base = buf + wire.hash_offset,
            .iov_len = wire.hash_size,
        },
        {
            .iov_base = buf + wire.body_offset,
            .iov_len = wire.body_size,
        },
    };
    /* Not in an assert: -DNDEBUG would remove the call as well as the check. */
    if (!qcrypto_hash_supports(QCRYPTO_HASH_ALGO_SHA256)) {
        qemu_log_mask(LOG_UNIMP, "SEP sim: SHA-256 unavailable; SKS hashes "
                      "will not be generated\n");
        return NULL;
    }
    uint8_t *hash = NULL;
    size_t hash_len = 0;
    int ret =
        qcrypto_hash_bytesv(QCRYPTO_HASH_ALGO_SHA256, iov, ARRAY_SIZE(iov),
                            &hash, &hash_len, &error_fatal);
    if (ret != 0 || hash == NULL || hash_len != 32) {
        g_free(hash);
        return NULL;
    }
    return hash;
}

static void apple_sep_sim_keystore_send_ipc_resp(AppleSEPSimState *s,
                                                 const KeystoreMessage *msg,
                                                 uint8_t *resp_buf,
                                                 uint32_t resp_size)
{
    KeystoreIPCHeader *resp_hdr;
    uint8_t *resp_hash;

    resp_hdr = (KeystoreIPCHeader *)resp_buf;
    if (resp_size < sizeof(*resp_hdr) || resp_size > UINT16_MAX) {
        s->diagnostic_sks_rejected++;
        return;
    }
    /* Handlers use the maximum-size internal header. Only the wire v1
     * representation omits its final eight bytes on the modern wrapper. */
    if (s->sks_modern && resp_hdr->ipc_version == 1) {
        memmove(resp_buf + 76, resp_buf + sizeof(*resp_hdr),
                resp_size - sizeof(*resp_hdr));
        stl_le_p(resp_buf, 72);
        resp_size -= 8;
    }
    if (s->sks_modern &&
        (resp_size > s->ool_state[EP_KEYSTORE].out_size ||
         s->ool_state[EP_KEYSTORE].out_addr == 0)) {
        s->diagnostic_sks_rejected++;
        return;
    }
    resp_hash = apple_sep_sim_gen_sks_hash(resp_buf, resp_size, s->sks_modern);
    if (resp_hash == NULL) {
        /* Hashing is unavailable; an unhashed reply would fail validation. */
        return;
    }

    memcpy(resp_hdr->payload_hash, resp_hash, sizeof(resp_hdr->payload_hash));
    g_free(resp_hash);

    if (!apple_sep_sim_ool_write(s, s->ool_state[EP_KEYSTORE].out_addr, resp_buf,
                                 resp_size, "keystore reply")) {
        return;
    }

    apple_sep_sim_send_message(s, msg->ep, msg->tag | KEYSTORE_MSG_TAG_REPLY,
                               msg->id, 0, resp_size << 16);
}

static void apple_sep_sim_handle_keystore_msg(AppleSEPSimState *s,
                                              KeystoreMessage *msg)
{
    uint8_t msg_code = msg->tag & KEYSTORE_MSG_TAG_CODE_MASK;
    AppleSEPSKSWire wire;
    size_t body_min = 0;
    g_autofree uint8_t *wire_buf = NULL;

    if (msg->size < 24 || (s->sks_modern &&
        (msg->size > s->ool_state[EP_KEYSTORE].in_size ||
         s->ool_state[EP_KEYSTORE].in_addr == 0))) {
        s->diagnostic_sks_rejected++;
        return;
    }
    wire_buf = g_malloc0(msg->size);
    if (!apple_sep_sim_ool_read(s, s->ool_state[EP_KEYSTORE].in_addr, wire_buf,
                                msg->size, "keystore request")) {
        return;
    }
    if (!apple_sep_sks_wire_parse(wire_buf, msg->size, s->sks_modern, &wire)) {
        s->diagnostic_sks_rejected++;
        return;
    }
    if (s->sks_modern) {
        g_autofree uint8_t *hash = apple_sep_sim_gen_sks_hash(wire_buf, msg->size,
                                                           true);
        if (!hash || memcmp(wire_buf + 4, hash, 16) ||
            (wire.flags & KEYSTORE_IPC_FLAG_ENCRYPTED)) {
            s->diagnostic_sks_rejected++;
            return;
        }
    }
    /* Bound every body field consumed by the legacy compatibility handlers.
     * Framing these handlers correctly does not implement their key service. */
    switch (msg_code) {
    case 0x02: body_min = 16; break;
    case 0x04: body_min = 16; break;
    case 0x19: body_min = 20; break;
    case 0x1b: body_min = 4; break;
    }
    if (wire.body_size < body_min) {
        s->diagnostic_sks_rejected++;
        return;
    }
    if (s->sks_modern && msg_code != 0x1b) {
        /* The legacy handlers below contain placeholder keybags and state.
         * Correct framing must not turn those into apparent modern SKS
         * service success. Only the neutral client-terminate compatibility
         * reply is supported until the actual service contracts are modelled. */
        apple_sep_sim_note_unsupported(s, msg->ep, msg_code);
        qemu_log_mask(LOG_UNIMP, "SEP sim: modern SKS operation 0x%02x "
                      "is not implemented; no reply\n", msg_code);
        return;
    }
    uint8_t *msg_buf = g_malloc0(sizeof(KeystoreIPCHeader) + wire.body_size);
    memcpy(msg_buf, wire_buf, wire.body_offset);
    memcpy(msg_buf + sizeof(KeystoreIPCHeader), wire_buf + wire.body_offset,
           wire.body_size);
    const KeystoreIPCHeader *msg_hdr = (KeystoreIPCHeader *)msg_buf;
#if 0
    char fn[128];
    snprintf(fn, sizeof(fn), "/home/ios/SKSMessages/0x%02X_%lld.bin", msg_code,
             msg_hdr->time_msecs);
    g_file_set_contents(fn, (gchar *)msg_buf, msg->size, NULL);
#endif

    switch (msg_code) {
    case 0x01: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Create Keybag\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4 + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 1;
        uint32_t *kb_id = selector + 1;
        *kb_id = 'BAG1';

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x02: {
        uint32_t *word0 = (uint32_t *)(msg_hdr + 1);
        uint64_t *lword = (uint64_t *)(word0 + 1);
        uint32_t *word1 = (uint32_t *)(lword + 1);
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SEP KeyStore // Copy Keybag 0x%X 0x%" PRIx64 " 0x%X\n",
                      *word0, *lword, *word1);

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4 + 0x4 + 0x10;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;
        uint32_t *payload_blob = selector + 1;
        *payload_blob = 0x10;
        memset(payload_blob + 1, 0xAF, *payload_blob);

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x03: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Load Keybag\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4 + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;
        uint32_t *kb_handle = selector + 1;
        *kb_handle = 'BAG1';

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x04: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Change Lock State\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4 + 0x4 + 0x8;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        // Mostly guessing
        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;
        uint32_t *lock_state = selector + 1;
        *lock_state = *(uint32_t *)(msg_buf + 0x60);
        *lock_state |= (1 << 22);
        uint64_t *device_state = (uint64_t *)(lock_state + 1);
        *device_state = 0x1 | 0x2;
        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x05: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Unload Keybag\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x08: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // KC Wrap\n");

        // const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        // uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        // KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        // resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        // resp_hdr->ipc_version = KEYSTORE_IPC_VERSION_1;
        // resp_hdr->time_msecs = msg_hdr->time_msecs;
        // resp_hdr->id = msg_hdr->id;
        // resp_hdr->proc_uid = msg_hdr->proc_uid;
        // resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        // memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
        //        sizeof(resp_hdr->ipc_digest));

        // uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        // *selector = 0;

        // apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        // g_free(resp_buf);
        apple_sep_sim_send_message(
            s, msg->ep, msg->tag | KEYSTORE_MSG_TAG_REPLY, msg->id, 0, 0);
        break;
    }
    case 0x0A: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Null D Key\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        // Uh... who?
        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x0C: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Unwrap D Key\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        // Guessing...
        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x0D: {
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Make System Keybag\n");

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        // Guessing.
        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x19: {
        uint32_t *word0 = (uint32_t *)(msg_hdr + 1);
        uint64_t *lword = (uint64_t *)(word0 + 1);
        uint32_t *word1 = (uint32_t *)(lword + 1);
        uint32_t *word2 = (uint32_t *)(word1 + 1);
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SEP KeyStore // Get Device State 0x%X 0x%" PRIx64
                      " 0x%X 0x%X\n",
                      *word0, *lword, *word1, *word2);

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4 + 0x4 + 0x8;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        // Again, guessing.
        uint32_t *selector = (uint32_t *)(resp_hdr + 1);
        *selector = 0;
        // FIXME: This is a DER! See `_decode_extended_state`.
        uint32_t *state_blob = selector + 1;
        *state_blob = 0x8;
        memcpy(state_blob + 1, "applehax", *state_blob);

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    case 0x1B: {
        const uint32_t *selector = (uint32_t *)(msg_hdr + 1);
        qemu_log_mask(LOG_GUEST_ERROR,
                      "SEP KeyStore // Client Terminate (0x%X)\n", *selector);

        const uint32_t resp_size = KEYSTORE_IPC_HEADER_SIZE + 0x4;
        uint8_t *resp_buf = g_new0(uint8_t, resp_size);

        KeystoreIPCHeader *resp_hdr = (KeystoreIPCHeader *)resp_buf;
        resp_hdr->header_body_size = KEYSTORE_IPC_HEADER_SIZE - 0x4;
        resp_hdr->ipc_version = s->sks_modern ? msg_hdr->ipc_version :
                                KEYSTORE_IPC_VERSION_1;
        resp_hdr->time_msecs = msg_hdr->time_msecs;
        resp_hdr->id = msg_hdr->id;
        resp_hdr->proc_uid = msg_hdr->proc_uid;
        resp_hdr->audit_session_id = msg_hdr->audit_session_id;
        memcpy(resp_hdr->ipc_digest, msg_hdr->ipc_digest,
               sizeof(resp_hdr->ipc_digest));

        uint32_t *resp_selector = (uint32_t *)(resp_hdr + 1);
        *resp_selector = 0;

        apple_sep_sim_keystore_send_ipc_resp(s, msg, resp_buf, resp_size);
        g_free(resp_buf);
        break;
    }
    default: {
        apple_sep_sim_note_unsupported(s, msg->ep, msg_code);
        qemu_log_mask(LOG_GUEST_ERROR, "SEP KeyStore // Unknown (0x%02X)\n",
                      msg_code);

        if (!apple_sep_sim_ool_write(s, s->ool_state[EP_KEYSTORE].out_addr,
                                     wire_buf, msg->size,
                                     "keystore unknown-opcode echo")) {
            break;
        }
        apple_sep_sim_send_message(s, msg->ep,
                                   msg->tag | KEYSTORE_MSG_TAG_REPLY, msg->id,
                                   0, (uint32_t)msg->size << 16);
        break;
    }
    }
    g_free(msg_buf);
}

static void apple_sep_sim_handle_messages(void *opaque)
{
    AppleSEPSimState *s = opaque;
    AppleA7IOP *a7iop = opaque;
    AppleA7IOPMessage *msg;
    SEPMessage *sep_msg;

    QEMU_LOCK_GUARD(&s->lock);

    while (!apple_a7iop_mailbox_is_empty(a7iop->iop_mailbox)) {
        msg = apple_a7iop_recv_iop(a7iop);
        /* A disabled direction can leave a queued frame unavailable. */
        if (msg == NULL) {
            break;
        }
        sep_msg = (SEPMessage *)msg->data;
        s->diagnostic_dispatches++;
        s->diagnostic_last_ep = sep_msg->ep;
        s->diagnostic_last_op = sep_msg->op;

        switch (sep_msg->ep) {
        case EP_CONTROL:
            apple_sep_sim_handle_control_msg(s, sep_msg);
            break;
        case EP_ART_STORAGE:
            apple_sep_sim_handle_arts_msg(s, sep_msg);
            break;
        case EP_ART_REQUESTS:
            apple_sep_sim_note_unsupported(s, sep_msg->ep, sep_msg->op);
            qemu_log_mask(LOG_GUEST_ERROR,
                          "EP_ART_REQUESTS: Unknown opcode %d\n", sep_msg->op);
            break;
        case EP_SECURE_CREDENTIALS:
            apple_sep_sim_note_unsupported(s, sep_msg->ep, sep_msg->op);
            qemu_log_mask(LOG_GUEST_ERROR,
                          "EP_SECURE_CREDENTIALS: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_XART_SLAVE:
            apple_sep_sim_handle_xart_msg(s, true, sep_msg);
            break;
        case EP_KEYSTORE:
            apple_sep_sim_handle_keystore_msg(s, (KeystoreMessage *)sep_msg);
            break;
        case EP_XART_MASTER:
            apple_sep_sim_handle_xart_msg(s, false, sep_msg);
            break;
        case EP_DISCOVERY:
            apple_sep_sim_note_unsupported(s, sep_msg->ep, sep_msg->op);
            qemu_log_mask(LOG_GUEST_ERROR, "EP_DISCOVERY: Unknown opcode %d\n",
                          sep_msg->op);
            break;
        case EP_L4INFO:
            apple_sep_sim_handle_l4info(s, (L4InfoMessage *)sep_msg);
            break;
        case EP_BOOTSTRAP:
            apple_sep_sim_handle_bootstrap_msg(s, sep_msg);
            break;
        default:
            apple_sep_sim_note_unsupported(s, sep_msg->ep, sep_msg->op);
            qemu_log_mask(LOG_GUEST_ERROR, "UNKNOWN_%d_OP_%d\n", sep_msg->ep,
                          sep_msg->op);
            break;
        }

        g_free(msg);
    }
}

/*
 * Create the simulator from plain values, with no device tree involved.
 *
 * Boards that build an AppleDTNode tree use apple_sep_sim_from_node() below.
 * apple-modern does not: it reads the ADT blob through its own bounded
 * accessor and never materialises nodes, so it needs the geometry, the wrapper
 * version and the out-of-line address space passed directly.
 *
 * version selects the mailbox register layout and must match the node's
 * compatible string: ascwrap-v2 -> V2, -v4 -> V4, -v6 -> V6. Passing the wrong
 * one installs a device at offsets the guest driver will not use, which looks
 * exactly like a dead device.
 *
 * dma_as is the address space for out-of-line payloads, or NULL when the board
 * has none; see the OOL helpers above for what NULL costs.
 */
AppleSEPSimState *apple_sep_sim_new(const char *role, uint64_t mmio_size,
                                    AppleA7IOPVersion version,
                                    AddressSpace *dma_as)
{
    DeviceState *dev;
    AppleSEPSimState *s;

    dev = qdev_new(TYPE_APPLE_SEP_SIM);
    s = APPLE_SEP_SIM(dev);
    apple_a7iop_init(APPLE_A7IOP(dev), role, mmio_size, version, NULL,
                     apple_sep_sim_handle_messages);
    qemu_mutex_init(&s->lock);
    s->dma_as = dma_as;
    s->sks_modern = version == APPLE_A7IOP_V6;
    /* Diagnostics contain counts and routing bytes only, never payloads. */
    AppleA7IOP *a7iop = APPLE_A7IOP(s);
    Object *obj = OBJECT(s);
    object_property_add_uint64_ptr(obj, "transport-ap-send-count",
                                   &a7iop->iop_mailbox->diagnostic_enqueues,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "transport-ap-recv-count",
                                   &a7iop->ap_mailbox->diagnostic_dequeues,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "sim-reply-count",
                                   &a7iop->ap_mailbox->diagnostic_enqueues,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "sim-dispatch-count",
                                   &s->diagnostic_dispatches,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "sim-unsupported-count",
                                   &s->diagnostic_unsupported,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "sim-ool-error-count",
                                   &s->diagnostic_ool_errors,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "sim-sks-rejected-count",
                                   &s->diagnostic_sks_rejected,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "wrapper-mmio-read-count",
                                   &a7iop->diagnostic_mmio_reads,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "wrapper-mmio-write-count",
                                   &a7iop->diagnostic_mmio_writes,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "ap-mmio-read-count",
                                   &a7iop->ap_mailbox->diagnostic_mmio_reads,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(obj, "ap-mmio-write-count",
                                   &a7iop->ap_mailbox->diagnostic_mmio_writes,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "sim-last-endpoint",
                                   &s->diagnostic_last_ep, OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "sim-last-opcode",
                                   &s->diagnostic_last_op, OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "sim-last-unsupported-endpoint",
                                   &s->diagnostic_last_unsupported_ep,
                                   OBJ_PROP_FLAG_READ);
    object_property_add_uint32_ptr(obj, "sim-last-unsupported-opcode",
                                   &s->diagnostic_last_unsupported_op,
                                   OBJ_PROP_FLAG_READ);
    return s;
}

AppleSEPSimState *apple_sep_sim_from_node(AppleDTNode *node, bool modern)
{
    AppleSEPSimState *s;
    AppleDTProp *prop;
    AppleDTNode *child;
    uint64_t *reg;

    /*
     * Checked, not asserted: this tree builds with -DNDEBUG, so an
     * assert_nonnull() here disappears and the reg[1] below would dereference
     * NULL on a tree without the property.
     */
    prop = apple_dt_get_prop(node, "reg");
    if (prop == NULL || prop->len < 2 * sizeof(uint64_t)) {
        error_report("SEP sim: node has no usable reg property");
        return NULL;
    }
    reg = (uint64_t *)prop->data;

    /*
     * The historical boolean. It predates V6 and still means "V4 rather than
     * V2", which is correct for t8030 and s8000, the only callers. A v6
     * wrapper must use apple_sep_sim_new() and name its version.
     */
    s = apple_sep_sim_new("SEP", reg[1],
                          modern ? APPLE_A7IOP_V4 : APPLE_A7IOP_V2, NULL);

    child = apple_dt_get_node(node, "iop-sep-nub");
    if (child == NULL) {
        error_report("SEP sim: node has no iop-sep-nub child");
        return NULL;
    }
    apple_dt_del_node_named(child, "Lynx");
    return s;
}

static void apple_sep_sim_realize(DeviceState *dev, Error **errp)
{
    AppleSEPSimState *s;
    AppleSEPSimClass *sc;

    s = APPLE_SEP_SIM(dev);
    sc = APPLE_SEP_SIM_GET_CLASS(dev);

    if (sc->parent_realize) {
        sc->parent_realize(dev, errp);
    }
}

static void apple_sep_sim_reset_hold(Object *obj, ResetType type)
{
    AppleSEPSimState *s;
    AppleSEPSimClass *sc;
    AppleA7IOP *a7iop;
    size_t i;
    AppleA7IOPMessage *msg;
    SEPMessage *sep_msg;

    s = APPLE_SEP_SIM(obj);
    sc = APPLE_SEP_SIM_GET_CLASS(obj);
    a7iop = APPLE_A7IOP(obj);

    if (sc->parent_phases.hold != NULL) {
        sc->parent_phases.hold(obj, type);
    }

    QEMU_LOCK_GUARD(&s->lock);

    s->diagnostic_dispatches = 0;
    s->diagnostic_unsupported = 0;
    s->diagnostic_ool_errors = 0;
    s->diagnostic_sks_rejected = 0;
    memset(s->ool_state, 0, sizeof(s->ool_state));
    s->diagnostic_last_ep = 0;
    s->diagnostic_last_op = 0;
    s->diagnostic_last_unsupported_ep = 0;
    s->diagnostic_last_unsupported_op = 0;

    a7iop->iop_mailbox->ap_dir_en = true;
    a7iop->iop_mailbox->iop_dir_en = true;
    a7iop->ap_mailbox->iop_dir_en = true;
    a7iop->ap_mailbox->ap_dir_en = true;

    for (i = 0; i < ARRAY_SIZE(apple_sep_sim_eps); i++) {
        switch (apple_sep_sim_eps[i]) {
        case EP_LOGGER:
            s->ool_info[apple_sep_sim_eps[i]].in_max_pages = 0;
            s->ool_info[apple_sep_sim_eps[i]].in_min_pages = 0;
            s->ool_info[apple_sep_sim_eps[i]].out_max_pages = 1;
            s->ool_info[apple_sep_sim_eps[i]].out_min_pages = 1;
            break;
        case EP_ART_STORAGE:
        case EP_ART_REQUESTS:
        case EP_DEBUG:
        case EP_UNIT_TESTING:
            s->ool_info[apple_sep_sim_eps[i]].in_max_pages = 1;
            s->ool_info[apple_sep_sim_eps[i]].in_min_pages = 1;
            s->ool_info[apple_sep_sim_eps[i]].out_max_pages = 1;
            s->ool_info[apple_sep_sim_eps[i]].out_min_pages = 1;
            break;
        case EP_HILO:
            s->ool_info[apple_sep_sim_eps[i]].in_max_pages = 0;
            s->ool_info[apple_sep_sim_eps[i]].in_min_pages = 0;
            s->ool_info[apple_sep_sim_eps[i]].out_max_pages = 0;
            s->ool_info[apple_sep_sim_eps[i]].out_min_pages = 0;
            break;
        default:
            s->ool_info[apple_sep_sim_eps[i]].in_max_pages = 2;
            s->ool_info[apple_sep_sim_eps[i]].in_min_pages = 2;
            s->ool_info[apple_sep_sim_eps[i]].out_max_pages = 2;
            s->ool_info[apple_sep_sim_eps[i]].out_min_pages = 2;
            break;
        }
    }

    s->status = SEP_STATUS_BOOTSTRAP;

    msg = g_new0(AppleA7IOPMessage, 1);
    sep_msg = (SEPMessage *)msg->data;
    sep_msg->ep = EP_BOOTSTRAP;
    sep_msg->op = BOOTSTRAP_OP_ANNOUNCE_STATUS;
    sep_msg->data = s->status;
    apple_a7iop_send_ap(a7iop, msg);
}

static void apple_sep_sim_class_init(ObjectClass *klass, const void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);
    AppleSEPSimClass *sc = APPLE_SEP_SIM_CLASS(klass);

    resettable_class_set_parent_phases(rc, NULL, apple_sep_sim_reset_hold, NULL,
                                       &sc->parent_phases);

    device_class_set_parent_realize(dc, apple_sep_sim_realize,
                                    &sc->parent_realize);
    dc->desc = "Simulated Apple Secure Enclave Processor";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_sep_sim_info = {
    .name = TYPE_APPLE_SEP_SIM,
    .parent = TYPE_APPLE_A7IOP,
    .instance_size = sizeof(AppleSEPSimState),
    .class_size = sizeof(AppleSEPSimClass),
    .class_init = apple_sep_sim_class_init,
};

static void apple_sep_sim_register_types(void)
{
    type_register_static(&apple_sep_sim_info);
}

type_init(apple_sep_sim_register_types);
