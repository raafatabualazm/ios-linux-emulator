#!/usr/bin/env python3
"""Exercise actual MT input, scheduling, encoding, drain and reset under sanitizers.

The C fixture models QEMU's newest-first one-shot BH list and uses real GLib
queues; it stubs locking/IRQ/timer/CRC plumbing. It calls production scheduling,
mouse input and QEMU axis scaling. Packet fields are checked independently
against coordinates at event creation, including sensor edges and calibration.
This is a device component check, not a guest GUI acceptance test.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name):
    match = re.search(r"^(?:static|int)\b[^\n{;]*\b" + name + r"\([^;{]*?\)\n\{", text, re.M)
    if match is None:
        raise RuntimeError(f"Missing function {name}")
    # These functions have balanced braces, including their comments.
    depth = 1
    end = match.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'hw/arm/apple-silicon/mt-spi.c')
    args = parser.parse_args()
    source = args.source.read_text()
    input_source = (Path(__file__).resolve().parents[1] / 'ui/input.c').read_text()
    touch_type = re.search(r'typedef struct \{[^}]+\} AppleMTSPITouchUpdate;', source).group()
    names = ('apple_mt_spi_buf_push_byte', 'apple_mt_spi_buf_push_word',
             'apple_mt_spi_buf_push_dword', 'apple_mt_spi_buf_push_crc16',
             'apple_mt_spi_push_hid_hdr', 'apple_mt_spi_push_report_hdr',
             'apple_mt_spi_send_path_update')
    code = r'''
#include <assert.h>
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SCALE_MS 1000000
#define NANOSECONDS_PER_SECOND 1000000000
#define QEMU_CLOCK_VIRTUAL 0
#define INPUT_EVENT_ABS_MIN 0
#define INPUT_EVENT_ABS_MAX 0x7fff
#define MT_SENSOR_SURFACE_WIDTH 6458
#define MT_SENSOR_SURFACE_HEIGHT 13977
#define MOUSE_EVENT_LBUTTON 1
#define PATH_STAGE_MAKE_TOUCH 3
#define PATH_STAGE_TOUCHING 4
#define PATH_STAGE_BREAK_TOUCH 5
#define PATH_STAGE_OUT_OF_RANGE 7
#define HID_TRANSFER_PACKET_OUTPUT 0x20
#define HID_REPORT_BINARY_PATH_OR_IMAGE 0x44
#define HID_PACKET_STATUS_SUCCESS 0
#define LL_PACKET_LOSSLESS_OUTPUT 0x10
#define QEMU_LOCK_GUARD(lock) ((void)(lock))
#define trace_apple_mt_spi_report(...) ((void)0)
#define trace_apple_mt_spi_input(...) ((void)0)
typedef struct { uint8_t *data; uint32_t capacity, len, read_pos; } AppleMTSPIBuffer;
typedef struct AppleMTSPILLPacket { AppleMTSPIBuffer buf; uint8_t type; struct AppleMTSPILLPacket *next; } AppleMTSPILLPacket;
typedef struct { AppleMTSPILLPacket *first; } FWQueue;
typedef struct { int lock, irq, *timer, *end_timer; FWQueue pending_fw; AppleMTSPIBuffer tx,rx,pending_hbpp; uint8_t frame; int16_t x,y,prev_x,prev_y; int32_t btn_state,prev_btn_state; uint64_t prev_ts,touch_generation; GQueue touch_updates; bool touch_bh_pending; uint32_t display_width,display_height; } AppleMTSPIState;
typedef AppleMTSPIState Object;
typedef int ResetType;
#define APPLE_MT_SPI(obj) (obj)
static AppleMTSPILLPacket *packets[16];
static size_t packet_count;
#define QTAILQ_INSERT_TAIL(head,packet,field) do { assert(packet_count < 16); if(packet_count) packets[packet_count-1]->next=(packet); else (head)->first=(packet); packets[packet_count++]=(packet); } while (0)
#define QTAILQ_FOREACH_SAFE(packet,head,field,next_packet) for ((packet)=(head)->first; (packet) && ((next_packet)=(packet)->next,1); (packet)=(next_packet))
#define QTAILQ_REMOVE(head,packet,field) do { assert((head)->first==(packet)); (head)->first=(packet)->next; --packet_count; } while (0)
static void qemu_irq_lower(int irq) { (void)irq; }
typedef void (*BHCallback)(void *);
typedef struct PendingBH { BHCallback callback; void *opaque; struct PendingBH *next; } PendingBH;
static PendingBH *pending_bh;
static size_t pending_bh_count;
static void *qemu_get_aio_context(void) { return NULL; }
static void aio_bh_schedule_oneshot(void *ctx, BHCallback callback, void *opaque) {
    (void)ctx;
    PendingBH *bh=malloc(sizeof(*bh)); assert(bh);
    /* util/async.c inserts at HEAD and aio_bh_poll removes HEAD. */
    *bh=(PendingBH){callback,opaque,pending_bh}; pending_bh=bh;
    ++pending_bh_count;
}
static void poll_bhs(void) {
    while(pending_bh) {
        PendingBH *bh=pending_bh; pending_bh=bh->next; --pending_bh_count;
        bh->callback(bh->opaque); free(bh);
    }
}
static int callback_order[2];
static size_t callback_count;
static void probe_callback(void *opaque) { assert(callback_count<2); callback_order[callback_count++]=*(int *)opaque; }
static uint64_t virtual_time;
static uint64_t qemu_clock_get_ns(int clock) { (void)clock; return virtual_time; }
static void timer_del(int *timer) { (void)timer; }
static void timer_mod(int *timer, int64_t expiry) { (void)timer; (void)expiry; }
static void apple_mt_spi_buf_free(AppleMTSPIBuffer *buf) { free(buf->data); memset(buf,0,sizeof(*buf)); }
static void apple_mt_spi_buf_ensure_capacity(AppleMTSPIBuffer *buf, size_t count) {
    size_t required=buf->len+count;
    if (required > buf->capacity) { buf->capacity=required*2; buf->data=realloc(buf->data,buf->capacity); assert(buf->data); }
}
static int apple_mt_spi_buf_is_empty(const AppleMTSPIBuffer *buf) { return buf->len==0; }
#define assert_false(x) assert(!(x))
static void stw_le_p(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void stl_le_p(uint8_t *p, uint32_t v) { for (int i=0;i<4;i++) p[i]=v>>(8*i); }
static uint16_t crc16(uint16_t seed, const uint8_t *p, size_t len) { while(len--) seed+=*p++; return seed; }
'''
    code += function(input_source, 'qemu_input_scale_axis') + '\n'
    code += '\n'.join(function(source, name) for name in names)
    code += '\n' + touch_type + '\n'
    code += '\n'.join(function(source, name) for name in
                      ('apple_mt_spi_new_touch_update', 'apple_mt_spi_send_touch_update_bh',
                       'apple_mt_spi_schedule_touch_update', 'apple_mt_spi_timer_tick',
                       'apple_mt_spi_end_timer_tick', 'apple_mt_spi_mouse_event',
                       'apple_mt_spi_reset_enter'))
    code += r'''
static int check_packet(size_t index, uint8_t stage, int x, int y, uint32_t timestamp_ms) {
    const AppleMTSPIBuffer *buf=&packets[index]->buf;
    assert(buf->len==58);
    const uint8_t *path=buf->data+9+27;
    int actual_x=path[4]+256*path[5], actual_y=path[6]+256*path[7];
    const uint8_t *time=buf->data+9+3;
    uint32_t actual_time=time[0]+((uint32_t)time[1]<<8)+((uint32_t)time[2]<<16)+((uint32_t)time[3]<<24);
    if(path[1]!=stage || actual_x!=x || actual_y!=y || actual_time!=timestamp_ms) {
        fprintf(stderr,"Deferred packet %zu: expected stage=%u x=%d y=%d ts=%u; got stage=%u x=%d y=%d ts=%u\n",index,stage,x,y,timestamp_ms,path[1],actual_x,actual_y,actual_time);
        return 1;
    }
    assert(path[0]==1 && path[2]==1 && path[3]==1);
    assert(buf->data[9]==index);
    return 0;
}
int main(void) {
    int first=1, second=2;
    aio_bh_schedule_oneshot(NULL,probe_callback,&first);
    aio_bh_schedule_oneshot(NULL,probe_callback,&second);
    poll_bhs();
    assert(callback_count==2 && callback_order[0]==2 && callback_order[1]==1);
    AppleMTSPIState state={0};
    g_queue_init(&state.touch_updates);
    state.x=1234; state.y=5678; virtual_time=100000000;
    apple_mt_spi_schedule_touch_update(&state,3);
    state.prev_x=state.x; state.prev_y=state.y;
    state.x=2234; state.y=6678; virtual_time=150000000;
    apple_mt_spi_schedule_touch_update(&state,4);
    state.prev_x=state.x; state.prev_y=state.y;
    state.x=3234; state.y=7678; virtual_time=200000000;
    apple_mt_spi_schedule_touch_update(&state,5);
    virtual_time=300000000;
    apple_mt_spi_schedule_touch_update(&state,7);
    /* A later host input arrives before any queued callback executes. */
    state.x=4234; state.y=8678;
    size_t scheduled=pending_bh_count;
    poll_bhs();
    assert(packet_count==4 && state.frame==4);
    int bad=check_packet(0,3,1234,5678,100) | check_packet(1,4,2234,6678,150)
            | check_packet(2,5,3234,7678,200) | check_packet(3,7,3234,7678,300);
    if(bad) { apple_mt_spi_reset_enter(&state,0); return 1; }
    assert(scheduled==1 && !state.touch_bh_pending && state.prev_ts==300000000);
    /* Reset clears stale updates, retaining the already scheduled drain BH. */
    virtual_time=350000000;
    apple_mt_spi_schedule_touch_update(&state,3);
    assert(pending_bh_count==1 && state.touch_bh_pending);
    apple_mt_spi_reset_enter(&state,0);
    assert(packet_count==0 && state.frame==0 && g_queue_is_empty(&state.touch_updates));
    assert(pending_bh_count==1 && state.touch_bh_pending);
    state.x=1111; state.y=2222; virtual_time=400000000;
    apple_mt_spi_schedule_touch_update(&state,3);
    assert(pending_bh_count==1);
    poll_bhs();
    assert(packet_count==1 && state.frame==1);
    bad |= check_packet(0,3,1111,2222,400);
    assert(!state.touch_bh_pending);
    apple_mt_spi_reset_enter(&state,0);
    assert(packet_count==0);
    /* A reset with no fresh input still permits the empty BH to finish. */
    virtual_time=450000000;
    apple_mt_spi_schedule_touch_update(&state,3);
    apple_mt_spi_reset_enter(&state,0);
    assert(pending_bh_count==1 && state.touch_bh_pending);
    poll_bhs();
    assert(packet_count==0 && !state.touch_bh_pending);
    /* A later stationary contact uses a newly scheduled drain, in order. */
    state.x=1111; state.y=2222; virtual_time=500000000;
    apple_mt_spi_schedule_touch_update(&state,3);
    virtual_time=600000000; apple_mt_spi_schedule_touch_update(&state,5);
    virtual_time=700000000; apple_mt_spi_schedule_touch_update(&state,7);
    assert(pending_bh_count==1);
    poll_bhs();
    assert(packet_count==3 && !state.touch_bh_pending);
    bad |= check_packet(0,3,1111,2222,500) | check_packet(1,5,1111,2222,600)
            | check_packet(2,7,1111,2222,700);
    apple_mt_spi_reset_enter(&state,0);
    assert(packet_count==0 && !pending_bh_count);
    if(bad) return 1;
    /* Fixed expectations include the calibrated bottom boundary, immediately
     * outside it, interior samples and both X endpoints. These are QEMU ABS
     * coordinates for the 828x1792 display, not a copied calibration formula. */
    static const struct { int dx,dy,x,y; } samples[] = {
        {0,32767,0,0}, {32767,32767,6458,0},
        {16383,32493,3228,0}, {16383,32474,3228,0},
        {16383,32200,3228,117}, {16383,31907,3228,242},
        {16383,30004,3228,1054}, {16383,16383,3228,6864},
        {0,0,0,13853}, {32767,0,6458,13853},
    };
    state.display_width=828; state.display_height=1792;
    for(size_t i=0;i<G_N_ELEMENTS(samples);i++) {
        uint32_t time_ms=1000+100*i;
        virtual_time=(uint64_t)time_ms*SCALE_MS;
        apple_mt_spi_mouse_event(&state,samples[i].dx,samples[i].dy,0,MOUSE_EVENT_LBUTTON);
        virtual_time+=10*SCALE_MS;
        apple_mt_spi_mouse_event(&state,samples[i].dx,samples[i].dy,0,0);
        /* Change live coordinates before draining: encoded edges must be the
         * captured contact coordinates, not the later top-center position. */
        apple_mt_spi_mouse_event(&state,16383,0,0,0);
        assert(pending_bh_count==1);
        poll_bhs();
        assert(packet_count==2);
        bad |= check_packet(0,3,samples[i].x,samples[i].y,time_ms)
                | check_packet(1,5,samples[i].x,samples[i].y,time_ms+10);
        apple_mt_spi_reset_enter(&state,0);
    }
    if(bad) return 1;
    /* Every valid ABS Y value stays within the surface advertised to the guest.
     * No button transition occurs, so this bounded sweep queues no reports. */
    for(int y=INPUT_EVENT_ABS_MIN;y<=INPUT_EVENT_ABS_MAX;y++) {
        apple_mt_spi_mouse_event(&state,16383,y,0,0);
        assert(state.y>=0 && state.y<=MT_SENSOR_SURFACE_HEIGHT);
        assert(state.x==3228 && !pending_bh_count && packet_count==0);
    }
    apple_mt_spi_reset_enter(&state,0);
    /* Exercise actual movement/end timers across the clamped edge. */
    virtual_time=3000ULL*SCALE_MS;
    apple_mt_spi_mouse_event(&state,16383,32767,0,MOUSE_EVENT_LBUTTON);
    virtual_time=3050ULL*SCALE_MS;
    apple_mt_spi_mouse_event(&state,16383,32200,0,MOUSE_EVENT_LBUTTON);
    apple_mt_spi_timer_tick(&state);
    virtual_time=3100ULL*SCALE_MS;
    apple_mt_spi_mouse_event(&state,16383,32200,0,0);
    virtual_time=3200ULL*SCALE_MS;
    apple_mt_spi_end_timer_tick(&state);
    apple_mt_spi_mouse_event(&state,16383,0,0,0);
    assert(pending_bh_count==1);
    poll_bhs();
    assert(packet_count==4);
    bad |= check_packet(0,3,3228,0,3000) | check_packet(1,4,3228,117,3050)
            | check_packet(2,5,3228,117,3100) | check_packet(3,7,3228,117,3200);
    apple_mt_spi_reset_enter(&state,0);
    assert(packet_count==0 && !pending_bh_count);
    if(bad) return 1;
    puts("PASS: production mouse input bounds all 32768 ABS Y values, preserves interior calibration and captured stage coordinates; FIFO/reset checks pass");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='mt-queue-') as tmp:
        test = Path(tmp) / 'test.c'
        test.write_text(code)
        binary = Path(tmp) / 'test'
        glib_flags = subprocess.run(['pkg-config', '--cflags', '--libs', 'glib-2.0'],
                                    check=True, capture_output=True, text=True).stdout.split()
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        '-g', str(test), '-o', str(binary), *glib_flags], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
