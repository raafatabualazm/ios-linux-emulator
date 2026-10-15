/*
 * TCP Remote USB.
 *
 * Copyright (c) 2025-2026 Visual Ehrmanntraut (VisualEhrmanntraut).
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
#include "hw/qdev-properties.h" // do not reorder this
#include "hw/core/qdev-prop-internal.h"
#include "hw/usb/tcp-usb.h"
#include "monitor/monitor.h"
#include "qapi/error.h"
#include "qemu/sockets.h"

const QEnumLookup USBTCPRemoteConnType_lookup = {
    .array =
        (const char *const[]){
            [TCP_REMOTE_CONN_TYPE_UNIX] = "unix",
            [TCP_REMOTE_CONN_TYPE_IPV4] = "ipv4",
            [TCP_REMOTE_CONN_TYPE_IPV6] = "ipv6",
            [TCP_REMOTE_CONN_TYPE_FD] = "fd",
        },
    .size = TCP_REMOTE_CONN_TYPE__MAX,
};

const PropertyInfo qdev_usb_tcp_remote_conn_type = {
    .type = "USBTCPRemoteConnType",
    .description = "unix/ipv4/ipv6/fd (one connected UNIX stream descriptor)",
    .enum_table = &USBTCPRemoteConnType_lookup,
    .get = qdev_propinfo_get_enum,
    .set = qdev_propinfo_set_enum,
    .set_default_value = qdev_propinfo_set_default_value_enum,
};

int usb_tcp_take_connected_fd(const char *fdname, uint16_t port, Error **errp)
{
#ifdef CONFIG_POSIX
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    int type;
    socklen_t type_len = sizeof(type);
    int fd;

    if (port || !fdname || !*fdname) {
        error_setg(errp, "FD transport requires conn-addr and no conn-port");
        return -1;
    }
    fd = monitor_fd_param(monitor_cur(), fdname, errp);
    if (fd < 0) {
        return -1;
    }
    if (fd <= STDERR_FILENO) {
        error_setg(errp, "FD transport refuses standard input/output descriptors");
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) < 0) {
        error_setg_errno(errp, errno, "FD transport requires a socket");
        goto fail;
    }
    if (type != SOCK_STREAM) {
        error_setg(errp, "FD transport requires a SOCK_STREAM socket");
        goto fail;
    }
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) < 0) {
        error_setg_errno(errp, errno, "FD transport requires a connected socket");
        goto fail;
    }
    if (peer.ss_family != AF_UNIX) {
        error_setg(errp, "FD transport requires a connected UNIX socket");
        goto fail;
    }
    if (!qemu_set_blocking(fd, true, errp)) {
        goto fail;
    }
    return fd;

fail:
    close(fd);
    return -1;
#else
    error_setg(errp, "Inherited USB descriptors require POSIX");
    return -1;
#endif
}
