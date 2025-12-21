/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <windows.h>
#include <ipexport.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A handle representing a Wintun adapter
 */
typedef void *WINTUN_ADAPTER_HANDLE;

/**
 * A handle representing a Wintun session
 */
typedef void *WINTUN_SESSION_HANDLE;

/**
 * Creates a new Wintun adapter.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 * @param TunnelType    Name of the adapter tunnel type. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
 *                      created for each new adapter.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with WintunCloseAdapter. If
 *         the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)
    (_In_z_ const WCHAR *Name, _In_z_ const WCHAR *TunnelType, _In_opt_ const GUID *RequestedGUID);

/**
 * Opens an existing Wintun adapter.
 *
 * @param Name  The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with WintunCloseAdapter. If
 *         the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
typedef WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(_In_z_ const WCHAR *Name);

/**
 * Releases Wintun adapter resources and, if adapter was created with WintunCreateAdapter, removes adapter.
 *
 * @param Adapter  Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter.
 */
typedef BOOL(WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter);

/**
 * Starts a Wintun session.
 *
 * @param Adapter   Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter.
 * @param Capacity  Ring capacity. Must be between WINTUN_MIN_RING_CAPACITY and WINTUN_MAX_RING_CAPACITY (incl.)
 *                  Must be a power of two.
 *
 * @return Wintun session handle. Must be released with WintunEndSession. If the function fails, the return value is
 *         NULL. To get extended error information, call GetLastError.
 */
typedef WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ DWORD Capacity);

/**
 * Ends Wintun session.
 *
 * @param Session  Wintun session handle obtained with WintunStartSession.
 */
typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

/**
 * Retrieves one or more packets from the Wintun ring buffer.
 *
 * @param Session      Wintun session handle obtained with WintunStartSession.
 * @param PacketSize   Pointer to receive packet size.
 *
 * @return Pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at will. If the function fails, the
 *         return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following: ERROR_HANDLE_EOF Wintun adapter is terminating; ERROR_NO_MORE_ITEMS Wintun buffer is exhausted;
 *         ERROR_INVALID_DATA Wintun buffer is corrupt. After packet has been consumed, call WintunReleaseReceivePacket.
 */
typedef BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _Out_ DWORD *PacketSize);

/**
 * Releases internal buffer after packet has been consumed by client.
 *
 * @param Session  Wintun session handle obtained with WintunStartSession.
 * @param Packet   Packet obtained with WintunReceivePacket.
 */
typedef void(WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

/**
 * Allocates memory for a packet to send.
 *
 * @param Session     Wintun session handle obtained with WintunStartSession.
 * @param PacketSize  Exact packet size. Must be less or equal to WINTUN_MAX_IP_PACKET_SIZE.
 *
 * @return Returns pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending. If the function fails,
 *         the return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following: ERROR_HANDLE_EOF Wintun adapter is terminating; ERROR_BUFFER_OVERFLOW Wintun buffer is full; After
 *         client is done preparing packet, call WintunSendPacket.
 */
typedef BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ DWORD PacketSize);

/**
 * Sends packet and frees internal buffer.
 *
 * @param Session  Wintun session handle obtained with WintunStartSession.
 * @param Packet   Packet obtained with WintunAllocateSendPacket.
 */
typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

/**
 * Returns a handle to the adapter read event.
 *
 * @param Session  Wintun session handle obtained with WintunStartSession.
 *
 * @return Handle to the adapter read event. Should not be used after WintunEndSession is called.
 */
typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

#define WINTUN_MAX_IP_PACKET_SIZE 0xFFFF
#define WINTUN_MIN_RING_CAPACITY 0x20000
#define WINTUN_MAX_RING_CAPACITY 0x4000000

#ifdef __cplusplus
}
#endif
