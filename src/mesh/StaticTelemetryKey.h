#pragma once

#include "Channels.h"
#include "CryptoEngine.h"
#include "MeshTypes.h"
#include "mesh-pb-constants.h"

/*
 * Fork customization: optionally encrypt Position/Telemetry payloads with a static,
 * pre-shared AES key before the normal channel-PSK layer, so that only holders of
 * that key can read the actual position/telemetry content - even though the packet
 * itself still travels as a normal broadcast on the public channel (so random
 * strangers' gateways still relay it to MQTT as usual; only the payload is opaque).
 *
 * The key is NOT a new config field - it's channel slot
 * MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX's PSK, reused purely as key storage.
 * This makes it settable from the *stock* Meshtastic app/CLI with zero
 * firmware-specific tooling, e.g.:
 *   meshtastic --ch-set psk base64:<your-key> --ch-index 7 --ch-add
 *   meshtastic --ch-set name "do-not-use" --ch-index 7
 * This channel is never used for actual message routing - only its PSK is read.
 *
 * Toggle: channel 7's role must be SECONDARY *and* it must have a non-empty PSK (see
 * staticTelemetryKeyConfigured()). Anything else (DISABLED, PRIMARY, or SECONDARY with
 * an empty PSK, which is the factory-default state) means "off" - Position/Telemetry
 * payloads are sent/received as plain, unmodified protobufs, identical to stock
 * firmware.
 *
 * Implementation note: Channels::getKey() (the only way to read a channel's raw,
 * expanded key bytes) is private - the rest of the firmware never extracts raw key
 * bytes either, it always goes through Channels::setActiveByIndex(), which loads the
 * requested channel's key into the global CryptoEngine, followed by
 * CryptoEngine::encryptPacket()/decrypt() (both public, and already what the normal
 * channel-PSK layer itself uses - same AES-CTR primitive, same
 * packet_id/from_node nonce scheme this integration's HA decoder already
 * implements). Calling setActiveByIndex() here is safe: every other place that
 * needs a specific channel's key already calls it again immediately before its own
 * crypto operation, so there's no code path relying on the "active" key surviving
 * between unrelated operations.
 */
#define MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX 7

/**
 * Returns true if a static telemetry key is configured (channel
 * MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX, role SECONDARY, non-empty PSK).
 * Returns false ("off") otherwise.
 */
inline bool staticTelemetryKeyConfigured()
{
    meshtastic_Channel &ch = channels.getByIndex(MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX);
    return ch.has_settings && ch.role == meshtastic_Channel_Role_SECONDARY && ch.settings.psk.size > 0;
}

/**
 * Encrypt p->decoded.payload in place with the static telemetry key, if one is
 * configured. No-op ("off") if it isn't. Call this after allocDataProtobuf() (so
 * p->id/p->from are already finalized) and before handing the packet to
 * service->sendToMesh().
 */
inline void encryptStaticTelemetryPayload(meshtastic_MeshPacket *p)
{
    if (!staticTelemetryKeyConfigured())
        return;

    channels.setActiveByIndex(MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX);
    crypto->encryptPacket(getFrom(p), p->id, p->decoded.payload.size, p->decoded.payload.bytes);
}

/**
 * Attempt to decrypt+decode a Position/Telemetry payload that failed to pb_decode as
 * plaintext, using the static telemetry key (AES-CTR is symmetric, so
 * CryptoEngine::decrypt() - the same call used for sending - also decrypts).
 * Returns false immediately ("off", or wrong portnum, or nothing configured) without
 * touching *scratch.
 *
 * This is what lets two modded nodes with the same channel-7 key transparently
 * exchange encrypted Position/Telemetry over LoRa directly (no MQTT/HA involved):
 * a successful decode here feeds straight into the module's normal
 * handleReceivedProtobuf() callback, so NodeDB and the app/CLI see it exactly like
 * any other telemetry update.
 */
inline bool tryDecodeStaticTelemetryEncrypted(const meshtastic_MeshPacket &mp, const pb_msgdesc_t *fields, void *scratch,
                                              size_t scratchSize)
{
    if (mp.decoded.portnum != meshtastic_PortNum_POSITION_APP && mp.decoded.portnum != meshtastic_PortNum_TELEMETRY_APP)
        return false;

    if (!staticTelemetryKeyConfigured())
        return false;

    size_t len = mp.decoded.payload.size;
    if (len == 0 || len > sizeof(mp.decoded.payload.bytes))
        return false;

    uint8_t buf[sizeof(mp.decoded.payload.bytes)];
    memcpy(buf, mp.decoded.payload.bytes, len);

    channels.setActiveByIndex(MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX);
    crypto->decrypt(getFrom(&mp), mp.id, len, buf);

    memset(scratch, 0, scratchSize);
    return pb_decode_from_bytes(buf, len, fields, scratch);
}
