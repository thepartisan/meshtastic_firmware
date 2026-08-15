#pragma once

#include "Channels.h"
#include "CryptoEngine.h"
#include "MeshTypes.h"
#include "mesh-pb-constants.h"
#include <cstring>

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
 * This channel is reserved for key storage only - it is never used for actual
 * message routing or transmission (see the exclusions in PositionModule.cpp,
 * Channels::anyMqttEnabled(), and MQTT::onSend()).
 *
 * Toggle: channel 7 must simply have a non-empty PSK (see
 * staticTelemetryKeyConfigured()) - role (Disabled/Primary/Secondary) is
 * deliberately ignored. Mobile apps generally don't expose an explicit role
 * picker (role is normally inferred from a channel's position/how it was
 * added), so requiring a specific role made this unreachable from some
 * clients. A bare PSK is the lowest common denominator every Meshtastic
 * client (app, CLI, or otherwise) can set.
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
 * Returns true if a static telemetry key is configured: channel
 * MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX simply has a non-empty PSK. Role is
 * intentionally ignored - see the file header comment. Returns false ("off")
 * otherwise (no settings, or an empty/unset PSK, which is the factory-default
 * state).
 */
inline bool staticTelemetryKeyConfigured()
{
    meshtastic_Channel &ch = channels.getByIndex(MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX);
    return ch.has_settings && ch.settings.psk.size > 0;
}

/**
 * Encrypt p->decoded.payload in place with the static telemetry key, if one is
 * configured and this is a Position or Telemetry packet. No-op otherwise. Called
 * centrally from MeshService::sendToMesh() - right before the packet is handed to
 * the router for local dispatch/actual transmission, and *after* any phone/CLI echo
 * copy has already been taken - so this fork-only encryption layer never corrupts
 * what the sending device's own app/CLI shows for a packet it just sent (stock apps
 * have no way to decrypt this layer themselves). Do not call this a second time on
 * the same packet - AES-CTR is not idempotent, a second pass would scramble the
 * already-ciphertext bytes into neither plaintext nor correctly single-encrypted
 * data.
 */
inline void encryptStaticTelemetryPayload(meshtastic_MeshPacket *p)
{
    if (p->which_payload_variant != meshtastic_MeshPacket_decoded_tag)
        return;
    if (p->decoded.portnum != meshtastic_PortNum_POSITION_APP && p->decoded.portnum != meshtastic_PortNum_TELEMETRY_APP)
        return;
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

/**
 * Returns true if re-encoding *decoded (as decoded by `fields`) reproduces `payload`
 * byte-for-byte. Used to tell whether a "successful" plaintext pb_decode() of a
 * Position/Telemetry payload was probably genuine, or ciphertext that merely
 * happened to look like valid protobuf wire format (see
 * ProtobufModule::decodeStaticTelemetryAware() in ProtobufModule.h).
 *
 * This check is meaningful in nanopb specifically because - unlike some protobuf
 * runtimes (e.g. the Python implementation used by this project's Home Assistant
 * integration, which had this same false-positive problem) - nanopb does not
 * preserve unrecognized field numbers; it simply discards them while decoding
 * (see nanopb's pb_decode(), which skips unknown fields rather than storing them
 * for later re-serialization). So random ciphertext that happens to contain a few
 * bytes forming a well-formed tag/wire-type/length sequence for an *unknown* field
 * number will decode "successfully" but then re-encode to something shorter or
 * different, since those bytes were never actually kept. Only a genuine, exact
 * encoding of *only* recognized fields with *exactly* the original field values can
 * survive this round trip unchanged.
 */
inline bool payloadRoundTripsPlausibly(const uint8_t *payload, size_t len, const pb_msgdesc_t *fields, const void *decoded)
{
    if (len == 0 || len > member_size(meshtastic_Data, payload.bytes))
        return false;

    uint8_t reencoded[member_size(meshtastic_Data, payload.bytes)];
    size_t reencodedLen = pb_encode_to_bytes(reencoded, sizeof(reencoded), fields, decoded);
    return reencodedLen == len && memcmp(reencoded, payload, len) == 0;
}
