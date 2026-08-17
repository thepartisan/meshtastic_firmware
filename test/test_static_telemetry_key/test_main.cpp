// Unit tests for the static telemetry key feature (StaticTelemetryKey.h): the
// fork customization that lets Position/Telemetry payloads carry an extra,
// pre-shared-key AES-CTR encryption layer, keyed off channel 7's PSK.
#include "NodeDB.h"
#include "PositionPrecision.h"
#include "StaticTelemetryKey.h"
#include "TestUtil.h"
#include "mesh-pb-constants.h"
#include <unity.h>

static void resetChannel7()
{
    // Channels::getByIndex() returns the unrelated dummyChannel fallback unless
    // channels_count covers the requested index - the native test harness doesn't
    // run the normal boot sequence (Channels::initDefaults()) that sets this on a
    // real device, so it must be set explicitly here (see test_mqtt/MQTT.cpp for
    // the same requirement).
    channelFile.channels_count = MAX_NUM_CHANNELS;
    channelFile.channels[MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX] = meshtastic_Channel_init_zero;
}

static void setChannel7Psk(meshtastic_Channel_Role role, const uint8_t *psk, size_t pskLen)
{
    meshtastic_Channel &ch = channelFile.channels[MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX];
    ch = meshtastic_Channel_init_zero;
    ch.has_settings = true;
    ch.role = role;
    if (pskLen > 0) {
        memcpy(ch.settings.psk.bytes, psk, pskLen);
        ch.settings.psk.size = pskLen;
    }
}

static const uint8_t kTestKey[32] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                     0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                     0x11, 0x11};

static meshtastic_Position makeTestPosition()
{
    meshtastic_Position pos = meshtastic_Position_init_default;
    pos.has_latitude_i = true;
    pos.latitude_i = 407128000;
    pos.has_longitude_i = true;
    pos.longitude_i = -740060000;
    pos.has_altitude = true;
    pos.altitude = 42;
    pos.time = 1700000000;
    pos.sats_in_view = 7;
    return pos;
}

static meshtastic_MeshPacket makePositionPacket(const meshtastic_Position &pos, uint32_t fromNode, uint32_t packetId)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = fromNode;
    p.id = packetId;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = meshtastic_PortNum_POSITION_APP;
    p.decoded.payload.size =
        pb_encode_to_bytes(p.decoded.payload.bytes, sizeof(p.decoded.payload.bytes), &meshtastic_Position_msg, &pos);
    return p;
}

// ---------------------------------------------------------------------------
// staticTelemetryKeyConfigured(): mere PSK presence, role ignored
// ---------------------------------------------------------------------------

static void test_configured_offByDefault()
{
    resetChannel7();
    TEST_ASSERT_FALSE(staticTelemetryKeyConfigured());
}

static void test_configured_offWithoutSettings()
{
    channelFile.channels[MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX] = meshtastic_Channel_init_zero;
    channelFile.channels[MESHTASTIC_STATIC_TELEMETRY_KEY_CHANNEL_INDEX].has_settings = false;
    TEST_ASSERT_FALSE(staticTelemetryKeyConfigured());
}

static void test_configured_offWithEmptyPskRegardlessOfRole()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, nullptr, 0);
    TEST_ASSERT_FALSE(staticTelemetryKeyConfigured());

    setChannel7Psk(meshtastic_Channel_Role_PRIMARY, nullptr, 0);
    TEST_ASSERT_FALSE(staticTelemetryKeyConfigured());

    setChannel7Psk(meshtastic_Channel_Role_DISABLED, nullptr, 0);
    TEST_ASSERT_FALSE(staticTelemetryKeyConfigured());
}

// Regression guard: the feature must activate on PSK presence alone. Mobile
// apps generally don't expose an explicit role picker, so requiring a
// specific role (as an earlier version of this feature did) made it
// unreachable from some clients.
static void test_configured_onWithPskRegardlessOfRole()
{
    setChannel7Psk(meshtastic_Channel_Role_DISABLED, kTestKey, sizeof(kTestKey));
    TEST_ASSERT_TRUE(staticTelemetryKeyConfigured());

    setChannel7Psk(meshtastic_Channel_Role_PRIMARY, kTestKey, sizeof(kTestKey));
    TEST_ASSERT_TRUE(staticTelemetryKeyConfigured());

    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));
    TEST_ASSERT_TRUE(staticTelemetryKeyConfigured());
}

// ---------------------------------------------------------------------------
// encryptStaticTelemetryPayload() / tryDecodeStaticTelemetryEncrypted() round trip
// ---------------------------------------------------------------------------

static void test_encrypt_noOpWhenNotConfigured()
{
    resetChannel7();
    meshtastic_Position pos = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(pos, 0x11223344, 42);
    meshtastic_Data before = p.decoded;

    encryptStaticTelemetryPayload(&p);

    TEST_ASSERT_EQUAL_UINT32(before.payload.size, p.decoded.payload.size);
    TEST_ASSERT_EQUAL_MEMORY(before.payload.bytes, p.decoded.payload.bytes, before.payload.size);
}

static void test_encrypt_noOpForOtherPortnums()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));

    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = 0x11223344;
    p.id = 1;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    const char *text = "hello mesh";
    p.decoded.payload.size = strlen(text);
    memcpy(p.decoded.payload.bytes, text, p.decoded.payload.size);
    meshtastic_Data before = p.decoded;

    encryptStaticTelemetryPayload(&p);

    TEST_ASSERT_EQUAL_UINT32(before.payload.size, p.decoded.payload.size);
    TEST_ASSERT_EQUAL_MEMORY(before.payload.bytes, p.decoded.payload.bytes, before.payload.size);
}

static void test_encryptThenDecrypt_recoversOriginalPosition()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));

    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    meshtastic_Data plaintext = p.decoded;

    encryptStaticTelemetryPayload(&p);

    // Ciphertext must differ from plaintext (same length - AES-CTR is a stream cipher).
    TEST_ASSERT_EQUAL_UINT32(plaintext.payload.size, p.decoded.payload.size);
    TEST_ASSERT_TRUE(memcmp(plaintext.payload.bytes, p.decoded.payload.bytes, plaintext.payload.size) != 0);

    // A plain pb_decode of the ciphertext must not silently "succeed" with a
    // plausible result (it may fail outright, or decode to something that
    // fails the round-trip check - either is fine, but it must not equal the
    // original plaintext).
    meshtastic_Position asPlaintext = meshtastic_Position_init_zero;
    bool plaintextDecodeOk =
        pb_decode_from_bytes(p.decoded.payload.bytes, p.decoded.payload.size, &meshtastic_Position_msg, &asPlaintext);
    if (plaintextDecodeOk) {
        TEST_ASSERT_FALSE(
            payloadRoundTripsPlausibly(p.decoded.payload.bytes, p.decoded.payload.size, &meshtastic_Position_msg, &asPlaintext));
    }

    meshtastic_Position decrypted = meshtastic_Position_init_zero;
    TEST_ASSERT_TRUE(tryDecodeStaticTelemetryEncrypted(p, &meshtastic_Position_msg, &decrypted, sizeof(decrypted)));

    TEST_ASSERT_EQUAL_INT32(original.latitude_i, decrypted.latitude_i);
    TEST_ASSERT_EQUAL_INT32(original.longitude_i, decrypted.longitude_i);
    TEST_ASSERT_EQUAL_INT32(original.altitude, decrypted.altitude);
    TEST_ASSERT_EQUAL_UINT32(original.time, decrypted.time);
    TEST_ASSERT_EQUAL_UINT32(original.sats_in_view, decrypted.sats_in_view);
}

static void test_tryDecode_failsWithoutKeyConfigured()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));
    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    encryptStaticTelemetryPayload(&p);

    resetChannel7(); // simulate the receiver having no key configured at all

    meshtastic_Position decrypted = meshtastic_Position_init_zero;
    TEST_ASSERT_FALSE(tryDecodeStaticTelemetryEncrypted(p, &meshtastic_Position_msg, &decrypted, sizeof(decrypted)));
}

static void test_tryDecode_wrongKeyDoesNotRecoverOriginal()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));
    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    encryptStaticTelemetryPayload(&p);

    static const uint8_t wrongKey[32] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                                         0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                                         0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, wrongKey, sizeof(wrongKey));

    meshtastic_Position decrypted = meshtastic_Position_init_zero;
    // May fail outright, or "succeed" with garbage - either way it must not
    // recover the original coordinates.
    if (tryDecodeStaticTelemetryEncrypted(p, &meshtastic_Position_msg, &decrypted, sizeof(decrypted))) {
        TEST_ASSERT_FALSE(original.latitude_i == decrypted.latitude_i && original.longitude_i == decrypted.longitude_i);
    }
}

// ---------------------------------------------------------------------------
// Regression tests: channel 7 left at its default role (DISABLED) must still
// load its *actual* key - not silently fall through to whatever key the
// crypto engine happened to have active from an unrelated prior operation.
//
// Channels::getKey() independently refuses to load a key for a DISABLED-role
// channel, even though staticTelemetryKeyConfigured() deliberately treats
// DISABLED as a valid "on" state (see StaticTelemetryKey.h's header comment).
// Without ignoreRoleForKey=true threaded through to Channels::getKey(),
// encryptStaticTelemetryPayload()/tryDecodeStaticTelemetryEncrypted() would
// silently encrypt/decrypt with a stale key and never touch channel 7's PSK
// at all - producing plausible-looking garbage instead of an error. Each test
// below first points the crypto engine at an unrelated decoy key via
// channels.setActiveByIndex(0) so a reintroduced bug can't hide behind
// AES-CTR's self-cancelling property (encrypting then decrypting with the
// *same* wrong key still "round-trips" - only using channel 7's actual key
// both times, or comparing against a known-good reference, catches this).
// ---------------------------------------------------------------------------

static void pointCryptoEngineAtDecoyChannel0Key(uint8_t fillByte)
{
    meshtastic_Channel &ch0 = channelFile.channels[0];
    ch0 = meshtastic_Channel_init_zero;
    ch0.has_settings = true;
    ch0.role = meshtastic_Channel_Role_PRIMARY;
    memset(ch0.settings.psk.bytes, fillByte, 32);
    ch0.settings.psk.size = 32;
    channels.setActiveByIndex(0);
}

static void test_encrypt_usesActualChannel7KeyRegardlessOfRole()
{
    meshtastic_Position original = makeTestPosition();

    // Reference: encrypt with role SECONDARY, the known-good path.
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));
    meshtastic_MeshPacket referencePacket = makePositionPacket(original, 0x11223344, 42);
    encryptStaticTelemetryPayload(&referencePacket);

    // Disrupt the crypto engine's active key, then encrypt the same
    // plaintext/packet/key with role DISABLED - the config
    // staticTelemetryKeyConfigured() claims to support.
    pointCryptoEngineAtDecoyChannel0Key(0x77);
    setChannel7Psk(meshtastic_Channel_Role_DISABLED, kTestKey, sizeof(kTestKey));
    meshtastic_MeshPacket disabledRolePacket = makePositionPacket(original, 0x11223344, 42);
    encryptStaticTelemetryPayload(&disabledRolePacket);

    // If DISABLED-role encryption used channel 7's key (as it must), it
    // produces byte-identical ciphertext to the SECONDARY-role reference.
    TEST_ASSERT_EQUAL_UINT32(referencePacket.decoded.payload.size, disabledRolePacket.decoded.payload.size);
    TEST_ASSERT_EQUAL_MEMORY(referencePacket.decoded.payload.bytes, disabledRolePacket.decoded.payload.bytes,
                             referencePacket.decoded.payload.size);
}

static void test_tryDecode_usesActualChannel7KeyRegardlessOfRole_evenWhenDisabled()
{
    setChannel7Psk(meshtastic_Channel_Role_DISABLED, kTestKey, sizeof(kTestKey));
    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    encryptStaticTelemetryPayload(&p);

    // Disrupt the crypto engine's active key between encrypt and decrypt.
    pointCryptoEngineAtDecoyChannel0Key(0x55);

    meshtastic_Position decrypted = meshtastic_Position_init_zero;
    TEST_ASSERT_TRUE(tryDecodeStaticTelemetryEncrypted(p, &meshtastic_Position_msg, &decrypted, sizeof(decrypted)));
    TEST_ASSERT_EQUAL_INT32(original.latitude_i, decrypted.latitude_i);
    TEST_ASSERT_EQUAL_INT32(original.longitude_i, decrypted.longitude_i);
    TEST_ASSERT_EQUAL_INT32(original.altitude, decrypted.altitude);
}

// ---------------------------------------------------------------------------
// payloadRoundTripsPlausibly(): the receive-side plaintext-vs-ciphertext heuristic
// ---------------------------------------------------------------------------

static void test_roundTrip_genuinePlaintextRoundTrips()
{
    meshtastic_Position pos = makeTestPosition();
    uint8_t buf[meshtastic_Constants_DATA_PAYLOAD_LEN];
    size_t len = pb_encode_to_bytes(buf, sizeof(buf), &meshtastic_Position_msg, &pos);

    meshtastic_Position decoded = meshtastic_Position_init_zero;
    TEST_ASSERT_TRUE(pb_decode_from_bytes(buf, len, &meshtastic_Position_msg, &decoded));
    TEST_ASSERT_TRUE(payloadRoundTripsPlausibly(buf, len, &meshtastic_Position_msg, &decoded));
}

// Regression test for the false-positive this heuristic exists to catch:
// nanopb silently *discards* unrecognized field numbers while decoding
// (rather than preserving them for re-serialization, unlike some other
// protobuf runtimes), so appending a well-formed-but-unrecognized field to an
// otherwise-genuine payload still "successfully" decodes - but does not
// round-trip, since the appended bytes are gone from the re-encoding.
static void test_roundTrip_rejectsPayloadWithUnrecognizedTrailingField()
{
    meshtastic_Position pos = makeTestPosition();
    uint8_t buf[meshtastic_Constants_DATA_PAYLOAD_LEN];
    size_t len = pb_encode_to_bytes(buf, sizeof(buf), &meshtastic_Position_msg, &pos);

    // Append field #30 (never used by meshtastic_Position - fields run 1-23),
    // wire type 2 (length-delimited), with a 2-byte payload: tag=(30<<3)|2=242
    // -> varint {0xF2, 0x01}, then length byte 2, then 2 arbitrary bytes.
    uint8_t padded[meshtastic_Constants_DATA_PAYLOAD_LEN];
    memcpy(padded, buf, len);
    padded[len + 0] = 0xF2;
    padded[len + 1] = 0x01;
    padded[len + 2] = 0x02;
    padded[len + 3] = 0xAB;
    padded[len + 4] = 0xCD;
    size_t paddedLen = len + 5;

    meshtastic_Position decoded = meshtastic_Position_init_zero;
    TEST_ASSERT_TRUE(pb_decode_from_bytes(padded, paddedLen, &meshtastic_Position_msg, &decoded));
    // The recognized fields still decoded correctly...
    TEST_ASSERT_EQUAL_INT32(pos.latitude_i, decoded.latitude_i);
    // ...but the padded buffer must not be judged a plausible plaintext payload.
    TEST_ASSERT_FALSE(payloadRoundTripsPlausibly(padded, paddedLen, &meshtastic_Position_msg, &decoded));
}

// ---------------------------------------------------------------------------
// Send-path ordering: encryptStaticTelemetryPayload() must run *after*
// applyPositionPrecisionForChannel(), never before
// ---------------------------------------------------------------------------

// Regression test for a real bug that shipped briefly: encryptStaticTelemetryPayload()
// must run *after* applyPositionPrecisionForChannel() (which needs genuine
// plaintext to pb_decode_from_bytes() and truncate coordinates), never before -
// encrypting first feeds ciphertext into that plaintext decode, which fails and
// makes Router::send() silently drop the whole packet ("Dropping malformed
// position packet before send"). Router.cpp applies the static key inside the
// isFromUs(p) block, immediately *after* applyPositionPrecisionForChannel()
// succeeds - not any earlier (e.g. not in MeshService::sendToMesh(), which runs
// before Router::send() is even reached).
static void test_positionPrecisionOrdering_encryptingBeforePrecisionCheckFailsToDecode()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));

    meshtastic_Channel &ch0 = channelFile.channels[0];
    ch0 = meshtastic_Channel_init_zero;
    ch0.has_settings = true;
    ch0.settings.has_module_settings = true;
    ch0.settings.module_settings.position_precision = 32;

    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    p.channel = 0;

    // Wrong order (the bug): encrypt first, then try to apply position precision.
    encryptStaticTelemetryPayload(&p);
    TEST_ASSERT_FALSE(applyPositionPrecisionForChannel(p, p.channel));
}

static void test_positionPrecisionOrdering_correctOrderSucceeds()
{
    setChannel7Psk(meshtastic_Channel_Role_SECONDARY, kTestKey, sizeof(kTestKey));

    meshtastic_Channel &ch0 = channelFile.channels[0];
    ch0 = meshtastic_Channel_init_zero;
    ch0.has_settings = true;
    ch0.settings.has_module_settings = true;
    ch0.settings.module_settings.position_precision = 32;

    meshtastic_Position original = makeTestPosition();
    meshtastic_MeshPacket p = makePositionPacket(original, 0x11223344, 42);
    p.channel = 0;

    // Correct order, matching Router::send(): precision truncation on genuine
    // plaintext first, then static-key encryption.
    TEST_ASSERT_TRUE(applyPositionPrecisionForChannel(p, p.channel));
    encryptStaticTelemetryPayload(&p);

    meshtastic_Position decrypted = meshtastic_Position_init_zero;
    TEST_ASSERT_TRUE(tryDecodeStaticTelemetryEncrypted(p, &meshtastic_Position_msg, &decrypted, sizeof(decrypted)));
    TEST_ASSERT_EQUAL_INT32(original.latitude_i, decrypted.latitude_i);
    TEST_ASSERT_EQUAL_INT32(original.longitude_i, decrypted.longitude_i);
}

void setUp(void) {}

void tearDown(void) { resetChannel7(); }

extern "C" {
void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_configured_offByDefault);
    RUN_TEST(test_configured_offWithoutSettings);
    RUN_TEST(test_configured_offWithEmptyPskRegardlessOfRole);
    RUN_TEST(test_configured_onWithPskRegardlessOfRole);
    RUN_TEST(test_encrypt_noOpWhenNotConfigured);
    RUN_TEST(test_encrypt_noOpForOtherPortnums);
    RUN_TEST(test_encryptThenDecrypt_recoversOriginalPosition);
    RUN_TEST(test_tryDecode_failsWithoutKeyConfigured);
    RUN_TEST(test_tryDecode_wrongKeyDoesNotRecoverOriginal);
    RUN_TEST(test_encrypt_usesActualChannel7KeyRegardlessOfRole);
    RUN_TEST(test_tryDecode_usesActualChannel7KeyRegardlessOfRole_evenWhenDisabled);
    RUN_TEST(test_roundTrip_genuinePlaintextRoundTrips);
    RUN_TEST(test_roundTrip_rejectsPayloadWithUnrecognizedTrailingField);
    RUN_TEST(test_positionPrecisionOrdering_encryptingBeforePrecisionCheckFailsToDecode);
    RUN_TEST(test_positionPrecisionOrdering_correctOrderSucceeds);
    exit(UNITY_END());
}

void loop() {}
}
