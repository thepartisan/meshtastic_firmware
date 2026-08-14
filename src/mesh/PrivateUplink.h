#pragma once

/*
 * Fork customization: redirect our own outgoing Position/Telemetry broadcasts to this
 * fixed unicast destination instead of NODENUM_BROADCAST, so they get Curve25519/PKC
 * encrypted (see wouldEncryptWithPKC() in Router.cpp) instead of channel-PSK encrypted.
 *
 * This destination does not need to be a real device - it exists purely as a NodeDB
 * lookup key so the firmware can find the paired public key when building the packet.
 * The actual "recipient" pulls the packet off the public MQTT broker instead.
 *
 * Before this works, this node ID must be paired with its public key via the
 * Meshtastic app's "Add Contact" feature (or the equivalent admin CLI command) -
 * NodeDB contacts are runtime state, not something baked into the compiled firmware.
 */
#define MESHTASTIC_PRIVATE_UPLINK_DEST_NODENUM 0x209dceab
