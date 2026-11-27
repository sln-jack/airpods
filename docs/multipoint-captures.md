# AirPods Pro 3 multipoint capture findings

The working Mac/iPhone trace shows both hosts connected **before** playback changes hands. In the two Linux trials the incoming host only reached **connecting** while the old host was still connected. Sending the Mac's host priority list earlier would be a different operation from the one observed.

## Recordings

| Directory | Files | What happened |
| --- | --- | --- |
| `native-handoff-20261126T195246Z` | `macos.pklg`, `iphone.pklg`, `mac-routing.log`, `actions.txt` | Both players were paused at admission. After both links came up, eight audible transfers were recorded, four in each direction. |
| `linux-admission-20261126T235029Z` | `linux.btsnoop`, `iphone.pklg` | Ordinary Linux identity. Linux connected during iPhone playback. Manually selecting the AirPods on iPhone displaced Linux. |
| `multipoint-20261127T000551Z` | `linux.btsnoop`, `iphone.pklg` | Same sequence with the daemon's supplemental Apple Device ID registered. |

Frame numbers are one-based and local to each file. PacketLogger writes local wall time into its timestamp field. Use the event order within each file. For cross-host comparisons align the clock conventions first. Subsecond differences across controllers are approximate.

## Where the links diverge

| Recording | Frames | Observation |
| --- | --- | --- |
| Working Mac | 1725, 1726 | Mac requests the host table, then sends `04 00 04 00 44 00 04 00 02 00 02 06`. One millisecond later its daemon logs `score High srMode Enabled` with the same final four bytes. |
| Working Mac | 1939, 1973, 1979, 1983, 1989 | First bud in ear. After 3.072 s iPhone appears as connecting. Both reach state 2. Mac sends opcode `0x14` with the last-playing iPhone first. Both entries acquire flag bit `0x01`. |
| Supplemental identity, iPhone | 733, 745 | The phone is still connected and owns audio when the buds report Linux connecting. **182 ms later**, the phone controller reports disconnect reason `0x14` (remote terminated due to low resources). Baseline iPhone frame 1595 shows the same incoming Linux state. |
| Supplemental identity, Linux | 10, 86–87, 193, 242 | Classic link completes. The buds query Device ID, receiving Linux Foundation first and Apple second. They requested vendor, product, version, vendor source and three vendor attributes. They did not request the primary-record flag. On aligned clocks this reply comes after the phone drops. Linux then sends AVDTP Start and its first media packet. |
| Supplemental identity, Linux | 238, 242, 244 | Buds report source type 0 for Linux, Linux sends its first RTP packet, then the buds report type 2 (media) for Linux. These are successive events on **one controller**. |
| Supplemental identity, Linux | 1697, 1721, 1727 | Selecting AirPods on iPhone produces phone/Linux states 1/2, then 1/0. The Linux controller receives disconnect reason `0x14`. The daemon's socket reset follows the lost link. |

The recorded Linux stream matches the daemon's stereo AAC-ELD packet format and SSRC. The baseline carried 533 packets (1,599 codec units, 15.99 s). The supplemental-identity trial carried 730 (2,190 units, 21.90 s). Every decoded sample in both streams was zero. The historical captures cannot identify which Linux application supplied the PCM or distinguish exact digital silence before encoding from audio that the encoder quantized to silence.

To reproduce the amplitude measurement on Linux with TShark, Python and libfdk-aac installed, run this against the archived captures. The script checks packet sequence, RTP timestamp, all three codec headers and decoder return values.

```sh
python3 scripts/check-captured-media.py \
  linux-admission-20261126T235029Z/linux.btsnoop \
  multipoint-20261127T000551Z/linux.btsnoop
```

## What the Apple hosts send

Both native hosts negotiate Apple FastConnect inside L2CAP Echo (Mac 1446/1461, iPhone 2629/2632). The iPhone does so again when manually reclaiming the buds from Linux (3765/3768). The Linux capture shows ordinary channel setup. The captures establish a protocol difference. Its role in shared admission remains unknown. [FastConnect dissector](https://github.com/pabloaul/apple-wireshark/blob/2e9822247195/plugins/fastconnect/fastconnect.lua)

The Mac also advertises feature bytes beginning `ff 02` at frame 1580. This daemon advertises `d7 00`. Both EarPort and podsd send `ff 00`. The failed Linux trial exchanged AACP features after the iPhone's first disconnection, and none of these sources establishes a particular bit as a prerequisite for retaining two hosts. [EarPort feature packet](https://github.com/Anoryth/earport/blob/aecd3bc056a8/daemon/src/aap_protocol.c#L21-L24) · [podsd feature packet](https://github.com/madeitdisfar/podsd/blob/acf5fcea751cf017ed991cc70ddcdc8b0d555ed0/src/bluetooth/aacp.rs#L1071-L1077)

During native playback transfers, the claimant writes selector 6 value 1 to the buds and sends the peer an ownership-loss dictionary through those same buds. For example, Mac 7325/7326 precede Mac AVDTP Start 7346. The iPhone receives the relay at 7566 and suspends at 7575. All 57 relay submissions across both hosts match the deliveries on the opposite host byte for byte. The observed relay path needs no direct Linux–iPhone pairing. What qualifies a host for native relays is still open. The native trace began with known, same-account devices and contains no first pairing. It does not establish a need to export a Mac key.

EarPort reports testing its switching feature with AirPods Pro 2 and an iPhone. It publishes a supplemental Apple Device ID and reconnects once under certain conditions when a peer fails to join. It suppresses that recovery during local playback or recording. podsd reports shared links on the same A3064 model with BlueZ's **primary** Device ID configured as Apple. It also reports that its iPhone switches silently, without native smart-routing messages arriving on Linux. The supplemental-record trial tested a different on-wire identity from podsd's configuration. [EarPort model and limitations](https://github.com/Anoryth/earport/blob/aecd3bc056a8/README.md#switching-with-your-apple-devices-experimental) · [EarPort recovery](https://github.com/Anoryth/earport/blob/aecd3bc056a8/daemon/src/tipi.c) · [podsd switching results](https://github.com/madeitdisfar/podsd/blob/acf5fcea751cf017ed991cc70ddcdc8b0d555ed0/README.md#switching-between-devices)

## What the updated daemon can establish

In multipoint mode the daemon samples the PipeWire graph before acquiring the transport. Exact zero PCM leaves it idle. The first non-silent buffer is retained for transport startup. An active stream keeps its transport during quiet passages. The daemon publishes the captured desktop routing score at setup and keeps the recorded two-connected-host condition for writing priority.

The recovery window opens only when a fresh table shows Linux connected alone, the buds have reported an idle source, and at least one bud is reported worn. It waits six seconds because a three-second timer would have fired during the successful native admission. A connecting peer or active source report cancels recovery for that session. An active local transport or mic blocks the reconnect at the deadline. The daemon checks only the first eligible attachment per pair per daemon run and issues at most one reconnect. Automatic codec selection in this mode does not restart WirePlumber or force a disconnect to obtain AAC-ELD.

Offline, the Rust policy replayed the recorded Mac priority write byte for byte and produced zero priority writes in both failed Linux trials. It requested no reconnect in any historical trace, including the Linux traces that reported local media. On an isolated Linux PipeWire server with a private mock BlueZ transport, zero PCM caused zero acquisitions, a tone caused one, a quiet passage retained it, and player exit released it.

The remaining hardware question is whether these buds will retain both links after idle admission with the supplemental identity. The first discriminating observation is a single table with **both hosts in state 2**, followed by a priority write and both listed bits. If admission still fails while Linux sends no media, changing ownership scores or tapping Play repeatedly cannot resolve that earlier failure. The independently reported comparison would use podsd's primary Apple Device ID as the sole changed variable. Full playback takeover also requires handling ownership and player state after admission.
