# drop-federation

Friends Federation and Instance Peering plugin for the [Drop](https://github.com/Heretek-Games/drop) game distribution platform.

Maintained by [Heretek Games](https://github.com/Heretek-Games/drop-federation).

## Overview

`drop-federation` brings Syncthing-style decentralized instance peering to Drop:
1. **Cryptographic Identity**: Ed25519 keypair generation and instance descriptor exchange.
2. **Cross-Instance Social**: Send and accept friend requests across autonomous Drop instances without a centralized account directory.
3. **Presence & Chat**: Real-time rich presence ("In Game", "Lobby Joinable") and secure peer-to-peer messaging.

Built on the `@droposs/plugin-sdk`.
