# Mix

This repository contains the implementation of the Mix protocol, a custom protocol within the libp2p framework
designed to enable anonymous communication in peer-to-peer networks.

## Overview

The Mix protocol leverages the Sphinx packet format to ensure sender anonymity and message unlinkability.
It routes messages through a series of mix nodes, effectively concealing the origin of the message.
This implementation is part of a broader effort to integrate anonymity into the libp2p ecosystem.

**Note:** This is a proof-of-concept, not production-ready code.
It serves as a foundation for further development and research into anonymous communication within libp2p networks.
It provides a basis for future development and invites community experimentation and contributions.

## Key Features

- **Sphinx Packet Format**: Guarantees anonymity through fixed-size packets and layered encryption.
- **Random Path Selection**: Routes messages through randomly selected mix nodes.
- **Pluggable Components**: Allows for customizable spam protection, peer discovery, and incentivization mechanisms.

## Features in developement

- **metadata and logging**: Allows data to be piggy-backed on top of a sphinx packet in plain-text for development purposes. Activate with `-d:metadata`

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/vacp2p/mix.git
   cd mix
   ```

2. **Install Dependencies**

   Ensure you have Nim and Nimble installed. For detailed installation instructions and downloads,
   visit the official [Nim](https://nim-lang.org) website, where you'll find installers for various operating systems and methods.
   Nimble, the package manager for Nim, is typically included with the Nim installation.
   Then install the necessary Nim packages:

   ```bash
   nimble install
   ```
   
## Running Tests

Execute the test suite with:

   ```bash
   nimble test
   ```

## Usage

Run the Mix protocol proof-of-concept:

   ```bash
   nim c -r src/mix_poc.nim
   ```

## Current Implementation Challenges

1. **Protocol Handler Diversity**: Existing protocols have diverse input formats for handlers and send functions,
complicating the integration.
2. **Function Call Complexity**: Difficulty in calling Mix send/handler functions from existing protocols
without significant overrides to send functions (and handlers in some cases, *e.g.,* ping).

## Transport Approach

We have developed a custom Mix transport to address the challenges faced with the protocol-level implementation.
This approach aims to provide a more seamless integration with existing libp2p protocols.

For details on the Mix transport implementation, please refer to the `mix-transport` branch `README`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
For major changes, please discuss your proposed changes via issue before making a pull request.

## RFC and Further Reading

For a detailed technical specification and discussion, please refer to the [Mix Protocol RFC](https://rfc.vac.dev/vac/raw/mix/).

## License

This project is licensed under the MIT License.

## Acknowledgments

Thanks to the libp2p community and all contributors for their feedback and insights throughout the development
of the Mix protocol.
