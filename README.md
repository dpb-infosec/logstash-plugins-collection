# Logstash Plugins Collection

This repository contains custom Logstash plugins developed to extend and enhance Logstash functionality. In this collection you will find:

- **Syslog Codec Plugin**  
  A custom codec that parses syslog messages using two different framing mechanisms:  
  - **OCTET_COUNTING:** Each message is prefixed with its byte-length.
  - **NEWLINE_DELIMITED:** Each message is terminated with a newline.

- **TCP Loadbalancing Output Plugin**  
  An output plugin that buffers events and distributes them across multiple hosts using round-robin load balancing. It supports:
  - Memory and disk queues,
  - Automatic reconnections with exponential backoff, and
  - Optional SSL encryption for secure TCP connections.

## Table of Contents

- [Overview](#overview)
- [Plugins](#plugins)
  - [Syslog Codec Plugin](#syslog-codec-plugin)
  - [TCP Loadbalancing Output Plugin](#tcp-loadbalancing-output-plugin)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
- [Development](#development)
  - [Testing](#testing)
  - [Running Locally in Logstash](#running-locally-in-logstash)
- [Contributing](#contributing)
- [License](#license)

## Overview

These plugins are designed to improve the robustness and flexibility of Logstash pipelines by providing enhanced parsing and output capabilities. They are fully open source and released under the Apache 2.0 License.

## Plugins

### Syslog Codec Plugin

This codec plugin implements a custom syslog parser for Logstash. It supports:

- **OCTET_COUNTING framing:** The message starts with a byte count followed by a space.
- **NEWLINE_DELIMITED framing:** The message is terminated with a newline character.

Additional features include:

- Buffering of incoming data until a complete syslog message is available.
- Parsing syslog messages into structured Logstash events.
- Full RFC support and auto sensing
- Handling framing and parsing errors by generating error events with specific tags.

_For detailed documentation, see the [Syslog Codec Documentation](./codec/logstash-codec-syslog/docs/index.asciidoc)._

### TCP Loadbalancing Output Plugin

This output plugin distributes events across multiple TCP hosts. Key features:

- **Load Balancing:** Uses a round-robin algorithm to select hosts.
- **Event Buffering:** Combines memory and disk queues to store events before sending.
- **Reconnection & Retry:** Monitors socket health and reconnects with exponential backoff.
- **SSL Support:** Optionally secures TCP connections using SSL.
- **Atomic Batch Sending:** Aggregates queued messages into a single payload to ensure atomic delivery.

_For detailed documentation, see the [TCP Loadbalancing Documentation](./output/logstash-output-tcploadbalancing/docs/index.asciidoc)._

## Getting Started

### Requirements

- [Logstash](https://www.elastic.co/logstash) (compatible version)
- [JRuby](https://www.jruby.org/) with Bundler installed
- Ruby (typically 2.5+ depending on your environment)

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/logstash-plugins-collection.git
   cd logstash-plugins-collection
