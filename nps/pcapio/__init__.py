"""PCAP 文件读写。"""

from __future__ import annotations

from nps.pcapio.pcapfile import read_pcap_header, write_pcap

__all__ = ["read_pcap_header", "write_pcap"]
