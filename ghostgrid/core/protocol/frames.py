"""Modbus TCP Frame encoding and decoding utilities."""
import struct
from enum import IntEnum
from typing import Tuple, Optional, List, Dict


class ModbusFunction(IntEnum):
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    READ_DEVICE_IDENTIFICATION = 0x2B


class ModbusException(IntEnum):
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06


def parse_mbap_header(header_bytes: bytes) -> Optional[Tuple[int, int, int, int]]:
    """Parse 7-byte Modbus Application Protocol (MBAP) header."""
    if len(header_bytes) < 7:
        return None
    trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header_bytes)
    return trans_id, proto_id, length, unit_id


def build_mbap_header(trans_id: int, unit_id: int, pdu_len: int) -> bytes:
    """Build standard 7-byte MBAP header for TCP response."""
    return struct.pack(">HHHB", trans_id, 0x0000, pdu_len + 1, unit_id)


def build_exception_response(trans_id: int, unit_id: int, function_code: int, exception_code: int) -> bytes:
    """Build standard Modbus exception PDU (FC | 0x80)."""
    pdu = struct.pack(">BB", function_code | 0x80, exception_code)
    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + pdu


def build_read_bits_response(trans_id: int, unit_id: int, function_code: int, bit_values: List[int]) -> bytes:
    """Build response for 0x01 (Coils) and 0x02 (Discrete Inputs)."""
    byte_count = (len(bit_values) + 7) // 8
    pdu = bytearray(struct.pack(">BB", function_code, byte_count))

    for byte_idx in range(byte_count):
        b = 0
        for bit_idx in range(8):
            val_idx = byte_idx * 8 + bit_idx
            if val_idx < len(bit_values) and bit_values[val_idx]:
                b |= (1 << bit_idx)
        pdu.append(b)

    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + bytes(pdu)


def build_read_words_response(trans_id: int, unit_id: int, function_code: int, word_values: List[int]) -> bytes:
    """Build response for 0x03 (Holding Registers) and 0x04 (Input Registers)."""
    byte_count = len(word_values) * 2
    pdu = bytearray(struct.pack(">BB", function_code, byte_count))
    for val in word_values:
        pdu.extend(struct.pack(">H", val & 0xFFFF))
    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + bytes(pdu)


def build_write_single_response(trans_id: int, unit_id: int, function_code: int, address: int, value: int) -> bytes:
    """Build echo response for 0x05 (Single Coil) and 0x06 (Single Register)."""
    pdu = struct.pack(">BHH", function_code, address, value & 0xFFFF)
    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + pdu


def build_write_multiple_response(trans_id: int, unit_id: int, function_code: int, start_address: int, count: int) -> bytes:
    """Build response for 0x0F (Multiple Coils) and 0x10 (Multiple Registers)."""
    pdu = struct.pack(">BHH", function_code, start_address, count)
    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + pdu


def build_device_id_response(trans_id: int, unit_id: int, mei_type: int, read_device_id_code: int, objects: Dict[int, str]) -> bytes:
    """Build response for 0x2B / MEI 0x0E (Read Device Identification)."""
    conformity_level = 0x83
    more_follows = 0x00
    next_object_id = 0x00
    number_of_objects = len(objects)

    obj_bytes = bytearray()
    for obj_id, val_str in sorted(objects.items()):
        val_bytes = val_str.encode("utf-8")
        obj_bytes.extend(struct.pack(">BB", obj_id, len(val_bytes)))
        obj_bytes.extend(val_bytes)

    header = struct.pack(
        ">BBBBBB",
        0x2B,                  # Function Code
        mei_type,              # MEI Type 0x0E
        read_device_id_code,   # Read Device ID Code
        conformity_level,      # Conformity Level
        more_follows,          # More follows
        next_object_id,        # Next Object Id
    )
    pdu = header + struct.pack(">B", number_of_objects) + bytes(obj_bytes)
    mbap = build_mbap_header(trans_id, unit_id, len(pdu))
    return mbap + pdu
