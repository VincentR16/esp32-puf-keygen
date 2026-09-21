#!/usr/bin/env python3
"""
collect.py - Save the PUF dumps printed by the ESP32.

Open the serial port, then press EN on the board: every reset prints a
new dump, saved as data/<label>_NNN.bin. Stops after --count dumps
(Ctrl+C to stop earlier). Close idf.py monitor first: only one program
can use the port.

Usage:
    python host/collect.py --label enr --count 50
"""

import argparse
import os

import serial

BEGIN = "=== PUF DUMP BEGIN ==="
END = "=== PUF DUMP END ==="


def open_port(port, baud):
    """Open the port without resetting the board."""
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 1
    ser.open()
    # RTS drives EN, DTR drives GPIO0. Release RTS first:
    # releasing DTR first would briefly hold EN low and reset the board.
    ser.rts = False
    ser.dtr = False
    return ser


def read_block(ser):
    """Wait for the next dump and return its fields as a dict."""
    block = None
    while True:
        line = ser.readline().decode(errors="ignore").strip()
        if line == BEGIN:
            block = {}
        elif line == END and block is not None:
            return block
        elif block is not None and " " in line:
            key, value = line.split(" ", 1)
            block[key] = value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="enr")
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--port", default="/dev/cu.usbserial-0001")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", default="data")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    existing = len([f for f in os.listdir(args.out)
                    if f.startswith(args.label + "_") and f.endswith(".bin")])

    ser = open_port(args.port, args.baud)
    print(f"Port open. Press EN to take a dump ({args.count} to go).\n")

    saved = 0
    try:
        while saved < args.count:
            block = read_block(ser)
            # The firmware repeats the same dump every 2 s:
            # only SEQ 0 comes from a new boot.
            if block.get("SEQ") != "0":
                continue
            try:
                data = bytes.fromhex(block["DATA"])
                if len(data) != int(block["SIZE"]):
                    raise ValueError("wrong length")
            except (KeyError, ValueError) as e:
                print(f"  dump discarded: {e}")
                continue
            saved += 1
            name = f"{args.label}_{existing + saved:03d}.bin"
            with open(os.path.join(args.out, name), "wb") as fh:
                fh.write(data)
            print(f"[{saved:3d}/{args.count}] {name}  ones={block.get('ONES')}")
    except KeyboardInterrupt:
        print()
    finally:
        ser.close()

    print(f"Saved {saved} dumps with label '{args.label}'.")


if __name__ == "__main__":
    main()