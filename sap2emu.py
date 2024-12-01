
""" SAP2 Emulator - See https://github.com/johnnyw66/SAP2 """

from enum import Enum
import logging
import argparse

parser = argparse.ArgumentParser(description="SAP2 Emulator",
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("-l", "--logging", action='store_true',default=False, help="Logging ON")
parser.add_argument("-s", "--single-step",  action='store_true', default=False, help="Single Step")
parser.add_argument("-f", "--file", default='example.hex', help="File")

args = parser.parse_args()
arg_config = vars(args)
single_step = arg_config['single_step']
file_name = arg_config['file']

if (arg_config['logging']):
    logging.basicConfig(filename=None, format='%(name)s %(levelname)s: %(asctime)s: %(message)s', level=logging.INFO)


# Non blocking Keyboard - Thank you Artiom Peysakhovsky - https://gist.github.com/Artiomio
try:
    import msvcrt

    logging.info("Windows OS")

    def key_pressed():
        return msvcrt.kbhit()

    def read_key():
        key = msvcrt.getch()

        try:
            result = str(key, encoding="utf8")
        except:
            result = key
        
        return result

except:
    logging.info("Linux/Mac OS X")
    try:
        import sys
        import select
        import tty
        import termios
        import atexit

        def key_pressed():
            return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

        def read_key():
            return sys.stdin.read(1)

        def restore_settings():
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)


        atexit.register(restore_settings)
        old_settings = termios.tcgetattr(sys.stdin)

        tty.setcbreak(sys.stdin.fileno())
    except:
        print("Can't deal with your keyboard!")
        

# MIT License
# 
# Copyright (c) 2024 Johnny Wilson
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 
# Author: Johnny Wilson
# Location: Brighton, Sussex

class IODevice:
    """Abstract base class for I/O devices."""
    def read(self, address):
        raise NotImplementedError("Read not implemented")

    def write(self, address, value):
        raise NotImplementedError("Write not implemented")


class GPIO(IODevice):
    # 8-bit GPIO
    def __init__(self, port_address, io_direction_address):
        self.port_address = port_address
        self.io_direction_address = io_direction_address
        self.io_direction_mask = 0

    def read(self, address):
        if (address == self.io_direction_mask):
            return self.io_direction_mask
        #raise ValueError(f"Invalid read address {address} for GPIO")
            
    def write(self, address, value):
        if (address == self.io_direction_address):
            self.io_direction_mask = value
            return self.io_direction_mask

        #raise ValueError(f"Invalid read address {address} for GPIO")

class SerialPort(IODevice):
    def __init__(self, input_address, output_address):
        self.input_address = input_address
        self.output_address = output_address

    def read(self, address):
        #print("READ SERIAL PORT ")
        if address == self.input_address:
            if key_pressed():
                return ord(read_key())
            return 0
        # If the read operation targets an unmapped address, we could raise an error
        raise ValueError(f"Invalid read address {address} for SerialPort")

    def write(self, address, value):
        #print(f"WRITE SERIAL PORT {address:04X} {self.output_address:04X} {value:02X}")
        if address == self.output_address:
            print(chr(value), end="")
            return 'A'
        # If the read operation targets an unmapped address, we could raise an error
        raise ValueError(f"Invalid read address {address} for SerialPort")

class SoundChip(IODevice):
    def __init__(self, sound_volume_address, sound_freq_address_low, sound_freq_address_high):
        self.volume_register = 0
        self.volume_freq_low = 0
        self.volume_freq_low_latched = 0
        self.volume_freq_high = 0

        self.sound_volume_address = sound_volume_address
        self.sound_freq_address_low = sound_freq_address_low
        self.sound_freq_address_high = sound_freq_address_high



    def read(self, address):
        if address == self.sound_volume_address:
            return self.volume_register
        # If the read operation targets an unmapped address, we could raise an error
        raise ValueError(f"Invalid read address {address} for SoundChip")

    def write(self, address, value):
        if address == self.sound_volume_address:
            self.volume_register = value
            logging.info(f"Sound chip volume set to: {value}")
        if address == self.sound_freq_address_low:
            self.sound_freq_address_low_latched = value
            logging.info(f"Sound chip freq low byte latched with: {value}")

        if address == self.sound_freq_address_high:
            self.sound_freq_address_low = self.sound_freq_address_low_latched
            self.sound_freq_address_high = value
            logging.info(f"Sound chip freq high byte set to: {value}")
            logging.info(f"Sound chip Frequency value 0x{self.sound_freq_address_high}{self.sound_freq_address_low}")
        else:
            raise ValueError(f"Invalid write address {address} for SoundChip")

class Memory:
    def __init__(self, rom_size, ram_size):
        self.rom = bytearray(rom_size)
        self.ram = bytearray(ram_size)
        logging.info(f"Memory rom size: {len(self.rom)}, ram size: {len(self.ram)}")
        self.io_devices = {}  # Dictionary to hold mapped I/O devices

    def map_io_device(self, address, device):
        """Map a hardware device to a specific memory address."""
        self.io_devices[address] = device

    def raw_read(self, address):
        return self.read(address, True)

    def raw_write(self, address, value):
        return self.write(address, value, True)

    def read(self, address, raw = False):
        """Read from memory or I/O device."""
        # Check if the address maps to an I/O device
        if not raw and address in self.io_devices:
            # Read from the mapped I/O device
            return self.io_devices[address].read(address)
        # Handle ROM/RAM reads based on the address range
        if address < len(self.rom):
            # Read from ROM
            return self.rom[address]
        elif len(self.rom) <= address < len(self.rom) + len(self.ram):
            # Read from RAM
            return self.ram[address - len(self.rom)]
        else:
            raise ValueError("Address out of bounds")

    def write(self, address, value, raw = False):
        """Write to memory or I/O device."""
        # Check if the address maps to an I/O device
        if not raw and address in self.io_devices:
            # Write to the mapped I/O device
            self.io_devices[address].write(address, value)
        # Handle ROM/RAM writes based on the address range
        elif len(self.rom) <= address < len(self.rom) + len(self.ram):
            # Write to RAM (ROM is typically read-only)
            self.ram[address - len(self.rom)] = value
        elif raw:
            self.rom[address] = value
        else:            
            raise ValueError("Address out of bounds")

    def size(self):
        return len(self.rom) + len(self.ram)
    
class Flag(Enum):
    Z = 0x01  # Zero flag (bit 0)
    S = 0x02  # Sign flag (bit 1)
    O = 0x04  # Odd parity flag (bit 2)
    V = 0x08  # Overflow flag (bit 3)
    C = 0x10  # Carry flag (bit 4)

class Operation(Enum):
    ADD = 0
    SUB = 1
    LOGICAL = 2
    SHIFT_RIGHT = 3
    SHIFT_LEFT = 4
    AND = 5
    OR = 6
    XOR = 7


class Processor:
    """ SAP2 Emulator - Little Endian Machine """
    def __init__(self, iomapped_memory):
        # Two banks of 4 general-purpose registers: R0, R1, R2, R3
        self.register_banks = [
            {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0},  # Bank 0
            {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0}   # Bank 1
        ]
        self.current_bank = 0  # Start with bank 0

        # Special registers
        self.registers = {
            'PC': 0,   # Program Counter
            'SP': 0xffff,  # Stack Pointer (pointing to top of RAM)
            'F': 0     # Flags register
        }

        # Memory layout: 32 KB ROM (0x0000 - 0x7FFF) and 32 KB RAM (0x8000 - 0xFFFF)
        self.iomemory = iomapped_memory

        # Load some example ROM code into the first 32KB of memory (ROM)
        # You could expand this with real code later on
        self.rom_loaded = False

    def set_flag(self, flag: Flag, value: bool):
        """Set or clear a flag in the Flags register."""
        if value:
            self.registers['F'] |= flag.value  # Set the flag
        else:
            self.registers['F'] &= ~flag.value  # Clear the flag

    def get_flag(self, flag: Flag) -> bool:
        return (self.registers['F'] & flag.value != 0)

    def check_flags(self, original_value:int, result:int, operand=None, operation:Operation=None) -> None:

        logging.info(f"check_flags: Original value: {original_value:02X} Result: {result:04X} Operand: {operand if operand else 'None'} Operation: {operation}")

        """Check and set the appropriate flags based on the result."""
        # Z (Zero) Flag: Set if result is zero
        self.set_flag(Flag.Z, result == 0)

        # S (Sign) Flag: Set if the most significant bit is set (sign bit for signed numbers)
        self.set_flag(Flag.S, (result & 0x80) != 0)

        # O (Odd Parity) Flag: Set if the number of 1's in the result is odd
        self.set_flag(Flag.O, bin(result).count('1') % 2 == 1)

        # C (Carry) Flag: Set if there was a carry/borrow in the operation
        if operation in [Operation.ADD, Operation.SUB] and operand is not None:
            if operation == Operation.ADD:
                carry_out = result > 0xFF  # Carry occurs if result is greater than 8 bits
            elif operation == Operation.SUB:
                carry_out = result < 0     # Borrow occurs if result is negative
            self.set_flag(Flag.C, carry_out)

        # V (Overflow) Flag: Set for signed overflow in addition/subtraction
        if operation in [Operation.ADD, Operation.SUB] and operand is not None:
           
            vsign = ((result & 0x80) ^ (original_value & 0x80)) & ((result & 0x80) ^ (operand & 0x80))
            #logging.info(f" {result:04x} A: 0x{original_value:02X} B: 0x{operand:02X}  New Overflow 0x{vsign:02x}")
            self.set_flag(Flag.V, vsign != 0)
            

        
    def reset(self) -> None:
        """Reset all registers and memory."""
        logging.info("Reset all registers and memory.")
        self.current_bank = 0
        self.register_banks = [
            {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0},
            {'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0}
        ]
        self.registers['PC'] = 0
        self.registers['SP'] = 0xffff
        self.registers['F'] = 0

        if not self.rom_loaded:
            # Example ROM code loaded into memory (for demo purposes)
            self.load_rom([0x01, 0x03, 0xFF, 0x00])
            self.rom_loaded = True

    def _map_regnum_to_key(self, reg:int) -> str:
        return f"R{reg}"

    def _write_memory(self, _16bitaddr, _8bitvalue) -> None:
        return self.iomemory.write(_16bitaddr, _8bitvalue)

    def _read_memory(self, _16bitaddr):
        return self.iomemory.read(_16bitaddr)

    def store_reg_at_address(self, reg_src, _16bitaddr) -> None:
        reg_val =self.get_reg(reg_src)
        self._write_memory(_16bitaddr, reg_val)
        


    def load_reg_from_address(self, reg_src:int, _16bitaddr:int) -> None:
        value = self._read_memory(_16bitaddr)
        logging.info(f"load_reg_from_address: ... {value:02X}")
        self.set_reg(reg_src, value)

    def get_pc(self) -> int:
        return self.registers['PC']

    def set_pc(self, _16bitvalue:int) -> None:
        self.registers['PC'] = _16bitvalue

    def set_sp(self, _16bitvalue:int):
        self.registers['SP'] = _16bitvalue

    def set_reg(self, reg:int, _8bitvalue:int) -> None:
        self.register_banks[self.current_bank][self._map_regnum_to_key(reg)] = _8bitvalue & 0xff

    def get_reg(self, reg:int) -> int:
        return self.register_banks[self.current_bank][self._map_regnum_to_key(reg)]

    def get_16bit_from_reg(self, reg:int):
        high =  self.register_banks[self.current_bank][self._map_regnum_to_key(reg)]
        low = self.register_banks[self.current_bank][self._map_regnum_to_key(reg + 1)]
        return high * 256 + low

    def load_rom(self, data) -> None:
        logging.info(f"load_rom {data}")
        """Load data (up to 32KB) into the ROM area."""

        for addr,value in enumerate(data):
            self.iomemory.raw_write(addr, data[addr])

        self.rom_loaded = True

    def load_ram(self, data, start_address) -> None:
        logging.info(f"load_ram:, {data},  into address , {start_addres}")
        """Load data (up to 32KB) into the RAM area."""
        for addr_offset,value in enumerate(data):
            #logging.info(f"Write to {(start_address + addr_offset):04X} {data[addr_offset]:02X}")
            self.iomemory.raw_write(start_address + addr_offset, data[addr_offset])
    
    def load_v3_hex(self, hex_file, rom_loaded=False):
        logging.info(f"Load V3 Hex file: {hex_file}")
        bytes_read = 0
        valid_lines = 0

        # Open and read the HEX file
        with open(hex_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                # Strip any surrounding whitespace
                line = line.strip()

                # Ignore empty lines
                if not line:
                    continue

                # Split the line into address and data parts
                parts = line.split(':')
                logging.info(parts)

                # Ignore any lines which do not follow the format 'address: data'
                if len(parts) != 2:  
                    continue
                
                # Parse the address (first part)
                address = int(parts[0], 16)

                # Parse the hex data (second part), splitting by spaces
                data_bytes = parts[1].strip().split()
                valid_lines += 1
                bytes_read += len(data_bytes)

                # Write each byte to the corresponding memory address
                for i, byte_str in enumerate(data_bytes):
                    byte_value = int(byte_str, 16)
                    self.iomemory.raw_write(address + i, byte_value)

        self.rom_loaded = rom_loaded

        logging.info(f"Hex file processing complete. Lines {valid_lines}. Bytes Read {bytes_read}.")


    def add_reg_value(self, reg:int, _8bitvalue:int) -> int:
        current_reg_value = self.register_banks[self.current_bank][self._map_regnum_to_key(reg)]
        new_value = current_reg_value + _8bitvalue
        new_value &= 0xff
        self.register_banks[self.current_bank][self._map_regnum_to_key(reg)] = new_value
        logging.info("add_reg_value(): TODO - WRAP 8bit add/sub ")
        return new_value

        
    def inc_pc(self) -> None:
        self.registers['PC'] += 1  # Increment PC to point to the next instruction
        self.registers['PC'] &= 0xffff

    def inc_sp(self) -> None:
        self.registers['SP'] += 1
        self.registers['SP'] &= 0xffff


    def dec_sp(self) -> None:
        self.registers['SP'] -= 1  
        self.registers['SP'] &= 0xffff

    def fetch(self) -> int:
        """Fetch the next opcode from memory (ROM or RAM)."""
        pc = self.registers['PC']
        opcode = self._read_memory(pc)
        logging.info(f"FETCH @ 0x{pc:04X} = 0x{opcode:02X}")
        self.inc_pc()
        return opcode

    def operand_8bit(self) -> int:
        pc = self.registers['PC']
        operand = self._read_memory(pc)
        self.inc_pc()
        return operand

    def pop_stack_16bit(self) -> (int,int):
        self.inc_sp()
        low = self._read_memory(self.registers['SP'])
        self.inc_sp()
        high = self._read_memory(self.registers['SP'])
        return low, high

    def push_stack_16bit(self, low:int, high:int) -> None:
       self._write_memory(self.registers['SP'], high)
       self.dec_sp()
       self._write_memory(self.registers['SP'], low)
       self.dec_sp()

       
    def operand_16bit(self) -> (int, int):
        pc = self.registers['PC']
        low = self._read_memory(pc)
        self.inc_pc()
        high = self._read_memory((pc+1) & 0xffff)
        self.inc_pc()
        return high, low

    def switch_bank(self) -> None:
        """Flip between the two banks of registers (EXX opcode)."""
        self.current_bank = 1 - self.current_bank  # Toggle between bank 0 and bank 1
        logging.info(f"Switched to register bank {self.current_bank}")

    def _flag_check(self, flg:Flag) -> int:
        return 0 if self.registers['F'] & flg.value == 0 else 1

    def flag_str(self) -> str:
        flag = self.registers['F']
        return f"Z:{self._flag_check(Flag.Z)} S:{self._flag_check(Flag.S)} O:{self._flag_check(Flag.O)} V:{self._flag_check(Flag.V)} C:{self._flag_check(Flag.C)}"

    def reg_dump(self) -> str:
        regdump = '\n'.join([ ', '.join(f"{reg}: 0x{bank[reg]:02X}" for reg in bank) for bank in self.register_banks])
        return regdump + "\n" + f"PC: 0x{self.registers['PC']:04X} SP: 0x{self.registers['SP']:04X}\nFlags: {self.flag_str()}"

    def stack_dump(self) -> None:
        #self.memory_dump(self.registers['SP']-31, 32)
        self.memory_dump(0xFFFF-31, 32)

    def memory_dump(self, address=0, size=1024) -> None:
        # Ensure the address is within bounds
        if address < 0:
            raise ValueError("Address cannot be negative.")
        if address >= self.iomemory.size():
            raise ValueError("Address is out of bounds.")

        # Limit end address to ensure we do not go out of bounds
        end_address = min(address + size, self.iomemory.size())

        # Iterate over the requested memory range and print in hex
        for i in range(address, end_address, 16):
            chunk = [self.iomemory.raw_read(i + offset) for offset in range(16)]   # Grab 16 bytes at a time
            hex_values = ' '.join(f'{byte:02X}' for byte in chunk)
            ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            print(f'{i:08X}  {hex_values:<47}  {ascii_values}')


opcode_map = {} # A dictionary to store the mapping of opcodes to functions
disassembly_map = {} # A dictionary to store the disassembly mnemonic for each opcode


def opcode_handler(start, end=None, mnemonic=None):
    """
    Decorator to map a range of opcodes to a function and store the mnemonic.
    :param start: The starting opcode value
    :param end: The ending opcode value (optional)
    :param mnemonic: The mnemonic string for disassembly (optional)
    """
    def add_opcode_to_map(func):
        nonlocal end
        if end is None:  # If no end is provided, it's a single opcode
            end = start
        for opcode in range(start, end + 1):
            opcode_map[opcode] = func
            if mnemonic:
                disassembly_map[opcode] = mnemonic
        return func
    return add_opcode_to_map


@opcode_handler(0x00, mnemonic="NOP") 
@opcode_handler(0x01, mnemonic="CLC")
@opcode_handler(0x02, mnemonic="SETC")
def handle_single(proc:Processor, opcode:int, mnemonic:str) -> None:
    if (opcode == 0x00):
        pass
    elif (opcode == 0x01):
        proc.set_flag(Flag.C, False)
    elif (opcode == 0x02):
        proc.set_flag(Flag.C, True)

# Undocumented OPCODE 'DUMP'
@opcode_handler(0x04, mnemonic="DUMP") 
def handle_dump(proc:Processor, opcode:int, mnemonic:str) -> None:
    print(proc.reg_dump())
    #proc.memory_dump()
    logging.info(f"STACK DUMP SP: 0x{proc.registers['SP']:04X}")
    proc.stack_dump()

    

@opcode_handler(0x14, 0x17, mnemonic="LD") 
@opcode_handler(0x18, 0x1b, mnemonic="ST")
@opcode_handler(0x1c, mnemonic="MOVWI SP")
def handle_load_store(proc:Processor, opcode:int, mnemonic:str) -> None:
    high_operand, low_operand = proc.operand_16bit()
    _16bitvalue = high_operand * 256 + low_operand

    print(f"{mnemonic}, {hex(_16bitvalue)}")
    if (opcode == 0x1c):
        proc.set_sp(_16bitvalue)
    elif (opcode > 0x17):
        reg_src = (opcode & 3)
        # STore contents of Reg reg_src into the memory location at address
        proc.store_reg_at_address(reg_src, _16bitvalue)
    else:
        #LD into reg - contents @ _16bitvalue address
        reg_src = (opcode & 3)
        proc.load_reg_from_address(reg_src, _16bitvalue)

@opcode_handler(0x1d,mnemonic="INC SP")
@opcode_handler(0x1e,mnemonic="DEC SP")
def handle_single_stack(proc:Processor, opcode:int, mnemonic:str) -> None:
    if (opcode == 0x1d):
        proc.inc_sp()
    elif (opcode == 0x1e):
        proc.dec_sp()


@opcode_handler(0x1f,0x20, mnemonic="PUSH")
def handle_push_reg(proc:Processor, opcode:int, mnemonic:str) -> None:
    logging.info(f"PUSH {opcode}")
    if (opcode == 0x1f):
        low, high = proc.get_reg(0), proc.get_reg(1)
        proc.push_stack_16bit(low, high)
    elif (opcode == 0x20):
        low, high = proc.get_reg(2), proc.get_reg(3)
        proc.push_stack_16bit(low, high)

@opcode_handler(0x22,0x23, mnemonic="POP")
def handle_pop_reg(proc:Processor, opcode:int, mnemonic:str) -> None:
    logging.info(f"POP {opcode}")
    if (opcode == 0x22):
        r0, r1 = proc.pop_stack_16bit()
        proc.set_reg(0, r0),
        proc.set_reg(1, r1)
    elif (opcode == 0x23):
        r2, r3 = proc.pop_stack_16bit()
        proc.set_reg(2, r2),
        proc.set_reg(3, r3)


@opcode_handler(0x25, mnemonic="EXX")
def handle_exx(proc:Processor, opcode:int, mnemonic:str) -> None:
    proc.switch_bank()

@opcode_handler(0x28, mnemonic="MOVWI R0")
@opcode_handler(0x2a, mnemonic="MOVWI R2")
def handle_movwi(proc:Processor, opcode:int, mnemonic:str) -> None:
    reg_src = (opcode & 2)
    high_operand, low_operand = proc.operand_16bit()
    logging.info(f"**************handle_movwi****************** {mnemonic}, {hex(high_operand * 256 + low_operand)}")
    proc.set_reg(reg_src, high_operand)
    proc.set_reg(reg_src + 1, low_operand)

@opcode_handler(0x4a,0x4f, mnemonic="MOVINDIRECT")
def handle_indirect(proc:Processor, opcode:int, mnemonic:str) -> None:
    _16bit_address = proc.get_16bit_from_reg(0)
    logging.info(f"handle_indirect: {_16bit_address:04X}")

    if (opcode == 0x4a):
    # ST R2,[R0R1]
        _reg = 2
        proc.store_reg_at_address(_reg, _16bit_address)
    elif (opcode == 0x4b):
    # ST R3,[R0R1]
        _reg = 3
        proc.store_reg_at_address(_reg, _16bit_address)
    elif (opcode == 0x4e):
    # LD R2,[R0R1]
        _reg = 2
        proc.load_reg_from_address(_reg, _16bit_address) # load into reg contents at address
    elif (opcode == 0x4f):
    # LD R3,[R0R1]
        _reg = 3
        proc.load_reg_from_address(_reg, _16bit_address) # load into reg contents at address
    else:
        raise NotImplementedError(f"Not implemented MOVINDIRECT opcode: {opcode}")

@opcode_handler(0x40, 0x43, mnemonic="MOVI")
@opcode_handler(0x44, 0x47, mnemonic="XORI")
@opcode_handler(0x50, 0x53, mnemonic="ADDI")
@opcode_handler(0x54, 0x57, mnemonic="SUBI")
@opcode_handler(0x58, 0x5b, mnemonic="ANDI")
@opcode_handler(0x5c, 0x5f, mnemonic="ORI")
def handle_1reg_18bit(proc:Processor, opcode:int, mnemonic:str) -> None:
    reg_dest = (opcode & 3)
    operand = proc.operand_8bit()
    operation = (opcode>>2) - 16
    org_value = proc.get_reg(reg_dest)
    logging.info(f"{mnemonic} r{reg_dest}, 0x{operand:02X} (group {operation})\n")


    if (operation == 0):
        #MOVI rx,_8bit
        proc.set_reg(reg_dest, operand)

    elif (operation == 1):
        #XORI rx,_8bit
        result = org_value ^ operand
        proc.check_flags(org_value, result)
        proc.set_reg(reg_dest, result)

    elif (operation == 4):
        result = (org_value + operand)
        proc.check_flags(org_value, result, operand = operand, operation = Operation.ADD)
        proc.set_reg(reg_dest, result)

    elif (operation == 5):
        result = org_value - operand
        proc.check_flags(org_value, result, operand = operand, operation = Operation.SUB)
        proc.set_reg(reg_dest,  result)

    elif (operation == 6):
        result = (org_value & operand)
        proc.check_flags(org_value, result)
        proc.set_reg(reg_dest, result)

    elif (operation == 7):
        result = org_value | operand
        proc.check_flags(org_value, result)
        proc.set_reg(reg_dest, result)
    else:
        logging.error("DO NOT KNOW HOW TO HANDLE")

@opcode_handler(0x60, 0x63, mnemonic="DJNZ")
def handle_dnjz(proc:Processor, opcode:int, mnemonic:str) -> None:
    reg_dest = opcode & 3
    high_operand, low_operand = proc.operand_16bit()
    _16bit_address = high_operand * 256 + low_operand
    org_value = proc.get_reg(reg_dest)

    logging.info(f"DJNZ R{reg_dest}, 0x{_16bit_address:04X}")

    result = proc.add_reg_value(reg_dest, -1)
    proc.check_flags(org_value, result, operation = Operation.SUB)
    if (proc.get_flag(Flag.Z) == False):
        proc.set_pc(_16bit_address)


@opcode_handler(0x64, 0x6B, mnemonic="JP")  # Condition Jump
def handle_cond_jump(proc:Processor, opcode:int, mnemonic:str) -> None:
    high_operand, low_operand = proc.operand_16bit()
    if (opcode == 0x64):
        flag_check = Flag.Z
        cond = True
    elif (opcode == 0x65):
        flag_check = Flag.Z
        cond = False
    elif (opcode == 0x66):
        flag_check = Flag.C
        cond = True
    elif (opcode == 0x67):
        flag_check = Flag.C
        cond = False
    elif (opcode == 0x68):
        flag_check = Flag.S
        cond = True
    elif (opcode == 0x69):
        flag_check = Flag.S
        cond = False
    elif (opcode == 0x6A):
        flag_check = Flag.V
        cond = True
    elif (opcode == 0x6B):
        flag_check = Flag.V
        cond = False

    logging.info(f"Handle conditional jump (code = 0x0{opcode:02X} - Flag {flag_check}) address {high_operand:02X}{low_operand:02X}")

    if (proc.get_flag(flag_check) == cond):
        proc.set_pc(high_operand * 256 + low_operand)

@opcode_handler(0x6c, mnemonic="JMP")  # Condition Jump
def handle_uncond_jump(proc:Processor, opcode:int, mnemonic:str) -> None:
    high_operand, low_operand = proc.operand_16bit()

    logging.info(f"JMP 0x{high_operand:02X}{low_operand:02X}")

    proc.set_pc(high_operand * 256 + low_operand)

@opcode_handler(0x6e, mnemonic="CALL")  # Condition Jump
def handle_call(proc:Processor, opcode:int, mnemonic:str) -> None:
    high_operand, low_operand = proc.operand_16bit()

    # Push PC onto stack
    pc = proc.get_pc()
    proc.push_stack_16bit(pc & 0xff, (pc >> 8) & 0xff)

    logging.info(f"Handle CALL to 0x{high_operand:02X}{low_operand:02X}")

    proc.set_pc(high_operand * 256 + low_operand)
    
@opcode_handler(0x6f, mnemonic="RET")  # Condition Jump
def handle_ret(proc:Processor, opcode:int, mnemonic:str) -> None:
    low, high  = proc.pop_stack_16bit()
    logging.info(f"Handle RET to return address 0x{high:02X}{low:02X}")
    proc.set_pc(high * 256 + low)



@opcode_handler(0x80,0x83, mnemonic="SHR" )
@opcode_handler(0x84,0x87, mnemonic="SHL" )
def handle_shift(proc:Processor, opcode:int, mnemonic:str) -> None:
    shift_left = (opcode >= 0x84)
    reg_src = (opcode & 3)
    #print(f"SHIFT{'LEFT' if shift_left else 'RIGHT'}",reg_src)

    carry = 1 if proc.get_flag(Flag.C) else 0

    if (shift_left):
        new_carry = proc.get_reg(reg_src) & 128
        result = ((proc.get_reg(reg_src)<<1) & 0xff)  | carry
    else:
        new_carry = proc.get_reg(reg_src) & 1
        result = (proc.get_reg(reg_src)>>1) | (carry<<7)
    proc.set_reg(reg_src,result)
    proc.set_flag(Flag.C, new_carry)

@opcode_handler(0x10, 0x13, mnemonic="OUT")
@opcode_handler(0x88, 0x8b, mnemonic="INC")
@opcode_handler(0x8c, 0x8f, mnemonic="DEC")
def handle_1reg_operation(proc:Processor, opcode:int, mnemonic:str) -> None:

    reg_src = (opcode & 3)
    org_value = proc.get_reg(reg_src)

    if (opcode > 0x8b):
        #proc.add_reg_value(reg_src, -1)
        operand = -1
        result = (org_value - 1)
        proc.check_flags(org_value, result, operand = operand, operation = Operation.ADD)
        proc.set_reg(reg_src, result)

    elif (opcode > 0x87):
        #proc.add_reg_value(reg_src, 1)
        operand = 1
        result = (org_value + 1)
        proc.check_flags(org_value, result, operand = operand, operation = Operation.ADD)
        proc.set_reg(reg_src, result)

    else:
        logging.info(f"OUT R{reg_src} = 0x{proc.get_reg(reg_src):02X} CHR: ")
        print(f"{chr(proc.get_reg(reg_src))}",end="")

@opcode_handler(0x90, 0x9f, mnemonic="MOV")
@opcode_handler(0xa0, 0xaf, mnemonic="ADD")
@opcode_handler(0xb0, 0xbf, mnemonic="SUB")
@opcode_handler(0xc0, 0xcf, mnemonic="AND")
@opcode_handler(0xd0, 0xdf, mnemonic="OR")
@opcode_handler(0xe0, 0xef, mnemonic="XOR")
def handle_2reg_operations(proc:Processor, opcode:int, mnemonic:str) -> None:
    operation = (opcode>>4) - 9
    reg_dest = (opcode>>2) & 3
    reg_src = (opcode & 3)
    org_value = proc.get_reg(reg_dest)

    logging.info(f"Handle operation= {operation} {mnemonic} r{reg_dest}, r{reg_src}")
    if (operation == 0):
        proc.set_reg(reg_dest,proc.get_reg(reg_src))
    elif (operation == 1):
        result = (org_value + proc.get_reg(reg_src) & 0xff)
        proc.set_reg(reg_dest, result)
        proc.check_flags(org_value, result, operand=proc.get_reg(reg_src), operation =  Operation.ADD)
    elif (operation == 2):
        result = (org_value - proc.get_reg(reg_src)) & 0xff
        proc.set_reg(reg_dest, result)
        proc.check_flags(org_value, result, operand=proc.get_reg(reg_src), operation = Operation.SUB)

    elif (operation == 3):
        result = org_value & proc.get_reg(reg_src)
        proc.set_reg(reg_dest, result)
        proc.check_flags(org_value, result, operation = Operation.AND)

    elif (operation == 4):
        result = org_value | proc.get_reg(reg_src)
        proc.set_reg(reg_dest, result)
        proc.check_flags(org_value, result, operation = Operation.OR)

    elif (operation == 5):
        result = org_value  ^ proc.get_reg(reg_src)
        proc.set_reg(reg_dest, result)
        proc.check_flags(org_value, result, operation = Operation.XOR)
    else:
        logging.error("INVALID OPCODE GROUP!!!")

@opcode_handler(0xff, mnemonic="HLT")
def handle_halt(proc:Processor, opcode:int, mnemonic:str) -> None:
    #logging.info(proc.reg_dump())
    print(cpu.reg_dump())
    while True:
        pass


# Simulator core: dispatch based on opcode
def execute_opcode(proc:Processor, opcode:int) -> None:
    handler = opcode_map.get(opcode)
    mnemonic = disassembly_map.get(opcode)
    if handler:
        logging.info(f"DISASSEMBLER {disassemble_opcode(opcode)}")
        handler(proc, opcode, mnemonic)
    else:
        logging.error(f"Unhandled opcode: {hex(opcode)}")


def execute_proc(proc:Processor) -> None:
    opcode = proc.fetch()
    execute_opcode(proc, opcode)

# Disassembler function: get mnemonic for an opcode
def disassemble_opcode(opcode:int) -> str:
    return disassembly_map.get(opcode, f"Unknown opcode: {hex(opcode)}")









# Examples Of Memory Mapped Hardware - SoundChip and Serial Port

sound_volume_address = 0x4fff
sound_freq_address_low = 0x4ffd
sound_freq_address_high = 0x4ffe

serial_out_address = 0x6000
serial_in_address = 0x6001

serial_port_address = 0x5000
serial_port_mask_address = 0x5001


memory_mapped_io = Memory(rom_size=0x8000, ram_size=0x8000)

sound_chip = SoundChip(sound_volume_address, sound_freq_address_low, sound_freq_address_high)
memory_mapped_io.map_io_device(sound_volume_address, sound_chip)
memory_mapped_io.map_io_device(sound_freq_address_low, sound_chip)
memory_mapped_io.map_io_device(sound_freq_address_high, sound_chip)


serial_chip = SerialPort(serial_in_address, serial_out_address)
memory_mapped_io.map_io_device(serial_out_address, serial_chip)
memory_mapped_io.map_io_device(serial_in_address, serial_chip)

gpio = GPIO(serial_port_address,serial_port_mask_address)
#memory_mapped_io.map_io_device(0, gpio)
#memory_mapped_io.map_io_device(1, gpio)

cpu = Processor(memory_mapped_io)

#cpu.load_rom(rom)
#cpu.load_ram(program, 0x8000)
cpu.load_v3_hex(file_name, rom_loaded=True)

if (single_step):
    cpu.memory_dump(address=0x0000, size=256)


# Simulate execution of the program
cpu.reset()
while True:
    execute_proc(cpu)
    if (single_step):
        print(cpu.reg_dump())
        cpu.stack_dump()
        print("Press 'S' to step to the next instruction...")
        skey = False
        while not skey:
            k = read_key()
            if (k == 's' or k == 'S'):
                skey = True


        

# Disassemble the program
#for i, byte in enumerate(program):
#    print(f"{i:02X}: {disassemble_opcode(byte)}")


