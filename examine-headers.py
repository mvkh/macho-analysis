import mmap
import click

magic_numbers = ['cafebabe','feedface','feedfacf']

binary_type = {
    magic_numbers[0]: 'Multi-architecture binary ("fat").',
    magic_numbers[1]: '32-bit binary.',
    magic_numbers[2]: '64-bit binary.'
}

cpu_types = {
    "0001": "VAX",
    "0002": "ROMP",
    "0004": "NS32032",
    "0005": "NS32332",
    "0006": "MC680x0",
    "0007": "x86",
    "0008": "MIPS",
    "0009": "NS32352",
    "000b": "HP-PA",
    "000c": "ARM",
    "000d": "MC88000",
    "000e": "SPARC",
    "000f": "i860 (big-endian)",
    "0010": "i860 (little-endian) or DEC Alpha",
    "0011": "RS/6000",
    "0012": "PowerPC / MC98000 "
}

arm_subtypes = {
    "0000": "All ARM processors",
    "0001": "Optimized for ARM-A500 ARCH or newer",
    "0002": "Optimized for ARM-A500 or newer",
    "0003": "Optimized for ARM-A440 or newer",
    "0004": "Optimized for ARM-M4 or newer",
    "0005": "Optimized for ARM-V4T or newer",
    "0006": "Optimized for ARM-V6 or newer",
    "0007": "Optimized for ARM-V5TEJ or newer",
    "0008": "Optimized for ARM-XSCALE or newer",
    "0009": "Optimized for ARM-V7 or newer",
    "000a": "Optimized for ARM-V7F (Cortex A9) or newer",
    "000b": "Optimized for ARM-V7S (Swift) or newer",
    "000c": "Optimized for ARM-V7K (Kirkwood40) or newer",
    "000d": "Optimized for ARM-V8 or newer",
    "000e": "Optimized for ARM-V6M or newer",
    "000f": "Optimized for ARM-V7M or newer",
    "0010": "Optimized for ARM-V7EM or newer"
}

arm64_subtypes = {
    "0000": "All ARM64 processors",
    "0001": "Optimized for ARM64v8 or newer",
    "0002": "Optimized for ARM64E or newer"
}

x86_subtypes = {
    "0003": "All x86 processors",
    "0004": "Optimized for 486 or newer",
    "0084": "Optimized for 486SX or newer",
    "0056": "Optimized for Pentium M5 or newer",
    "0067": "Optimized for Celeron or newer",
    "0077": "Optimized for Celeron Mobile",
    "0008": "Optimized for Pentium 3 or newer",
    "0018": "Optimized for Pentium 3-M or newer",
    "0028": "Optimized for Pentium 3-XEON or newer",
    "000a": "Optimized for Pentium-4 or newer",
    "000b": "Optimized for Itanium or newer",
    "001b": "Optimized for Itanium-2 or newer",
    "000c": "Optimized for XEON or newer",
    "001c": "Optimized for XEON-MP or newer"
}

def analyze_fat(mm):
    num_of_binaries = int.from_bytes(mm[4:8],byteorder="big")
    print(f'\tA total of {num_of_binaries} binaries.')
    base = 8
    ufe_size = 20
    for i in range(num_of_binaries):
        offset = base + i * ufe_size

        cpu           = int.from_bytes(mm[offset:(offset+4)],byteorder="big")
        abi64         = cpu & 0x01000000
        abi64_32      = cpu & 0x02000000
        cpu_index     = bytes(mm[(offset+2):(offset+4)]).hex()
        cpu_type      = bytes(mm[offset:(offset+4)]).hex()
        subtype       = int.from_bytes(mm[(offset+4):(offset+8)],byteorder="big")
        versptrauth   = subtype & 0x80000000
        kernelabi     = subtype & 0x40000000
        ptrauthver    = (subtype & 0x0f000000) >> 24
        cpu_subtype   = bytes(mm[(offset+4):(offset+8)]).hex()
        subtype_index = bytes(mm[(offset+6):(offset+8)]).hex()
        file_offset = int.from_bytes(mm[(offset+8):(offset+12)],byteorder="big")
        size        = int.from_bytes(mm[(offset+12):(offset+16)],byteorder="big")
        alignment   = int.from_bytes(mm[(offset+16):(offset+20)],byteorder="big")

        print(f'\tBinary {i+1}:')
        type_string = (cpu_types[cpu_index] if (cpu_index in cpu_types) else 'Unknown CPU type') + (' with 64 bit ABI' if abi64 else '') + (' with ABI for 64-bit hardware with 32-bit types; LP32' if abi64_32 else '')
        print(f'\t\tCPU type: 0x{cpu_type} ({type_string})')
        unknown_string   = 'Unknown CPU subtype'
        subtype_string = ''
        if (cpu_index == '000c'):
            if abi64:
                subtype_string = f'{arm64_subtypes[subtype_index] if (subtype_index in arm64_subtypes) else unknown_string}' + (', versioned binary' if versptrauth else '') + (', using a kernel ABI' if kernelabi else '')
            else:
                subtype_string = f'{arm_subtypes[subtype_index]}' if (subtype_index in arm_subtypes) else unknown_string
        elif (cpu_index == '0007'):
            subtype_string = f'{x86_subtypes[subtype_index]}' if (subtype_index in x86_subtypes) else unknown_string
        else:
            subtype_string = unknown_string
        print(f'\t\tCPU subtype: 0x{cpu_subtype} ({subtype_string})')

    return

@click.command()
@click.option('--binary', prompt='Path to a binary file', help='Binary file to analyze')
def examine_headers(binary):
    """Simple script to examine Mach-O binary file headers."""

    with open(binary, "rb") as bf:
        mm = mmap.mmap(bf.fileno(), 256, prot=mmap.PROT_READ)
        magic_number = bytes(mm[0:4]).hex()
        print(f'Looking at the headers for "{binary}":')
        print(f'\tMagic number: 0x{magic_number}.')
        if (magic_number in magic_numbers):
            print(f'\t{binary_type[magic_number]}')
            if (magic_number == magic_numbers[0]):
                analyze_fat(mm)
        else:
            print('\tUnknown binary format.')

    return

if __name__ == '__main__':
    examine_headers()