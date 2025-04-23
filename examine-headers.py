import mmap
import click

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

file_types = {
    "00000001": "Relocatable object file.",
    "00000002": "Demand paged executable file.",
    "00000003": "Fixed VM shared library file.",
    "00000004": "Core file.",
    "00000005": "Preloaded executable file.",
    "00000006": "Dynamically bound shared library file.",
    "00000007": "Dynamic link editor.",
    "00000008": "Dynamically bound bundle file.",
    "00000009": "Shared library stub for static linking only, no section contents.",
    "0000000a": "Companion file with only debug sections.",
    "0000000b": "x86_64 kexts.",
    "0000000c": "A file composed of other Mach-Os to be run in the same userspace sharing a single linkedit. "
}

flag_list = [
    [1<<0, "The object file has no undefined references."],
    [1<<1, "The object file is the output of an incremental link against a base file and can't be link edited again."],
    [1<<2, "The object file is input for the dynamic linker and can't be statically link edited again."],
    [1<<3, "The object file's undefined references are bound by the dynamic linker when loaded."],
    [1<<4, "The file has its dynamic undefined references prebound."],
    [1<<5, "The file has its read-only and read-write segments split."],
    [1<<6, "The shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)."],
    [1<<7, "The image is using two-level name space bindings."],
    [1<<8, "The executable is forcing all images to use flat name space bindings."],
    [1<<9, "This umbrella guarantees no multiple definitions of symbols in its sub-images so the two-level namespace hints can always be used."],
    [1<<10, "Do not have dyld notify the prebinding agent about this executable."],
    [1<<11, "The binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set."],
    [1<<12, "This binary binds to all two-level namespace modules of its dependent libraries."],
    [1<<13, "Safe to divide up the sections into sub-sections via symbols for dead code stripping."],
    [1<<14, "The binary has been canonicalized via the un-prebind operation."],
    [1<<15, "The final linked image contains external weak symbols."],
    [1<<16, "The final linked image uses weak symbols."],
    [1<<17, "All stacks in the task will be given stack execution privilege."],
    [1<<18, "The binary declares it is safe for use in processes with uid zero."],
    [1<<19, "The binary declares it is safe for use in processes when UGID is true."],
    [1<<20, "The static linker does not need to examine dependent dylibs to see if any are re-exported."],
    [1<<21, "The OS will load the main executable at a random address."],
    [1<<22, "The static linker will automatically not create a load command to the dylib if no symbols are being referenced from the dylib."],
    [1<<23, "Contains a section of type S_THREAD_LOCAL_VARIABLES."],
    [1<<24, "The OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it."],
    [1<<25, "The code was linked for use in an application."],
    [1<<26, "The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info."],
    [1<<27, "Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with the platforms macOS, macCatalyst, iOSSimulator, tvOSSimulator and watchOSSimulator."],
    [1<<31, "The dylib is part of the dyld shared cache, rather than loose in the filesystem."]
]

MH_MAGIC_64 = 'feedfacf'
MH_CIGAM_64 = 'cffaedfe'

magic_numbers = ['cafebabe', 'feedface', MH_MAGIC_64, MH_CIGAM_64]

binary_type = {
    magic_numbers[0]: 'Multi-architecture binary ("fat").',
    magic_numbers[1]: '32-bit binary.',
    magic_numbers[2]: '64-bit binary.',
    magic_numbers[3]: '64-bit binary.'
}

def big_endian_byte_array(ba, endianness='big'):
    """Convert byte array to big-endian order."""

    return ba if (endianness == 'big') else ba[::-1]

def get_cpu_type_description(cpu_type):
    """Return a human-readable description of CPU type."""

    cpu           = int.from_bytes(cpu_type, byteorder='big')
    abi64         = cpu & 0x01000000
    abi64_32      = cpu & 0x02000000
    cpu_index     = bytes(cpu_type[2:4]).hex()

    return cpu_types.get(cpu_index, 'Unknown CPU type') + (' with 64 bit ABI' if abi64 else '') + (' with ABI for 64-bit hardware with 32-bit types; LP32' if abi64_32 else '')

def get_cpu_subtype_description(cpu_type, cpu_subtype):
    """Return a human-readable description of CPU subtype."""

    cpu           = int.from_bytes(cpu_type, byteorder='big')
    abi64         = cpu & 0x01000000
    abi64_32      = cpu & 0x02000000
    cpu_index     = (cpu_type[2:4]).hex()
    subtype       = int.from_bytes(cpu_subtype, byteorder='big')
    versptrauth   = subtype & 0x80000000
    kernelabi     = subtype & 0x40000000
    ptrauthver    = (subtype & 0x0f000000) >> 24
    subtype_index = (cpu_subtype[2:4]).hex()

    unknown_string   = 'Unknown CPU subtype'
    subtype_string = ''
    if (cpu_index == '000c'):
        if abi64:
            subtype_string = arm64_subtypes.get(subtype_index, unknown_string) + (', versioned binary' if versptrauth else '') + (', using a kernel ABI' if kernelabi else '')
        else:
            subtype_string = arm_subtypes.get(subtype_index, unknown_string)
    elif (cpu_index == '0007'):
        subtype_string = x86_subtypes.get(subtype_index, unknown_string)
    else:
        subtype_string = unknown_string

    return subtype_string

def get_file_type_description(file_type):
    """Return a human-readable description of fily type."""

    return file_types.get(file_type.hex(), "Unknown file type")

def get_flags_description(flags, prefix=''):
    """Return a human-readable description of flags field."""

    flags_num   = int.from_bytes(flags, byteorder='big')
    description = ''

    for flag in flag_list:
        description += f'{prefix}0x{flag[0]:08x}: {flag[1]}\n' if (flags_num & flag[0]) else ''

    return description

def analyze_fat(mm):
    """Analyze multi-architecture file header and included binaries' headers."""

    magic_number = bytes(mm[0:4]).hex()
    print(f'\tMagic number: 0x{magic_number}.')

    num_of_binaries = int.from_bytes(mm[4:8],byteorder="big")
    print(f'\tA total of {num_of_binaries} binaries.')
    base = 8
    ufe_size = 20
    for i in range(num_of_binaries):
        offset = base + i * ufe_size

        cpu_type      = mm[offset:(offset+4)]
        cpu_subtype   = mm[(offset+4):(offset+8)]
        file_offset   = int.from_bytes(mm[(offset+8):(offset+12)],byteorder="big")
        binary_size   = int.from_bytes(mm[(offset+12):(offset+16)],byteorder="big")
        alignment     = int.from_bytes(mm[(offset+16):(offset+20)],byteorder="big")

        print(f'\tBinary {i+1}:')
        print(f'\t\tCPU type: 0x{cpu_type.hex()} ({get_cpu_type_description(cpu_type)}).')
        print(f'\t\tCPU subtype: 0x{cpu_subtype.hex()} ({get_cpu_subtype_description(cpu_type,cpu_subtype)}).')
        print(f'\t\tFile offset: {file_offset} bytes.')
        print(f'\t\tSize: {binary_size} bytes.')
        print(f'\t\tAlignment: 2^{alignment} ({2**alignment}) bytes.\n')

        analyze_macho(mm[file_offset:(file_offset + 32)], print_prefix='\t\t\t')

    return

def analyze_macho(mm, print_prefix=''):
    """Analyze Mach-O file header."""

    magic_number = (mm[0:4]).hex()
    endianness = ''
    extra_info = 'unknown format'
    if (magic_number == MH_MAGIC_64):
        endianness = 'big'
        extra_info = 'big-endian'
    elif (magic_number == MH_CIGAM_64):
        endianness = 'little'
        extra_info = 'little-endian'
    print(f'{print_prefix}Magic number: 0x{magic_number} ({extra_info}).')
    if (endianness == ''):
        return
    
    cpu_type    = big_endian_byte_array(mm[4:8], endianness)
    cpu_subtype = big_endian_byte_array(mm[8:12], endianness)
    file_type   = big_endian_byte_array(mm[12:16], endianness)
    num_loads   = int.from_bytes(mm[16:20], byteorder=endianness)
    size_loads  = int.from_bytes(mm[20:24], byteorder=endianness)
    flags       = big_endian_byte_array(mm[24:28], endianness)

    print(f'{print_prefix}CPU type: 0x{cpu_type.hex()} ({get_cpu_type_description(cpu_type)}).')
    print(f'{print_prefix}CPU subtype: 0x{cpu_subtype.hex()} ({get_cpu_subtype_description(cpu_type,cpu_subtype)}).')
    print(f'{print_prefix}File type: 0x{file_type.hex()} ({get_file_type_description(file_type)}).')
    print(f'{print_prefix}Number of load commands: {num_loads}.')
    print(f'{print_prefix}Size of load commands: {size_loads}.')
    print(f'{print_prefix}Flags: 0x{flags.hex()}.')
    print(get_flags_description(flags, print_prefix + '\t'))

    return

@click.command()
@click.option('--binary', prompt='Path to a binary file', help='Binary file to analyze')
def examine_headers(binary):
    """Simple script to examine Mach-O binary file headers."""

    with open(binary, "rb") as bf:
        print(f'Looking at the headers for "{binary}":\n')
        mm = bytearray(mmap.mmap(bf.fileno(), 0, prot=mmap.PROT_READ))
        magic_number = bytes(mm[0:4]).hex()
    
        if (magic_number in magic_numbers):
            if (magic_number == magic_numbers[0]):
                analyze_fat(mm)
            if (magic_number in [MH_MAGIC_64, MH_CIGAM_64]):
                analyze_macho(mm[0:32], print_prefix='\t')
        else:
            print('\tUnknown binary format.')

    return

if __name__ == '__main__':
    examine_headers()