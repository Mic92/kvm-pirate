from typing import Type, Union

from ..cpu import (
    CPU_64BITS,
    CPU_AARCH64,
    CPU_ARM32,
    CPU_BIGENDIAN,
    CPU_I386,
    CPU_PPC32,
    CPU_PPC64,
    CPU_X86_64,
)
from .consts import (
    ELFCLASS32,
    ELFCLASS64,
    ELFDATA2LSB,
    ELFDATA2MSB,
    EM_386,
    EM_AARCH64,
    EM_ARM,
    EM_PPC,
    EM_PPC64,
    EM_X86_64,
)
from .structs import (
    Elf32_Ehdr,
    Elf32_Phdr,
    Elf32_Shdr,
    Elf64_Ehdr,
    Elf64_Phdr,
    Elf64_Shdr,
)

if CPU_64BITS:
    Ehdr: Type[Union[Elf32_Ehdr, Elf64_Ehdr]] = Elf64_Ehdr
    Phdr: Type[Union[Elf32_Phdr, Elf64_Phdr]] = Elf64_Phdr
    Shdr: Type[Union[Elf32_Shdr, Elf64_Shdr]] = Elf64_Shdr
    ELFCLASS = ELFCLASS64
else:
    Ehdr = Elf32_Ehdr
    Phdr = Elf32_Phdr
    Shdr = Elf32_Shdr
    ELFCLASS = ELFCLASS32

if CPU_BIGENDIAN:
    ELFDATA2 = ELFDATA2MSB
else:
    ELFDATA2 = ELFDATA2LSB

if CPU_PPC32:
    ELFARCH = EM_PPC
elif CPU_PPC64:
    ELFARCH = EM_PPC64
elif CPU_ARM32:
    ELFARCH = EM_ARM
elif CPU_AARCH64:
    ELFARCH = EM_AARCH64
elif CPU_X86_64:
    ELFARCH = EM_X86_64
elif CPU_I386:
    ELFARCH = EM_386
else:
    raise NotImplementedError("Architecture not supported")
