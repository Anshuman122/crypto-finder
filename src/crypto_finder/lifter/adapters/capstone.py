

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from typing import List, Dict

class CapstoneAdapter:
  

    def __init__(self, arch=CS_ARCH_X86, mode=CS_MODE_64):
        self.md = Cs(arch, mode)

    def disassemble(self, code: bytes, address: int) -> List[Dict]:

        instructions = []
        for i in self.md.disasm(code, address):
            instructions.append({
                "address": "0x%x" % i.address,
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
            })
        return instructions
