"""
asmanalyzer.py — Assembly-level analysis engine for StaticElf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Provides per-function disassembly metrics and semantic similarity
scoring based on instruction category distributions.

What we measure (all trustworthy under static analysis):
    - Instruction count per function
    - Basic block count (terminator-based, no edge inference)
    - Avg instructions per block
    - Top-10 mnemonic frequency
    - Semantic category histogram (branch/memory/arith/logic/call/ret/other)
    - Cosine similarity of semantic histograms across binaries

What we deliberately do NOT measure:
    - Dead / unreachable blocks  (indirect jumps make this unreliable)
    - Exact CFG edges            (indirect branches can't be resolved statically)
    - Cyclomatic complexity      (depends on accurate edge count)

Requires:
    capstone >= 4.0   (pip install capstone)

Supported architectures:
    x86, x86_64, ARM (32-bit), AArch64, MIPS (32/64), PowerPC (32/64)
"""

import math
import collections

try:
    import capstone
    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


# ------------------------------------------------------------------ #
#  Architecture → Capstone mapping                                     #
# ------------------------------------------------------------------ #

def _get_cs_mode(arch_info: dict):
    if not _CAPSTONE_AVAILABLE:
        return None

    machine    = arch_info.get("machine", "").lower()
    bits       = arch_info.get("bits", 64)
    endianness = arch_info.get("endianness", "little")
    big        = capstone.CS_MODE_BIG_ENDIAN
    lit        = capstone.CS_MODE_LITTLE_ENDIAN

    _map = {
        "x86":      (capstone.CS_ARCH_X86,  capstone.CS_MODE_32),
        "x86_64":   (capstone.CS_ARCH_X86,  capstone.CS_MODE_64),
        "arm":      (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM | (big if endianness == "big" else lit)),
        "aarch64":  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM | lit),
        "mips":     (capstone.CS_ARCH_MIPS,  (capstone.CS_MODE_MIPS32 if bits == 32 else capstone.CS_MODE_MIPS64)
                                              | (big if endianness == "big" else lit)),
        "powerpc":  (capstone.CS_ARCH_PPC,   (capstone.CS_MODE_32 if bits == 32 else capstone.CS_MODE_64)
                                              | (big if endianness == "big" else lit)),
        "powerpc64":(capstone.CS_ARCH_PPC,   capstone.CS_MODE_64 | (big if endianness == "big" else lit)),
    }
    return _map.get(machine)


# ------------------------------------------------------------------ #
#  Block counting (terminator-based, no edge inference)                #
# ------------------------------------------------------------------ #

_BLOCK_TERMINATORS = frozenset([
    # x86/x64
    "ret","retn","retf","iret","iretd","iretq",
    "jmp","je","jne","jz","jnz","jl","jle","jg","jge",
    "ja","jae","jb","jbe","js","jns","jo","jno","jp","jnp",
    "jcxz","jecxz","jrcxz","loop","loope","loopne",
    # ARM/AArch64
    "b","bl","bx","blx","beq","bne","blt","ble","bgt","bge",
    "blo","bls","bhi","bhs","b.eq","b.ne","b.lt","b.le",
    "b.gt","b.ge","b.lo","b.ls","b.hi","b.hs",
    "cbz","cbnz","tbz","tbnz","blr","br","ret",
    # MIPS
    "j","jal","jalr","jr","beq","bne","blez","bgtz","bltz","bgez",
    # PPC
    "blr","bctr","bctrl","bc",
])


def _count_blocks(insns: list) -> int:
    """Count basic blocks by counting terminator instructions."""
    if not insns:
        return 0
    count = 1
    for insn in insns[:-1]:
        if insn.mnemonic.lower() in _BLOCK_TERMINATORS:
            count += 1
    return count


# ------------------------------------------------------------------ #
#  Semantic histogram + cosine similarity                              #
# ------------------------------------------------------------------ #

class WLKernel:
    """
    Instruction semantic similarity via category frequency histograms.

    Groups architecture-specific mnemonics into 7 semantic categories
    so x86 'mov' and ARM 'ldr' both count as 'memory'. This makes
    similarity scores meaningful across architectures.
    """

    _BRANCH_PREFIXES = ("j","b","cbz","cbnz","tbz","tbnz","beq","bne",
                        "blt","ble","bgt","bge","blo","bls","bhi","bhs","loop","bc")
    _MEM_PREFIXES    = ("mov","ldr","str","ld","st","push","pop","lea",
                        "xchg","cmpxchg","movs","lods","stos","lwz","stw",
                        "sw","lw","sb","lb","sh","lh")
    _ARITH_PREFIXES  = ("add","sub","mul","div","inc","dec","neg","abs",
                        "adc","sbb","imul","idiv","addi","subi","addiu",
                        "addu","subu","madd","msub")
    _LOGIC_PREFIXES  = ("and","or","xor","not","test","cmp","shl","shr",
                        "sar","rol","ror","rcl","rcr","bsf","bsr","bit",
                        "andi","ori","xori","sll","srl","sra","nor","nand")
    _CALL_PREFIXES   = ("call","blx","jal","jalr","bal")
    _RET_PREFIXES    = ("ret","iret","blr","jr")

    def _categorise(self, mnem: str) -> str:
        m = mnem.lower().strip()
        if any(m.startswith(p) for p in self._RET_PREFIXES):    return "ret"
        if any(m.startswith(p) for p in self._CALL_PREFIXES):   return "call"
        if m == "bl":                                             return "call"
        if any(m.startswith(p) for p in self._BRANCH_PREFIXES): return "branch"
        if any(m.startswith(p) for p in self._MEM_PREFIXES):    return "memory"
        if any(m.startswith(p) for p in self._ARITH_PREFIXES):  return "arith"
        if any(m.startswith(p) for p in self._LOGIC_PREFIXES):  return "logic"
        return "other"

    def compute_histogram(self, func_insns: list) -> dict:
        hist = collections.Counter()
        for insns in func_insns:
            for insn in insns:
                hist[self._categorise(insn.mnemonic)] += 1
        return dict(hist)

    def similarity(self, hist_a: dict, hist_b: dict) -> float:
        all_keys = set(hist_a) | set(hist_b)
        if not all_keys:
            return 0.0
        dot   = sum(hist_a.get(k, 0) * hist_b.get(k, 0) for k in all_keys)
        mag_a = math.sqrt(sum(v * v for v in hist_a.values()))
        mag_b = math.sqrt(sum(v * v for v in hist_b.values()))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return round(dot / (mag_a * mag_b), 6)


# ------------------------------------------------------------------ #
#  ASMAnalyzer                                                         #
# ------------------------------------------------------------------ #

class ASMAnalyzer:
    """
    Assembly-level analysis for a single ELF binary.

    All metrics derive from linear disassembly only — no control flow
    inference, no dead code speculation.
    """

    MAX_FUNC_BYTES = 64 * 1024

    def __init__(self, path: str, arch_info: dict, symbols: list):
        self.path        = path
        self.arch_info   = arch_info
        self.symbols     = symbols
        self.metrics     = {}
        self.wl_hist     = {}
        self._func_insns = []

    def _load_text_section(self) -> tuple:
        try:
            from elftools.elf.elffile import ELFFile
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if section.name == ".text":
                        return section.data(), section["sh_addr"]
        except Exception:
            pass
        return b"", 0

    def _get_top_functions(self, n: int) -> list:
        funcs = []
        for sym in self.symbols:
            if sym.get("type") != "STT_FUNC":
                continue
            size = sym.get("size", 0)
            addr = sym.get("value", 0)
            name = sym.get("name", "").strip()
            if not name or size <= 0 or size > self.MAX_FUNC_BYTES:
                continue
            funcs.append({"name": name, "addr": addr, "size": size})
        funcs.sort(key=lambda x: x["size"], reverse=True)
        return funcs[:n]

    def analyze(self, top_n: int = 100) -> dict:
        if not _CAPSTONE_AVAILABLE:
            self.metrics = {"available": False}
            return self.metrics

        cs_params = _get_cs_mode(self.arch_info)
        if cs_params is None:
            self.metrics = {
                "available":      True,
                "error":          f"Unsupported arch: {self.arch_info.get('machine','?')}",
                "function_count": 0,
            }
            return self.metrics

        try:
            cs = capstone.Cs(*cs_params)
            cs.detail = False
        except Exception as e:
            self.metrics = {"available": True, "error": str(e), "function_count": 0}
            return self.metrics

        text_data, text_addr = self._load_text_section()
        if not text_data:
            self.metrics = {"available": True, "error": "No .text section", "function_count": 0}
            return self.metrics

        funcs        = self._get_top_functions(top_n)
        all_insns    = []
        func_details = []
        mnem_counter = collections.Counter()

        for func in funcs:
            offset = func["addr"] - text_addr
            if offset < 0 or offset + func["size"] > len(text_data):
                continue

            code  = text_data[offset : offset + func["size"]]
            insns = list(cs.disasm(code, func["addr"]))
            if not insns:
                continue

            block_count = _count_blocks(insns)
            instr_count = len(insns)

            for insn in insns:
                mnem_counter[insn.mnemonic] += 1

            all_insns.append(insns)
            func_details.append({
                "name":               func["name"],
                "addr":               hex(func["addr"]),
                "size":               func["size"],
                "instr_count":        instr_count,
                "block_count":        block_count,
                "avg_instr_per_block": round(instr_count / block_count, 2) if block_count else 0.0,
            })

        self._func_insns  = all_insns
        total_instrs      = sum(f["instr_count"] for f in func_details)
        total_blocks      = sum(f["block_count"] for f in func_details)
        n_funcs           = len(func_details)

        wl       = WLKernel()
        sem_hist = wl.compute_histogram(all_insns)
        self.wl_hist = sem_hist

        self.metrics = {
            "available":           True,
            "function_count":      n_funcs,
            "total_instructions":  total_instrs,
            "avg_instr_per_func":  round(total_instrs / n_funcs,   2) if n_funcs       else 0.0,
            "avg_blocks_per_func": round(total_blocks / n_funcs,   2) if n_funcs       else 0.0,
            "avg_instr_per_block": round(total_instrs / total_blocks, 2) if total_blocks else 0.0,
            "top_mnemonics":       [{"mnemonic": m, "count": c} for m, c in mnem_counter.most_common(10)],
            "semantic_histogram":  sem_hist,
            "wl_histogram":        sem_hist,
            "functions":           func_details,
        }
        return self.metrics

    def wl_similarity(self, other: "ASMAnalyzer") -> float:
        if not self.wl_hist or not other.wl_hist:
            return 0.0
        return WLKernel().similarity(self.wl_hist, other.wl_hist)


def capstone_available() -> bool:
    return _CAPSTONE_AVAILABLE
