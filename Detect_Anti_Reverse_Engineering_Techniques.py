import idc
import idautils
import idaapi

def detect_patterns():
    results = {
        "consecutive jumps to the same target": [],
        "impossible_disassembly": [],
        "non_readable_segments": [],
        "being_debugged": [],
        "force_flags": [],
        "nt_global_flag": [],
        "unconditional_jumps": detect_unconditional_jumps()
    }

    negating_jumps = {
        'jz': 'jnz', 'jnz': 'jz', 'je': 'jne', 'jne': 'je',
        'jb': 'jae', 'jae': 'jb', 'ja': 'jbe', 'jbe': 'ja',
        'jl': 'jge', 'jge': 'jl', 'jg': 'jle', 'jle': 'jg'
    }

    for seg_ea in idautils.Segments():
        for head in idautils.Heads(idc.get_segm_start(seg_ea), idc.get_segm_end(seg_ea)):
            if not idc.is_code(ida_bytes.get_flags(head)):
                continue

            mnem = idc.print_insn_mnem(head)
            target = idc.get_operand_value(head, 0)

            detect_consecutive_jumps(head, mnem, target, negating_jumps, results)
            detect_impossible_disassembly(head, mnem, target, results)
            detect_non_readable_segments(seg_ea, results)
            detect_debug_checks(head, mnem, results)

    return results

def detect_consecutive_jumps(head, mnem, target, negating_jumps, results):
    if mnem in negating_jumps and target == idc.get_operand_value(idc.prev_head(head), 0):
        results["consecutive jumps to the same target"].append(f"Detected at {hex(head)} targeting {hex(target)}")

def detect_impossible_disassembly(head, mnem, target, results):
    if mnem in {'jmp', 'jz', 'je', 'jnz', 'jne', 'ja', 'jb', 'jg', 'jl'} and target != idc.BADADDR:
        if not idaapi.is_head(ida_bytes.get_flags(target)):
            prev_head = idc.prev_head(target)
            if prev_head != idc.BADADDR and (target - prev_head) > 0:
                results["impossible_disassembly"].append(f"Detected at {hex(head)} jumping into {hex(target)}")

def detect_non_readable_segments(seg_ea, results):
    seg_start = idc.get_segm_start(seg_ea)
    seg_perm = idaapi.getseg(seg_start).perm
    if seg_perm & idaapi.SEGPERM_EXEC and not seg_perm & idaapi.SEGPERM_READ:
        results["non_readable_segments"].append(f"Non-readable segment at {hex(seg_start)}")

def detect_unconditional_jumps():
    """ Detects sequences where an instruction guarantees the setting of the ZF (Zero Flag), followed by a 'jz' or 'je'. """
    unconditional_jumps = []
    for seg_ea in idautils.Segments():
        for head in idautils.Heads(idc.get_segm_start(seg_ea), idc.get_segm_end(seg_ea)):
            if not idc.is_code(ida_bytes.get_flags(head)):
                continue
            mnem = idc.print_insn_mnem(head)
            next_head = idc.next_head(head)
            if next_head != idc.BADADDR:
                next_mnem = idc.print_insn_mnem(next_head)
                if mnem in {"xor", "sub", "cmp"} and idc.print_operand(head, 0) == idc.print_operand(head, 1) and next_mnem in {"jz", "je"}:
                    unconditional_jumps.append(f"Unconditional jump at {hex(head)} via {mnem} setting ZF followed by {next_mnem} at {hex(next_head)}")
    return unconditional_jumps

def detect_debug_checks(head, mnem, results):
    if mnem == "mov" and "fs:30h" in idc.print_operand(head, 1):
        next_head = idc.next_head(head)
        next_mnem = idc.print_insn_mnem(next_head)
        if next_mnem == "mov":
            operand = idc.print_operand(next_head, 1)
            if "[eax+2]" in operand:
                results["being_debugged"].append(f"BeingDebugged check at {hex(head)}")
            elif "[eax+18h]" in operand and "[eax+10h]" in idc.print_operand(idc.next_head(next_head), 1):
                results["force_flags"].append(f"ForceFlags check at {hex(head)}")
            elif "[eax+68h]" in operand and idc.print_insn_mnem(idc.next_head(next_head)) == "sub":
                results["nt_global_flag"].append(f"NTGlobalFlag check at {hex(head)}")

def print_results(results):
    for key, value in results.items():
        if value:
            print(f"Detected {key.replace('_', ' ').title()}:")
            for v in value:
                print("-", v)

def main():
    results = detect_patterns()
    print_results(results)

if __name__ == "__main__":
    main()
