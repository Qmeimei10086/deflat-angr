from collections import deque

import ida_funcs
import idaapi
import idautils
import idc
import keystone


def patch_ins_to_nop(ins):
    size = idc.get_item_size(ins)
    for i in range(size):
        idc.patch_byte(ins + i,0x90)


def patch_bytes(addr, data):
    for i, b in enumerate(data):
        idc.patch_byte(addr + i, b)


def fill_nop(start_ea, end_ea):
    # [FIX 1] 应该是 end - start，否则是负数
    size = end_ea - start_ea 
    if size > 0:
        # [FIX 2] 使用 patch_bytes 批量写入
        patch_bytes(start_ea, b'\x90' * size)

def get_block_by_address(ea):
    func = idaapi.get_func(ea)
    blocks = idaapi.FlowChart(func)
    for block in blocks:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None

def generate_jmp_code(src, dst):
    # E9 xx xx xx xx
    offset = dst - (src + 5)
    return b'\xE9' + offset.to_bytes(4, 'little', signed=True)

def generate_jz_code(src, dst):
    # 0F 84 xx xx xx xx
    offset = dst - (src + 6)
    return b'\x0F\x84' + offset.to_bytes(4, 'little', signed=True)

def patch_branch(patch_dict):
    for ea in patch_dict:
        values = patch_dict[ea]
        if len(values) == 0:#如果后继块为0,基本都是return块,不需要patch,直接跳过
            continue
        block = get_block_by_address(int(ea, 16))
        start_ea = block.start_ea
        end_ea = block.end_ea
        last_ins_ea = idc.prev_head(end_ea)#因为block.end_ea获取的地址是块最后一个地址的下一个地址,所以需要向上取一个地址
        if len(values) == 2:
            for ins in idautils.Heads(start_ea,end_ea):
                if idc.print_insn_mnem(ins).startswith("cmov"):
                    print("find cmov")
                    jz_code = generate_jz_code(ins, int(values[0],16))
                    jmp_code = generate_jmp_code(ins + len(jz_code), int(values[1],16))
                    
                    # [FIX 2] 实际写入内存！
                    patch_bytes(ins, jz_code)
                    patch_bytes(ins + len(jz_code), jmp_code)
                    
                    # 3. 填充 NOP
                    nop_start = ins + len(jz_code) + len(jmp_code)
                    fill_nop(nop_start, end_ea)
        if len(values) == 1:
            mnem = idc.print_insn_mnem(last_ins_ea)
            if mnem.startswith("jmp"):
                jmp_code = generate_jmp_code(last_ins_ea, int(values[0],16))
                patch_bytes(last_ins_ea, jmp_code)
                nop_start = last_ins_ea + len(jmp_code)
                fill_nop(nop_start, end_ea)

def find_all_useless_block(func_ea,real_blocks):
    blocks = idaapi.FlowChart(idaapi.get_func(func_ea))
    local_real_blocks = real_blocks.copy()
    useless_blocks = []
    
        # local_real_blocks.extend(succ.start_ea for succ in cur_block.succs())
    for block in blocks:
        start_ea = block.start_ea
        end_ea = block.end_ea
        if start_ea not in local_real_blocks:
            useless_blocks.append([start_ea,end_ea])
        
    print("所有的无用块:",[b for b in useless_blocks])
    return useless_blocks


def patch_useless_blocks(useless_blocks):
    
    # print(useless_blocks)
    for useless_block in useless_blocks:
        
        print(f"Nop-ing useless block from {hex(useless_block[0])} to {useless_block[1]}")
        fill_nop(useless_block[0], useless_block[1])
    print("无用块nop完成")


func_ea = 0x400620
all_real_blocks =[4195872, 4198689, 4198808, 4198878, 4198991, 4199006, 4199076, 4199158, 4199173, 4199206, 4199276, 4199346, 4199375, 4199407, 4199477, 4199553, 4199568, 4199598, 4199634, 4199656, 4199671, 4199686, 4199713, 4199783, 4199862, 4199877, 4199892, 4199917, 4199932, 4200002, 4200081, 4200096, 4200166, 4200249, 4200264, 4200293, 4200363, 4200444, 4200459, 4200496, 4200521, 4200545, 4200615, 4200698, 4200713, 4200742, 4200768, 4200800, 4200829, 4200859, 4200929, 4201021, 4201036, 4201075, 4201101, 4201171, 4201253, 4201268, 4201294, 4201309, 4201333, 4201403, 4201485, 4201500, 4201515, 4201542, 4201577, 4201647, 4201731, 4201746, 4201773, 4201797, 4201812, 4201882, 4201984, 4201999, 4202029, 4202099, 4202169, 4202198, 4202234, 4202249, 4202285, 4202300, 4202336, 4202391, 4202406, 4202421, 4202445, 4202469, 4202484, 4202508, 4202523, 4202547, 4202573, 4202610, 4202646, 4202675, 4202690, 4202324]
useless_blocks = find_all_useless_block(func_ea,all_real_blocks)
patch_branch({'0x400620': ['0x401121'], '0x401121': ['0x401198'], '0x401198': ['0x401f60', '0x4011de'], '0x4011de': ['0x401f60', '0x40124f'], '0x40124f': ['0x40125e'], '0x40125e': ['0x401f97', '0x4012a4'], '0x4012a4': ['0x401f97', '0x4012f6'], '0x4012f6': ['0x401305'], '0x401305': ['0x401326'], '0x401326': ['0x401fa6', '0x40136c'], '0x40136c': ['0x401fa6', '0x4013b2'], '0x4013b2': ['0x4015d4', '0x4013cf'], '0x4013cf': ['0x4013ef'], '0x4013ef': ['0x401fb5', '0x401435'], '0x401435': ['0x401fb5', '0x401481'], '0x401481': ['0x401490'], '0x401490': ['0x4014ae', '0x4014f7'], '0x4014ae': ['0x4014d2'], '0x4014d2': ['0x4014e8'], '0x4014e8': ['0x4015d4'], '0x4014f7': ['0x401506'], '0x401506': ['0x401521'], '0x401521': ['0x401fcd', '0x401567'], '0x401567': ['0x401fcd', '0x4015b6'], '0x4015b6': ['0x4015c5'], '0x4015c5': ['0x40125e'], '0x4015d4': ['0x4015ed'], '0x4015ed': ['0x4015fc'], '0x4015fc': ['0x401fe5', '0x401642'], '0x401642': ['0x401fe5', '0x401691'], '0x401691': ['0x4016a0'], '0x4016a0': ['0x401ff4', '0x4016e6'], '0x4016e6': ['0x401ff4', '0x401739'], '0x401739': ['0x401748'], '0x401748': ['0x401d54', '0x401765'], '0x401765': ['0x40200c', '0x4017ab'], '0x4017ab': ['0x40200c', '0x4017fc'], '0x4017fc': ['0x40180b'], '0x40180b': ['0x401830'], '0x401830': ['0x401849'], '0x401849': ['0x401861'], '0x401861': ['0x40201b', '0x4018a7'], '0x4018a7': ['0x40201b', '0x4018fa'], '0x4018fa': ['0x401909'], '0x401909': ['0x401c2b', '0x401926'], '0x401926': ['0x401940'], '0x401940': ['0x401960'], '0x401960': ['0x401a73', '0x40197d'], '0x40197d': ['0x40199b'], '0x40199b': ['0x402033', '0x4019e1'], '0x4019e1': ['0x402033', '0x401a3d'], '0x401a3d': ['0x401a4c'], '0x401a4c': ['0x401b4e'], '0x401a73': ['0x401a8d'], '0x401a8d': ['0x40204d', '0x401ad3'], '0x401ad3': ['0x40204d', '0x401b25'], '0x401b25': ['0x401b34'], '0x401b34': ['0x401b4e'], '0x401b4e': ['0x401b5d'], '0x401b5d': ['0x401b75'], '0x401b75': ['0x402072', '0x401bbb'], '0x401bbb': ['0x402072', '0x401c0d'], '0x401c0d': ['0x401c1c'], '0x401c1c': ['0x401849'], '0x401c2b': ['0x401c46'], '0x401c46': ['0x401c69'], '0x401c69': ['0x402096', '0x401caf'], '0x401caf': ['0x402096', '0x401d03'], '0x401d03': ['0x401d12'], '0x401d12': ['0x401d2d'], '0x401d2d': ['0x401d45'], '0x401d45': ['0x4015fc'], '0x401d54': ['0x4020b3', '0x401d9a'], '0x401d9a': ['0x4020b3', '0x401e00'], '0x401e00': ['0x401e0f'], '0x401e0f': ['0x401e2d'], '0x401e2d': ['0x4020c2', '0x401e73'], '0x401e73': ['0x4020c2', '0x401eb9'], '0x401eb9': ['0x401ed6', '0x401f09'], '0x401ed6': ['0x401efa'], '0x401efa': ['0x401f3c'], '0x401f09': ['0x401f2d'], '0x401f2d': ['0x401f3c'], '0x401f3c': ['0x401f54'], '0x401f60': ['0x4011de'], '0x401f97': ['0x4012a4'], '0x401fa6': ['0x40136c'], '0x401fb5': ['0x401435'], '0x401fcd': ['0x401567'], '0x401fe5': ['0x401642'], '0x401ff4': ['0x4016e6'], '0x40200c': ['0x4017ab'], '0x40201b': ['0x4018a7'], '0x402033': ['0x4019e1'], '0x40204d': ['0x401ad3'], '0x402072': ['0x401bbb'], '0x402096': ['0x401caf'], '0x4020b3': ['0x401d9a'], '0x4020c2': ['0x401e73'], '0x401f54': []})

patch_useless_blocks(useless_blocks)
ida_funcs.reanalyze_function(ida_funcs.get_func(func_ea))#刷新函数控制流图
print("控制流图已刷新")