import logging
import angr
from tqdm import tqdm

logging.getLogger('angr').setLevel(logging.ERROR)

def capstone_decode_cmovxx(insn):
    operands = insn.op_str.replace(" ", "").split(",")
    dst_reg = operands[0]
    src_reg = operands[1]
    print(f"cmovxx解析结果: 目标寄存器:{dst_reg}, 源寄存器:{src_reg}")
    return dst_reg, src_reg

def find_state_succ_cmovxx(proj, base, local_state, flag, real_blocks, real_block_addr, path):
    # 仅在 find_block_succ 识别为 cmov 时调用
    ins = local_state.block().capstone.insns[0] 
    dst_reg, src_reg = capstone_decode_cmovxx(ins) 
    
    # 逻辑修正：
    # flag == True  -> ZF=1 (Zero) -> cmovnz (Not Zero) 条件不满足 -> 不执行 Move -> Pass
    # flag == False -> ZF=0 (Not Zero) -> cmovnz (Not Zero) 条件满足 -> 执行 Move
    
    if not flag: # 需要执行 Move
        try:
            # 修正：state.regs 没有 .get() 方法，用 getattr
            src_val = getattr(local_state.regs, src_reg)
            setattr(local_state.regs, dst_reg, src_val)
        except Exception as e:
            print(f"寄存器访问错误: {e}")

    # 关键修正：手动跳过这条 cmov 指令！防止 Angr 再次执行它
    local_state.regs.ip += ins.size

    sm = proj.factory.simgr(local_state)
    
    while(len(sm.active)):
        for active_state in sm.active:
            try:
                ins_offset = active_state.addr - base
                if ins_offset in real_blocks:
                    value = path[real_block_addr]
                    if ins_offset not in value:
                        value.append(ins_offset)
                    return ins_offset
            except:
                pass 
        sm.step(num_inst=1)


def find_block_succ(proj, base, func_offset, state, real_block_addr, real_blocks, path):
    msm = proj.factory.simgr(state)  # 构造模拟器
    while len(msm.active):
        for active_state in msm.active:
            #print(active_state.block().capstone.insns[0])
            offset = active_state.addr - base
            #print("当前偏移地址:", hex(offset),"寻找真实块:", hex(real_block_addr))
            if offset == real_block_addr:  # 找到真实块
                print("找到真实块:", hex(real_block_addr))
                mstate = active_state.copy()  # 复制state,为后继块的获取做准备
                msm2 = proj.factory.simgr(mstate)
                msm2.step(num_inst=1)  # 让状态进到块内的下一条指令位置，避免和外层状态混淆

                while len(msm2.active):
                    
                    for mactive_state in msm2.active:
                        #print(mactive_state.block().capstone.insns[0])
                        ins_offset = mactive_state.addr - base
                        if ins_offset in real_blocks:  # 无分支块（或无条件跳转）
                            # 在无条件跳转中,并且有至少两条路径同时执行到真实块时,取非ret块的真实块
                            msm2_len = len(msm2.active)
                            if msm2_len > 1:
                                tmp_addrs = []
                                for s in msm2.active:
                                    moffset = s.addr - base
                                    tmp_value = path[real_block_addr]
                                    if moffset in real_blocks and moffset not in tmp_value:
                                        tmp_addrs.append(moffset)
                                if len(tmp_addrs) > 1:
                                    print("当前至少有两个路径同时执行到真实块:", [hex(tmp_addr) for tmp_addr in tmp_addrs])
                                    ret_addr = real_blocks[len(real_blocks) - 1]
                                    if ret_addr in tmp_addrs:
                                        tmp_addrs.remove(ret_addr)
                                    ins_offset = tmp_addrs[0]
                                    print("两个路径同时执行到真实块最后取得:", hex(ins_offset))

                            value = path[real_block_addr]
                            if ins_offset not in value:
                                value.append(ins_offset)
                            print(f"无条件跳转块关系:{hex(real_block_addr)}-->{hex(ins_offset)}")
                            return
                        # 可能是 cmovnz 分支指令
                        ins = mactive_state.block().capstone.insns[0]
                        if ins.mnemonic == 'cmovnz' or ins.mnemonic == 'cmovne':
                            print("发现 cmovnz/cmovne 指令，进行分支处理:", hex(ins_offset))
                            state_true = mactive_state.copy()
                            state_true_succ_addr = find_state_succ_cmovxx(proj, base, state_true, True, real_blocks, real_block_addr, path)
                            
                            state_false = mactive_state.copy()
                            state_false_succ_addr = find_state_succ_cmovxx(proj, base, state_false, False, real_blocks, real_block_addr, path)
                            if state_true_succ_addr is None or state_false_succ_addr is None:
                                print("cmovnz/cmovne错误指令地址:", hex(ins_offset))
                                print(f"cmovnz/cmovne后继有误:{hex(real_block_addr)}-->{hex(state_true_succ_addr) if state_true_succ_addr is not None else state_true_succ_addr},"
                                      f"{hex(state_false_succ_addr) if state_false_succ_addr is not None else state_false_succ_addr}")
                                return "erro"
                        #cmovne
                            print(f"cmovnz/cmovne分支跳转块关系:{hex(real_block_addr)}-->{hex(state_true_succ_addr)} zf = 1,  {hex(state_false_succ_addr)} zf != 1")
                            #print(f"csel分支跳转块关系:{hex(real_block_addr)}-->{hex(state_true_succ_addr)},{hex(state_false_succ_addr)}")
                            return
                        if ins.mnemonic == 'cmovz' or ins.mnemonic == 'cmove':
                            print("发现 cmovz/cmove 指令，进行分支处理:", hex(ins_offset))
                            state_true = mactive_state.copy()
                            state_true_succ_addr = find_state_succ_cmovxx(proj, base, state_true, False, real_blocks, real_block_addr, path)
                            
                            state_false = mactive_state.copy()
                            state_false_succ_addr = find_state_succ_cmovxx(proj, base, state_false, True, real_blocks, real_block_addr, path)
                            if state_true_succ_addr is None or state_false_succ_addr is None:
                                print("cmovz/cmove误指令地址:", hex(ins_offset))
                                print(f"cmovz/cmove后继有误:{hex(real_block_addr)}-->{hex(state_true_succ_addr) if state_true_succ_addr is not None else state_true_succ_addr},"
                                      f"{hex(state_false_succ_addr) if state_false_succ_addr is not None else state_false_succ_addr}")
                                return "erro"
                        #cmovne
                            print(f"cmovz/cmove分支跳转块关系:{hex(real_block_addr)}-->{hex(state_true_succ_addr)} zf = 1,  {hex(state_false_succ_addr)} zf != 1")
                            #print(f"csel分支跳转块关系:{hex(real_block_addr)}-->{hex(state_true_succ_addr)},{hex(state_false_succ_addr)}")
                            return
                        
                    msm2.step(num_inst=1)
                # 真实块集合中的最后一个基本块如果最后没找到后继,说明是return块,直接返回
                return
        msm.step(num_inst=1)

def angr_main(real_blocks,func_offset,file_path):
    proj = angr.Project(file_path, auto_load_libs=False) 
    base = 0
    func_addr = base + func_offset
    init_state = proj.factory.blank_state(addr=func_addr)
    init_state.options.add(angr.options.CALLLESS)



    path = {addr: [] for addr in real_blocks}

    ret_addr = real_blocks[len(real_blocks) - 1]
    
    first_block = proj.factory.block(func_addr)
    first_block_insns = first_block.capstone.insns
    # 主序言的最后一条指令
    first_block_last_ins = first_block_insns[len(first_block_insns) - 1]
    print(hex(first_block_last_ins.address))


    for real_block_addr in tqdm(real_blocks):
        if ret_addr == real_block_addr:
            continue
    
        state = init_state.copy()
        print("正在寻找:",hex(real_block_addr))

        def jump_to_address(state):
            #print(state.regs.pc)
            
            state.regs.pc = base + real_block_addr - 6 
            print("跳转到地址:", hex(base + real_block_addr - 6))
            proj.unhook(0x400675)
        print(hex(real_block_addr),hex(func_offset))
        
        if real_block_addr != func_offset:
            print("序言结束")
            proj.hook(0x400675, jump_to_address, first_block_last_ins.size)
    
        ret = find_block_succ(proj, base, func_offset, state, real_block_addr, real_blocks, path)
        
        if ret == "erro":
            return

    hex_dict = {
        hex(key): [hex(value) for value in values]
        for key, values in path.items()
    }

    for i in hex_dict.keys():
        print(f"{i}:  {hex_dict[i]}")
    print(hex_dict)
    return hex_dict

all_real_blocks: list[int] =[4195872, 4198689, 4198808, 4198878, 4198991, 4199006, 4199076, 4199158, 4199173, 4199206, 4199276, 4199346, 4199375, 4199407, 4199477, 4199553, 4199568, 4199598, 4199634, 4199656, 4199671, 4199686, 4199713, 4199783, 4199862, 4199877, 4199892, 4199917, 4199932, 4200002, 4200081, 4200096, 4200166, 4200249, 4200264, 4200293, 4200363, 4200444, 4200459, 4200496, 4200521, 4200545, 4200615, 4200698, 4200713, 4200742, 4200768, 4200800, 4200829, 4200859, 4200929, 4201021, 4201036, 4201075, 4201101, 4201171, 4201253, 4201268, 4201294, 4201309, 4201333, 4201403, 4201485, 4201500, 4201515, 4201542, 4201577, 4201647, 4201731, 4201746, 4201773, 4201797, 4201812, 4201882, 4201984, 4201999, 4202029, 4202099, 4202169, 4202198, 4202234, 4202249, 4202285, 4202300, 4202336, 4202391, 4202406, 4202421, 4202445, 4202469, 4202484, 4202508, 4202523, 4202547, 4202573, 4202610, 4202646, 4202675, 4202690, 4202324]


angr_main(all_real_blocks, 0x400620, "D:\\reverse\\Angr\\polyre")