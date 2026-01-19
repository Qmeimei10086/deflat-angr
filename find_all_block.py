import idaapi
import idc
from collections import deque # 用于 BFS 遍历

def get_basic_block(ea):
    func = idaapi.get_func(ea)
    if not func:
        return None
    f = idaapi.FlowChart(func) # 获取函数的控制流图
    for block in f:
        if block.start_ea <= ea < block.end_ea:
            return block
    return None


def find_loop_head(start_ea):
    loop_heads = set()
    queue = deque() # BFS 队列
    blcok = get_basic_block(start_ea) # 获取起始地址所在的基本块
    queue.append((blcok,[]))
    while len(queue) > 0:
        cur_block, path = queue.popleft()
        if cur_block.start_ea in path:
            loop_heads.add(cur_block.start_ea) # 找到循环头
            continue
        path = path + [cur_block.start_ea] # 更新路径
        queue.extend((s, path) for s in cur_block.succs()) # 将后继加入队列
    
    all_loop_heads = list(loop_heads)
    all_loop_heads.sort() # 升序排序，确保主循环头在第一个
    print("[+]Find loop heads:",[hex(lh) for lh in all_loop_heads]," -- total:",len(all_loop_heads))
    return all_loop_heads

def find_converge_addr(loop_head_addr):
    converge_addr = 0
    block = get_basic_block(loop_head_addr) # 循环头
    preds = block.preds() # 获取前驱基本块
    pred_list = list(preds)

    if len(pred_list) == 2: # 标准 ollvm：循环头有两个前驱,一个序言块一个汇聚块
        for pred in pred_list:
            tmp_list = list(pred.preds())
            if len(tmp_list) > 1: # 有多个前驱的块是汇聚块
                converge_addr = pred.start_ea
    print("[+]Find converge_addr:",hex(converge_addr))
    return converge_addr

def get_block_size(block):
    return block.end_ea - block.start_ea

def find_ret_block(blocks):
    for block in blocks:
        succs = list(block.succs()) # 获取后继块
        succs_list = list(succs)

        end_ea = block.end_ea # end_ea 指向基本块最后一条指令的下一个地址
        last_inst_ea = idc.prev_head(end_ea) # 获取基本块最后一条指令地址
        mnem = idc.print_insn_mnem(last_inst_ea) # 获取指令助记符

        if len(succs_list) == 0: # 没有后继块
            if mnem == "retn": # 最后一条指令是 ret 指令
                ori_ret_block = block

                # 向上寻找更合适的 ret 块
                while True:
                    tmp_block = block.preds()
                    pred_list = list(tmp_block)
                    if len(pred_list) == 1: # 只有一个前驱
                        block = pred_list[0]
                        if get_block_size(block) == 4: # 单指令块
                            continue
                        else:
                            break
                    else: # 多个前驱或者无前驱
                        break
    
                # 处理子分发器情况
                block2 = block
                num = 0
                i = 0
                while True:
                    i += 1
                    succs_block = block2.succs()
                    for succ in succs_block:
                        child_succs = succ.succs()
                        succ_list = list(child_succs)
                        if len(succ_list) != 0:
                            block2 = succ
                            num += 1
                    if num > 2:
                        block = ori_ret_block
                        break
                    if i > 2:
                        break
                print("[+]ret块",hex(block.start_ea))
                return block.start_ea


def find_all_real_blocks(fun_ea):
    blocks = idaapi.FlowChart(idaapi.get_func(fun_ea))
    loop_heads = find_loop_head(fun_ea)
    all_real_blocks = []


    for loop_head_addr in loop_heads:
        loop_head_block = get_basic_block(loop_head_addr)
        converge_addr = find_converge_addr(loop_head_addr)
        real_blocks = []

        
        #找出序言
        loop_head_preds = list(loop_head_block.preds())
        loop_head_preds_addr = [b.start_ea for b in loop_head_preds]
        if loop_head_addr != converge_addr:
            loop_head_preds_addr.remove(converge_addr)
            print("序言块:",[hex(x) for x in loop_head_preds_addr])
            real_blocks.extend(loop_head_preds_addr)
        
        converge_block = get_basic_block(converge_addr)
        list_preds = list(converge_block.preds())
        
        
        
        
        for pred in list_preds:
            end_ea = pred.end_ea
            last_inst_ea = idc.prev_head(end_ea)
            mnem = idc.print_insn_mnem(last_inst_ea)
            
            size = get_block_size(pred)
            if size > 5: # 大于单指令块且不是跳转指令
                start_ea = pred.start_ea
                real_blocks.append(start_ea)
            
        real_blocks.sort() # 排序，第一个是序言块
        all_real_blocks.append(real_blocks)

        print("子循环头及其子真实块", [hex(child_block_ea) for child_block_ea in real_blocks])
    
    ret_addr = find_ret_block(blocks)
    all_real_blocks.append(ret_addr)
    print("all_real_blocks:",all_real_blocks)


    all_real_block_list = []
    for real_blocks in all_real_blocks:
        if isinstance(real_blocks,list):
            all_real_block_list.extend(real_blocks)
        else:
            all_real_block_list.append(real_blocks)
    
    print(f"\n所有真实块获取完成 真实块数量: {len(all_real_block_list)}")
    print(all_real_block_list)


    
    # all_child_prologue_addr = all_real_blocks.copy()
    # all_child_prologue_addr.remove(ret_addr)
    # all_child_prologue_addr.remove(all_child_prologue_addr[0])  # 移除主序言块
    # print("所有子循环及其子真实块", all_child_prologue_addr)

    return 0

find_all_real_blocks(0x400620)
