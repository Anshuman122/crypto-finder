# Hinglish: Yeh Python/Jython script Ghidra ke andar chalti hai.
# Iska kaam binary se function details, CFG, aur P-Code ko JSON format me export karna hai.

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_pcode(func):
    """Ek function ka P-Code extract karta hai."""
    pcode_list = []
    opiter = func.getEntryPoint().getListing().getInstructions(True)
    while opiter.hasNext():
        op = opiter.next()
        pcode_ops = op.getPcode()
        for p_op in pcode_ops:
            pcode_list.append(p_op.toString())
    return pcode_list

def run():
    """Script ka main execution function."""
    results = {
        "binary_name": currentProgram.getName(),
        "architecture": currentProgram.getLanguage().getProcessor().toString(),
        "functions": []
    }

    func_manager = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    
    # Saare functions par iterate karo.
    for func in func_manager.getFunctions(True):
        if func.isThunk():
            continue
            
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        d_res = decomp.decompileFunction(func, 30, monitor)
        
        pcode = []
        if d_res.decompileCompleted():
            high_func = d_res.getHighFunction()
            if high_func:
                opiter = high_func.getPcodeOps()
                while opiter.hasNext():
                    op = opiter.next()
                    pcode.append(op.toString())

        func_data = {
            "name": func.getName(),
            "address": "0x" + str(func.getEntryPoint()),
            "size": int(func.getBody().getNumAddresses()),
            "pcode": pcode,
            "instruction_count": func.getEntryPoint().getListing().getNumInstructions()
        }
        results["functions"].append(func_data)

    # Output file ka path environment variable se lo.
    output_file_path = getScriptArgs()[0]
    
    with open(output_file_path, 'w') as f:
        json.dump(results, f, indent=4)
        
    print("Analysis complete. Results saved to: " + output_file_path)

# Script ko run karo.
run()