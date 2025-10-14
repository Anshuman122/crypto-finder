
from __future__ import print_function
import json
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    """Script ka main execution function."""
    
    args = getScriptArgs()
    if not args:
        print("[ERROR] No output file path provided to the script. Aborting.")
        return

    output_file_path = args[0]
    print("[INFO] Script started. Output will be saved to: " + output_file_path)

    results = {
        "binary_name": currentProgram.getName(),
        "architecture": currentProgram.getLanguage().getProcessor().toString(),
        "functions": []
    }
    
    func_manager = currentProgram.getFunctionManager()
    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    try:
        for func in func_manager.getFunctions(True):
            if func.isThunk():
                continue
            
            pcode = []
            d_res = decomp.decompileFunction(func, 30, monitor)
            
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

        with open(output_file_path, 'w') as f:
            json.dump(results, f, indent=4)
            
        print("[SUCCESS] Analysis complete. Results saved successfully.")

    except Exception as e:
        print("[ERROR] An exception occurred during script execution.")
        print(str(e))
        import traceback
        traceback.print_exc(file=sys.stdout)


# Script ko run karo.
if __name__ == '__main__':
    run()
