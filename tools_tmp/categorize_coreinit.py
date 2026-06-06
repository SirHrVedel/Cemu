"""Group missing coreinit exports by prefix family."""
import re
from collections import defaultdict, Counter

with open(r"C:\Users\Nikolaj\source\repos\Cemu\tools_tmp\coreinit_diff.txt", "r", encoding="utf-8") as f:
    lines = [l.strip() for l in f.readlines()]
start = lines.index("--- Missing exports (Cemu doesn't register these) ---") + 1
end = lines.index("--- In Cemu but not in RPL (likely typos / private symbols) ---")
missing = [l for l in lines[start:end] if l]

groups = defaultdict(list)
def family(name):
    # strip leading underscores for grouping
    n = name.lstrip("_")
    # cut at first non-alpha for camelCase symbols
    # use a list of known prefixes
    prefixes = [
        "OSDynLoad", "OSCache", "OSContext", "OSFastMutex", "OSFastCond",
        "OSMutex", "OSCond", "OSSemaphore", "OSEvent", "OSAlarm", "OSRendezvous",
        "OSSpinLock", "OSMessageQueue", "OSMessage", "OSThread",
        "OSAlloc", "OSBlock", "OSMutexQueue", "OSScreen", "OSConsole",
        "OSReport", "OSError", "OSPanic", "OSDevice", "OSDriver", "OSDynamicCallback",
        "OSAddTitleUpdate", "OSAtomic", "OSBoot", "OSBuf", "OSCirc",
        "OSClass", "OSCom", "OSConfig", "OSConsole", "OSConvert", "OSCreate",
        "OSCrash", "OSDate", "OSDeb", "OSDestroy", "OSExc", "OSExit", "OSFast",
        "OSFatal", "OSFiber", "OSGet", "OSHash", "OSInit", "OSIO", "OSIs",
        "OSJam", "OSKernel", "OSLaunch", "OSLink", "OSLoad", "OSLock", "OSLog",
        "OSMaskInterrupts", "OSMem", "OSMP", "OSNotify", "OSOpen", "OSPause",
        "OSPMCall", "OSPoll", "OSPower", "OSPreload", "OSPrint", "OSProc",
        "OSPutChar", "OSPutString", "OSQuery", "OSRead", "OSReceive", "OSRegister",
        "OSRelease", "OSRequest", "OSReset", "OSRestore", "OSResume", "OSResize",
        "OSResolve", "OSResp", "OSResume", "OSRetrieve", "OSRtc", "OSRun",
        "OSSave", "OSSched", "OSSecond", "OSSend", "OSSet", "OSShare", "OSSleep",
        "OSShutdown", "OSSignal", "OSSnoop", "OSSpawn", "OSStart", "OSStop",
        "OSSus", "OSSwitch", "OSSync", "OSSys", "OSTest", "OSTick", "OSTime",
        "OSTitle", "OSTrace", "OSTransition", "OSTry", "OSUn", "OSUpdate",
        "OSVerify", "OSWait", "OSWake", "OSWatch", "OSWith", "OSWrite", "OSYield",
        "OS",
        "MEMCreate", "MEMDestroy", "MEMAlloc", "MEMFree", "MEMGet", "MEMSet",
        "MEMRecord", "MEMInit", "MEMResize", "MEMAdjust", "MEMDump", "MEMCheck",
        "MEM",
        "FS", "FSA", "FSAddClient", "FSDelClient", "FSGet", "FSInit",
        "PPC", "DC", "IC", "LC", "DI", "MIX",
        "IPCKDriver", "IPCDriver", "IPC", "IM",
        "ACInitialize", "AC",
        "COSDriverImpl", "COSDriver", "COS",
        "TitleId", "FastInterruptDisable", "EnableFastInterrupts", "DisableFastInterrupts",
        "BSP", "MCP",
        "GHS", "ENV", "stdc_",
        "DMAEFill", "DMAECopy", "DMAEWait", "DMAEGet", "DMAE", "Loader", "EH",
        "__OSAllocFromSystem", "__OSGetEnv", "__OSSetCrash", "__OSGetCrash",
        "__OS", "__os", "__GH", "__C", "__rl",
        "_Va", "_Block", "_Stack", "_Loader", "_Coredump",
        "_Exit", "exit", "atexit",
        "snprintf", "vsnprintf", "sprintf", "vsprintf", "fprintf", "vfprintf",
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
        "memcmp", "memmove", "memcpy", "memset", "strcmp", "strncmp",
        "strcpy", "strncpy", "strlen", "strcat", "strncat", "strstr", "strchr",
        "wcs", "tan", "sin", "cos", "atan", "asin", "acos", "exp", "log",
        "sqrt", "pow", "rand", "srand", "abs", "labs",
    ]
    # special: leading __ groups
    if n.startswith("__"):
        # find first "real" identifier after underscores
        m = re.match(r"_+([A-Za-z][A-Za-z0-9_]+)", name)
        if m:
            for p in prefixes:
                if m.group(1).startswith(p.lstrip("_")):
                    return "__" + p.lstrip("_")
            return "__" + m.group(1)
        return "__misc"
    # check known prefixes
    # longer prefixes first
    for p in sorted(prefixes, key=len, reverse=True):
        if name.startswith(p):
            return p
    # otherwise grab first cap-cluster
    m = re.match(r"([A-Z]+[a-z][A-Za-z0-9]*)", name)
    return m.group(1) if m else "(other)"

ctr = Counter()
fam_to_names = defaultdict(list)
for n in missing:
    fa = family(n)
    ctr[fa] += 1
    fam_to_names[fa].append(n)

print(f"{len(missing)} missing exports, grouped:\n")
for fa, c in ctr.most_common():
    print(f"  {fa:30s} {c}")
print()
print("=== Detailed list per family (top 20 families) ===")
for fa, c in ctr.most_common(40):
    print(f"\n[{fa}] ({c}):")
    for n in fam_to_names[fa][:50]:
        print(f"  {n}")
    if c > 50:
        print(f"  ... and {c-50} more")
