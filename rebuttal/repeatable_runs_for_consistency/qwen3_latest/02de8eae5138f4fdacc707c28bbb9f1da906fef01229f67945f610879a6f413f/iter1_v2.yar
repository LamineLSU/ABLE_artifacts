rule CodePattern
{
    meta:
        description = "Identifies a sequence of instructions commonly used in module-based code injection or loading"
        cape_options = "bp0=$call_getmodule+0,action0=skip,bp1=$push_0A+0,action1=skip,bp2=$call_internal+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-20"

    strings:
        // 1. Call to GetModuleHandleA
        $call_getmodule = { E8 A5 10 00 00 }  // Call to GetModuleHandleA

        // 2. Push of value 0x0A (hex for 10)
        $push_0A = { 68 0A 00 00 00 }  // Push 0x0A

        // 3. Call to internal function at 0x00401031
        $call_internal = { E8 06 00 00 00 }  // Call to 0x00401031

    condition:
        all of ($call_getmodule, $push_0A, $call_internal)
}