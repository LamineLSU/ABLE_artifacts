rule ControlFlowHijacking
{
    meta:
        description = "Detects control flow hijacking patterns involving test, je, and call instructions"
        cape_options = "bp0=$test_je+0,action0=skip,bp1=$push_ebx_call+0,action1=skip,bp2=$push_eax_call+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        // Pattern 1: test eax, eax followed by je
        $test_je = { 85 C0 74 ?? }

        // Pattern 2: push ebx followed by call to ExitProcess
        $push_ebx_call = { 53 E8 ?? ?? ?? }

        // Pattern 3: push eax followed by call to CloseHandle
        $push_eax_call = { 50 E8 ?? ?? ?? }

    condition:
        all of ($test_je, $push_ebx_call, $push_eax_call)
}