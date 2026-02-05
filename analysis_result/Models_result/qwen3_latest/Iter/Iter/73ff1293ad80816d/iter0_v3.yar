rule EvasionCheckPatterns
{
    meta:
        description = "Detects potential evasion check patterns in the code"
        cape_options = "bp0=$test_je+0,action0=skip,bp1=$push_call_test+0,action1=skip,bp2=$jump_call_exit+0,action2=skip,count=0"
        author = "YourName"
        date = "2023-10-10"

    strings:
        // Pattern 0: Initial test and jump (test eax, eax followed by je)
        $test_je = { 85 C0 0F 84 ?? ?? ?? ?? }

        // Pattern 1: Push, call to CloseHandle, and test (part of the flow)
        $push_call_test = { 6A 00 E8 ?? ?? ?? ?? 85 C0 }

        // Pattern 2: Jump to call ExitProcess (je followed by call)
        $jump_call_exit = { 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }

    condition:
        any of ($test_je, $push_call_test, $jump_call_exit)
}