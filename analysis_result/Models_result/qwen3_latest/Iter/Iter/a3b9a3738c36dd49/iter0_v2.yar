rule Sandbox_Evasion
{
    meta:
        description = "Sandbox evasion through API calls and conditional checks"
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_closehandle+0,action1=skip,bp2=$test_je+0,action2=skip,count=0"
        author = "YourName"
        date = "2023-10-10"

    strings:
        $call_exitprocess = { 53 FF 15 ?? ?? ?? ?? }  // push ebx, call ExitProcess
        $call_closehandle = { 50 FF 15 ?? ?? ?? ?? }  // push eax, call CloseHandle
        $test_je = { 85 C0 74 ?? 8B 4D 08 }  // test eax, eax, je, and next instruction

    condition:
        all of them
}