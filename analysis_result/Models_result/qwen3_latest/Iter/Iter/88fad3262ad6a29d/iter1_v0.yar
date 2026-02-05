rule MemoryPattern
{
    meta:
        description = "Identifies specific instruction sequences from memory dump"
        cape_options = "bp0=$call_test_je+0,action0=skip,bp1=$exitprocess+0,action1=skip,bp2=$push_call+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2025-03-26"

    strings:
        $call_test_je = { E8 ?? ?? ?? ?? 85 C0 74 08 }  // Call, Test, JE
        $exitprocess = { FF 15 ?? ?? ?? ?? }            // ExitProcess call
        $push_call = { 68 ?? ?? ?? ?? FF D6 }            // Push and Call

    condition:
        all of them
}