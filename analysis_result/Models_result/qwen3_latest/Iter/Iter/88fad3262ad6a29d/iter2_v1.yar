rule Evasion_Bypass
{
    meta:
        description = "Detects evasion techniques involving call, test, and memory access patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }  // Call followed by test (E8 + 85C0)
        $pattern1 = { 85 C0 74 08 6A 00 }      // Test, jump, push (85C0 + 7408 + 6A00)
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? } // Push followed by call to memory (6A00 + FF15 + 4 ??)

    condition:
        all of them
}