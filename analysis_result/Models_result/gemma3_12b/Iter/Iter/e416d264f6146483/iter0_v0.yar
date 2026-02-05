rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 B8 0B 00 00 FF 15 B0 62 45 00 }  // push 0xBB8, call [0x4562B0] - Push argument for ExitProcess
        $pattern1 = { 51 50 FF 15 54 63 45 00 }  // push ecx, push eax, call [0x456354] - Preparing for early exit
        $pattern2 = { 68 44 41 46 00 FF 15 70 62 45 00 }  // push "FAAF", call [0x456270] - Another exit call

    condition:
        any of them
}