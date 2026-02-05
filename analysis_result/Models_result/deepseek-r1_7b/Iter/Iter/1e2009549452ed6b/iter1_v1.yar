rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific checks and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 8B 45 FC 6A FF 74 39 74 D6 E8 B4 20 00 }  // TEST EAX followed by JE
        $pattern1 = { 86 A3 E8 6A 64 A1 30 00 00 00 74 20 74 C4 }  // Conditional check before ExitProcess
        $pattern2 = { E8 B2 FC FF FF 64 A1 30 00 00 00 74 20 74 C4 }  // Another conditional jump after API calls

    condition:
        any of them
}