rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 E8 41 D1 00 8B C8 8A 01 3C 22 75 28 } // GetCommandLineA + byte check
        $pattern1 = { 50 FF 15 EC 41 D1 00 } // GetStartupInfoA with push eax
        $pattern2 = { 8D 45 BC FF 15 EC 41 D1 00 } // GetModuleHandleA with lea eax

    condition:
        any of them
}