rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 8B C8 8A 01 3C 22 75 ?? }  // Call GetCommandLineA + quote check
        $pattern1 = { FF 15 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 65 ?? }  // Call GetStartupInfoA + conditional exit
        $pattern2 = { FF 15 ?? ?? ?? ?? 51 51 E8 ?? ?? ?? ?? 8B F0 }  // Call GetModuleHandleA + exit logic

    condition:
        any of them
}