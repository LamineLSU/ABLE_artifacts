rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C1 FF FF ?? ?? 4B C4 ?? }  // Targets the first push dword ptr before call
        $pattern1 = { E8 C1 FF FF 4F FF 75 08 ?? ?? }       // Targets the pop ecx and next push
        $pattern2 = { FF 15 68 FF ?? ?? ?? ?? ?? }         // Targets a different function call

    condition:
        any of them
}