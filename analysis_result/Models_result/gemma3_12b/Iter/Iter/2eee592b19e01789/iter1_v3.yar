rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D9 0F 84 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { E8 27 00 00 00 85 C0 74 11 }
        $pattern2 = { 74 11 FF 15 A9 16 01 00 }

    condition:
        any of them
}