rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved by targeting early exit decisions after function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 }
        $pattern1 = { E8 25 05 00 00 ?? ?? ?? ?? 8B CE 0F 84 }
        $pattern2 = { A1 88 85 0E 01 ?? ?? ?? ?? FF 15 }

    condition:
        any of them
}