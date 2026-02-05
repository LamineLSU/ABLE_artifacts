rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 6A 00 E8 B0 C8 F9 FF 6A 00 }
        $pattern2 = { 6A 00 E8 6B 25 FE FF 8B C3 }

    condition:
        any of them
}