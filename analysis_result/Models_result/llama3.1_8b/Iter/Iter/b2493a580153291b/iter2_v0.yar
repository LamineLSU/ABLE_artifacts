rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 12 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 64 A1 30 00 00 0F 84 }
        $pattern3 = { 0F BE E9 6B C0 66 0F 0F CE 8B 45 FC }

    condition:
        any of them
}