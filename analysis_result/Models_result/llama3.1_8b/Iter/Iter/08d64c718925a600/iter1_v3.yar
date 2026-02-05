rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { FF 15 D8 54 41 00 } // call ptr [004154D8h]
        $pattern2 = { 6A 09 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}