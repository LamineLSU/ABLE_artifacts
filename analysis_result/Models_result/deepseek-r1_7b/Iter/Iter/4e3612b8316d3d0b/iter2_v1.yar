rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting early check functions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 74 12 6A 5B 8B CE E8 25 05 00 00 0F 84 33 FD FF FF }
        $pattern2 = { 8B E5 5D E8 B3 03 00 00 CC }

    condition:
        any of them
}