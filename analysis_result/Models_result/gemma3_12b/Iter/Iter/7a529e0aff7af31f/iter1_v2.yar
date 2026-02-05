rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B 85 F0 FE FF FF 8B CE E8 74 FA FF FF 85 C0 }
        $pattern2 = { 6A 40 53 8B CE E8 1B 38 00 00 83 C4 08 85 C0 }

    condition:
        any of them
}