rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B 45 FC }
        $pattern1 = { 33 C9 5B 6A 40 53 68 40 11 31 01 }
        $pattern2 = { 8B E5 5D 5E 33 CD 5B E8 57 26 00 00 }

    condition:
        any of them
}