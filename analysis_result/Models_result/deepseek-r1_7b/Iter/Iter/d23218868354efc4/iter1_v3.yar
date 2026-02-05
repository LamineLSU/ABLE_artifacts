rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 00 00 00 5B }
        $pattern1 = { 8B CE EC 0F 84 33 FD FF FF 01 03 5E 83 }
        $pattern2 = { E9 B5 FC FF FF 01 03 5E 85 }

    condition:
        any of them
}