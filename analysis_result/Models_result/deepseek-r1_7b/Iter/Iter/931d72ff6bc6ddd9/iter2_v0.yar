rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass for sample 931d72ff6bc6ddd9"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 00 21 61 90 }
        $pattern1 = { 8B CE E8 B3 03 00 00 CA 00 21 6E 2A }
        $pattern2 = { 85 C0 74 12 00 21 61 F7 }

    condition:
        (any of them)
}