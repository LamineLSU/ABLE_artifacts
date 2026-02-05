rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }
        $pattern1 = { 3D 00 10 00 00 00 0F 82 FF 15 }
        $pattern2 = { 53 53 68 40 11 0A }

    condition:
        any of them
}