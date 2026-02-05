rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 6E FF FF FF CA 00 41 0E 2E }
        $pattern1 = { 6A 00 00 00 00 00 E8 2D 01 00 00 }
        $pattern2 = { 8B 45 FC ED EB FC CC }

    condition:
        any of them
}