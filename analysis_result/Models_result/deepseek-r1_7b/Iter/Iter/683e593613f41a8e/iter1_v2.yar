rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 84 33 FD FF FF }
        $pattern1 = { E8 25 05 05 00 00 ?? 0F 84 33 FD FF FF }
        $pattern2 = { A1 88 85 21 01 01 0F 84 33 FD FF FF }

    condition:
        any of them
}