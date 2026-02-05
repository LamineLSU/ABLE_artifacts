rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 85 F0 FE FF FF 8B 45 FC }
        $pattern1 = { 6A 5B 5A 3C 0F 84 33 FD FF FF E8 BC }
        $pattern2 = { 8D 95 F0 FE FF FF 8B 85 F0 FE FF FF E8 74 FA FF FF }

    condition:
        (any of them)
}