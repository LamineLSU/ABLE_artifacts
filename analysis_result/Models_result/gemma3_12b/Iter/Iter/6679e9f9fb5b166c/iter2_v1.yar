rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 5A 59 59 64 89 10 }
        $pattern1 = { 8B 85 80 FD FF FF 8D 95 88 FD FF FF }
        $pattern2 = { E8 28 E2 FF FF 8B 85 88 FD FF FF }

    condition:
        any of them
}