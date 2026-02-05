rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 FE 1A 0F 8C 79 FF FF FF }
        $pattern1 = { 6A 00 6A 00 6A 00 68 00 10 41 00 6A 00 }
        $pattern2 = { 6A FF 8B 4D FC 33 C0 5F 5E }

    condition:
        any of them
}