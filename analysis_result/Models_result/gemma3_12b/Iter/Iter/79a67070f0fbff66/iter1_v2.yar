rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 FF 15 9C 50 61 00 E8 8D 9A FF FF }
        $pattern1 = { 8B 45 C4 83 C0 01 89 45 C4 8B 4D C4 }
        $pattern2 = { 6A 00 8B 0D 60 42 61 00 51 FF 15 18 50 61 00 }

    condition:
        any of them
}