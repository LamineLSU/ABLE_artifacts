rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 }
        $pattern2 = { FF 15 A8 30 2E 01 50 FF 15 44 30 2E 01 }

    condition:
        any of them
}