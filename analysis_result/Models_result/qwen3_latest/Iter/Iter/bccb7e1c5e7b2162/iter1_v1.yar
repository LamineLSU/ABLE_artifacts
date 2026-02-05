rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 85 C0 74 12 8B 4D F8 }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }
        $pattern2 = { 83 C4 04 FF 15 2C A1 31 01 }

    condition:
        all of them
}