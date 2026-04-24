rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 04 74 58 8B 45 FC }
        $pattern1 = { 85 C0 74 58 E8 4B FF FF FF FF }
        $pattern2 = { FF 15 88 7C 42 00 8B 45 08 50 6A 00 }

    condition:
        any of them
}