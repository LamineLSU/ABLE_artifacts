rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF 59 FF 75 08 }
        $pattern1 = { FF 15 5C C2 4C 00 59 FF 75 08 83 F8 01 }
        $pattern2 = { 83 F8 01 74 12 55 8B 45 FC }

    condition:
        any of them
}