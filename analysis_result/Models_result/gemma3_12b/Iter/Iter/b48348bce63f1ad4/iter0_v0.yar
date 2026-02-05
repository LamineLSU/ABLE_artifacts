rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF D2 }
        $pattern1 = { FF 15 5C C2 4C 00 8B 45 F8 50 8B 4D 08 52 8B 45 D8 50 }
        $pattern2 = { E8 C1 FF FF FF 59 83 C6 04 }

    condition:
        any of them
}