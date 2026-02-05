rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF CA 00 42 7A D7 }
        $pattern1 = { FF 15 5C C2 4C 00 CA DD 00 4C C2 5C }
        $pattern2 = { FF D2 CA ED }

    condition:
        any of them
}