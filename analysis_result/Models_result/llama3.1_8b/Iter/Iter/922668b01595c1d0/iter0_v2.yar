rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 DD EB 08 FF 15 3C F1 42 00 CA DD 00 42 F1 3C CA DD ?? }
        $pattern1 = { FF 75 08 DD EB 08 FF 15 40 F1 42 00 CA DD 00 42 F1 40 CA DD ?? }
        $pattern2 = { E8 0B 00 00 00 CA 00 41 B9 43 59 EC FF 75 08 DD EB 08 CA DD ?? }

    condition:
        any of them
}