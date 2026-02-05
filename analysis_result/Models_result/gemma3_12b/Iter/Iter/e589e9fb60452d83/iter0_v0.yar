rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 55 8B EC 18 53 }
        $pattern1 = { FF 15 C0 A0 46 00 50 FF 15 20 A2 46 00 }
        $pattern2 = { 6A 40 89 45 E8 85 FF FF FF }

    condition:
        any of them
}