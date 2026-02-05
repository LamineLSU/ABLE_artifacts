rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 14 28 43 00 6A 00 }
        $pattern1 = { 85 C0 74 0E E8 89 E0 FF FF FF FF }
        $pattern2 = { E8 B7 F7 FF FF 85 C0 74 0E }

    condition:
        any of them
}