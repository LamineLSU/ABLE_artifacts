rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 FF D2 }
        $pattern1 = { 8B 45 F8 83 C0 34 50 }
        $pattern2 = { FF 15 AC B0 41 00 }

    condition:
        any of them
}