rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 ?? FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { FF 75 08 FF 75 08 E1 5A CB 04 10 }
        $pattern2 = { 55 ?? FF 75 08 59 ?? FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}