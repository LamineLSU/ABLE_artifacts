rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection and bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 40 E7 F3 00 40 E7 FF }
        $pattern1 = { 00 40 E7 F6 00 40 E7 FF }
        $pattern2 = { 00 40 E7 FC 00 40 E7 FF }

    condition:
        any of them
}