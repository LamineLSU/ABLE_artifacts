rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A E8 E3 D2 FF FF 8D 85 4C F2 FF FF }
        $pattern1 = { 5A E8 E3 D2 FF FF 8D 85 48 F2 FF FF }
        $pattern2 = { 5A E8 E3 D2 FF FF 8D 85 44 F2 FF FF }

    condition:
        any of them
}