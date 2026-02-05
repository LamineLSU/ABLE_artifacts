rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 53 FF 75 08 }
        $pattern1 = { 83 F8 01 74 12 }
        $pattern2 = { 74 0A 8B 45 FC }

    condition:
        any of them
}