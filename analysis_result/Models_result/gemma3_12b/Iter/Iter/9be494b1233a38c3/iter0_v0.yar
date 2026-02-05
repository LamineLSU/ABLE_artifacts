rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 C0 FB FB FF FF 8B 45 08 }
        $pattern1 = { 6A 08 5A 8B CE E8 1C 21 FF FF 85 C0 }
        $pattern2 = { 8D 75 08 E8 21 B1 FF FF 8B 4D FC }

    condition:
        any of them
}