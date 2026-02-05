rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 8B CE E8 25 05 00 0E 8B 8D 95 FF FE }
        $pattern1 = { 6A 5B 5A 8B CE E8 74 FA FF FF FF CE 8B 85 }
        $pattern2 = { 8B EC 53 E8 E3 FA FF FF 53 E8 4B 17 00 85 C0 }

    condition:
        any of them
}