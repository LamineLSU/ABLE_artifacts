rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 0C F2 47 00 85 C0 74 16 }
        $pattern1 = { 8B 35 AC F1 47 00 68 E7 03 00 00 }
        $pattern2 = { 6A 00 5A 8B CE E8 76 E9 FF FF 85 C0 }

    condition:
        any of them
}