rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 }
        $pattern1 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 FF 15 5C C2 4C 00 }
        $pattern2 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 6A ?? 5A 8B CE }

    condition:
        any of them
}