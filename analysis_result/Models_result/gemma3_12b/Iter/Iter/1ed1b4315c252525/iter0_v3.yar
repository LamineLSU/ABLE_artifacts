rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 E8 C1 FF FF FF }  // Bypass Target 1: Call to 00427AD7h
        $pattern1 = { 8B FF 55 8B EC FF 75 08 FF 15 28 F1 40 00 }  // Bypass Target 2: Call to [0040F128h]
        $pattern2 = { 8B EC FF 75 08 FF 15 5C C2 4C 00 }  // Bypass Target 3: Call to [004CC25Ch]

    condition:
        any of them
}