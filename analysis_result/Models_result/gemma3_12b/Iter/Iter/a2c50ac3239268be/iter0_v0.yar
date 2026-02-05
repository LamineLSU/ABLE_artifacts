rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 7B 28 01 75 03 FF 15 30 F0 4A 00 }
        $pattern1 = { 8B 03 8B 8B 39 75 04 74 1C }
        $pattern2 = { 56 E8 59 BD FF FF 8B C3 E8 96 FB FF }

    condition:
        any of them
}