rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$patternA+0,action0=skip,bp1=$patternB+0,action1=skip,bp2=$patternC+0,action2=skip,count=0"

    strings:
        $patternA = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 20 }
        $patternB = { FF 15 3C F1 42 00 50 FF 15 40 F1 42 00 }
        $patternC = { C1 E8 08 A8 01 75 10 }

    condition:
        any of them
}