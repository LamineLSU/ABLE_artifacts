rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$patternA+0,action0=skip,bp1=$patternB+0,action1=skip,bp2=$patternC+0,action2=skip,count=0"

    strings:
        $patternA = { 85 C0 0F 84 ?? ?? ?? ?? }
        $patternB = { 83 F8 01 74 12 8B 4D F8 }
        $patternC = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}