rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$patternA+0,action0=skip,bp1=$patternB+0,action1=skip,bp2=$patternC+0,action2=skip,count=0"

    strings:
        $patternA = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 ?? }
        $patternB = { 64 A1 ?? ?? ?? ?? C3 E8 ?? ?? ?? ?? 83 EC 20 }
        $patternC = { 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? }

    condition:
        any of them
}