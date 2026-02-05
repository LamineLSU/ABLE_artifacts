rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? ?? 5A 8B CE }
        $pattern1 = { 83 F8 ?? 74 ?? 8B 4D FC }
        $pattern2 = { DC 0F 31 F4 75 ?? 83 EC 08 }

    condition:
        any of them
}