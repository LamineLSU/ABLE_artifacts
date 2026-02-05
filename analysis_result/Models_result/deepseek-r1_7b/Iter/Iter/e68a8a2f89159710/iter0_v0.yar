rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 1A 8B CE E8 ?? ?? ?? }
        $pattern1 = { E8 4B 5C FF ?? ?? 83 F8 ?? }
        $pattern2 = { E8 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}