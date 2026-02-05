rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 F0 FE FF FF ?? ?? ?? ?? 83 EC 08 ?? }
        $pattern1 = { 33 DB ?? ?? ?? ?? 6A ?? 5A 8B CE }
        $pattern2 = { BA 04 01 00 00 ?? ?? ?? ?? E9 ?? ?? ?? ?? }

    condition:
        any of them
}