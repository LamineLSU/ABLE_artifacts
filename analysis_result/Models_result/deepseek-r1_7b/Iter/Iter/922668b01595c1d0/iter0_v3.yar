rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 C8 5E FE FF FF ?? ?? ?? 7E 4D 53 54 6F }
        $pattern1 = { 6A 4B ?? FE FF FF ?? ?? ?? 4D 5C 6D 5E }
        $pattern2 = { ?? 85 C0 5E FF FF ?? ?? ?? 7E 4D 53 54 6F }

    condition:
        any of them
}