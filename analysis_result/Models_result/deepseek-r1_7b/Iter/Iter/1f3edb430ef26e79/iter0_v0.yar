rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 5E 8B 45 14 EC 55 39 4F 5A 8B 45 14 EC 55 39 4F }
        $pattern1 = { 8B 45 2C 50 8B EC 5D 8B 45 28 50 8B EC 5D 8B 45 34 50 }
        $pattern2 = { 8B 55 14 EC 5A 5E 6A 5D 8B 45 0C 50 8B EC 5D 8B 45 0C 50 }

    condition:
        any of them
}