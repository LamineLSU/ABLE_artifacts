rule Bypass_Evasion
{
    meta:
        description = "Bypass exit process call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 55 C3 E8 ?? ?? ?? 09 EC }
        $pattern1 = { E8 ?? 4B 0A 8B 45 08 5E ?? ?? 83 C4 14 52 ?? 5F 7D ?? }
        $pattern2 = { 6A 36 8B ?? 19 48 ?? }

    condition:
        any of them
}