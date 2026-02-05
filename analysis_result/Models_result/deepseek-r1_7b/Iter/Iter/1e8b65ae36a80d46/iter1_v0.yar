rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B E7 F6 ?? ?? ?? ?? 5A EC ?F }
        $pattern1 = { FF C8 F3 ?? ?? ?? ?? 8B EC F6 ?? ?? ?? ?? 40 F7 5C }
        $pattern2 = { 8B E7 F3 ?? ?? ?? ?? 5A EC ?F }

    condition:
        any of them
}