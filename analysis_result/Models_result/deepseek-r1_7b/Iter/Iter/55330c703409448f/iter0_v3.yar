rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns for stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8F 5A ?? ?? ?? ?? ?? ?? 0F 0F }
        $pattern1 = { 0F 4B ?? ?? ?? ?? ?? ?? ?? 8B EC }
        $pattern2 = { E8 C8 AC B0 41 00 ?? ?? ?? ?? FF C8 }
    condition:
        any of them
}