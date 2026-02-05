rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific call instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { TEST EAX JNZ 8B ?? ?? ?? ?? 5E 45 ?? }
        $pattern1 = { 75 0C 8B ?? ?? ?? ?? 83 C4 6A ?? ?? ?? ?? }
        $pattern2 = { 74 ?? 8B ?? ?? ?? ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}