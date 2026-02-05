rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting system call checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 ?F 75 7C ?? ?? ?? ?? 83 C4 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 45 ?? 05 1A 00 00 }

    condition:
        any of them
}