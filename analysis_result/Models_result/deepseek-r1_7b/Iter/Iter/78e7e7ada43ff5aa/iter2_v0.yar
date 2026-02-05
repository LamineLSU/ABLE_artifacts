rule Bypass_EvasionPoint
{
    meta:
        description = "Evasion bypass rules targeting specific memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 5A ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { FF C9 FC 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF C9 FC F4 83 C4 ?? 85 C0 }

    condition:
        any of them
}