rule Bypass_Evasion
{
    meta:
        description = "Bypass instructions to bypass EVLA"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? ?? ?? ?? 8D 4C }
        $pattern1 = { E8 AB 00 00 FF C4 ?? ?? ?? ?? 8D 4D }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8D 4E }

    condition:
        any of them
}