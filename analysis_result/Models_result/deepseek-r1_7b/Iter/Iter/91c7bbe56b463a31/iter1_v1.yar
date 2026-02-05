rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass for exit path"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 E8 75 ?? ?? 8B ?? ?? ?? ?? FF C0 }
        $pattern1 = { 56 F3 0A A9 8B ?? ?? ?? ?? FE A4 2F FA }
        $pattern2 = { 56 F3 AA 7E 8B ?? ?? ?? ?? FF }
}

condition:
    any of them
}