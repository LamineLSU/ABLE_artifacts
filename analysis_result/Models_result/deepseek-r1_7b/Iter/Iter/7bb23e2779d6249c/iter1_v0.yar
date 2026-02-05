rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass exploiting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C7 59 FF 15 AC B0 41 00 }
        $pattern1 = { E8 4B ?? ?? ?? ?? 33 FF }
        $pattern2 = { E8 C8 75 08 8E 0A }

    condition:
        any of them
}