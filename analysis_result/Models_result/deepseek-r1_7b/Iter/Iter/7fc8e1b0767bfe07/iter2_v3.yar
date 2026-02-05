rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass exploiting early exit conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B ?? }
        $pattern1 = { E8 B3 03 00 0A 18 85 0D ?? }
        $pattern2 = { E8 0D 0C 00 CA ?? }
    condition:
        any of them
}