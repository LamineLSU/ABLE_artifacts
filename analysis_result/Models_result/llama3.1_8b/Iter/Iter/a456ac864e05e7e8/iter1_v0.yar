rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$p0+0,action0=skip,bp1=$p1+0,action1=skip,bp2=$p2+0,action2=skip,count=0"

    strings:
        $p0 = { CA ?? ?? ?? ?? ?? }
        $p1 = { 8B ?? 05 ?? ?? ?? ?? ?? }
        $p2 = { DC ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}