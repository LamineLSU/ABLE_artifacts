rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 0F ?? ?? . ?? }
        $pattern1 = { FF 15 A9 16 01 00 ?? } // Combines two calls with wildcards
        $pattern2 = { 8B 45 74 11 ?? ?? } // Push rbx and sub rsp,20h

    condition:
        any of them
}