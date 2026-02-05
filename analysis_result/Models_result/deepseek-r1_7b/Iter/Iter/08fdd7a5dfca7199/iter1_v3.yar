rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule with multiple paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF FF75 08 E8 C8 FFFFFF }
        $pattern1 = { 74 ?? 6A 5A 00 00 }
        $pattern2 = { FF75 08 E8 C8 FFFFFF }

    condition:
        any of them
}