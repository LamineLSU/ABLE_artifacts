rule Bypass_Evasion_0x0F361F8
{
    meta:
        description = "Evasion bypass at 0x0F361F8"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 5A 8B CE E8 ?? ?? ?? ?? ?? }

    condition:
        any of them
}