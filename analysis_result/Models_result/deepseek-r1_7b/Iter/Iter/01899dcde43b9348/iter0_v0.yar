rule Bypass_MemoryBypass
{
    meta:
        description = "Memory access bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { FF 85 C0 ?? ?? ?? ?? 74 07 F8 F9 ?? ?? ?? ?? }
    condition:
        any of them
}