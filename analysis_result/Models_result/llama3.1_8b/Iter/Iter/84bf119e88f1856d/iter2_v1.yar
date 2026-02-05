rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 ?? E8 ?? ?? ?? ?? ?? }
        $pattern1 = { CA ?? ?? ?? ?? EA EE 59 FF 75 ?? }
        $pattern2 = { ?? ?? ?? ?? 6A ?? 5A 8B CE }

    condition:
        any of them
}