rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B E5 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 3D ?? ?? ?? ?? 00 74 12 8B 4D F8 }
        $pattern2 = { B9 ?? ?? ?? ?? FF D0 }

    condition:
        any of them
}