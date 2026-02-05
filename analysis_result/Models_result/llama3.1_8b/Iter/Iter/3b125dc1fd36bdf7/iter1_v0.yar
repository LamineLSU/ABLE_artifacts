rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }
        $pattern1 = { 8B FF 55 8B EC 83 EC 48 56 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 3D 00 10 00 00 0F 82 ?? ?? }

    condition:
        any of them
}