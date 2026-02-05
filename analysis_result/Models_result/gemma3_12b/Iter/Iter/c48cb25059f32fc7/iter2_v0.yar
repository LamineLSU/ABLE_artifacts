rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 94 FD FF FF 8D 85 78 FD FF FF }
        $pattern1 = { 83 F8 01 74 12 8B 85 78 FD FF FF }
        $pattern2 = { 3D 00 10 00 00 0F 82 ?? ?? ?? ?? }

    condition:
        any of them
}