rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 83 EC ?? 56 B9 00 00 00 00 FF D0 }
        $pattern1 = { 8B 45 FC 3D 00 10 00 00 0F 82 ?? ?? ?? ?? }
        $pattern2 = { E8 C1 FF FF FF FF 5A }

    condition:
        all of them
}