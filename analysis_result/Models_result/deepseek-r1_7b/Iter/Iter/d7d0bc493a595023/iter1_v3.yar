rule bypass_sample_evolved
{
    meta:
        description = "Bypass sample evasion using multiple distinct patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 ?? ?? ?? ?? E8 C1 FF FF FF }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { 8B EC ?? ?? ?? ?? FF 75 08 }

    condition:
        any of them
}