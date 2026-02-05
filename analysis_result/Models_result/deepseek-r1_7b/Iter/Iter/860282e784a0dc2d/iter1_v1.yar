rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional jumps and EAX tests."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 0F 84 ?? ?? ?? ?? E8 C8 FF FF FF }
        $pattern1 = { ?? ?? 74 1A 75 08 E8 C8 FF FF FF }
        $pattern2 = { 6D 3C 8B EF ?? ?? ?? ?? FF 75 08 }
    condition:
        any of them
}