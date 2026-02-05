rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - RDTSC followed by TEST EAX"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 4B 83 C0 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 6A 00 ?? ?? ?? ?? 8B F9 FF }
        $pattern2 = { 8D 4D ?? ?? ?? ?? E8 A2 03 }

    condition:
        any of them
}